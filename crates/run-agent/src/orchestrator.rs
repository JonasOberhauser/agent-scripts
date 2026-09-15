use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fuse_protocol::SystemIo;
use tracing::{info, warn};

use crate::config::{
    build_create_args, build_exec_args, AgentConfig, NESTED_SECCOMP_PROFILE,
};

/// The agentbox Dockerfile, embedded into the binary at compile time
/// (`include_str!`).  It is the single source for rebuilding the image:
/// no runtime discovery of repo checkouts (the binary may be installed
/// anywhere) — the file is materialized into a temp path on demand.
/// The Dockerfile must stay COPY/ADD-free so any build context works.
const EMBEDDED_DOCKERFILE: &str = include_str!("../../../Dockerfile");

/// The Dockerfile content used for image builds.  Debug builds honor
/// `RUN_AGENT_TEST_DOCKERFILE` (path) so tests can substitute a trivial
/// image; release builds always use the embedded copy.
fn dockerfile_content() -> Result<String, String> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("RUN_AGENT_TEST_DOCKERFILE") {
        return std::fs::read_to_string(p)
            .map_err(|e| format!("RUN_AGENT_TEST_DOCKERFILE: {e}"));
    }
    Ok(EMBEDDED_DOCKERFILE.to_string())
}

/// Run a runtime command with **inherited stdio** so long-running work
/// (image builds/pulls) streams its progress to the user live.
fn run_streamed<S: SystemIo>(
    io: &S,
    wrapper: Option<&str>,
    container_bin: &str,
    args: &[&str],
) -> Result<i32, String> {
    match wrapper {
        Some(w) => {
            let parts: Vec<&str> = w.split_whitespace().collect();
            let mut full: Vec<&str> = parts[1..].to_vec();
            full.push(container_bin);
            full.extend(args.iter());
            io.run_interactive(parts[0], &full)
        }
        None => io.run_interactive(container_bin, args),
    }
    .map_err(|e| format!("spawn {container_bin}: {e}"))
}

/// Result of a completed agent session.
#[derive(Debug)]
pub struct RunResult {
    pub container_exit_code: i32,
    pub reset_ok: bool,
    pub server_was_spawned: bool,
}

// ── mount-point recovery ───────────────────────────────────────

/// Run `prog args`, prefixed with the runtime wrapper (e.g.
/// `flatpak-spawn --host`) when one is configured. Returns whether the
/// command reported success.
fn run_wrapped<S: SystemIo>(io: &S, wrapper: Option<&str>, prog: &str, args: &[&str]) -> bool {
    let mut parts: Vec<String> = Vec::new();
    if let Some(w) = wrapper {
        let (wrapped, prefix) = crate::config::split_wrapper(w);
        parts.push(wrapped);
        parts.extend(prefix);
    }
    parts.push(prog.to_string());
    parts.extend(args.iter().map(|s| s.to_string()));
    let argv: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();
    io.run_command(&parts[0], &argv)
        .map(|o| o.success())
        .unwrap_or(false)
}

/// Try to clear a stale FUSE mount from `mount_point` with a lazy
/// unmount, trying the available unmount helpers in turn. Returns true
/// when one of them reports success.
fn lazy_unmount<S: SystemIo>(io: &S, mount_point: &str, wrapper: Option<&str>) -> bool {
    for (cmd, flag) in [("fusermount", "-uz"), ("fusermount3", "-uz"), ("umount", "-l")] {
        if run_wrapped(io, wrapper, cmd, &[flag, mount_point]) {
            info!("Lazy unmount succeeded via {cmd} {flag}");
            return true;
        }
    }
    false
}

/// Tear down the whole gatekeeper stack — the same sequence
/// `fuse-client restart` performs — so a fresh one can be built:
/// kill the policy server (its supervised data daemon dies with it)
/// and any *orphaned* `fused` (manually restarted, or parent killed
/// with SIGKILL — its mount keeps answering with stale listings),
/// then clear the dead mount, the stale socket, and the mountpoint.
fn teardown_stack<S: SystemIo>(io: &mut S, config: &AgentConfig) {
    let wrapper = config.runtime_wrapper.as_deref();
    run_wrapped(io, wrapper, "pkill", &["-f", "fuse-server"]);
    run_wrapped(io, wrapper, "pkill", &["-x", "fused"]);
    io.sleep_ms(500);

    lazy_unmount(io, &config.mount_point.to_string_lossy(), wrapper);
    io.sleep_ms(200);
    if io.file_exists(&config.socket_path) {
        let _ = io.remove_path(&config.socket_path);
    }
    let _ = io.remove_path(&config.mount_point);
}

/// Ask the running server for its version. `Ok(None)` when the reply
/// is not a version response; `Err` when the command failed or the
/// payload was unparseable.
fn server_version<F>(send: &F) -> Result<Option<String>, String>
where
    F: Fn(&str, &str) -> Result<String, String>,
{
    let payload = send("version", "")?;
    let resp: fuse_protocol::Response =
        serde_json::from_str(payload.trim()).map_err(|e| format!("unparseable reply: {e}"))?;
    match resp {
        fuse_protocol::Response::Version { version } => Ok(Some(version)),
        _ => Ok(None),
    }
}

/// Whether a failed pre-flight justifies rebuilding the stack: a
/// broken mount side does (an orphaned or dead mount heals by
/// respawning server + data daemon), a missing host-side source file
/// does not — no rebuild can bring the user's file back.
fn preflight_should_rebuild(results: &[crate::preflight::CheckResult]) -> bool {
    let mount_broken = results
        .iter()
        .any(|r| !r.ok && r.check == "fuse-mount");
    let host_broken = results
        .iter()
        .any(|r| !r.ok && r.check == "source-file");
    mount_broken && !host_broken
}

/// Make sure `mount_point` is a usable plain directory (issue #23).
///
/// Decides via [`SystemIo::path_state`] — no errno-string guessing:
/// - `Dir` — a plain directory or a **live** mount: nothing to do.
/// - `Missing` — create it.
/// - `File` — a regular file blocks the name: remove, create.
/// - `Unreachable` — the name exists but stat fails: a **dead FUSE
///   mount** (the data daemon died). Clear it with a lazy unmount,
///   wait, and re-probe; only an unclearable mount aborts, with the
///   manual remediation spelled out.
fn ensure_mount_point<S: SystemIo>(
    io: &mut S,
    mount_point: &Path,
    wrapper: Option<&str>,
) -> Result<(), String> {
    use fuse_protocol::PathState;

    fn create(io: &impl SystemIo, mp: &Path) -> Result<(), String> {
        io.create_dir_all(mp)
            .map_err(|e| format!("cannot create mount point {}: {e}", mp.display()))
    }

    match io.path_state(mount_point) {
        PathState::Dir => return Ok(()),
        PathState::Missing => return create(io, mount_point),
        PathState::File => {
            io.remove_path(mount_point).map_err(|e| {
                format!(
                    "a file blocks the mount point {} and cannot be removed: {e}",
                    mount_point.display()
                )
            })?;
            info!("Removed a file blocking the mount point {}", mount_point.display());
            return create(io, mount_point);
        }
        PathState::Unreachable(_) => {}
    }

    // Dead mount: clear it, wait for the lazy unmount, re-probe.
    lazy_unmount(io, &mount_point.to_string_lossy(), wrapper);
    io.sleep_ms(200);
    match io.path_state(mount_point) {
        PathState::Dir | PathState::Missing => {
            info!("Recovered mount point {} from a stale FUSE mount", mount_point.display());
            create(io, mount_point)
        }
        state @ (PathState::File | PathState::Unreachable(_)) => {
            // File: remove + create, same as above. Unreachable: give up
            // with the manual remediation.
            if matches!(state, PathState::File) {
                io.remove_path(mount_point).map_err(|e| {
                    format!(
                        "a file blocks the mount point {} and cannot be removed: {e}",
                        mount_point.display()
                    )
                })?;
                return create(io, mount_point);
            }
            Err(format!(
                "cannot use mount point {}: a stale FUSE mount is blocking it and could not be \
                 cleared.\n\
                 Recover manually with:\n  \
                 fusermount -uz {m} && rm -rf {m}\n  \
                 (root-owned: sudo umount -l {m} && sudo rm -rf {m})\n\
                 or run: fuse-client restart",
                mount_point.display(),
                m = mount_point.display(),
            ))
        }
    }
}


/// Full orchestration loop — the Rust replacement for `run-agent.sh`.
///
/// The fuse-server is **shared**: `run-agent` probes for an existing server
/// at the well-known socket path.  If none is found it spawns one as an
/// independent daemon (survives `run-agent`'s exit).  The secret is then
/// added at runtime via the socket, not via a `--secret` CLI flag.
///
/// Steps:
/// 1. Validate workspace directories.
/// 2. Probe for an existing fuse-server (discovery).
/// 3. If none: spawn independent server, wait for socket.
/// 4. Expand secrets (walk directories), load each file into FUSE,
///    create symlinks inside the config directory.
/// 5. Detect container runtime.
/// 6. Run the container (foreground).
/// 7. **Auto-reset** all secret counters.
/// 8. Done (server stays running, symlinks persist).
pub fn run_agent<S, F>(
    io: &mut S,
    config: &AgentConfig,
    send: &F,
    restart_container: bool,
) -> Result<RunResult, String>
where
    S: SystemIo,
    F: Fn(&str, &str) -> Result<String, String>,
{
    // ── 1. Generate missing workspace folders ────────────────────
    // The agent's structure (config/, workspace/, fuse_mnt/) is created
    // when missing — a fresh agent path just works. The fuse bind source
    // especially must exist BEFORE the container is created: docker/
    // podman would generate it root-owned, breaking later host access.
    let host_config = config.host_config_dir();
    let host_workspace = config.host_workspace();
    for dir in [&host_config, &host_workspace] {
        io.create_dir_all(dir).map_err(|e| {
            format!(
                "cannot create {}: {e}.\n\
                 Is the agent path writable (or does a file block the name)?",
                dir.display()
            )
        })?;
    }
    // The fuse mountpoint is special: after the data daemon (`fused`)
    // dies, the kernel keeps a dead mount on the name — mkdir returns
    // EEXIST and stat fails (ENOTCONN), so create_dir_all errors with
    // "File exists" (issue #23). Recover instead of aborting: lazy-
    // unmount, then retry; a plain file blocking the name is removed.
    ensure_mount_point(io, &config.mount_point, config.runtime_wrapper.as_deref())?;
    info!("Workspace folders ready.");

    // Mounting is CLIENT-side orchestration: run-agent owns the data
    // daemon. A missing fused must abort here, loudly — never degrade
    // into a mount-less server accepting adds into an empty directory
    // (the PR #37 field report).
    if config.fused_path.as_os_str().is_empty() || !io.file_exists(&config.fused_path) {
        return Err(
            "data daemon (`fused`) not found — no mount can come up.\n\
             Build it and re-run: cargo build --workspace"
                .to_string(),
        );
    }

    // ── 2..4.5  Build-and-verify loop ────────────────────────────
    // The stack (server + data daemon + mount) can turn out stale at
    // pre-flight — e.g. an orphaned `fused` still owns the mount and
    // every secret reads as missing (issue #23).  Steps 2 through 4.5
    // therefore run as a loop: on an out-of-sync pre-flight the whole
    // stack is torn down and rebuilt ONCE (same sequence as
    // `fuse-client restart`) before giving up with the manual
    // remediation.
    let socket = &config.socket_path;
    let mut server_was_spawned;
    let mut stack_rebuilds = 0u8;
    let mut force_respawn = false;

    let loaded = loop {
        let mut spawned_server_pid = 0u32;
        let mut server_healthy = false;
        server_was_spawned = false;

        // After a teardown there is nothing to reuse by construction —
        // and the (mocked) socket may still claim to answer.
        let reuse_existing = !force_respawn && io.try_unix_connect(socket);
        if reuse_existing {
        // A successful connect() is not proof of life: a crashed or wedged
        // server leaves the socket behind and the kernel still accepts on
        // the backlog — later adds then die with 'Broken pipe'.  Do a real
        // read-only round-trip before trusting the server.
        match send("status", "") {
            Ok(_) => {
                info!("Reusing existing fuse-server at {}", socket.display());
                server_healthy = true;
            }
            Err(e) => {
                warn!(
                    "fuse-server at {} accepted a connection but failed the health check ({e}) \
                     — it is stale or wedged; respawning a fresh server",
                    socket.display()
                );
            }
        }
        }

        if !server_healthy {
            // ── 3. Spawn independent server ───────────────────────────
            server_was_spawned = true;
            if !io.try_unix_connect(socket) {
                info!("No fuse-server found — spawning a new one.");
            }

            // Clean up stale socket file (e.g., root-owned from a previous
            // --sudo run, or leftover from a crashed server).
            if io.file_exists(socket) {
                info!("Removing stale socket at {}", socket.display());
                io.remove_path(socket).map_err(|e| format!(
                    "Cannot remove stale socket {}: {e}.\n\
                     If it is root-owned from a previous --sudo run:\n  \
                     flatpak-spawn --host sudo rm -f {}",
                    socket.display(),
                    socket.display(),
                ))?;
            }

            // Ensure the mount point is fresh and owned by the current user.
            // Always try to clean up stale mounts/ownership, even if the
            // directory already exists (create_dir_all succeeds on an
            // existing dir, but fusermount may still fail if it's root-owned
            // or has a stale FUSE mount).
            {
                let mount_str = config.mount_point.to_string_lossy().to_string();
                let wrapper = config.runtime_wrapper.as_deref();

                // Try lazy unmount to clear any stale FUSE mount.
                lazy_unmount(io, &mount_str, wrapper);

                // Wait for lazy unmount, then remove + recreate.
                std::thread::sleep(std::time::Duration::from_millis(200));
                let _ = io.remove_path(&config.mount_point);

                io.create_dir_all(&config.mount_point).map_err(|e| format!(
                    "create mount point {}: {e}.\n\
                     If the problem persists, run manually:\n  \
                     fusermount -uz {} && rm -rf {}",
                    config.mount_point.display(),
                    config.mount_point.display(),
                    config.mount_point.display(),
                ))?;

                // Make the mount point 'shared' so that mount changes (FUSE
                // unmount/remount on server restart) propagate to container
                // bind mounts with 'slave' propagation.
                {
                    let mount_str2 = config.mount_point.to_string_lossy().to_string();
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(w) = wrapper {
                        let (prog, prefix) = crate::config::split_wrapper(w);
                        parts.push(prog);
                        parts.extend(prefix);
                    }
                    parts.push("mount".to_string());
                    parts.push("--make-shared".to_string());
                    parts.push(mount_str2);
                    let prog = parts[0].clone();
                    let args: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();
                    let _ = io.run_command(&prog, &args);
                }
            }

            let sock = socket
                .to_str()
                .ok_or_else(|| format!("socket path is not valid UTF-8: {}", socket.display()))?;
            // Policy-only: the data daemon is spawned by run-agent
            // directly below — mounting must not depend on the
            // server's build state or co-located binaries.
            let mut fuse_args: Vec<&str> = vec![
                "--socket", sock,
            ];
            if config.allow_other {
                fuse_args.push("--allow-other");
            }
            fuse_args.push("--log-level");
            let log_level_str = config.log_level.clone();
            fuse_args.push(&log_level_str);
            let args = fuse_args;

            let server_bin = config
                .fuse_server_path
                .to_str()
                .ok_or_else(|| format!("fuse-server path is not valid UTF-8: {}", config.fuse_server_path.display()))?;

            let log_path = config.agent_path.join("fuse-server.log");
            let log_str = log_path.to_str()
                .ok_or_else(|| format!("log path is not valid UTF-8: {}", log_path.display()))?;

            // If using sudo, pre-authenticate interactively (with terminal
            // access) so the detached daemon can use `sudo -n` without one.
            if config.use_sudo {
                let mut auth_parts: Vec<String> = Vec::new();
                if let Some(w) = &config.runtime_wrapper {
                    let (prog, prefix) = crate::config::split_wrapper(w);
                    auth_parts.push(prog);
                    auth_parts.extend(prefix);
                }
                auth_parts.push("sudo".into());
                auth_parts.push("-v".into());

                let auth_prog = auth_parts[0].clone();
                let auth_args: Vec<&str> = auth_parts[1..].iter().map(|s| s.as_str()).collect();

                info!("Pre-authenticating sudo (enter your password if prompted)...");
                let exit = io
                    .run_interactive(&auth_prog, &auth_args)
                    .map_err(|e| format!("sudo pre-authentication failed: {e}"))?;
                if exit != 0 {
                    return Err(format!("sudo pre-authentication returned exit code {exit}"));
                }
            }

            // Build the full argv.  The fuse-server must run in the same
            // mount namespace as the container, so when a runtime wrapper
            // (e.g. `flatpak-spawn --host`) is set we prepend it here too.
            let mut cmd_parts: Vec<String> = Vec::new();
            if let Some(w) = &config.runtime_wrapper {
                let (prog, prefix) = crate::config::split_wrapper(w);
                cmd_parts.push(prog);
                cmd_parts.extend(prefix);
            }
            if config.use_sudo {
                cmd_parts.push("sudo".into());
                cmd_parts.push("-n".into());
            }
            cmd_parts.push(server_bin.to_string());
            cmd_parts.extend(args.iter().map(|s| s.to_string()));

            let spawn_prog = cmd_parts[0].clone();
            let spawn_args: Vec<&str> = cmd_parts[1..].iter().map(|s| s.as_str()).collect();

            let pid = io
                .spawn_independent(&spawn_prog, &spawn_args, Some(std::path::Path::new(log_str)))
                .map_err(|e| format!("spawn fuse-server: {e}"))?;
            spawned_server_pid = pid;
            info!(
                "fuse-server spawned as independent daemon (pid {pid}, wrapper={}, sudo={}).",
                config.runtime_wrapper.is_some(),
                config.use_sudo,
            );

            // Wait for socket.
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if io.try_unix_connect(socket) {
                    break;
                }
                if Instant::now() > deadline {
                    let mut detail = String::new();
                    if let Ok(log) = io.read_file(&log_path) {
                        let log_str = String::from_utf8_lossy(&log);
                        if !log_str.trim().is_empty() {
                            detail = format!("\nfuse-server log:\n{log_str}");
                        }
                    }
                    return Err(format!(
                        "fuse-server socket did not appear within 10s (pid {pid} may have crashed){detail}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            info!("Socket ready at {}", socket.display());
        }

        // ── 3.5 Version handshake ───────────────────────────────────
        // The reused-or-spawned fuse-server may be a stale binary from
        // an older build — dev checkouts routinely mix vintages when
        // only some crates get rebuilt.  fuse-client has always checked
        // this; run-agent — the SPAWNER — must too, or a mixed-vintage
        // stack surfaces later as a mystery empty mount (PR #37).
        match server_version(send) {
            Ok(Some(v)) if !fuse_protocol::versions_compatible(&v, fuse_protocol::VERSION) => {
                warn!(
                    "fuse-server v{v} at {} is protocol-incompatible with this run-agent \
                     (v{}) — mixed-vintage binaries",
                    socket.display(),
                    fuse_protocol::VERSION
                );
                if stack_rebuilds == 0 {
                    stack_rebuilds += 1;
                    warn!("respawning the server from the current binaries and retrying once");
                    teardown_stack(io, config);
                    force_respawn = true;
                    continue;
                }
                break Err(format!(
                    "fuse-server v{v} is protocol-incompatible with run-agent v{} — the \
                     binaries are mixed-vintage. Rebuild everything: cargo build --workspace",
                    fuse_protocol::VERSION
                ));
            }
            Ok(_) => {}
            Err(e) => {
                // Cannot determine (ancient server without the version
                // command, or a transient failure) — proceed, loudly.
                warn!("could not verify fuse-server version ({e}) — proceeding");
            }
        }

        // ── 3.6 Data daemon ─────────────────────────────────────────
        // On a fresh stack run-agent mounts directly: fused is spawned
        // HERE (independent — survives run-agent AND policy-daemon
        // restarts, per the split design), connecting to the server's
        // oracle socket (both default to the same path). On a reused
        // healthy stack the existing mount stays; if it is gone or out
        // of sync, pre-flight triggers the rebuild path which respawns
        // everything, fused included.
        if server_was_spawned {
            let fused_str = config
                .fused_path
                .to_str()
                .ok_or_else(|| format!("fused path is not valid UTF-8: {}", config.fused_path.display()))?;
            let mountpoint_str = config.mount_point.to_string_lossy().to_string();
            let mut fused_parts: Vec<String> = Vec::new();
            if let Some(w) = &config.runtime_wrapper {
                let (prog, prefix) = crate::config::split_wrapper(w);
                fused_parts.push(prog);
                fused_parts.extend(prefix);
            }
            fused_parts.push(fused_str.to_string());
            fused_parts.push("--mount-point".into());
            fused_parts.push(mountpoint_str.clone());
            fused_parts.push("--log-level".into());
            fused_parts.push(config.log_level.clone());
            let fused_prog = fused_parts[0].clone();
            let fused_args: Vec<&str> = fused_parts[1..].iter().map(|s| s.as_str()).collect();
            let fused_pid = io
                .spawn_independent(&fused_prog, &fused_args, None)
                .map_err(|e| format!("spawn data daemon (fused): {e}"))?;
            info!(
                "data daemon (fused) spawned independently (pid {fused_pid}) — mount at {}",
                config.mount_point.display()
            );
        }

        // ── 4. Expand + load secrets into FUSE ───────────────────────
        let pid = std::process::id();
        let mut counter = 0usize;
        let mut loaded: Vec<LoadedSecret> = Vec::new();

        for mapping in &config.secrets {
            load_secret_recursive(
                io, send, &mapping.host, &mapping.container,
                config, pid, &mut counter, &mut loaded,
            )?;
        }

        // Write state file so fuse-client can restart the server if needed.
        write_state_file(config, &loaded, io, spawned_server_pid);

        // ── 4.5 Pre-flight: every hosted secret must be reachable ───
        // A stale or dead FUSE mount would hang the box on first read with no
        // diagnostic; fail fast with an actionable message instead.
        let results = crate::preflight::run(
            io,
            &loaded,
            &config.mount_point,
            crate::preflight::DEFAULT_TIMEOUT_SECS,
        );
        for r in &results {
            if r.ok {
                info!("{r}");
            } else {
                warn!("{r}");
            }
        }
        if let Some(err) = crate::preflight::failure_summary(&results) {
            if preflight_should_rebuild(&results) && stack_rebuilds == 0 {
                stack_rebuilds += 1;
                warn!(
                    "pre-flight: server and mount are out of sync — tearing down and \
                     rebuilding the gatekeeper stack (fuse-server + data daemon + mount), \
                     then retrying once"
                );
                teardown_stack(io, config);
                force_respawn = true;
                continue;
            }
            let err = if stack_rebuilds > 0 {
                format!(
                    "{err}\nAutomatic stack rebuild did not help — manual repair: \
                     `fuse-client restart`"
                )
            } else {
                err
            };
            break Err(err);
        }

        break Ok(loaded);
    };

    let loaded = loaded?;

    // ── 5. Detect container runtime ──────────────────────────────
    let wrapper = config.runtime_wrapper.as_deref();
    let container_bin = match config.runtime.resolve(io, wrapper) {
        Some(bin) => bin,
        None => {
            return Err("Specified container runtime not available.".into());
        }
    };
    info!("Using container runtime: {container_bin}");

    if container_bin == "docker" && wrapper.is_none() {
        setup_rootless_docker();
    }

    // ── 5.5 Materialize the seccomp profile referenced by
    // `--security-opt` in the create args.  Must exist on the host
    // before `podman/docker run` reads it.
    io.write_file(&config.seccomp_profile, NESTED_SECCOMP_PROFILE.as_bytes())
        .map_err(|e| {
            format!(
                "cannot write seccomp profile {}: {e}",
                config.seccomp_profile.display()
            )
        })?;

    // Pass through the char devices nested rootless podman needs, when
    // the host has them: /dev/fuse for fuse-overlayfs storage (and FUSE
    // work generally), /dev/net/tun for pasta/slirp networking.
    let passthrough_devices: Vec<String> = ["/dev/fuse", "/dev/net/tun"]
        .into_iter()
        .filter(|d| io.file_exists(std::path::Path::new(d)))
        .map(str::to_string)
        .collect();

    // ── 6. Ensure persistent container is running ────────────────
    let container_name = config.container_name();

    if restart_container {
        info!("Restarting container {container_name}...");
        gentle_stop(io, wrapper, container_bin, &container_name);
        let _ = run_with_wrapper(io, wrapper, container_bin, &["rm", "-f", &container_name]);
    }

    match check_container_running(io, wrapper, container_bin, &container_name) {
        Some(true) => {
            info!("Reusing running container {container_name}.");
        }
        Some(false) => {
            // The container exists but is stopped.  `start` (never recreate)
            // re-applies the `-v` binds against the CURRENT host mounts —
            // which also heals a /fuse bind that went stale across a
            // host-side FUSE remount — and preserves all container data.
            info!(
                "Container {container_name} exists but is stopped — starting it \
                 (bind mounts are re-applied, data preserved)..."
            );
            match run_with_wrapper(io, wrapper, container_bin, &["start", &container_name]) {
                Ok(o) if o.success() => {
                    info!("Container started.");
                }
                Ok(o) => {
                    return Err(format!(
                        "Failed to start container {}: exit {}\nstdout: {}\nstderr: {}",
                        container_name,
                        o.status.unwrap_or(-1),
                        o.stdout,
                        o.stderr
                    ));
                }
                Err(e) => {
                    return Err(format!("Failed to start container {container_name}: {e}"));
                }
            }
        }
         None => {
            // ── 6.4 Fail fast on a missing image (issue #1) ─────────
            // A missing image must never reach headless `podman run`.
            ensure_image_available(io, wrapper, container_bin, config)?;

            info!("Creating persistent container {container_name}...");
            let create_args = build_create_args(config, &passthrough_devices);
            let create_refs: Vec<&str> = create_args.iter().map(|s| s.as_str()).collect();
            match run_with_wrapper(io, wrapper, container_bin, &create_refs) {
                Ok(o) if o.success() => {
                    info!("Container created.");
                }
                Ok(o) => {
                    return Err(format!(
                        "Failed to create container: exit {}\nstdout: {}\nstderr: {}",
                        o.status.unwrap_or(-1), o.stdout, o.stderr
                    ));
                }
                Err(e) => {
                    return Err(format!("Failed to create container: {e}"));
                }
            }
        }
    }

    // ── 6.5 Container-side FUSE pre-flight (heal stale /fuse binds) ──
    verify_container_fuse(io, wrapper, container_bin, &container_name, &loaded)?;

    // ── 7. Exec into container (setup script creates symlinks) ───
    let setup_script = build_setup_script(&loaded);
    let args = build_exec_args(config, &setup_script);
    let exit_code = if let Some(w) = wrapper {
        let (prog, prefix) = crate::config::split_wrapper(w);
        let mut full: Vec<&str> = prefix.iter().map(|s| s.as_str()).collect();
        full.push(container_bin);
        full.extend(args.iter().map(|s| s.as_str()));
        io.run_interactive(&prog, &full).unwrap_or(-1)
    } else {
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        io.run_interactive(container_bin, &arg_refs).unwrap_or(-1)
    };
    // The session may have died hard (e.g. the container was stopped
    // under it) without restoring the terminal it borrowed from us —
    // heal ours before saying goodbye.
    io.heal_terminal();
    if exit_code == 0 {
        info!("Session exited with code 0.");
    } else {
        warn!("Session exited with code {exit_code}.");
    }

    // ── 7. Auto-reset all secret counters ────────────────────────
    let mut reset_ok = true;
    for s in &loaded {
        match send("reset", &s.fuse_name) {
            Ok(_) => {
                info!("Auto-reset successful for '{}'.", s.fuse_name);
            }
            Err(e) => {
                warn!("Auto-reset failed for '{}': {e}", s.fuse_name);
                reset_ok = false;
            }
        }
    }

    // ── 8. Done ──────────────────────────────────────────────────
    Ok(RunResult {
        container_exit_code: exit_code,
        reset_ok,
        server_was_spawned,
    })
}

/// A secret loaded into the FUSE server, ready to be symlinked.
pub(crate) struct LoadedSecret {
    pub(crate) fuse_name: String,
    pub(crate) container: PathBuf,
    pub(crate) host_path: PathBuf,
}

/// Recursively load a secret file or directory into the FUSE server.
///
/// Destination semantics match `cp`:
/// - File + `/dir/` (trailing slash) → file placed inside dir as `dir/basename`
/// - File + `/dir/name` → file placed at exact path
/// - Dir + `/dest` → directory contents mapped under `dest/`
/// - Dir + `/dest/` → same (contents mapped under `dest/`)
///
/// FUSE-visible secret name carrying the sanitized host file name
/// (issue #18): recognizable in /fuse listings and pending requests,
/// while the pid/counter prefix keeps it collision-free.
fn secret_name(host: &Path, pid: u32, counter: usize) -> String {
    let safe: String = host
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        format!("p{pid}_s{counter}")
    } else {
        format!("p{pid}_s{counter}_{safe}")
    }
}

#[allow(clippy::too_many_arguments)]
fn load_secret_recursive<S, F>(
    io: &mut S,
    send: &F,
    host: &Path,
    container: &Path,
    config: &AgentConfig,
    pid: u32,
    counter: &mut usize,
    loaded: &mut Vec<LoadedSecret>,
) -> Result<(), String>
where
    S: SystemIo,
    F: Fn(&str, &str) -> Result<String, String>,
{
    if io.is_dir(host) {
        let entries = io
            .list_dir(host)
            .map_err(|e| format!("list dir {}: {e}", host.display()))?;
        for entry in entries {
            let name = entry
                .file_name()
                .ok_or_else(|| format!("invalid path: {}", entry.display()))?;
            load_secret_recursive(
                io, send, &entry, &container.join(name),
                config, pid, counter, loaded,
            )?;
        }
        return Ok(());
    }

    // ── Single file ──
    // cp semantics: if container ends with '/', it's a directory destination.
    let dest = resolve_dest(host, container);

    // Names carry the host file name (issue #18): p{pid}_s{n}_{file}
    // so /fuse listings and pending requests are recognizable.  The
    // pid/counter prefix keeps names collision-free even when two
    // secrets share a file name.
    let fuse_name = secret_name(host, pid, *counter);
    *counter += 1;

    let args = format!("{} {} {}", fuse_name, host.display(), config.binary_hash);
    send("add", &args)
        .map_err(|e| format!("failed to add secret {fuse_name}: {e}"))?;

    info!("Secret loaded: {} → /fuse/{fuse_name}", host.display());

    loaded.push(LoadedSecret {
        fuse_name,
        container: dest,
        host_path: host.to_path_buf(),
    });
    Ok(())
}

/// Resolve the actual container destination path.
///
/// `cp foo/x.txt bar/`   → `bar/x.txt`   (trailing slash = directory dest)
/// `cp foo/x.txt bar/y`  → `bar/y`       (no trailing slash = explicit name)
fn resolve_dest(host: &Path, container: &Path) -> PathBuf {
    if container.to_string_lossy().ends_with('/') {
        if let Some(basename) = host.file_name() {
            return container.join(basename);
        }
    }
    container.to_path_buf()
}

/// Build a shell snippet that creates symlinks inside the container.
/// Each entry: `mkdir -p "$(dirname PATH)" && ln -sf /fuse/NAME PATH`
fn build_setup_script(loaded: &[LoadedSecret]) -> String {
    loaded
        .iter()
        .map(|s| {
            let target = format!("/fuse/{}", s.fuse_name);
            let path = s.container.to_string_lossy();
            format!("mkdir -p \"$(dirname {path})\" && ln -sf {target} {path}")
        })
        .collect::<Vec<_>>()
        .join(" && ")
}

fn setup_rootless_docker() {
    let sock = format!("unix://{}", crate::config::rootless_docker_socket());
    std::env::set_var("DOCKER_HOST", &sock);
    info!("Docker rootless socket: {sock}");
}

/// Run a container runtime command, optionally prefixed with the wrapper.
fn run_with_wrapper<S: SystemIo>(
    io: &S,
    wrapper: Option<&str>,
    runtime: &str,
    args: &[&str],
) -> Result<fuse_protocol::CommandOutput, fuse_protocol::IoError> {
    match wrapper {
        Some(w) => {
            let parts: Vec<&str> = w.split_whitespace().collect();
            let mut full: Vec<&str> = parts[1..].to_vec();
            full.push(runtime);
            full.extend(args.iter());
            io.run_command(parts[0], &full)
        }
        None => io.run_command(runtime, args),
    }
}

/// Check whether a named container is currently running.
/// Inspect a container's running state.
/// `Some(is_running)` when the container exists; `None` when it does not.
/// Ask an interactive user `prompt` (y/N) with a 10s countdown.  No TTY,
/// timeout, or anything but an affirmative answer counts as No.
fn prompt_yes_no(prompt: &str) -> bool {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return false;
    }
    eprint!("{prompt} [y/N] (default N in 10s): ");
    let _ = std::io::stderr().flush();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        let _ = tx.send(line);
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(line) => matches!(line.trim(), "y" | "Y" | "yes"),
        Err(_) => {
            eprintln!("(timeout — defaulting to No)");
            false
        }
    }
}

/// How to create a missing image.
enum Remedy {
    /// Build from the embedded Dockerfile, materialized into a temp path.
    Build { dockerfile: PathBuf },
    /// Pull a fully-qualified reference from its registry.
    Pull,
}

/// Fail fast on a missing image instead of delegating to headless
/// `podman run` (which dies with a config-dependent registry error —
/// issue #1).  Prints the exact remediation command and, for interactive
/// users (or `--yes`), creates the image right away.
fn ensure_image_available<S: SystemIo>(
    io: &S,
    wrapper: Option<&str>,
    container_bin: &str,
    config: &AgentConfig,
) -> Result<(), String> {
    let image = &config.image_name;
    // `image exists` is podman-native; docker only has `image inspect`
    // (exit != 0 when missing).
    let probe = |io: &S| {
        let args: Vec<&str> = if container_bin == "docker" {
            vec!["image", "inspect", "-f", "{{.Id}}", image]
        } else {
            vec!["image", "exists", image]
        };
        run_with_wrapper(io, wrapper, container_bin, &args)
            .map(|o| o.success())
            .unwrap_or(false)
    };
    if probe(io) {
        return Ok(());
    }

    // A fully-qualified reference comes from a registry → pull it.
    // A local-only short name (the `agentbox` default) → build from the
    // embedded Dockerfile in a temp location.
    let tmp_ctx = std::env::temp_dir();
    let (manual_cmd, verb, remedy) = if image.contains('/') {
        (
            format!("{container_bin} pull {image}"),
            "Pull",
            Remedy::Pull,
        )
    } else {
        let dockerfile = tmp_ctx.join(format!("agentbox-{}.Dockerfile", std::process::id()));
        (
            format!(
                "{container_bin} build -t {image} -f {} {}",
                dockerfile.display(),
                tmp_ctx.display()
            ),
            "Build",
            Remedy::Build { dockerfile },
        )
    };

    eprintln!("Image `{image}` not found locally. To create it, run:\n  {manual_cmd}");
    if !(config.auto_confirm || prompt_yes_no(&format!("{verb} it now?"))) {
        return Err(format!(
            "image `{image}` is missing — create it first:\n  {manual_cmd}"
        ));
    }

    eprintln!("{verb}ing image `{image}` — output follows (this can take a few minutes)…");
    let streamed = |args: Vec<&str>| run_streamed(io, wrapper, container_bin, &args);
    let code = match &remedy {
        Remedy::Build { dockerfile } => {
            if let Err(e) = std::fs::write(dockerfile, dockerfile_content()?) {
                return Err(format!("cannot write {}: {e}", dockerfile.display()));
            }
            let df = dockerfile.to_string_lossy().to_string();
            let ctx_s = tmp_ctx.to_string_lossy().to_string();
            streamed(vec!["build", "-t", image, "-f", &df, &ctx_s])
        }
        Remedy::Pull => streamed(vec!["pull", image]),
    }?;
    if code != 0 {
        return Err(format!("{verb} of image `{image}` failed with exit {code}"));
    }

    if probe(io) {
        info!("Image {image} is now available.");
        Ok(())
    } else {
        Err(format!(
            "image `{image}` is still missing after {verb} — try manually:\n  {manual_cmd}"
        ))
    }
}

fn check_container_running<S: SystemIo>(    io: &S,
    wrapper: Option<&str>,
    runtime: &str,
    name: &str,
) -> Option<bool> {
    match run_with_wrapper(io, wrapper, runtime, &["inspect", "-f", "{{.State.Running}}", name]) {
        Ok(o) if o.success() => Some(o.stdout.trim() == "true"),
        _ => None,
    }
}

/// Stop a container gently: give in-container processes a chance to shut
/// down before the teardown SIGKILLs them and severs their ptys.
///
/// `docker/podman stop` signals PID 1 only; when it exits, the remaining
/// (exec'd) processes are killed hard and their ptys are torn down — a
/// TUI dying that way cannot restore the host-side terminal it borrowed,
/// leaving the user's shell with mouse capture on and a dead scroll
/// wheel. A TERM sweep first lets cooperative processes (servatui TUIs
/// restore on SIGTERM/SIGHUP) clean up over their still-connected ptys.
///
/// The sweep walks /proc in pure shell (no pkill needed in the image) and
/// skips PID 1 (signalling the init would race the intended stop).
/// Best-effort: failures are ignored, `stop` follows regardless.
fn gentle_stop<S: SystemIo>(
    io: &S,
    wrapper: Option<&str>,
    container_bin: &str,
    container_name: &str,
) {
    let sweep = "for p in /proc/[0-9]*; do pid=${p##*/}; if [ \"$pid\" != 1 ]; then \
                 kill -TERM \"$pid\" 2>/dev/null; fi; done; true";
    let _ = run_with_wrapper(
        io,
        wrapper,
        container_bin,
        &["exec", container_name, "sh", "-c", sweep],
    );
    io.sleep_ms(1500);
    let _ = run_with_wrapper(io, wrapper, container_bin, &["stop", "-t", "2", container_name]);
}

/// Verify every secret is reachable INSIDE the container at `/fuse/<name>`.
///
/// A persistent container created before a host-side FUSE remount keeps its
/// bind to the dead mount — reads then fail with "Transport endpoint is not
/// connected" (or hang) with no hint what's wrong.  The probe runs
/// `timeout stat` via `exec` so a wedged mount cannot block the host either.
/// On failure the container is stopped and **started** (never removed —
/// user data is preserved): `start` re-applies the `-v` binds against the
/// current host mount, healing the stale bind.  Aborts with guidance if the
/// re-probe still fails.
fn verify_container_fuse<S: SystemIo>(
    io: &S,
    wrapper: Option<&str>,
    container_bin: &str,
    container_name: &str,
    loaded: &[LoadedSecret],
) -> Result<(), String> {
    if loaded.is_empty() {
        return Ok(());
    }
    let secs = crate::preflight::DEFAULT_TIMEOUT_SECS.to_string();
    let probe_failed = |io: &S| -> Vec<String> {
        loaded
            .iter()
            .filter(|s| {
                let path = format!("/fuse/{}", s.fuse_name);
                run_with_wrapper(
                    io,
                    wrapper,
                    container_bin,
                    &["exec", container_name, "timeout", &secs, "stat", "-c", "%s", &path],
                )
                .map(|o| !o.success())
                .unwrap_or(true)
            })
            .map(|s| s.fuse_name.clone())
            .collect()
    };

    let failed = probe_failed(io);
    if failed.is_empty() {
        info!("Container {container_name}: /fuse answers for all secrets.");
        return Ok(());
    }
    for name in &failed {
        warn!(
            "stale bind inside {container_name}: stat /fuse/{name} failed — \
             healing via stop/start (binds are re-applied, data is preserved)"
        );
    }
    gentle_stop(io, wrapper, container_bin, container_name);
    match run_with_wrapper(io, wrapper, container_bin, &["start", container_name]) {
        Ok(o) if o.success() => {}
        Ok(o) => {
            return Err(format!(
                "failed to restart container {container_name} after stale /fuse: exit {}\n\
                 stdout: {}\nstderr: {}",
                o.status.unwrap_or(-1),
                o.stdout,
                o.stderr
            ))
        }
        Err(e) => {
            return Err(format!(
                "failed to restart container {container_name} after stale /fuse: {e}"
            ))
        }
    }

    let still = probe_failed(io);
    if still.is_empty() {
        info!("Healed: /fuse re-bound and answering inside {container_name}.");
        return Ok(());
    }
    let paths: Vec<String> = still.iter().map(|n| format!("/fuse/{n}")).collect();
    Err(format!(
        "the container's /fuse bind is stale and a stop/start did not heal it \
         (failing: {}).\n\
         The host-side mount is healthy (see the earlier pre-flight), but this \
         container was created against an older mount.\n\
         Options:\n  \
         - inspect the mounts manually: {container_bin} exec {container_name} ls -l /fuse\n  \
         - recreate the box with --restart-container (WARNING: discards changes \
           made inside the container)",
        paths.join(", "),
    ))
}

/// Write a state file so `fuse-client` can restart the server with the same
/// secrets when a version mismatch is detected.
fn write_state_file<S: SystemIo>(
    config: &AgentConfig,
    loaded: &[LoadedSecret],
    io: &mut S,
    server_pid: u32,
) {
    let state = fuse_protocol::ServerStateFile {
        version: fuse_protocol::VERSION.to_string(),
        server_pid,
        server_binary: config.fuse_server_path.to_string_lossy().to_string(),
        mount_point: config.mount_point.to_string_lossy().to_string(),
        socket: config.socket_path.to_string_lossy().to_string(),
        allow_other: config.allow_other,
        log_level: config.log_level.clone(),
        pending_timeout: 300,
        runtime_wrapper: config.runtime_wrapper.clone(),
        secrets: loaded
            .iter()
            .map(|s| fuse_protocol::StateSecretEntry {
                fuse_name: s.fuse_name.clone(),
                host_path: s.host_path.to_string_lossy().to_string(),
                hash: config.binary_hash.clone(),
            })
            .collect(),
    };

    let json = match serde_json::to_string_pretty(&state) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize state file: {e}");
            return;
        }
    };

    let state_path = fuse_protocol::state_file();
    if let Err(e) = io.write_file(&state_path, json.as_bytes()) {
        warn!("Failed to write state file: {e}");
    } else if let Err(e) = io.set_file_mode(&state_path, 0o600) {
        warn!("Failed to set state file permissions: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, Runtime, SecretMapping};
    use fuse_protocol::MockSystemIo;
    use std::path::PathBuf;

    fn test_config() -> AgentConfig {
        AgentConfig {
            binary_hash: "abc123".into(),
            secrets: vec![SecretMapping {
                host: PathBuf::from("/home/user/secrets.yaml"),
                container: PathBuf::from("/root/.config/goose/secrets.yaml"),
            }],
            agent_subfolder: "goose".into(),
            container_args: vec![],
            agent_path: PathBuf::from("/work/agent1"),
            fuse_server_path: "fuse-server".into(),
            fused_path: "/tmp/fused".into(),
            image_name: "agentbox".into(),
            seccomp_profile: PathBuf::from("/tmp/agentbox-seccomp.json"),
            memory: "16G".into(),
            cpus: "4".into(),
            auto_confirm: false,
            socket_path: PathBuf::from("/tmp/fgk.sock"),
            mount_point: PathBuf::from("/tmp/fgk-mnt"),
            use_sudo: false,
            allow_other: false,
            pidns_host: false,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: "info".to_string(),
            plans_path: None,
        }
    }

    fn base_mock() -> MockSystemIo {
        MockSystemIo::new()
            // These are directories in reality; modeling them as files
            // would now (correctly) make create_dir_all fail with EEXIST.
            .with_dir("/work/agent1/config")
            .with_dir("/work/agent1/workspace")
            // The resolved data-daemon binary exists (fused_path in
            // test_config points here).
            .with_file("/tmp/fused", b"")
    }

    // ── resolve_dest (cp semantics) ──────────────────────────────

    #[test]
    fn resolve_dest_explicit_name() {
        // cp foo/x.txt bar/y.txt → bar/y.txt
        let d = resolve_dest(
            Path::new("/host/key.json"),
            Path::new("/root/.config/app/auth.json"),
        );
        assert_eq!(d, PathBuf::from("/root/.config/app/auth.json"));
    }

    #[test]
    fn resolve_dest_trailing_slash_directory() {
        // cp foo/x.txt bar/ → bar/x.txt
        let d = resolve_dest(
            Path::new("/host/key.json"),
            Path::new("/root/.config/app/"),
        );
        assert_eq!(d, PathBuf::from("/root/.config/app/key.json"));
    }

    #[test]
    fn resolve_dest_tilde_path() {
        // ~ is passed through as-is (container shell expands it);
        let d = resolve_dest(
            Path::new("/host/key.json"),
            Path::new("~/.config/app/key.json"),
        );
        assert_eq!(d, PathBuf::from("~/.config/app/key.json"));
    }

    // ── build_setup_script ───────────────────────────────────────

    #[test]
    fn setup_script_single_secret() {
        let loaded = vec![LoadedSecret {
            fuse_name: "p100_s0".into(),
            container: PathBuf::from("/root/.config/app/auth.json"),
            host_path: PathBuf::from("/host/auth.json"),
        }];
        let script = build_setup_script(&loaded);
        assert!(script.contains("ln -sf /fuse/p100_s0 /root/.config/app/auth.json"));
        assert!(script.contains("mkdir -p"));
    }

    #[test]
    fn setup_script_multiple_secrets() {
        let loaded = vec![
            LoadedSecret {
                fuse_name: "p100_s0".into(),
                container: PathBuf::from("/root/.config/app/a.json"),
                host_path: PathBuf::from("/host/a.json"),
            },
            LoadedSecret {
                fuse_name: "p100_s1".into(),
                container: PathBuf::from("/root/.config/app/b.json"),
                host_path: PathBuf::from("/host/b.json"),
            },
        ];
        let script = build_setup_script(&loaded);
        assert!(script.contains("a.json"));
        assert!(script.contains("b.json"));
        assert!(script.contains("&&"));
    }

    #[test]
    fn setup_script_empty_when_no_secrets() {
        let script = build_setup_script(&[]);
        assert!(script.is_empty());
    }

    // ── secret naming (#18) ────────────────────────────────────────

    #[test]
    fn secret_name_carries_the_host_file_name() {
        let n = secret_name(Path::new("/home/u/.config/goose/auth.json"), 42, 0);
        assert_eq!(n, "p42_s0_auth.json");
    }

    #[test]
    fn secret_name_sanitizes_unsafe_characters() {
        let n = secret_name(Path::new("/x/my key! v2.bin"), 7, 3);
        assert_eq!(n, "p7_s3_my_key__v2.bin");
    }

    #[test]
    fn secret_name_falls_back_when_no_file_name() {
        assert_eq!(secret_name(Path::new("/"), 9, 1), "p9_s1");
    }

    // ── run_agent integration ────────────────────────────────────

    #[test]
    fn missing_image_fails_fast_with_remediation() {
        // Issue #1: a missing image must never be delegated to headless
        // `podman run`.  The error must name the image and the exact
        // build command, and no container may be created.
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when("podman", "inspect", Some(1))
            .with_command_result_when("podman", "exists", Some(1));
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let err = result.expect_err("missing image must fail run_agent");
        assert!(
            err.contains("agentbox"),
            "error must name the image: {err}"
        );
        assert!(
            err.contains("podman build"),
            "error must contain the build command: {err}"
        );
        assert!(
            !err.contains("Failed to create container"),
            "must fail before podman run: {err}"
        );
    }

    #[test]
    fn missing_image_declined_prompt_is_error_not_crash() {
        // Same as above but through the user-decline path: headless
        // (no TTY) prompts default to No and yield the remediation error.
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when("podman", "inspect", Some(1))
            .with_command_result_when("podman", "exists", Some(1))
            .with_command_result_when("podman", "build", Some(0));
        let mut cfg = test_config();
        cfg.image_name = "agentbox".into();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let err = result.expect_err("declined build must fail run_agent");
        assert!(err.contains("create it first"), "got: {err}");
        // The build command must NOT have run: the image probe would
        // still report missing and the flow must stop before `run`.
        assert!(!err.contains("Failed to create container"), "got: {err}");
    }

    #[test]
    fn missing_image_auto_confirm_builds_and_proceeds() {
        // With auto_confirm the remediation runs without a prompt: the
        // first `image exists` probe fails, the build succeeds, the
        // re-probe passes (rule expires after one use), and the flow
        // continues to container creation.
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when("podman", "inspect", Some(1))
            .with_command_result_when_n("podman", "exists", Some(1), 1);
        let mut cfg = test_config();
        cfg.auto_confirm = true;
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        // The build must STREAM (run_interactive: inherited stdio) so the
        // user sees podman/apt progress instead of a silent multi-minute
        // hang, and it must not go through the captured run_command path.
        let interactive = mock.interactive_calls.borrow();
        assert!(
            interactive
                .iter()
                .any(|(bin, args)| bin == "podman"
                    && args.first().map(String::as_str) == Some("build")),
            "podman build must stream via run_interactive: {interactive:?}"
        );
        let calls = mock.command_calls.borrow();
        assert!(
            !calls.iter().any(|(bin, args)| bin == "podman"
                && args.first().map(String::as_str) == Some("build")),
            "podman build must NOT use the captured path: {calls:?}"
        );
    }

    #[test]
    fn missing_workspace_folders_are_created() {
        // A fresh agent path with none of the structure present: run-agent
        // generates the missing folders instead of refusing to run.
        let mut mock = MockSystemIo::new()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_file("/tmp/fused", b"");
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        let created = mock.created_dirs.borrow();
        let fuse = cfg.host_fuse().to_string_lossy().to_string();
        for dir in ["/work/agent1/config", "/work/agent1/workspace", fuse.as_str()] {
            assert!(
                created.iter().any(|c| c == dir),
                "folder {dir} must be generated (created: {created:?})"
            );
        }
    }

    #[test]
    fn spawns_server_when_none_exists() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);

        assert!(result.is_ok(), "got: {:?}", result.err());
        let run = result.unwrap();
        assert!(run.server_was_spawned);
        assert!(run.reset_ok);
    }

    #[test]
    fn reuses_existing_server() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");
        mock.unix_connected = true;

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);

        assert!(result.is_ok(), "got: {:?}", result.err());
        assert!(!result.unwrap().server_was_spawned);
    }

    #[test]
    fn pending_only_hash_flows_through_add() {
        // The add command the orchestrator dispatches must carry the
        // sentinel — no real digest can match it downstream.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        let mut cfg = test_config();
        cfg.binary_hash = fuse_protocol::PENDING_ONLY_HASH.into();
        let sent: std::cell::RefCell<Vec<String>> = Default::default();
        let captured = &sent;
        let _ = run_agent(&mut mock, &cfg, &|name, args| {
            if name == "add" {
                captured.borrow_mut().push(args.to_string());
            }
            Ok(String::new())
        }, false)
        .unwrap();
        let adds = sent.borrow();
        assert!(
            adds.iter().any(|a| a.contains(fuse_protocol::PENDING_ONLY_HASH)),
            "sentinel must be sent to the server: {adds:?}"
        );
    }

    #[test]
    fn no_secrets_works() {
        let mut cfg = test_config();
        cfg.secrets = vec![];

        let mut mock = base_mock();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    // ── cp-style secret scenarios ────────────────────────────────

    #[test]
    fn cp_file_to_explicit_name() {
        // --secret /host/key.json:/root/.config/app/auth.json
        let mut cfg = test_config();
        cfg.secrets = vec![SecretMapping {
            host: PathBuf::from("/home/user/key.json"),
            container: PathBuf::from("/root/.config/goose/auth.json"),
        }];

        let mut mock = base_mock()
            .with_file("/home/user/key.json", b"KEY");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn cp_file_to_directory() {
        // --secret /host/key.json:/root/.config/goose/
        // Should resolve to /root/.config/goose/key.json
        let mut cfg = test_config();
        cfg.secrets = vec![SecretMapping {
            host: PathBuf::from("/home/user/key.json"),
            container: PathBuf::from("/root/.config/goose/"),
        }];

        let mut mock = base_mock()
            .with_file("/home/user/key.json", b"KEY");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn cp_directory_recursive() {
        // --secret /host/secrets:/root/.config/goose/secrets
        // key1.json → /root/.config/goose/secrets/key1.json
        // subdir/key2.json → /root/.config/goose/secrets/subdir/key2.json
        let mut cfg = test_config();
        cfg.secrets = vec![SecretMapping {
            host: PathBuf::from("/home/user/secrets"),
            container: PathBuf::from("/root/.config/goose/secrets"),
        }];

        let mut mock = base_mock()
            .with_file("/home/user/secrets/key1.json", b"K1")
            .with_file("/home/user/secrets/subdir/key2.json", b"K2");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn cp_directory_into_existing_dir() {
        // --secret /host/secrets/:/root/.config/goose/
        // Contents spread into destination
        let mut cfg = test_config();
        cfg.secrets = vec![SecretMapping {
            host: PathBuf::from("/home/user/secrets/"),
            container: PathBuf::from("/root/.config/goose/"),
        }];

        let mut mock = base_mock()
            .with_file("/home/user/secrets/key1.json", b"K1")
            .with_file("/home/user/secrets/key2.json", b"K2");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn mixed_file_and_directory_in_same_run() {
        let mut cfg = test_config();
        cfg.secrets = vec![
            SecretMapping {
                host: PathBuf::from("/home/user/key.json"),
                container: PathBuf::from("/root/.config/goose/key.json"),
            },
            SecretMapping {
                host: PathBuf::from("/home/user/secrets"),
                container: PathBuf::from("/root/.config/goose/secrets"),
            },
        ];

        let mut mock = base_mock()
            .with_file("/home/user/key.json", b"KEY")
            .with_file("/home/user/secrets/token.json", b"TOK");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    // ── stale state recovery ─────────────────────────────────────

    #[test]
    fn stale_socket_removed_before_spawn() {
        let mut mock = base_mock()
            .with_file("/tmp/fgk.sock", b"stale")
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert!(
            !mock.files.contains_key("/tmp/fgk.sock"),
            "stale socket should have been removed"
        );
    }

    #[test]
    fn stale_socket_removal_fails_clear_error() {
        let mut mock = base_mock()
            .with_file("/tmp/fgk.sock", b"stale")
            .with_busy_path("/tmp/fgk.sock")
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_err());
    }

    #[test]
    fn stale_mount_point_lazy_unmounted() {
        let mut mock = base_mock()
            .with_dir("/tmp/fgk-mnt")
            .with_busy_path("/tmp/fgk-mnt")
            .with_command_result("fusermount", Some(0))
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn stale_mount_point_all_unmounts_fail() {
        // A LIVE mount whose dir is still stat-able: create_dir_all
        // succeeds on the real system (is_dir → true), so cleanup stays
        // best-effort and the run proceeds — the mount failure, if any,
        // would surface in the FUSE server later. The DEAD-mount variant
        // (stat fails, create_dir_all errors) is covered below.
        let mut mock = base_mock()
            .with_dir("/tmp/fgk-mnt")
            .with_busy_path("/tmp/fgk-mnt")
            .with_command_result("fusermount", Some(1))
            .with_command_result("fusermount3", Some(1))
            .with_command_result("umount", Some(1))
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn dead_fuse_mount_recovered_at_startup() {
        // Issue #23 incident: fused died, the kernel keeps the dead
        // mount — mkdir → EEXIST, stat → ENOTCONN, create_dir_all
        // errors "File exists (os error 17)". The run must recover via
        // a lazy unmount instead of aborting at step 1.
        let mut mock = base_mock()
            .with_stale_mount("/tmp/fgk-mnt")
            .with_command_result("fusermount", Some(0))
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        let calls = mock.command_calls.borrow();
        assert!(
            calls.iter().any(|(p, a)| p == "fusermount"
                && a.first().map(|s| s.as_str()) == Some("-uz")
                && a.contains(&"/tmp/fgk-mnt".to_string())),
            "recovery must lazy-unmount the dead mount: {:?}",
            calls
        );
    }

    #[test]
    fn dead_fuse_mount_all_unmounts_fail_early_actionable_error() {
        // The dead mount cannot be cleared: run-agent must abort BEFORE
        // spawning a server or touching the container, and spell out the
        // manual fix (this is the error the #23 report got as a
        // misleading "Is the agent path writable" instead).
        let mut mock = base_mock()
            .with_stale_mount("/tmp/fgk-mnt")
            .with_command_result("fusermount", Some(1))
            .with_command_result("fusermount3", Some(1))
            .with_command_result("umount", Some(1))
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let err = result.expect_err("an unclearable dead mount must abort the run");
        assert!(err.contains("fusermount -uz"), "must spell out the manual fix: {err}");
        assert!(
            mock.spawned.is_empty(),
            "no fuse-server may be spawned before the mount point is usable"
        );
    }

    #[test]
    fn file_blocking_mount_point_is_removed() {
        // A regular file occupies the mount-point name: mkdir → EEXIST
        // with a healthy stat — not a mount, so it is simply removed.
        let mut mock = base_mock()
            .with_file("/tmp/fgk-mnt", b"not a dir")
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert!(
            !mock.files.contains_key("/tmp/fgk-mnt"),
            "the blocking file must have been removed"
        );
    }

    #[test]
    fn fused_spawned_directly_and_server_is_policy_only() {
        // PR #37 design fix: mounting is client-side — run-agent spawns
        // the data daemon itself; the policy server gets NO
        // --mount-point (its fused supervision stays for standalone
        // use only).
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        let server_spawn = mock
            .spawned
            .iter()
            .find(|(p, _)| p.contains("fuse-server"))
            .expect("policy server must be spawned");
        assert!(
            !server_spawn.1.contains(&"--mount-point".to_string()),
            "server must be policy-only: {server_spawn:?}"
        );
        let fused_spawn = mock
            .spawned
            .iter()
            .find(|(p, _)| p.ends_with("fused"))
            .expect("data daemon must be spawned directly");
        assert!(
            fused_spawn.1.contains(&"--mount-point".to_string())
                && fused_spawn.1.contains(&"/tmp/fgk-mnt".to_string()),
            "fused must mount the configured mountpoint: {fused_spawn:?}"
        );
    }

    #[test]
    fn missing_fused_binary_fails_fast_without_spawning() {
        // The PR #37 field report: fused was never built, the stack ran
        // mount-less, and adds succeeded into an empty directory. Now
        // the run refuses to start and names the repair.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        // base_mock seeds /tmp/fused — remove it for this scenario.
        mock.files.remove("/tmp/fused");
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let err = result.expect_err("a missing data daemon must abort the run");
        assert!(err.contains("cargo build --workspace"), "must name the repair: {err}");
        assert!(
            mock.spawned.is_empty(),
            "nothing may be spawned without a data daemon"
        );
    }

    // ── out-of-sync stack: automatic rebuild (PR #37 review) ──────

    #[test]
    fn preflight_should_rebuild_classification() {
        use crate::preflight::CheckResult;
        let r = |check: &'static str, ok: bool| CheckResult {
            fuse_name: "s".into(),
            host_path: "/h/s".into(),
            check,
            ok,
            detail: String::new(),
        };
        let mount_fail = [r("fuse-mount", false), r("source-file", true)];
        assert!(preflight_should_rebuild(&mount_fail));
        let source_fail = [r("fuse-mount", true), r("source-file", false)];
        assert!(
            !preflight_should_rebuild(&source_fail),
            "a missing host file cannot be healed by rebuilding the stack"
        );
        let both = [r("fuse-mount", false), r("source-file", false)];
        assert!(!preflight_should_rebuild(&both));
        let all_ok = [r("fuse-mount", true), r("source-file", true)];
        assert!(!preflight_should_rebuild(&all_ok));
    }

    #[test]
    fn out_of_sync_mount_rebuilt_automatically() {
        // The #23/PR-37-review incident: an orphaned `fused` still owns
        // the mount; stat through it ENOENTs every secret (exit 1).
        // run-agent must tear down and rebuild the stack once — server
        // respawned, secrets re-added — and then succeed.
        let adds = std::cell::Cell::new(0usize);
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            // Persistent through pre-flight's 4 appear-retries in
            // iteration 1 (uses 4), still failing once at the top of
            // iteration 2 (5th use) before expiring: exactly one full
            // rebuild, then success.
            .with_command_result_when_n("timeout", "/tmp/fgk-mnt/", Some(1), 5);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|name, _| {
            if name == "add" {
                adds.set(adds.get() + 1);
            }
            Ok(String::new())
        }, false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert_eq!(adds.get(), 2, "secrets must be re-added after the rebuild");
        assert_eq!(mock.spawned.len(), 4, "server + fused per stack build, rebuilt once");
        let calls = mock.command_calls.borrow();
        assert!(
            calls
                .iter()
                .any(|(p, a)| p == "pkill" && a.contains(&"fuse-server".to_string())),
            "teardown must kill the old server: {calls:?}"
        );
        assert!(
            calls.iter().any(|(p, a)| p == "pkill" && a.contains(&"fused".to_string())),
            "teardown must kill an orphaned data daemon: {calls:?}"
        );
    }

    #[test]
    fn hanging_mount_rebuilt_automatically() {
        // The dead-mount variant (stat times out → exit 124) is healed
        // by the same rebuild path.
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when_n("timeout", "/tmp/fgk-mnt/", Some(124), 1);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert_eq!(mock.spawned.len(), 4, "server + fused per stack build, rebuilt once");
    }

    #[test]
    fn mount_appearing_late_needs_no_rebuild() {
        // A freshly spawned data daemon can take a moment to mount.
        // The stat must retry briefly and succeed WITHOUT tearing the
        // stack apart (PR #37 follow-up: rebuilds healed nothing when
        // the mount was merely late).
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when_n("timeout", "/tmp/fgk-mnt/", Some(1), 3);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert_eq!(
            mock.spawned.len(),
            2,
            "one stack (server + fused); a late mount must NOT rebuild it"
        );
        let calls = mock.command_calls.borrow();
        assert!(
            !calls.iter().any(|(p, _)| p == "pkill"),
            "no teardown may run for a late mount: {calls:?}"
        );
    }

    #[test]
    fn stale_version_server_respawned_from_current_binaries() {
        // The PR #37 root cause: run-agent happily reused/spawned a
        // fuse-server of incompatible vintage and failed later at
        // pre-flight with an unexplained empty mount. The handshake
        // must catch it, tear the stack down once, and respawn from
        // the current binaries.
        let payloads = std::cell::RefCell::new(vec![
            "{\"type\":\"version\",\"version\":\"0.26.0\"}".to_string(),
            format!("{{\"type\":\"version\",\"version\":\"{}\"}}", fuse_protocol::VERSION),
        ]);
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.unix_connected = true;

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|name, _| {
            if name == "version" {
                let mut p = payloads.borrow_mut();
                if p.is_empty() {
                    return Ok(format!(
                        "{{\"type\":\"version\",\"version\":\"{}\"}}",
                        fuse_protocol::VERSION
                    ));
                }
                return Ok(p.remove(0));
            }
            Ok(String::new())
        }, false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert_eq!(mock.spawned.len(), 2, "one fresh stack: policy server + data daemon");
        let calls = mock.command_calls.borrow();
        assert!(
            calls.iter().any(|(p, a)| p == "pkill" && a.contains(&"fuse-server".to_string())),
            "the incompatible server must be torn down: {calls:?}"
        );
    }

    #[test]
    fn incompatible_version_aborts_with_rebuild_hint() {
        // The respawned binary is STILL incompatible (everything stale):
        // abort with the mixed-vintage diagnosis instead of a mystery.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.unix_connected = true;

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|name, _| {
            if name == "version" {
                return Ok("{\"type\":\"version\",\"version\":\"0.26.0\"}".to_string());
            }
            Ok(String::new())
        }, false);
        let err = result.expect_err("persistently incompatible server must abort");
        assert!(err.contains("mixed-vintage"), "got: {err}");
        assert!(err.contains("cargo build --workspace"), "must name the repair: {err}");
        assert!(
            mock.interactive_calls.borrow().is_empty(),
            "no container interaction may happen"
        );
    }

    #[test]
    fn persistent_out_of_sync_aborts_after_one_rebuild() {
        let adds = std::cell::Cell::new(0usize);
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when("timeout", "/tmp/fgk-mnt/", Some(1));

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|name, _| {
            if name == "add" {
                adds.set(adds.get() + 1);
            }
            Ok(String::new())
        }, false);
        let err = result.expect_err("a persistently out-of-sync stack must abort");
        assert!(err.contains("pre-flight"), "got: {err}");
        assert!(err.contains("fuse-client restart"), "must point at manual repair: {err}");
        assert_eq!(adds.get(), 2, "exactly one rebuild, then abort");
        assert_eq!(mock.spawned.len(), 4);
        assert!(
            mock.interactive_calls.borrow().is_empty(),
            "no container interaction may happen after pre-flight failure"
        );
    }

    // ── spawn argv validation ────────────────────────────────────

    #[test]
    fn spawn_command_no_allow_other_by_default() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        assert!(!mock.spawned.is_empty(), "should have spawned fuse-server");
        assert!(
            !mock.spawn_contains(0, &["--allow-other"]),
            "should NOT pass --allow-other by default"
        );
    }

    #[test]
    fn spawn_command_includes_allow_other_when_sudo() {
        let mut cfg = test_config();
        cfg.use_sudo = true;
        cfg.allow_other = true; // mirrors main.rs: allow_other = cli.allow_other || cli.sudo

        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        assert!(
            mock.spawn_contains(0, &["--allow-other"]),
            "--sudo should imply --allow-other"
        );
    }

    #[test]
    fn spawn_command_explicit_allow_other() {
        let mut cfg = test_config();
        cfg.allow_other = true;

        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        assert!(
            mock.spawn_contains(0, &["--allow-other"]),
            "--allow-other should be passed through"
        );
    }

    #[test]
    fn spawn_command_uses_sudo_n_when_sudo() {
        let mut cfg = test_config();
        cfg.use_sudo = true;
        cfg.allow_other = true;

        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        assert!(!mock.spawned.is_empty());
        // Without wrapper: prog="sudo", args=["-n", "fuse-server", ...]
        // With wrapper:    prog="flatpak-spawn", args=["--host", "sudo", "-n", ...]
        let (prog, args) = &mock.spawned[0];
        let has_sudo = prog == "sudo" || args.contains(&"sudo".to_string());
        let has_n = args.contains(&"-n".to_string());
        assert!(has_sudo && has_n, "should use sudo -n: prog={prog}, args={args:?}");
    }

    #[test]
    fn sudo_preauth_called_when_sudo() {
        let mut cfg = test_config();
        cfg.use_sudo = true;

        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());

        let calls = mock.interactive_calls.borrow();
        let has_sudo_v = calls.iter().any(|(prog, args)| {
              prog == "sudo" && args.iter().any(|a| a == "-v")
        });
        assert!(
            has_sudo_v,
            "should have called 'sudo -v' for pre-authentication, got: {calls:?}"
        );
    }

    #[test]
    fn no_preauth_when_not_sudo() {
        let cfg = test_config();

        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());

        let calls = mock.interactive_calls.borrow();
        // Container launch uses run_interactive, but no sudo -v
        let has_sudo_v = calls.iter().any(|(prog, _)| prog == "sudo");
        assert!(!has_sudo_v, "should NOT call sudo when --sudo not set");
    }

    // ── spawn failure ────────────────────────────────────────────

    #[test]
    fn spawn_failure_clear_error() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_spawn_error("command not found");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_err());
    }

    // ── pre-flight (stale mount aborts before container start) ────

    #[test]
    fn run_agent_aborts_on_stale_mount_without_starting_container() {
        // `timeout` exit 124 = the FUSE mount never answered the probe,
        // i.e. exactly the state that hangs the box on first read.
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result("timeout", Some(124));

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let err = result.expect_err("must abort on stale mount");
        assert!(err.contains("pre-flight"), "got: {err}");
        assert!(err.to_lowercase().contains("hang"), "got: {err}");
        // The container must NOT have been created or exec'd into.
        assert!(
            mock.interactive_calls.borrow().is_empty(),
            "no container interaction may happen after pre-flight failure: {:?}",
            mock.interactive_calls.borrow()
        );
    }

    // ── reuse vs. respawn (zombie server detection) ──────────────

    #[test]
    fn unhealthy_reused_server_is_respawned() {
        // The socket accepts connections (kernel backlog) but the server
        // behind it is a zombie: the health round-trip fails and adds die
        // with 'Broken pipe'.  run-agent must respawn a fresh server.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.unix_connected = true;

        let probed = std::cell::Cell::new(false);
        let send = |name: &str, _args: &str| -> Result<String, String> {
            if name == "status" && !probed.get() {
                probed.set(true);
                return Err("server closed the connection".into());
            }
            Ok(String::new())
        };

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &send, false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        assert!(probed.get(), "a health probe must have been attempted");
        assert!(
            !mock.spawned.is_empty(),
            "the zombie server must be replaced by a fresh spawn"
        );
    }

    #[test]
    fn healthy_reused_server_is_not_respawned() {
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.unix_connected = true;

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        assert!(
            mock.spawned.is_empty(),
            "a healthy server must be reused, not respawned"
        );
    }

    // ── container lifecycle + container-side FUSE pre-flight ─────

    #[test]
    fn stopped_container_is_started_not_recreated() {
        // inspect succeeds (container exists) but Running != true.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        let calls = mock.command_calls.borrow();
        assert!(
            calls
                .iter()
                .any(|(_, a)| a.first().map(|s| s.as_str()) == Some("start")),
            "a stopped container must be started (re-applies binds): {calls:?}"
        );
        assert!(
            !calls
                .iter()
                .any(|(_, a)| a.first().map(|s| s.as_str()) == Some("run")),
            "an existing container must NOT be recreated (would fail anyway): {calls:?}"
        );
    }

    #[test]
    fn missing_container_is_created() {
        // inspect fails → the container does not exist → create it.
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_command_result_when("podman", "inspect", Some(1));
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());
        let calls = mock.command_calls.borrow();
        assert!(
            calls
                .iter()
                .any(|(_, a)| a.first().map(|s| s.as_str()) == Some("run")),
            "a missing container must be created: {calls:?}"
        );
    }

    #[test]
    fn stale_container_fuse_is_healed_by_restart() {
        // Running container, but /fuse inside is the stale bind from before
        // a host remount: the first exec probe fails; stop/start re-applies
        // the bind and the re-probe succeeds.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.command_stdout = "true".into(); // inspect → Running = true
        mock.unix_connected = true;
        mock = mock.with_command_result_when_n("podman", "exec", Some(1), 1);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(
            result.is_ok(),
            "stop/start heal must recover the session: {:?}",
            result.err()
        );
        let calls = mock.command_calls.borrow();
        assert!(
            calls
                .iter()
                .any(|(_, a)| a.first().map(|s| s.as_str()) == Some("stop")),
            "heal must stop the container: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|(_, a)| a.first().map(|s| s.as_str()) == Some("start")),
            "heal must start the container: {calls:?}"
        );
        assert!(
            !calls.iter().any(|(_, a)| a.iter().any(|x| x == "rm")),
            "heal must NEVER remove the container (user data!): {calls:?}"
        );
    }

    #[test]
    fn unhealable_container_fuse_aborts_with_guidance() {
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.command_stdout = "true".into();
        mock.unix_connected = true;
        mock = mock.with_command_result_when("podman", "exec", Some(1)); // always fails

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let err = result.expect_err("must abort when /fuse cannot be healed");
        assert!(
            err.contains("restart-container"),
            "must mention --restart-container as the last resort: {err}"
        );
        assert!(
            !mock.command_calls
                .borrow()
                .iter()
                .any(|(_, a)| a.iter().any(|x| x == "rm")),
            "must never rm the container on its own"
        );
    }

    #[test]
    fn container_probe_goes_through_exec_with_timeout() {
        // AGENTS.md argv discipline: the probe must run `timeout stat`
        // INSIDE the container so a wedged mount cannot block the host.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.command_stdout = "true".into();
        let cfg = test_config();
        let _ = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        let calls = mock.command_calls.borrow();
        let probe = calls
            .iter()
            .find(|(_, a)| a.first().map(|s| s.as_str()) == Some("exec"))
            .expect("an exec probe must happen before the session");
        assert!(
            probe.1.contains(&"timeout".to_string())
                && probe.1.contains(&"stat".to_string()),
            "probe must be `timeout stat`: {probe:?}"
        );
        assert!(
            probe.1.iter().any(|a| a.contains("/fuse/p")),
            "probe must stat the fuse-side secret path: {probe:?}"
        );
    }

    // ── gentle shutdown: terminals must survive container teardown ──

    #[test]
    fn stale_fuse_heal_terms_container_processes_before_stop() {
        // Same scenario as stale_container_fuse_is_healed_by_restart, but
        // the teardown must be GENTLE: TERM the in-container processes
        // first (a TUI then restores the user's terminal over its
        // still-connected pty), wait out a grace period, and only then
        // `stop -t 2`. A bare `stop` SIGKILLs exec sessions when PID 1
        // exits and severs their ptys mid-restore.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        mock.command_stdout = "true".into();
        mock.unix_connected = true;
        mock = mock.with_command_result_when_n("podman", "exec", Some(1), 1);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok(), "got: {:?}", result.err());

        let calls = mock.command_calls.borrow();
        let stop_idx = calls
            .iter()
            .position(|(_, a)| a.first().map(|s| s.as_str()) == Some("stop"))
            .expect("heal must stop the container");
        assert!(
            calls[stop_idx].1.contains(&"-t".to_string())
                && calls[stop_idx].1.contains(&"2".to_string()),
            "stop must carry a short explicit grace period (-t 2): {:?}",
            calls[stop_idx]
        );
        let sweep_idx = calls
            .iter()
            .position(|(_, a)| {
                a.first().map(|s| s.as_str()) == Some("exec")
                    && a.iter().any(|x| x.contains("/proc/[0-9]*"))
            })
            .expect("heal must TERM in-container processes before stopping");
        assert!(
            sweep_idx < stop_idx,
            "the TERM sweep must precede the stop: sweep at {sweep_idx}, stop at {stop_idx}"
        );
        let sweep = calls[sweep_idx]
            .1
            .iter()
            .find(|x| x.contains("/proc/[0-9]*"))
            .unwrap();
        assert!(
            sweep.contains("kill -TERM") && sweep.contains("!= 1"),
            "sweep must TERM every process except PID 1: {sweep}"
        );
        assert!(
            mock.sleeps.borrow().contains(&1500),
            "a grace period must separate the TERM sweep from the stop"
        );
    }

    #[test]
    fn restart_container_terms_processes_before_rm() {
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), true);
        assert!(result.is_ok(), "got: {:?}", result.err());
        let calls = mock.command_calls.borrow();
        let rm_idx = calls
            .iter()
            .position(|(_, a)| a.iter().any(|x| x == "rm"))
            .expect("restart must remove the container");
        let sweep_idx = calls
            .iter()
            .position(|(_, a)| a.iter().any(|x| x.contains("/proc/[0-9]*")))
            .expect("restart must TERM in-container processes first");
        assert!(
            sweep_idx < rm_idx,
            "the TERM sweep must precede the rm: sweep at {sweep_idx}, rm at {rm_idx}"
        );
    }

    #[test]
    fn interactive_session_ends_with_terminal_heal() {
        // If the foreground session dies hard (container killed under it),
        // the host tty keeps the child's raw mode / mouse capture. When
        // run_interactive returns, run-agent still owns that tty and must
        // heal it.
        let mut mock = base_mock().with_file("/home/user/secrets.yaml", b"DATA");
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        assert!(
            !mock.interactive_calls.borrow().is_empty(),
            "precondition: the interactive session ran"
        );
        assert_eq!(
            mock.heal_terminal_calls.get(),
            1,
            "the host terminal must be healed exactly once after the session"
        );
    }

    // ── fresh start (no stale state) ─────────────────────────────

    #[test]
    fn fresh_start_no_cleanup_needed() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg, &|_, _| Ok(String::new()), false);
        assert!(result.is_ok());
        // No stale socket or mount point, so no removals attempted
        assert!(!mock.spawned.is_empty());
    }
}
