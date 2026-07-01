use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fuse_protocol::{Command, SystemIo};
use tracing::{info, warn};

use crate::config::{build_container_args, AgentConfig};

/// Result of a completed agent session.
#[derive(Debug)]
pub struct RunResult {
    pub container_exit_code: i32,
    pub reset_ok: bool,
    pub server_was_spawned: bool,
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
pub fn run_agent<S: SystemIo>(io: &mut S, config: &AgentConfig) -> Result<RunResult, String> {
    // ── 1. Validate ──────────────────────────────────────────────
    let host_config = config.host_config_dir();
    let host_workspace = config.host_workspace();

    for dir in [&host_config, &host_workspace] {
        if !io.file_exists(dir) {
            return Err(format!(
                "Directory {} not found. Is this really an agent workspace?",
                dir.display()
            ));
        }
    }
    info!("Workspace validated.");

    // ── 2. Probe for existing server ─────────────────────────────
    let socket = &config.socket_path;
    let mut server_was_spawned = false;

    if fuse_client::server_exists(io, socket) {
        info!("Reusing existing fuse-server at {}", socket.display());
    } else {
        // ── 3. Spawn independent server ───────────────────────────
        server_was_spawned = true;
        info!("No fuse-server found — spawning a new one.");

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
        // A previous run may have left a stale FUSE mount (whose stat()
        // fails, so file_exists() returns false) or a root-owned directory.
        // Strategy: try create_dir_all first; on failure, unmount + remove
        // + retry.
        if io.create_dir_all(&config.mount_point).is_err() {
            info!("Mount point unavailable; attempting cleanup");

            // Try lazy unmount to clear any stale FUSE mount.
            let mount_str = config.mount_point.to_string_lossy().to_string();
            let wrapper = config.runtime_wrapper.as_deref();
            for (cmd, flag) in [("fusermount", "-uz"), ("fusermount3", "-uz"), ("umount", "-l")] {
                let mut parts: Vec<String> = Vec::new();
                if let Some(w) = wrapper {
                    let (prog, prefix) = crate::config::split_wrapper(w);
                    parts.push(prog);
                    parts.extend(prefix);
                }
                parts.push(cmd.to_string());
                parts.push(flag.to_string());
                parts.push(mount_str.clone());

                let prog = parts[0].clone();
                let args: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();
                if io.run_command(&prog, &args).map(|o| o.success()).unwrap_or(false) {
                    info!("Lazy unmount succeeded via {cmd} {flag}");
                    break;
                }
            }

            // Wait for lazy unmount, then remove stale path.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = io.remove_path(&config.mount_point);

            // Retry creation.
            io.create_dir_all(&config.mount_point).map_err(|e| format!(
                "create mount point {}: {e}.\n\
                 If the problem persists, run manually:\n  \
                 fusermount -uz {} && rm -rf {}",
                config.mount_point.display(),
                config.mount_point.display(),
                config.mount_point.display(),
            ))?;
        }

        let mount = config
            .mount_point
            .to_str()
            .ok_or_else(|| format!("mount point is not valid UTF-8: {}", config.mount_point.display()))?;
        let sock = socket
            .to_str()
            .ok_or_else(|| format!("socket path is not valid UTF-8: {}", socket.display()))?;
        let mut fuse_args: Vec<&str> = vec![
            "--mount-point", mount,
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

    // ── 4. Expand + load secrets into FUSE ───────────────────────
    let pid = std::process::id();
    let mut counter = 0usize;
    let mut loaded: Vec<LoadedSecret> = Vec::new();

    for mapping in &config.secrets {
        load_secret_recursive(
            io, socket, &mapping.host, &mapping.container,
            config, pid, &mut counter, &mut loaded,
        )?;
    }

    // Write state file so fuse-client can restart the server if needed.
    write_state_file(config, &loaded, io);

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

    // ── 6. Run container (setup script creates symlinks inside) ──
    let setup_script = build_setup_script(&loaded);
    let args = build_container_args(config, &setup_script);
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
    if exit_code == 0 {
        info!("Container exited with code 0.");
    } else {
        warn!("Container exited with code {exit_code}.");
    }

    // ── 7. Auto-reset all secret counters ────────────────────────
    let mut reset_ok = true;
    for s in &loaded {
        match fuse_client::send_command(io, socket, Command::Reset {
            name: Some(s.fuse_name.clone()),
        }) {
            Ok(fuse_protocol::Response::Ok) => {
                info!("Auto-reset successful for '{}'.", s.fuse_name);
            }
            Ok(other) => {
                warn!("Auto-reset returned unexpected response for '{}': {other:?}", s.fuse_name);
                reset_ok = false;
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
struct LoadedSecret {
    fuse_name: String,
    container: PathBuf,
    host_path: PathBuf,
}

/// Recursively load a secret file or directory into the FUSE server.
///
/// Destination semantics match `cp`:
/// - File + `/dir/` (trailing slash) → file placed inside dir as `dir/basename`
/// - File + `/dir/name` → file placed at exact path
/// - Dir + `/dest` → directory contents mapped under `dest/`
/// - Dir + `/dest/` → same (contents mapped under `dest/`)
#[allow(clippy::too_many_arguments)]
fn load_secret_recursive<S: SystemIo>(
    io: &mut S,
    socket: &Path,
    host: &Path,
    container: &Path,
    config: &AgentConfig,
    pid: u32,
    counter: &mut usize,
    loaded: &mut Vec<LoadedSecret>,
) -> Result<(), String> {
    if io.is_dir(host) {
        let entries = io
            .list_dir(host)
            .map_err(|e| format!("list dir {}: {e}", host.display()))?;
        for entry in entries {
            let name = entry
                .file_name()
                .ok_or_else(|| format!("invalid path: {}", entry.display()))?;
            load_secret_recursive(
                io, socket, &entry, &container.join(name),
                config, pid, counter, loaded,
            )?;
        }
        return Ok(());
    }

    // ── Single file ──
    // cp semantics: if container ends with '/', it's a directory destination.
    let dest = resolve_dest(host, container);

    let fuse_name = format!("p{pid}_s{counter}");
    *counter += 1;

    let content = io
        .read_file(host)
        .map_err(|e| format!("read secret {}: {e}", host.display()))?;

    match fuse_client::send_command(io, socket, Command::AddSecret {
        name: fuse_name.clone(),
        content,
        hash: config.binary_hash.clone(),
    }) {
        Ok(fuse_protocol::Response::Ok) => {
            info!("Secret loaded: {} → /fuse/{fuse_name}", host.display());
        }
        Ok(other) => return Err(format!("unexpected response adding secret: {other:?}")),
        Err(e) => return Err(format!("failed to add secret: {e}")),
    }

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

/// Write a state file so `fuse-client` can restart the server with the same
/// secrets when a version mismatch is detected.
fn write_state_file<S: SystemIo>(config: &AgentConfig, loaded: &[LoadedSecret], io: &mut S) {
    let state = fuse_protocol::ServerStateFile {
        version: fuse_protocol::VERSION.to_string(),
        server_pid: std::process::id(),
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

    let state_path = std::path::Path::new("/tmp/fuse-gatekeeper-state.json");
    if let Err(e) = io.write_file(state_path, json.as_bytes()) {
        warn!("Failed to write state file: {e}");
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
            image_name: "agentbox".into(),
            memory: "16G".into(),
            cpus: "4".into(),
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
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
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
        // ~ is passed through as-is (container shell expands it)
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

    // ── run_agent integration ────────────────────────────────────

    #[test]
    fn missing_workspace_dirs_errors() {
        let mut mock = MockSystemIo::new();
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn spawns_server_when_none_exists() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

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
        mock = mock
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

        assert!(result.is_ok(), "got: {:?}", result.err());
        assert!(!result.unwrap().server_was_spawned);
    }

    #[test]
    fn no_secrets_works() {
        let mut cfg = test_config();
        cfg.secrets = vec![];

        let mut mock = base_mock();
        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/key.json", b"KEY")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/key.json", b"KEY")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets/subdir/key2.json", b"K2")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets/key2.json", b"K2")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets/token.json", b"TOK")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    // ── stale state recovery ─────────────────────────────────────

    #[test]
    fn stale_socket_removed_before_spawn() {
        let mut mock = base_mock()
            .with_file("/tmp/fgk.sock", b"stale")
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
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
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn stale_mount_point_lazy_unmounted() {
        let mut mock = base_mock()
            .with_dir("/tmp/fgk-mnt")
            .with_busy_path("/tmp/fgk-mnt")
            .with_command_result("fusermount", Some(0))
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());
    }

    #[test]
    fn stale_mount_point_all_unmounts_fail() {
        let mut mock = base_mock()
            .with_dir("/tmp/fgk-mnt")
            .with_busy_path("/tmp/fgk-mnt")
            .with_command_result("fusermount", Some(1))
            .with_command_result("fusermount3", Some(1))
            .with_command_result("umount", Some(1))
            .with_file("/home/user/secrets.yaml", b"DATA");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
    }

    // ── spawn argv validation ────────────────────────────────────

    #[test]
    fn spawn_command_no_allow_other_by_default() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
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
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
    }

    // ── fresh start (no stale state) ─────────────────────────────

    #[test]
    fn fresh_start_no_cleanup_needed() {
        let mut mock = base_mock()
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok());
        // No stale socket or mount point, so no removals attempted
        assert!(!mock.spawned.is_empty());
    }
}
