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
/// 4. Add the secret via `fuse-client add-secret`.
/// 5. Detect container runtime.
/// 6. Create the config symlink (with wrong-target / collision handling).
/// 7. Run the container (foreground).
/// 8. **Auto-reset** this secret's counter.
/// 9. Done (server stays running, symlink persists — no cleanup).
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

        io.create_dir_all(&config.mount_point)
            .map_err(|e| format!("create mount point: {e}"))?;

        let mount = config
            .mount_point
            .to_str()
            .ok_or_else(|| format!("mount point is not valid UTF-8: {}", config.mount_point.display()))?;
        let sock = socket
            .to_str()
            .ok_or_else(|| format!("socket path is not valid UTF-8: {}", socket.display()))?;
        let args: Vec<&str> = vec![
            "--mount-point", mount,
            "--socket", sock,
            "--allow-other",
            "--log-level", &config.log_level,
        ];

        let server_bin = config
            .fuse_server_path
            .to_str()
            .ok_or_else(|| format!("fuse-server path is not valid UTF-8: {}", config.fuse_server_path.display()))?;

        let log_path = config.agent_path.join("fuse-server.log");
        let log_str = log_path.to_str()
            .ok_or_else(|| format!("log path is not valid UTF-8: {}", log_path.display()))?;

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

    // ── 4. Add secret via socket ─────────────────────────────────
    let secret_abs = config
        .host_config_file
        .canonicalize()
        .unwrap_or_else(|_| config.host_config_file.clone());
    let content = io
        .read_file(&config.host_config_file)
        .map_err(|e| format!("read secret file {}: {e}", secret_abs.display()))?;

    match fuse_client::send_command(io, socket, Command::AddSecret {
        name: config.filename(),
        content: content.clone(),
        hash: config.binary_hash.clone(),
    }) {
        Ok(fuse_protocol::Response::Ok) => {
            info!("Secret '{}' added to server.", config.filename());
        }
        Ok(other) => {
            return Err(format!("unexpected response adding secret: {other:?}"));
        }
        Err(e) => {
            return Err(format!("failed to add secret: {e}"));
        }
    }

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

    // ── 6. Symlink config → /fuse/<file> ─────────────────────────
    let cont_fuse_file = config.container_fuse_file();
    let host_link = config.host_config_link();

    if io.is_symlink(&host_link) {
        match io.read_link(&host_link) {
            Ok(target) if target == PathBuf::from(&cont_fuse_file) => {
                info!("Symlink already exists and points to correct target: {}", host_link.display());
            }
            _ => {
                let agent_name = config.agent_name();
                let running = probe_running_agents(io, container_bin, wrapper, &agent_name);
                if running {
                    return Err(format!(
                        "Symlink at {} points to wrong target and agent '{}' appears to be running. \
                         Cannot override symlink while agent is active.",
                        host_link.display(), agent_name
                    ));
                }
                warn!("Symlink target mismatch — no running agents, overriding symlink.");
                io.remove_path(&host_link)
                    .map_err(|e| format!("remove stale symlink: {e}"))?;
                create_symlink_with_collision(io, &host_link, &cont_fuse_file)?;
            }
        }
    } else {
        create_symlink_with_collision(io, &host_link, &cont_fuse_file)?;
    }

    // ── 7. Run container ─────────────────────────────────────────
    let args = build_container_args(config);
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

    // ── 8. Auto-reset this secret ────────────────────────────────
    let reset_ok = match fuse_client::send_command(io, socket, Command::Reset {
        name: Some(config.filename()),
    }) {
        Ok(fuse_protocol::Response::Ok) => {
            info!("Auto-reset successful for '{}'.", config.filename());
            true
        }
        Ok(other) => {
            warn!("Auto-reset returned unexpected response: {other:?}");
            false
        }
        Err(e) => {
            warn!("Auto-reset failed: {e}");
            false
        }
    };

    // ── 9. Done (server stays running, symlink persists) ──────
    Ok(RunResult {
        container_exit_code: exit_code,
        reset_ok,
        server_was_spawned,
    })
}

/// Create symlink at `link` pointing to `target`, handling collision
/// with an existing regular file by moving it aside to `<link>.orig`.
fn create_symlink_with_collision<S: SystemIo>(
    io: &mut S,
    link: &Path,
    target: &str,
) -> Result<(), String> {
    if io.file_exists(link) {
        let backup = PathBuf::from(format!("{}.orig", link.display()));
        info!(
            "Collision at {} — moving original to {}",
            link.display(),
            backup.display()
        );
        io.rename_path(link, &backup)
            .map_err(|e| format!("rename original aside: {e}"))?;
    }

    match io.create_symlink(Path::new(target), link) {
        Ok(()) => {
            info!("Symlink: {} -> {target}", link.display());
            Ok(())
        }
        Err(e) => {
            warn!(
                "Could not create symlink at {} ({}). \
                 The FUSE mount is still available at {target}.",
                link.display(), e
            );
            Ok(())
        }
    }
}

fn setup_rootless_docker() {
    let sock = format!("unix://{}", crate::config::rootless_docker_socket());
    std::env::set_var("DOCKER_HOST", &sock);
    info!("Docker rootless socket: {sock}");
}

/// Check whether any container whose name matches `agent_name` is currently
/// running, by querying `<wrapper>? <container_bin> ps`.  Returns `false`
/// when the command fails or when no containers match (safe default: do not
/// block the user on a transient runtime error).
fn probe_running_agents<S: SystemIo>(
    io: &S,
    container_bin: &str,
    wrapper: Option<&str>,
    agent_name: &str,
) -> bool {
    let filter = format!("name={}", agent_name);
    let ps_args: Vec<&str> = vec![
        "ps",
        "--filter", &filter,
        "--format", "{{.Names}}",
        "--no-trunc",
    ];

    let result = match wrapper {
        Some(w) => {
            let (prog, prefix) = crate::config::split_wrapper(w);
            let mut full: Vec<&str> = prefix.iter().map(|s| s.as_str()).collect();
            full.push(container_bin);
            full.extend(ps_args.iter().copied());
            io.run_command(&prog, &full)
        }
        None => {
            io.run_command(container_bin, &ps_args)
        }
    };

    match result {
        Ok(o) if o.success() => {
            let count = o.stdout.lines().filter(|l| !l.trim().is_empty()).count();
            if count > 0 {
                info!("Found {count} running container(s) matching '{agent_name}'.");
                true
            } else {
                false
            }
        }
        Ok(o) => {
            warn!(
                "Container ps query returned non-zero status {:?} — assuming no agents running.",
                o.status
            );
            false
        }
        Err(e) => {
            warn!("Could not probe for running agents: {e} — proceeding with override.");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, Runtime};
    use fuse_protocol::MockSystemIo;
    use std::path::PathBuf;

    fn test_config() -> AgentConfig {
        AgentConfig {
            binary_hash: "abc123".into(),
            host_config_file: "secrets.yaml".into(),
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
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: "info".to_string(),
            plans_path: None,
        }
    }

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
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("secrets.yaml", b"DATA")
            // unix_connected defaults to false → server doesn't exist → spawn
            .with_unix_response(br#"{"type":"ok"}"#)  // AddSecret response
            .with_unix_response(br#"{"type":"ok"}"#); // Reset response

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

        assert!(result.is_ok(), "got: {:?}", result.err());
        let run = result.unwrap();
        assert!(run.server_was_spawned);
        assert!(run.reset_ok);
        assert_eq!(run.container_exit_code, 0);

        // fuse-server was spawned independently
        assert_eq!(mock.spawned.len(), 1);
        assert_eq!(mock.spawned[0].0, "fuse-server");
    }

    #[test]
    fn reuses_existing_server() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("secrets.yaml", b"DATA");
        mock.unix_connected = true; // server already running
        mock = mock
            .with_unix_response(br#"{"type":"ok"}"#)  // AddSecret
            .with_unix_response(br#"{"type":"ok"}"#); // Reset

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

        assert!(result.is_ok(), "got: {:?}", result.err());
        let run = result.unwrap();
        assert!(!run.server_was_spawned); // didn't spawn
        assert_eq!(mock.spawned.len(), 0); // no spawn calls
    }

    #[test]
    fn symlink_persists_after_run() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let _ = run_agent(&mut mock, &cfg);

        let link = cfg.host_config_link();
        assert!(mock.is_symlink(&link), "symlink should persist after run");
    }

    #[test]
    fn symlink_collision_persists_symlink() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("config/secrets.yaml", b"SECRET_DATA")
            .with_file("/work/agent1/config/secrets.yaml", b"SECRET_DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let mut cfg = test_config();
        cfg.host_config_file = PathBuf::from("config/secrets.yaml");
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());

        let link = cfg.host_config_link();
        assert!(
            mock.is_symlink(&link),
            "symlink should persist after collision (not restored)"
        );

        let backup = PathBuf::from(format!("{}.orig", link.display()));
        assert!(
            mock.file_exists(&backup),
            "original file should remain at .orig"
        );
        assert_eq!(
            mock.read_file(&backup).unwrap(),
            b"SECRET_DATA",
            ".orig content must match original"
        );
    }

    #[test]
    fn symlink_correct_target_skips_creation() {
        let cfg = test_config();
        let link = cfg.host_config_link();
        let correct_target = cfg.container_fuse_file();

        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);
        // Pre-populate symlink with the correct target.
        mock.symlinks
            .insert(link.to_string_lossy().to_string(), correct_target.clone());

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());

        // Symlink should still exist and point to the correct target.
        assert!(mock.is_symlink(&link));
        assert_eq!(
            mock.read_link(&link).unwrap(),
            PathBuf::from(&correct_target),
            "symlink target should be unchanged"
        );
    }

    #[test]
    fn symlink_wrong_target_overrides_when_no_agents_running() {
        let cfg = test_config();
        let link = cfg.host_config_link();
        let correct_target = cfg.container_fuse_file();

        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);
        // Pre-populate symlink with a WRONG target.
        mock.symlinks
            .insert(link.to_string_lossy().to_string(), "/wrong/target".to_string());
        // command_stdout defaults to "" → no containers running.

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());

        // Symlink should now point to the correct target.
        assert_eq!(
            mock.read_link(&link).unwrap(),
            PathBuf::from(&correct_target),
            "symlink should be overridden to correct target"
        );
    }

    #[test]
    fn symlink_wrong_target_errors_when_agents_running() {
        let cfg = test_config();
        let link = cfg.host_config_link();

        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);
        // Pre-populate symlink with a WRONG target.
        mock.symlinks
            .insert(link.to_string_lossy().to_string(), "/wrong/target".to_string());
        // Simulate a running container in the ps output.
        mock.command_stdout = "agent1_12345\n".to_string();

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("appears to be running"),
            "error should mention running agent: {err}"
        );

        // Symlink should NOT have been changed.
        assert_eq!(
            mock.read_link(&link).unwrap(),
            PathBuf::from("/wrong/target"),
            "symlink should not be overridden when agents are running"
        );
    }
}
