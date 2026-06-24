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
/// 5. Create the config symlink.
/// 6. Detect container runtime.
/// 7. Run the container (foreground).
/// 8. **Auto-reset** this secret's counter.
/// 9. Clean up symlink (server is left running).
pub fn run_agent<S: SystemIo>(io: &mut S, config: &AgentConfig) -> Result<RunResult, String> {
    // ── 1. Validate ──────────────────────────────────────────────
    let host_config = config.host_config_dir();
    let host_workspace = config.host_workspace();

    for dir in [&host_config, &host_workspace] {
        if !io.file_exists(dir) {
            return Err(format!(
                "Directory {} not found. Is this really a Goose agent workspace?",
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

        // Build the full argv.  When sudo is requested, we spawn
        // `sudo <fuse-server> <args...>` so the FUSE mount has root
        // privileges (required for `allow_other` without editing fuse.conf).
        let mut spawn_args: Vec<&str> = Vec::new();
        let spawn_prog: &str;
        if config.use_sudo {
            spawn_prog = "sudo";
            spawn_args.push(server_bin);
        } else {
            spawn_prog = server_bin;
        }
        spawn_args.extend_from_slice(&args);

        let pid = io
            .spawn_independent(spawn_prog, &spawn_args, Some(std::path::Path::new(log_str)))
            .map_err(|e| format!("spawn fuse-server: {e}"))?;
        info!("fuse-server spawned as independent daemon (pid {pid}, sudo={}).", config.use_sudo);

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

    // ── 5. Symlink config → /fuse/<file> ─────────────────────────
    let cont_fuse_file = config.container_fuse_file();
    let host_link = config.host_config_link();
    let mut backup_path: Option<PathBuf> = None;

    if io.is_symlink(&host_link) {
        info!("Symlink already exists: {}", host_link.display());
    } else {
        // Collision: the symlink path is occupied by the original file.
        if io.file_exists(&host_link) {
            let backup = PathBuf::from(format!("{}.orig", host_link.display()));
            info!(
                "Collision at {} — moving original to {}",
                host_link.display(),
                backup.display()
            );
            io.rename_path(&host_link, &backup)
                .map_err(|e| format!("rename original aside: {e}"))?;
            backup_path = Some(backup);
        }

        match io.create_symlink(Path::new(&cont_fuse_file), &host_link) {
            Ok(()) => info!("Symlink: {} -> {cont_fuse_file}", host_link.display()),
            Err(e) => {
                // Symlink failed; restore original if we moved it.
                if let Some(backup) = backup_path.take() {
                    let _ = io.rename_path(&backup, &host_link);
                }
                warn!(
                    "Could not create symlink at {} ({}). \
                     The FUSE mount is still available at {cont_fuse_file}.",
                    host_link.display(), e
                );
            }
        }
    }

    // ── 6. Detect container runtime ──────────────────────────────
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
    info!("Container exited with code {exit_code}.");

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

    // ── 9. Restore original file if it was moved aside ─────────
    if let Some(backup) = backup_path {
        info!(
            "Restoring original config file from {} to {}",
            backup.display(),
            host_link.display()
        );
        let _ = io.remove_path(&host_link);
        let _ = io.rename_path(&backup, &host_link);
    }

    // ── 10. Done (server stays running) ──────────────────────
    Ok(RunResult {
        container_exit_code: exit_code,
        reset_ok,
        server_was_spawned,
    })
}

fn setup_rootless_docker() {
    let sock = format!("unix://{}", crate::config::rootless_docker_socket());
    std::env::set_var("DOCKER_HOST", &sock);
    info!("Docker rootless socket: {sock}");
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
    fn symlink_collision_restores_original() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            // Both relative (for read_file) and absolute (for file_exists collision check)
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
            !mock.is_symlink(&link),
            "symlink should not persist after collision restore"
        );
        assert!(
            mock.file_exists(&link),
            "original file should be restored at link path"
        );
        assert_eq!(
            mock.read_file(&link).unwrap(),
            b"SECRET_DATA",
            "restored content must match original"
        );

        let backup = PathBuf::from(format!("{}.orig", link.display()));
        assert!(
            !mock.file_exists(&backup),
            "backup .orig file should not remain"
        );
        assert!(
            !mock.is_symlink(&backup),
            "backup path should not exist as symlink"
        );
    }
}
