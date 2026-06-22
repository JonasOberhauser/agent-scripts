use std::path::Path;
use std::time::{Duration, Instant};

use fuse_protocol::{Command, SystemIo};
use tracing::{info, warn};

use crate::config::{build_container_args, detect_container_runtime_name, AgentConfig};

/// Result of a completed agent session.
#[derive(Debug)]
pub struct RunResult {
    pub container_exit_code: i32,
    pub reset_ok: bool,
}

/// Full orchestration loop.  This is the Rust replacement for `run-agent.sh`.
///
/// Steps:
/// 1. Validate workspace directories.
/// 2. Create the FUSE mount-point directory.
/// 3. Spawn `fuse-server` as a background process.
/// 4. Wait for the Unix socket to appear.
/// 5. Create the config symlink.
/// 6. Detect the container runtime.
/// 7. Run the container (foreground, inheriting stdio).
/// 8. **Auto-reset** the FUSE gatekeeper counter via the socket.
/// 9. Clean up: remove symlink, shut down fuse-server.
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

    // ── 2. Create FUSE mount-point ────────────────────────────────
    let host_fuse = config.host_fuse();
    io.create_dir_all(&host_fuse)
        .map_err(|e| format!("create {}: {e}", host_fuse.display()))?;

    // ── 3. Spawn fuse-server ──────────────────────────────────────
    let socket_path = config.socket_path();
    let secret_spec = format!(
        "{}:{}:{}",
        config.filename(),
        config.host_config_file.display(),
        config.binary_hash
    );

    let fuse_args: Vec<&str> = vec![
        "--mount-point",
        host_fuse.to_str().unwrap(),
        "--socket",
        socket_path.to_str().unwrap(),
        "--secret",
        &secret_spec,
        "--allow-other",
    ];

    let fuse_pid = io
        .spawn_detached(
            config.fuse_server_path.to_str().unwrap(),
            &fuse_args,
        )
        .map_err(|e| format!("spawn fuse-server: {e}"))?;
    info!("fuse-server spawned (pid {fuse_pid}).");

    // ── 4. Wait for socket ────────────────────────────────────────
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if io.file_exists(&socket_path) {
            break;
        }
        if Instant::now() > deadline {
            return Err("fuse-server socket did not appear within 10s".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    info!("Socket ready at {}", socket_path.display());

    // ── 5. Symlink config → /fuse/<file> ─────────────────────────
    let cont_fuse_file = config.container_fuse_file();
    let host_link = config.host_config_link();
    // Remove stale symlink if present.
    let _ = io.remove_path(&host_link);
    io.create_symlink(Path::new(&cont_fuse_file), &host_link)
        .map_err(|e| format!("symlink: {e}"))?;
    info!("Symlink: {} -> {cont_fuse_file}", host_link.display());

    // ── 6. Detect container runtime ──────────────────────────────
    let container_bin = match detect_container_runtime_name(io) {
        Some(bin) => bin,
        None => {
            cleanup(io, &host_link);
            return Err("Neither docker nor podman found in PATH.".into());
        }
    };
    info!("Using container runtime: {container_bin}");

    // Docker rootless setup.
    if container_bin == "docker" {
        setup_rootless_docker(io);
    }

    // ── 7. Run container ─────────────────────────────────────────
    let args = build_container_args(config);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let exit_code = io
        .run_interactive(container_bin, &arg_refs)
        .unwrap_or(-1);
    info!("Container exited with code {exit_code}.");

    // ── 8. Auto-reset ────────────────────────────────────────────
    let reset_ok = match fuse_client::send_command(&socket_path, Command::Reset { name: None }) {
        Ok(fuse_protocol::Response::Ok) => {
            info!("Auto-reset successful.");
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

    // ── 9. Cleanup ───────────────────────────────────────────────
    cleanup(io, &host_link);

    Ok(RunResult {
        container_exit_code: exit_code,
        reset_ok,
    })
}

fn setup_rootless_docker<S: SystemIo>(io: &S) {
    let uid = std::process::id();
    let sock = format!("unix:///run/user/{uid}/docker.sock");
    std::env::set_var("DOCKER_HOST", &sock);
    // Best-effort: start the user docker service.
    let _ = io.run_command("systemctl", &["--user", "start", "docker.service"]);
    info!("Docker rootless socket: {sock}");
}

fn cleanup<S: SystemIo>(io: &mut S, link: &Path) {
    let _ = io.remove_path(link);
    info!("Symlink removed.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
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
        }
    }

    #[test]
    fn missing_workspace_dirs_errors() {
        let mut mock = MockSystemIo::new(); // no files
        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not found") || err.contains("workspace"));
    }

    #[test]
    fn full_flow_with_mock() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"") // config dir "exists"
            .with_file("/work/agent1/workspace", b""); // workspace "exists"
        // socket needs to "appear" — the mock returns true for file_exists
        // only for files we've added, so pre-add the socket path too.
        mock = mock.with_file("/work/agent1/fuse-gatekeeper.sock", b"");

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

        // The mock's send_command will fail (no real socket), but the flow
        // should still complete because auto-reset failures are non-fatal.
        assert!(result.is_ok(), "got: {:?}", result.err());
        let run = result.unwrap();
        assert_eq!(run.container_exit_code, 0);
        // auto-reset fails because there's no real socket → false
        assert!(!run.reset_ok);

        // fuse-server was spawned
        assert_eq!(mock.spawned.len(), 1);
        assert_eq!(mock.spawned[0].0, "fuse-server");
    }

    #[test]
    fn cleanup_removes_symlink() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("/work/agent1/fuse-gatekeeper.sock", b"");

        let cfg = test_config();
        let _ = run_agent(&mut mock, &cfg);

        // The symlink file should have been removed during cleanup.
        let link = cfg.host_config_link();
        assert!(!mock.files.contains_key(&link.to_string_lossy().to_string()));
    }
}
