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

    // ── 4. Expand + load secrets, create symlinks ────────────────
    let pid = std::process::id();
    let mut fuse_names: Vec<String> = Vec::new();
    let mut counter = 0usize;

    for mapping in &config.secrets {
        load_secret_recursive(
            io, socket, &mapping.host, &mapping.container,
            config, pid, &mut counter, &mut fuse_names,
        )?;
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

    // ── 6. Run container ─────────────────────────────────────────
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

    // ── 7. Auto-reset all secret counters ────────────────────────
    let mut reset_ok = true;
    for name in &fuse_names {
        match fuse_client::send_command(io, socket, Command::Reset {
            name: Some(name.clone()),
        }) {
            Ok(fuse_protocol::Response::Ok) => {
                info!("Auto-reset successful for '{name}'.");
            }
            Ok(other) => {
                warn!("Auto-reset returned unexpected response for '{name}': {other:?}");
                reset_ok = false;
            }
            Err(e) => {
                warn!("Auto-reset failed for '{name}': {e}");
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

/// Recursively load a secret file or directory into the FUSE server and
/// create the corresponding symlink inside the config directory.
fn load_secret_recursive<S: SystemIo>(
    io: &mut S,
    socket: &Path,
    host: &Path,
    container: &Path,
    config: &AgentConfig,
    pid: u32,
    counter: &mut usize,
    fuse_names: &mut Vec<String>,
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
                config, pid, counter, fuse_names,
            )?;
        }
        return Ok(());
    }

    // ── Single file ──
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
        Ok(fuse_protocol::Response::Ok) => {}
        Ok(other) => return Err(format!("unexpected response adding secret: {other:?}")),
        Err(e) => return Err(format!("failed to add secret: {e}")),
    }

    // Map the absolute container path to a host-side symlink location
    // inside one of the bind-mounted directories.
    let host_link = container_to_host_path(container, config)?;

    // Create parent directories if needed (for nested paths).
    if let Some(parent) = host_link.parent() {
        io.create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }

    // Remove existing path (symlink or regular file) before creating.
    if io.is_symlink(&host_link) || io.file_exists(&host_link) {
        let _ = io.remove_path(&host_link);
    }

    let fuse_target = format!("/fuse/{fuse_name}");
    match io.create_symlink(Path::new(&fuse_target), &host_link) {
        Ok(()) => {
            info!("Secret: {} → {} → {}", host.display(), host_link.display(), fuse_target);
        }
        Err(e) => {
            warn!(
                "Could not create symlink {} → {fuse_target} ({e}). \
                 The FUSE mount is still available at {fuse_target}.",
                host_link.display()
            );
        }
    }

    fuse_names.push(fuse_name);
    Ok(())
}

/// Map an absolute container path back to the corresponding host path
/// within a bind-mounted directory.
fn container_to_host_path(
    container: &Path,
    config: &AgentConfig,
) -> Result<PathBuf, String> {
    let container_str = container.to_string_lossy();
    let config_prefix = format!("{}/", config.container_config_dir());
    let workspace_prefix = "/workspace/";

    if let Some(rel) = container_str.strip_prefix(&config_prefix) {
        Ok(config.host_config_dir().join(rel))
    } else if let Some(rel) = container_str.strip_prefix(workspace_prefix) {
        Ok(config.host_workspace().join(rel))
    } else {
        Err(format!(
            "container path {} is not under any bind-mounted directory ({} or /workspace/)",
            container.display(),
            config.container_config_dir()
        ))
    }
}

fn setup_rootless_docker() {
    let sock = format!("unix://{}", crate::config::rootless_docker_socket());
    std::env::set_var("DOCKER_HOST", &sock);
    info!("Docker rootless socket: {sock}");
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
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

        assert!(result.is_ok(), "got: {:?}", result.err());
        let run = result.unwrap();
        assert!(run.server_was_spawned);
        assert!(run.reset_ok);
        assert_eq!(run.container_exit_code, 0);
    }

    #[test]
    fn reuses_existing_server() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("/home/user/secrets.yaml", b"DATA");
        mock.unix_connected = true;
        mock = mock
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let result = run_agent(&mut mock, &cfg);

        assert!(result.is_ok(), "got: {:?}", result.err());
        let run = result.unwrap();
        assert!(!run.server_was_spawned);
    }

    #[test]
    fn symlink_created_in_config_dir() {
        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("/home/user/secrets.yaml", b"DATA")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let cfg = test_config();
        let _ = run_agent(&mut mock, &cfg);

        let link = PathBuf::from("/work/agent1/config/secrets.yaml");
        assert!(
            mock.is_symlink(&link),
            "symlink should exist at {}",
            link.display()
        );
        let target = mock.read_link(&link).unwrap();
        assert!(
            target.starts_with("/fuse/"),
            "symlink should point to /fuse/, got {}",
            target.display()
        );
    }

    #[test]
    fn multiple_secrets_all_get_symlinks() {
        let mut cfg = test_config();
        cfg.secrets = vec![
            SecretMapping {
                host: PathBuf::from("/home/user/key1.json"),
                container: PathBuf::from("/root/.config/goose/auth1.json"),
            },
            SecretMapping {
                host: PathBuf::from("/home/user/key2.json"),
                container: PathBuf::from("/root/.config/goose/auth2.json"),
            },
        ];

        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("/home/user/key1.json", b"KEY1")
            .with_file("/home/user/key2.json", b"KEY2")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());

        assert!(mock.is_symlink(Path::new("/work/agent1/config/auth1.json")));
        assert!(mock.is_symlink(Path::new("/work/agent1/config/auth2.json")));
    }

    #[test]
    fn directory_secret_expands_recursively() {
        let mut cfg = test_config();
        cfg.secrets = vec![SecretMapping {
            host: PathBuf::from("/home/user/secrets"),
            container: PathBuf::from("/root/.config/goose/secrets"),
        }];

        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("/home/user/secrets/key1.json", b"KEY1")
            .with_file("/home/user/secrets/subdir/key2.json", b"KEY2")
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#)
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_ok(), "got: {:?}", result.err());

        assert!(
            mock.is_symlink(Path::new("/work/agent1/config/secrets/key1.json")),
            "should have symlink for key1.json"
        );
        assert!(
            mock.is_symlink(Path::new("/work/agent1/config/secrets/subdir/key2.json")),
            "should have symlink for subdir/key2.json"
        );
    }

    #[test]
    fn container_path_outside_binds_errors() {
        let mut cfg = test_config();
        cfg.secrets = vec![SecretMapping {
            host: PathBuf::from("/home/user/key.json"),
            container: PathBuf::from("/etc/passwd"),
        }];

        let mut mock = MockSystemIo::new()
            .with_file("/work/agent1/config", b"")
            .with_file("/work/agent1/workspace", b"")
            .with_file("/home/user/key.json", b"KEY")
            .with_unix_response(br#"{"type":"ok"}"#);

        let result = run_agent(&mut mock, &cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not under any bind-mounted"));
    }
}
