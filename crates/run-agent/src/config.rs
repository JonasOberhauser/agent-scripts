use std::path::{Path, PathBuf};

use fuse_protocol::SystemIo;

/// Well-known default Unix socket path for the shared fuse-server.
pub const DEFAULT_SOCKET: &str = "/tmp/fuse-gatekeeper.sock";

/// Well-known default FUSE mount point for the shared fuse-server.
pub const DEFAULT_MOUNT_POINT: &str = "/tmp/fuse-gatekeeper-mnt";

/// Which container runtime to use.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum Runtime {
    /// Auto-detect: rootless podman first, then rootless docker.
    Auto,
    Docker,
    Podman,
}

/// Returns the Unix UID of the current process.
fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// Path to the rootless Docker socket for the current user.
pub fn rootless_docker_socket() -> String {
    format!("/run/user/{}/docker.sock", current_uid())
}

impl Runtime {
    /// Resolve to a concrete runtime name, probing the system.
    /// Returns `None` if the runtime is not available.
    /// When `wrapper` is set, detection runs `<wrapper> <runtime> --version`.
    pub fn resolve<S: SystemIo>(
        &self,
        io: &S,
        wrapper: Option<&str>,
    ) -> Option<&'static str> {
        match self {
            Runtime::Podman => {
                if runtime_available(io, wrapper, "podman") {
                    Some("podman")
                } else {
                    None
                }
            }
            Runtime::Docker => {
                if runtime_available(io, wrapper, "docker") {
                    Some("docker")
                } else {
                    None
                }
            }
            Runtime::Auto => {
                if runtime_available(io, wrapper, "podman") {
                    Some("podman")
                } else if runtime_available(io, wrapper, "docker") {
                    Some("docker")
                } else {
                    None
                }
            }
        }
    }
}

/// Check whether `<wrapper>? <runtime> --version` succeeds.
fn runtime_available<S: SystemIo>(
    io: &S,
    wrapper: Option<&str>,
    runtime: &str,
) -> bool {
    match wrapper {
        Some(w) => {
            let parts: Vec<&str> = w.split_whitespace().collect();
            if parts.is_empty() {
                return false;
            }
            let mut args: Vec<&str> = parts[1..].to_vec();
            args.push(runtime);
            args.push("--version");
            io.run_command(parts[0], &args)
                .map(|o| o.success())
                .unwrap_or(false)
        }
        None => {
            // Podman: just check the binary. Docker: require rootless socket.
            if runtime == "docker" {
                let sock = rootless_docker_socket();
                io.try_unix_connect(Path::new(&sock))
            } else {
                io.run_command(runtime, &["--version"])
                    .map(|o| o.success())
                    .unwrap_or(false)
            }
        }
    }
}

/// Split a wrapper string like `"flatpak-spawn --host"` into
/// `("flatpak-spawn", ["--host"])`.
pub fn split_wrapper(wrapper: &str) -> (String, Vec<String>) {
    let parts: Vec<String> = wrapper.split_whitespace().map(|s| s.to_string()).collect();
    (parts[0].clone(), parts[1..].to_vec())
}

/// A single secret mapping, Docker `-v` style: `HOST:CONTAINER`.
///
/// The real file (or directory) at `host` is loaded into the FUSE
/// gatekeeper.  A symlink is created inside the bind-mounted config
/// directory so the secret appears at `container` (an absolute container
/// path) and reads are redirected to `/fuse/<name>`.
///
/// If `host` is a directory, it is mapped recursively (`cp -r` style).
#[derive(Debug, Clone)]
pub struct SecretMapping {
    /// Host-side path to the real secret file or directory.
    pub host: PathBuf,
    /// Absolute path inside the container where the secret should appear.
    pub container: PathBuf,
}

impl SecretMapping {
    /// Parse a `HOST:CONTAINER` string.
    ///
    /// `~` is **not** expanded by us — the caller's shell expands it for
    /// host paths, and the container's `sh -c` expands it for container
    /// paths (where `~` = `/root`).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (host, container) = s
            .split_once(':')
            .ok_or_else(|| format!("--secret expects HOST:CONTAINER, got '{s}'"))?;
        let host = host.trim();
        let container = container.trim();
        if host.is_empty() || container.is_empty() {
            return Err(format!(
                "--secret host and container must be non-empty: '{s}'"
            ));
        }
        Ok(Self {
            host: PathBuf::from(host),
            container: PathBuf::from(container),
        })
    }
}

/// All parameters needed to launch an agent session.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// SHA-256 of the binary allowed to read the secret.
    pub binary_hash: String,
    /// Secret files to serve through the FUSE gatekeeper.
    pub secrets: Vec<SecretMapping>,
    /// Subfolder under `~/.config/` inside the container (e.g. `goose`).
    pub agent_subfolder: String,
    /// Extra arguments forwarded to the container command.
    pub container_args: Vec<String>,
    /// Working directory (the agent workspace root on the host).
    pub agent_path: PathBuf,
    /// Path to the `fuse-server` binary.
    pub fuse_server_path: PathBuf,
    /// Docker/Podman image name.
    pub image_name: String,
    /// Container memory limit.
    pub memory: String,
    /// Container CPU limit.
    pub cpus: String,
    /// Unix socket path for the shared fuse-server.
    pub socket_path: PathBuf,
    /// FUSE mount point (shared across projects).
    pub mount_point: PathBuf,
    /// Run fuse-server under `sudo` (needed for `allow_other` without
    /// editing `/etc/fuse.conf`).
    pub use_sudo: bool,
    /// Pass `--allow-other` to the fuse-server so users other than the
    /// mount owner can access the FUSE filesystem.  **Not needed** with
    /// rootless podman, where the container's root maps to the host user
    /// that created the mount.
    pub allow_other: bool,
    /// Pass `--pidns=host` to the container so its processes share the
    /// host's PID namespace.  This allows the FUSE server (on the host)
    /// to read `/proc/{pid}/exe` and verify the binary hash.
    pub pidns_host: bool,
    /// Container runtime preference.
    pub runtime: Runtime,
    /// Optional prefix command for the container runtime (e.g.
    /// `flatpak-spawn --host` to reach the host's podman from a toolbox).
    pub runtime_wrapper: Option<String>,

    /// Log level for the fuse-server (e.g. "info", "debug", "warn").
    pub log_level: String,

    /// Host path to the plans directory (optional – only mounted when set).
    pub plans_path: Option<PathBuf>,
}

impl AgentConfig {
    /// Derive a config from positional args, using sensible defaults.
    pub fn from_args(
        binary_hash: &str,
        secrets: Vec<SecretMapping>,
        agent_subfolder: &str,
        container_args: &[String],
    ) -> Self {
        Self {
            binary_hash: binary_hash.to_string(),
            secrets,
            agent_subfolder: agent_subfolder.to_string(),
            container_args: container_args.to_vec(),
            agent_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            fuse_server_path: PathBuf::from("fuse-server"),
            image_name: "agentbox".to_string(),
            memory: "224G".to_string(),
            cpus: "90".to_string(),
            socket_path: PathBuf::from(DEFAULT_SOCKET),
            mount_point: PathBuf::from(DEFAULT_MOUNT_POINT),
            use_sudo: false,
            allow_other: false,
            pidns_host: false,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: "info".to_string(),
            plans_path: None,
        }
    }

    // ── computed paths ────────────────────────── ──────────────────────────────────────────

    pub fn host_config_dir(&self) -> PathBuf {
        self.agent_path.join("config")
    }

    pub fn host_workspace(&self) -> PathBuf {
        self.agent_path.join("workspace")
    }

    pub fn host_fuse(&self) -> PathBuf {
        self.mount_point.clone()
    }

    pub fn agent_name(&self) -> String {
        self.agent_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "agent".to_string())
    }

    pub fn container_config_dir(&self) -> String {
        format!("/root/.config/{}", self.agent_subfolder)
    }

    pub fn container_name(&self) -> String {
        format!(
            "{}_{}",
            self.agent_name(),
            chrono_like_timestamp()
        )
    }
}

fn chrono_like_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

/// Build the full `docker run` / `podman run` argument vector.
///
/// `setup_script` is a shell snippet (e.g. `mkdir -p ... && ln -sf ...`)
/// that runs inside the container before the main command.  When non-empty,
/// the container command is wrapped as `sh -c '<setup> && exec "$@"' sh <args>`
/// so the symlinks are created inside the container using native paths.
///
/// Pure function — trivially unit-testable without any I/O.
pub fn build_container_args(config: &AgentConfig, setup_script: &str) -> Vec<String> {
    let mut args = vec![
        "run".into(),
        "-it".into(),
        "--rm".into(),
        "--name".into(),
        config.container_name(),
        "-m".into(),
        config.memory.clone(),
        "--cpus".into(),
        config.cpus.clone(),
        "--user".into(),
        "root".into(),
        "-v".into(),
        format!(
            "{}:{}:slave,Z",
            config.host_config_dir().display(),
            config.container_config_dir()
        ),
        "-v".into(),
        format!(
            "{}:/workspace:slave,Z",
            config.host_workspace().display()
        ),
    ];

    if let Some(plans) = &config.plans_path {
        args.push("-v".into());
        args.push(format!("{}:/workspace/plans:Z", plans.display()));
    }

    args.extend_from_slice(&[
        "-v".into(),
        format!("{}_home:/root:z", config.agent_name()),
        "-v".into(),
        format!("{}:/fuse:ro,z", config.host_fuse().display()),
        "--workdir".into(),
        "/workspace".into(),
    ]);

    if config.pidns_host {
        args.push("--pid".into());
        args.push("host".into());
    }

    args.push(config.image_name.clone());

    if setup_script.is_empty() {
        args.extend(config.container_args.iter().cloned());
    } else {
        // Wrap: sh -c '<setup> && exec "$@"' sh <original args>
        args.push("sh".into());
        args.push("-c".into());
        if config.container_args.is_empty() {
            args.push(format!("{setup_script} && exec bash"));
        } else {
            args.push(format!("{setup_script} && exec \"$@\""));
            args.push("sh".into());
            args.extend(config.container_args.iter().cloned());
        }
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::MockSystemIo;

    #[test]
    fn secret_mapping_parse() {
        let m = SecretMapping::parse("/home/jonas/key.json:/root/.config/opencode/auth.json").unwrap();
        assert_eq!(m.host, PathBuf::from("/home/jonas/key.json"));
        assert_eq!(m.container, PathBuf::from("/root/.config/opencode/auth.json"));
    }

    #[test]
    fn secret_mapping_parse_rejects_missing_colon() {
        assert!(SecretMapping::parse("no_colon").is_err());
    }

    #[test]
    fn secret_mapping_parse_rejects_empty_host() {
        assert!(SecretMapping::parse(":/container/path").is_err());
    }

    #[test]
    fn secret_mapping_parse_rejects_empty_container() {
        assert!(SecretMapping::parse("/host:").is_err());
    }

    #[test]
    fn secret_mapping_parse_allows_tilde_container() {
        let m = SecretMapping::parse("/host/key:~/.config/app/key.json").unwrap();
        assert_eq!(m.container, PathBuf::from("~/.config/app/key.json"));
    }

    #[test]
    fn secret_mapping_parse_directory_paths() {
        let m = SecretMapping::parse("/host/secrets/:/root/.config/app/secrets/").unwrap();
        assert_eq!(m.host, PathBuf::from("/host/secrets/"));
        assert_eq!(m.container, PathBuf::from("/root/.config/app/secrets/"));
    }

    #[test]
    fn container_args_basics() {
        let cfg = AgentConfig {
            binary_hash: "h".into(),
            secrets: vec![],
            agent_subfolder: "goose".into(),
            container_args: vec!["--flag".into()],
            agent_path: PathBuf::from("/work/myagent"),
            fuse_server_path: "fuse-server".into(),
            image_name: "myimg".into(),
            memory: "16G".into(),
            cpus: "4".into(),
            socket_path: PathBuf::from("/tmp/fuse-gatekeeper.sock"),
            mount_point: PathBuf::from("/tmp/fuse-gatekeeper-mnt"),
            use_sudo: false,
            allow_other: false,
            pidns_host: false,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: "info".to_string(),
            plans_path: None,
        };
        let args = build_container_args(&cfg, "");
        assert!(args.contains(&"run".to_string()));
        assert!(args.contains(&"-it".to_string()));
        assert!(args.contains(&"--rm".to_string()));
        assert!(args.contains(&"--user".into()));
        assert!(args.contains(&"root".into()));
        assert!(args.contains(&"--workdir".into()));
        assert!(args.contains(&"/workspace".into()));
        assert!(args.contains(&"myimg".into()));
        assert!(args.contains(&"--flag".into()));

        // config volume mapping
        let cfg_vol: String = args
            .iter()
            .find(|a| a.contains("config") && a.contains("/root/.config/goose"))
            .cloned()
            .unwrap();
        assert!(cfg_vol.contains("slave,Z"));

        // fuse mount
        assert!(args.iter().any(|a| a.contains("/fuse:ro")));
        // no pidns by default
        assert!(!args.iter().any(|a| a.contains("--pidns")));
    }

    #[test]
    fn container_args_pidns_host() {
        let mut cfg = AgentConfig {
            binary_hash: "h".into(),
            secrets: vec![],
            agent_subfolder: "goose".into(),
            container_args: vec![],
            agent_path: PathBuf::from("/work/myagent"),
            fuse_server_path: "fuse-server".into(),
            image_name: "myimg".into(),
            memory: "16G".into(),
            cpus: "4".into(),
            socket_path: PathBuf::from("/tmp/fuse-gatekeeper.sock"),
            mount_point: PathBuf::from("/tmp/fuse-gatekeeper-mnt"),
            use_sudo: false,
            allow_other: false,
            pidns_host: true,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: "info".to_string(),
            plans_path: None,
        };
        let args = build_container_args(&cfg, "");
        assert!(
            args.iter().any(|a| a == "--pid") && args.iter().any(|a| a == "host"),
            "should include --pid host when pidns_host is true"
        );
    }

    #[test]
    fn runtime_auto_prefers_podman() {
        let mock = MockSystemIo::new();
        assert_eq!(Runtime::Auto.resolve(&mock, None), Some("podman"));
    }

    #[test]
    fn runtime_auto_falls_back_to_docker() {
        let mut mock = MockSystemIo::new();
        mock.command_status = None;
        mock.unix_connected = true;
        assert_eq!(Runtime::Auto.resolve(&mock, None), Some("docker"));
    }

    #[test]
    fn runtime_auto_none_when_nothing_available() {
        let mut mock = MockSystemIo::new();
        mock.command_status = None;
        assert_eq!(Runtime::Auto.resolve(&mock, None), None);
    }

    #[test]
    fn runtime_podman_forces_podman() {
        let mock = MockSystemIo::new();
        assert_eq!(Runtime::Podman.resolve(&mock, None), Some("podman"));
    }

    #[test]
    fn runtime_docker_forces_docker() {
        let mut mock = MockSystemIo::new();
        mock.unix_connected = true;
        assert_eq!(Runtime::Docker.resolve(&mock, None), Some("docker"));
    }

    #[test]
    fn runtime_with_wrapper() {
        let mock = MockSystemIo::new();
        assert_eq!(
            Runtime::Podman.resolve(&mock, Some("flatpak-spawn --host")),
            Some("podman")
        );
    }

    #[test]
    fn split_wrapper_parses() {
        let (prog, args) = super::split_wrapper("flatpak-spawn --host");
        assert_eq!(prog, "flatpak-spawn");
        assert_eq!(args, vec!["--host"]);
    }

    #[test]
    fn container_name_contains_agent_name() {
        let cfg = AgentConfig::from_args("h", vec![], "goose", &[]);
        let name = cfg.container_name();
        assert!(name.starts_with(&cfg.agent_name()));
    }
}
