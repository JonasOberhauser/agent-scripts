#![cfg_attr(test, allow(unknown_lints, inline_literal))]
use std::path::{Path, PathBuf};

use fuse_protocol::SystemIo;

/// Well-known default Unix socket path for the shared fuse-server.
pub const DEFAULT_SOCKET: &str = fuse_protocol::DEFAULT_SOCKET;

/// Well-known default FUSE mount point for the shared fuse-server.
pub const DEFAULT_MOUNT_POINT: &str = fuse_protocol::DEFAULT_MOUNT_POINT;

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
    // SAFETY: getuid(2) is a pure FFI getter with no preconditions,
    // no pointers, and no failure mode on Linux.
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
                if runtime_available(io, wrapper, RUNTIME_PODMAN) {
                    Some(RUNTIME_PODMAN)
                } else {
                    None
                }
            }
            Runtime::Docker => {
                if runtime_available(io, wrapper, RUNTIME_DOCKER) {
                    Some(RUNTIME_DOCKER)
                } else {
                    None
                }
            }
            Runtime::Auto => {
                if runtime_available(io, wrapper, RUNTIME_PODMAN) {
                    Some(RUNTIME_PODMAN)
                } else if runtime_available(io, wrapper, RUNTIME_DOCKER) {
                    Some(RUNTIME_DOCKER)
                } else {
                    None
                }
            }
        }
    }
}

/// Check whether `<wrapper>? <runtime> --version` succeeds.
// Necessity: wrapper argv splitting (parts[0], parts[1..]).
#[allow(unknown_lints)]
#[allow(inline_literal)]
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
            args.push(VERSION_FLAG);
            io.run_command(parts[0], &args)
                .map(|o| o.success())
                .unwrap_or(false)
        }
        None => {
            // Podman: just check the binary. Docker: require rootless socket.
            if runtime == RUNTIME_DOCKER {
                let sock = rootless_docker_socket();
                io.try_unix_connect(Path::new(&sock))
            } else {
                io.run_command(runtime, &[VERSION_FLAG])
                    .map(|o| o.success())
                    .unwrap_or(false)
            }
        }
    }
}

/// Split a wrapper string like `"flatpak-spawn --host"` into
/// `("flatpak-spawn", ["--host"])`.
// Necessity: wrapper argv splitting (parts[0], parts[1..]).
#[allow(unknown_lints)]
#[allow(inline_literal)]
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
/// Container runtime names.
pub(crate) const RUNTIME_PODMAN: &str = "podman";
pub(crate) const RUNTIME_DOCKER: &str = "docker";
/// Default resource budget for the agent box.
const DEFAULT_IMAGE: &str = "agentbox";
const DEFAULT_MEMORY: &str = "224G";
const DEFAULT_CPUS: &str = "90";
/// Container-side workspace path.
pub(crate) const CONTAINER_WORKDIR: &str = "/workspace";
/// Container engine verbs + flags (podman/docker run dialect).
pub(crate) const RUN_CMD: &str = "run";
const DETACH_FLAG: &str = "-d";
const NAME_FLAG: &str = "--name";
const MEMORY_FLAG: &str = "-m";
const CPUS_FLAG: &str = "--cpus";
const USER_FLAG: &str = "--user";
const ROOT_USER: &str = "root";
const VOLUME_FLAG: &str = "-v";
const DEVICE_FLAG: &str = "--device";
const WORKDIR_FLAG: &str = "--workdir";
const SECCOMP_FLAG: &str = "--security-opt";
const PID_FLAG: &str = "--pid";
const PID_HOST: &str = "host";
const SLEEP_CMD: &str = "sleep";
const SLEEP_INFINITY: &str = "infinity";
const EXEC_CMD: &str = "exec";
const TTY_INTERACTIVE: &str = "-it";
const CHDIR_FLAG: &str = "-w";
const SHELL_BIN: &str = "sh";
const SHELL_CMD_FLAG: &str = "-c";
/// Container-mount option suffixes.
const OPT_SLAVE_Z: &str = "slave,Z";
const OPT_Z: &str = ":Z";
const OPT_RO_Z_SLAVE: &str = "ro,z,slave";
/// Volume mount targets (container side).
/// Version probe flag.
const VERSION_FLAG: &str = "--version";
/// Temp-file name for the materialized seccomp profile.
const SECCOMP_TMP_NAME: &str = "agentbox-seccomp.json";
/// Default log level + agent name fallback.
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_AGENT_NAME: &str = "agent";
/// Fallback cwd when the current dir is unreadable.
const FALLBACK_CWD: &str = ".";
/// The container-side fuse mount target.
const FUSE_MOUNT_TARGET: &str = "/fuse";
/// Local config/workspace dir names under agent_path.
const CONFIG_DIR: &str = "config";
const WORKSPACE_DIR: &str = "workspace";
/// Short-hash prefix length in container names.
const NAME_HASH_CHARS: usize = 8;

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
    /// paths (where `~` = `/root`). Built from the two WORDS clap
    /// delivers (`--secret HOST CONTAINER`, num_args = 2): no
    /// delimiter grammar, nothing to escape, no parsing — colons are
    /// ordinary path characters and the shell expands ~ in both.
    pub fn from_pair(host: &str, container: &str) -> Result<Self, String> {
        if host.is_empty() || container.is_empty() {
            return Err("--secret host and container must be non-empty".to_string());
        }
        Ok(Self {
            host: PathBuf::from(host),
            container: PathBuf::from(container),
        })
    }
}

/// All parameters needed to launch an agent session.
/// Seccomp profile applied to every container run-agent creates.
///
/// Vendored from containers-common's `/usr/share/containers/seccomp.json`
/// (podman's own shipped profile).  Unlike moby-style defaults it allows
/// the namespace/mount syscall group (`clone`, `clone3`, `unshare`,
/// `setns`, `mount`, `umount2`, the new mount API) so the agent box can
/// run nested *rootless* podman/docker — no capabilities are granted;
/// the kernel still limits mounts to user-namespace-scoped filesystems.
pub const NESTED_SECCOMP_PROFILE: &str = include_str!("seccomp_profile.json");

/// Host-side location the profile is written to before container
/// creation.  Fixed path is fine: content is identical every run.
pub fn seccomp_profile_path() -> PathBuf {
    std::env::temp_dir().join(SECCOMP_TMP_NAME)
}

#[derive(Debug, Clone)]
/// Container runtime names.
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
    /// Host-side path of the seccomp profile passed via
    /// `--security-opt seccomp=…` at container creation.
    pub seccomp_profile: PathBuf,
    /// Container memory limit.
    pub memory: String,
    /// Container CPU limit.
    pub cpus: String,
    /// Non-interactively accept remediation prompts (e.g. building the
    /// missing agentbox image) — for scripts and tests.
    pub auto_confirm: bool,
    /// Unix socket path for the shared fuse-server.
    pub socket_path: PathBuf,
    /// Oracle rendezvous override for the spawned policy daemon;
    /// `None` = the server's global default (single-stack
    /// production). Harnesses isolate per tempdir.
    pub oracle_socket: Option<std::path::PathBuf>,
    /// FUSE mount point (shared across projects).
    pub mount_point: PathBuf,
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
            agent_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(FALLBACK_CWD)),
            fuse_server_path: PathBuf::from(fuse_protocol::SERVER_BIN),
            oracle_socket: None,
            image_name: DEFAULT_IMAGE.to_string(),
            seccomp_profile: seccomp_profile_path(),
            memory: DEFAULT_MEMORY.to_string(),
            cpus: DEFAULT_CPUS.to_string(),
            auto_confirm: false,
            socket_path: PathBuf::from(DEFAULT_SOCKET),
            mount_point: PathBuf::from(DEFAULT_MOUNT_POINT),
            pidns_host: false,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            plans_path: None,
        }
    }

    // ── computed paths ────────────────────────── ──────────────────────────────────────────

    pub fn host_config_dir(&self) -> PathBuf {
        self.agent_path.join(CONFIG_DIR)
    }

    pub fn host_workspace(&self) -> PathBuf {
        self.agent_path.join(WORKSPACE_DIR)
    }

    pub fn host_fuse(&self) -> PathBuf {
        self.mount_point.clone()
    }

    pub fn agent_name(&self) -> String {
        self.agent_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| DEFAULT_AGENT_NAME.to_string())
    }

    pub fn container_config_dir(&self) -> String {
        format!("/root/.config/{}", self.agent_subfolder)
    }

    pub fn container_name(&self) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.agent_path.to_string_lossy().as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        format!("{DEFAULT_IMAGE}-{}", &hash[..NAME_HASH_CHARS])
    }
}

/// Build `docker run -d` args to create the persistent container.
/// `devices` are host device paths to pass through (e.g. `/dev/fuse`,
/// `/dev/net/tun`) — the caller passes only those that exist.
pub fn build_create_args(config: &AgentConfig, devices: &[String]) -> Vec<String> {
    let mut args = vec![
        RUN_CMD.into(),
        DETACH_FLAG.into(),
        NAME_FLAG.into(),
        config.container_name(),
        MEMORY_FLAG.into(),
        config.memory.clone(),
        CPUS_FLAG.into(),
        config.cpus.clone(),
        USER_FLAG.into(),
        ROOT_USER.into(),
        VOLUME_FLAG.into(),
        format!(
            "{}:{}:{OPT_SLAVE_Z}",
            config.host_config_dir().display(),
            config.container_config_dir()
        ),
        VOLUME_FLAG.into(),
        format!(
            "{}:{CONTAINER_WORKDIR}:{OPT_SLAVE_Z}",
            config.host_workspace().display()
        ),
    ];

    if let Some(plans) = &config.plans_path {
        args.push(VOLUME_FLAG.into());
        args.push(format!(
            "{}:{CONTAINER_WORKDIR}/plans:{OPT_Z}",
            plans.display()
        ));
    }

    for d in devices {
        args.push(DEVICE_FLAG.into());
        args.push(d.clone());
    }

    args.extend_from_slice(&[
        VOLUME_FLAG.into(),
        format!("{}_home:/root:z", config.agent_name()),
        VOLUME_FLAG.into(),
        format!(
            "{}:{FUSE_MOUNT_TARGET}:{OPT_RO_Z_SLAVE}",
            config.host_fuse().display()
        ),
        WORKDIR_FLAG.into(),
        CONTAINER_WORKDIR.into(),
        SECCOMP_FLAG.into(),
        format!("seccomp={}", config.seccomp_profile.display()),
    ]);

    if config.pidns_host {
        args.push(PID_FLAG.into());
        args.push(PID_HOST.into());
    }

    args.push(config.image_name.clone());
    args.push(SLEEP_CMD.into());
    args.push(SLEEP_INFINITY.into());

    args
}

/// Build `docker exec -it` args to run a session inside the persistent container.
///
/// `setup_script` is a shell snippet (e.g. `mkdir -p ... && ln -sf ...`)
/// that creates symlinks before the main command.  When non-empty,
/// the exec command is wrapped as `sh -c '<setup> && exec "$@"' sh <args>`.
pub fn build_exec_args(config: &AgentConfig, setup_script: &str) -> Vec<String> {
    let mut args = vec![
        EXEC_CMD.into(),
        TTY_INTERACTIVE.into(),
        CHDIR_FLAG.into(),
        CONTAINER_WORKDIR.into(),
        config.container_name(),
    ];

    if setup_script.is_empty() {
        args.extend(config.container_args.iter().cloned());
    } else {
        args.push(SHELL_BIN.into());
        args.push(SHELL_CMD_FLAG.into());
        if config.container_args.is_empty() {
            args.push(format!("{setup_script} && exec bash"));
        } else {
            args.push(format!("{setup_script} && exec \"$@\""));
            args.push(SHELL_BIN.into());
            args.extend(config.container_args.iter().cloned());
        }
    }

    args
}

// Tests may hand-parse output/protocol lines: sanctioned by policy
// (test + allow), NOT available to production code. unknown_lints:
// the custom_parser lint exists only under the servyi driver.
#[cfg(test)]
#[allow(unknown_lints)]
#[allow(custom_parser)]
mod tests {
    use super::*;
    use fuse_protocol::MockSystemIo;

    #[test]
    fn secret_mapping_from_pair() {
        let m = SecretMapping::from_pair(
            "/home/jonas/key.json",
            "/root/.config/opencode/auth.json",
        )
        .unwrap();
        assert_eq!(m.host, PathBuf::from("/home/jonas/key.json"));
        assert_eq!(m.container, PathBuf::from("/root/.config/opencode/auth.json"));
    }

    #[test]
    fn secret_mapping_accepts_colons_in_either_path() {
        // two words, no delimiter: colons are ordinary characters
        let m = SecretMapping::from_pair("/host/a:b", "/root/c:d/e").unwrap();
        assert_eq!(m.host, PathBuf::from("/host/a:b"));
        assert_eq!(m.container, PathBuf::from("/root/c:d/e"));
    }

    #[test]
    fn secret_mapping_rejects_empty_either_side() {
        assert!(SecretMapping::from_pair("", "/c").is_err());
        assert!(SecretMapping::from_pair("/h", "").is_err());
    }

    #[test]
    fn secret_mapping_allows_tilde_container() {
        let m = SecretMapping::from_pair("/host/key", "~/.config/app/key.json").unwrap();
        assert_eq!(m.container, PathBuf::from("~/.config/app/key.json"));
    }

    #[test]
    fn secret_mapping_directory_paths() {
        let m = SecretMapping::from_pair("/host/secrets/", "/root/.config/app/secrets/").unwrap();
        assert_eq!(m.host, PathBuf::from("/host/secrets/"));
        assert_eq!(m.container, PathBuf::from("/root/.config/app/secrets/"));
    }

    #[test]
    fn container_name_is_stable() {
        let cfg = AgentConfig::from_args("h", vec![], "goose", &[]);
        let name1 = cfg.container_name();
        let name2 = cfg.container_name();
        assert_eq!(name1, name2, "container name should be deterministic");
        assert!(name1.starts_with("agentbox-"));
    }

    #[test]
    fn create_args_basics() {
        let cfg = AgentConfig {
            binary_hash: "h".into(),
            secrets: vec![],
            agent_subfolder: "goose".into(),
            container_args: vec![],
            agent_path: PathBuf::from("/work/myagent"),
            fuse_server_path: fuse_protocol::SERVER_BIN.into(),
            oracle_socket: None,
            image_name: "myimg".into(),
            seccomp_profile: PathBuf::from("/tmp/agentbox-seccomp.json"),
            memory: "16G".into(),
            cpus: "4".into(),
            auto_confirm: false,
            socket_path: PathBuf::from(fuse_protocol::DEFAULT_SOCKET),
            mount_point: PathBuf::from(fuse_protocol::DEFAULT_MOUNT_POINT),
            pidns_host: false,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            plans_path: None,
        };
        let args = build_create_args(
            &cfg,
            &["/dev/fuse".to_string(), "/dev/net/tun".to_string()],
        );
        assert!(args.contains(&"run".to_string()));
        // Device passthrough enables nested rootless podman.
        let di = args
            .iter()
            .position(|a| a == "--device")
            .expect("--device present");
        assert_eq!(args[di + 1], "/dev/fuse");
        assert!(args.contains(&"-d".to_string()));
        assert!(!args.contains(&"--rm".to_string()), "persistent container should NOT use --rm");
        assert!(args.contains(&"sleep".into()));
        assert!(args.contains(&"infinity".into()));
        assert!(args.contains(&"myimg".into()));
        // Nested rootless podman: widened seccomp profile must be applied.
        let i = args
            .iter()
            .position(|a| a == "--security-opt")
            .expect("--security-opt present");
        assert!(
            args[i + 1].starts_with("seccomp="),
            "must reference a seccomp profile: {:?}",
            args[i + 1]
        );
        // No pidns by default
        assert!(!args.iter().any(|a| a == "--pid"));
    }

    #[test]
    fn create_args_pidns_host() {
        let cfg = AgentConfig {
            binary_hash: "h".into(),
            secrets: vec![],
            agent_subfolder: "goose".into(),
            container_args: vec![],
            agent_path: PathBuf::from("/work/myagent"),
            fuse_server_path: "fuse-server".into(),
            oracle_socket: None,
            image_name: "myimg".into(),
            seccomp_profile: PathBuf::from("/tmp/agentbox-seccomp.json"),
            memory: "16G".into(),
            cpus: "4".into(),
            auto_confirm: false,
            socket_path: PathBuf::from(fuse_protocol::DEFAULT_SOCKET),
            mount_point: PathBuf::from(fuse_protocol::DEFAULT_MOUNT_POINT),
            pidns_host: true,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            plans_path: None,
        };
        let args = build_create_args(&cfg, &[]);
        assert!(
            args.iter().any(|a| a == "--pid") && args.iter().any(|a| a == "host"),
            "should include --pid host when pidns_host is true"
        );
        assert!(
            !args.iter().any(|a| a == "--device"),
            "no --device flags when the host lacks the devices"
        );
    }

    #[test]
    fn exec_args_with_setup() {
        let cfg = AgentConfig {
            binary_hash: "h".into(),
            secrets: vec![],
            agent_subfolder: "goose".into(),
            container_args: vec!["--flag".into()],
            agent_path: PathBuf::from("/work/myagent"),
            fuse_server_path: "fuse-server".into(),
            oracle_socket: None,
            image_name: "myimg".into(),
            seccomp_profile: PathBuf::from("/tmp/agentbox-seccomp.json"),
            memory: "16G".into(),
            cpus: "4".into(),
            auto_confirm: false,
            socket_path: PathBuf::from(fuse_protocol::DEFAULT_SOCKET),
            mount_point: PathBuf::from(fuse_protocol::DEFAULT_MOUNT_POINT),
            pidns_host: false,
            runtime: Runtime::Auto,
            runtime_wrapper: None,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            plans_path: None,
        };
        let args = build_exec_args(&cfg, "ln -sf /fuse/x /root/x");
        assert!(args.contains(&"exec".to_string()));
        assert!(args.contains(&"-it".to_string()));
        assert!(args.contains(&cfg.container_name()));
        assert!(args.contains(&"sh".into()));
        assert!(args.contains(&"-c".into()));
        assert!(args.contains(&"--flag".into()));
        // Should NOT contain run/d/sleep/infinity
        assert!(!args.contains(&"run".to_string()));
        assert!(!args.contains(&"sleep".to_string()));
    }

    #[test]
    fn runtime_auto_prefers_podman() {
        let mock = MockSystemIo::new();
        assert_eq!(Runtime::Auto.resolve(&mock, None), Some(RUNTIME_PODMAN));
    }

    #[test]
    fn runtime_auto_falls_back_to_docker() {
        let mut mock = MockSystemIo::new();
        mock.command_status = None;
        mock.unix_connected = true;
        assert_eq!(Runtime::Auto.resolve(&mock, None), Some(RUNTIME_DOCKER));
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
        assert_eq!(Runtime::Podman.resolve(&mock, None), Some(RUNTIME_PODMAN));
    }

    #[test]
    fn runtime_docker_forces_docker() {
        let mut mock = MockSystemIo::new();
        mock.unix_connected = true;
        assert_eq!(Runtime::Docker.resolve(&mock, None), Some(RUNTIME_DOCKER));
    }

    #[test]
    fn runtime_with_wrapper() {
        let mock = MockSystemIo::new();
        assert_eq!(
            Runtime::Podman.resolve(&mock, Some("flatpak-spawn --host")),
            Some(RUNTIME_PODMAN)
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
        assert!(name.starts_with("agentbox-"));
    }
}
