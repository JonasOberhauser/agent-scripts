use std::path::PathBuf;

/// All parameters needed to launch an agent session.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// SHA-256 of the binary allowed to read the secret.
    pub binary_hash: String,
    /// Host path to the secret config file (e.g. `production.yaml`).
    pub host_config_file: PathBuf,
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
}

impl AgentConfig {
    /// Derive a config from the three positional args the original shell
    /// script expected, using sensible defaults for the rest.
    pub fn from_args(
        binary_hash: &str,
        host_config_file: &str,
        agent_subfolder: &str,
        container_args: &[String],
    ) -> Self {
        Self {
            binary_hash: binary_hash.to_string(),
            host_config_file: PathBuf::from(host_config_file),
            agent_subfolder: agent_subfolder.to_string(),
            container_args: container_args.to_vec(),
            agent_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            fuse_server_path: PathBuf::from("fuse-server"),
            image_name: "agentbox".to_string(),
            memory: "224G".to_string(),
            cpus: "90".to_string(),
        }
    }

    // ── computed paths ──────────────────────────────────────────

    pub fn filename(&self) -> String {
        self.host_config_file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    pub fn host_config_dir(&self) -> PathBuf {
        self.agent_path.join("config")
    }

    pub fn host_workspace(&self) -> PathBuf {
        self.agent_path.join("workspace")
    }

    pub fn host_fuse(&self) -> PathBuf {
        self.agent_path.join("fuse_mnt")
    }

    pub fn socket_path(&self) -> PathBuf {
        self.agent_path.join("fuse-gatekeeper.sock")
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

    /// The symlink target *as seen inside the container*.
    pub fn container_fuse_file(&self) -> String {
        format!("/fuse/{}", self.filename())
    }

    /// Where the symlink lives on the host (inside the bind-mounted config dir).
    pub fn host_config_link(&self) -> PathBuf {
        self.host_config_dir().join(self.filename())
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
/// Pure function — trivially unit-testable without any I/O.
pub fn build_container_args(config: &AgentConfig) -> Vec<String> {
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
        "-v".into(),
        "./plans/shared:/workspace/plans:Z".into(),
        "-v".into(),
        format!("{}_home:/root:z", config.agent_name()),
        "-v".into(),
        format!("{}:/fuse:ro", config.host_fuse().display()),
        "--workdir".into(),
        "/workspace".into(),
    ];
    args.push(config.image_name.clone());
    args.extend(config.container_args.iter().cloned());
    args
}

/// Detect whether `podman` or `docker` is available.
pub fn detect_container_runtime_name<S: fuse_protocol::SystemIo>(
    io: &S,
) -> Option<&'static str> {
    if io
        .run_command("podman", &["--version"])
        .map(|o| o.success())
        .unwrap_or(false)
    {
        return Some("podman");
    }
    if io
        .run_command("docker", &["--version"])
        .map(|o| o.success())
        .unwrap_or(false)
    {
        return Some("docker");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::MockSystemIo;

    #[test]
    fn filename_extraction() {
        let cfg = AgentConfig::from_args("abc", "/path/to/secrets.yaml", "goose", &[]);
        assert_eq!(cfg.filename(), "secrets.yaml");
    }

    #[test]
    fn container_args_basics() {
        let cfg = AgentConfig {
            binary_hash: "h".into(),
            host_config_file: "s.yaml".into(),
            agent_subfolder: "goose".into(),
            container_args: vec!["--flag".into()],
            agent_path: PathBuf::from("/work/myagent"),
            fuse_server_path: "fuse-server".into(),
            image_name: "myimg".into(),
            memory: "16G".into(),
            cpus: "4".into(),
        };
        let args = build_container_args(&cfg);
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
    }

    #[test]
    fn detect_runtime_with_mock() {
        let mut mock = MockSystemIo::new();
        mock.command_stdout = "podman version 4.0".into();
        assert_eq!(detect_container_runtime_name(&mock), Some("podman"));
    }

    #[test]
    fn detect_runtime_prefers_podman() {
        let mock = MockSystemIo::new();
        // Both succeed — podman should win.
        assert_eq!(detect_container_runtime_name(&mock), Some("podman"));
    }

    #[test]
    fn container_name_contains_agent_name() {
        let cfg = AgentConfig::from_args("h", "f.yaml", "goose", &[]);
        let name = cfg.container_name();
        assert!(name.starts_with(&cfg.agent_name()));
    }
}
