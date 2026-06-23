use std::path::Path;

use crate::error::IoError;

/// Outcome of running an external command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: Option<i32>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

/// Filesystem, process, and hashing operations — the non-generic half of
/// [`IoProvider`].
pub trait SystemIo {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError>;
    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError>;
    fn file_exists(&self, path: &Path) -> bool;
    fn create_dir_all(&self, path: &Path) -> Result<(), IoError>;
    fn remove_path(&mut self, path: &Path) -> Result<(), IoError>;
    fn create_symlink(&self, original: &Path, link: &Path) -> Result<(), IoError>;
    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, IoError>;
    fn spawn_detached(&mut self, program: &str, args: &[&str]) -> Result<u32, IoError>;
    /// Spawn a process that is **fully independent** of the caller — it
    /// survives the caller's death (new session via `setsid`, new process
    /// group, no shared stdio).  Returns the child PID.
    fn spawn_independent(&mut self, program: &str, args: &[&str]) -> Result<u32, IoError>;
    /// Run a process inheriting the caller's stdin/stdout/stderr (foreground).
    /// Returns the exit code.
    fn run_interactive(&self, program: &str, args: &[&str]) -> Result<i32, IoError>;
    fn sha256_file(&self, path: &Path) -> Result<String, IoError>;
    fn sha256_process_exe(&self, pid: u32) -> Result<String, IoError>;

    // ── Unix domain socket helpers ───────────────────────────────

    /// Try to connect to a Unix domain socket.  Returns `true` if the
    /// connection succeeds (i.e. a server is listening).
    fn try_unix_connect(&self, path: &Path) -> bool;
    /// Send a blob over a Unix domain socket (newline-terminated) and read
    /// one line of response.
    fn unix_send_recv(&self, path: &Path, data: &[u8]) -> Result<Vec<u8>, IoError>;
}

/// Bidirectional message transport, generic over input `I` and output `O`.
pub trait Transport<I, O> {
    fn send(&mut self, message: I) -> Result<(), IoError>;
    fn recv(&mut self) -> Result<O, IoError>;
}

/// Unified I/O provider combining system operations **and** transport.
///
/// Any type that implements both [`SystemIo`] and [`Transport<I, O>`]
/// automatically satisfies this trait.
pub trait IoProvider<I, O>: SystemIo + Transport<I, O> {}
impl<T, I, O> IoProvider<I, O> for T where T: SystemIo + Transport<I, O> {}
