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

/// Dependency-injection trait that encapsulates **every** external interaction
/// (filesystem, processes, hashing, and message transport).
///
/// Generic over the transport input type `I` and output type `O` so that the
/// same abstraction covers socket communication (`Command`/`Response`),
/// while crates that have no transport layer can instantiate it with `()`.
///
/// Production code uses [`RealIoProvider`](crate::io) implementations; tests
/// supply a mock that operates entirely in memory.
pub trait IoProvider<I, O> {
    // ── filesystem ──────────────────────────────────────────────
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError>;
    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError>;
    fn file_exists(&self, path: &Path) -> bool;
    fn create_dir_all(&self, path: &Path) -> Result<(), IoError>;
    fn remove_path(&self, path: &Path) -> Result<(), IoError>;
    fn create_symlink(&self, original: &Path, link: &Path) -> Result<(), IoError>;

    // ── processes ───────────────────────────────────────────────
    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, IoError>;
    fn spawn_detached(&mut self, program: &str, args: &[&str]) -> Result<u32, IoError>;

    // ── hashing / integrity ─────────────────────────────────────
    fn sha256_file(&self, path: &Path) -> Result<String, IoError>;
    fn sha256_process_exe(&self, pid: u32) -> Result<String, IoError>;

    // ── transport (generic over I, O) ───────────────────────────
    fn send(&mut self, message: I) -> Result<(), IoError>;
    fn recv(&mut self) -> Result<O, IoError>;
}
