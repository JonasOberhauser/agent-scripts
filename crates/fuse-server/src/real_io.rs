use std::path::Path;

use fuse_protocol::{CommandOutput, IoError, SystemIo};
use sha2::{Digest, Sha256};

/// Production [`SystemIo`] backed by the real OS filesystem and process
/// spawning.
#[derive(Default)]
pub struct RealSystemIo;

impl RealSystemIo {
    pub fn new() -> Self {
        Self
    }
}

impl SystemIo for RealSystemIo {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError> {
        Ok(std::fs::read(path)?)
    }

    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError> {
        std::fs::write(path, data)?;
        Ok(())
    }

    fn file_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), IoError> {
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn remove_path(&self, path: &Path) -> Result<(), IoError> {
        if path.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    fn create_symlink(&self, original: &Path, link: &Path) -> Result<(), IoError> {
        std::os::unix::fs::symlink(original, link)?;
        Ok(())
    }

    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, IoError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| IoError(format!("spawn {program}: {e}")))?;
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            status: output.status.code(),
        })
    }

    fn spawn_detached(&mut self, program: &str, args: &[&str]) -> Result<u32, IoError> {
        let child = std::process::Command::new(program)
            .args(args)
            .spawn()
            .map_err(|e| IoError(format!("spawn {program}: {e}")))?;
        Ok(child.id())
    }

    fn sha256_file(&self, path: &Path) -> Result<String, IoError> {
        let data = std::fs::read(path)?;
        let digest = Sha256::digest(&data);
        Ok(hex(&digest))
    }

    fn sha256_process_exe(&self, pid: u32) -> Result<String, IoError> {
        let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| IoError(format!("read /proc/{pid}/exe: {e}")))?;
        let data = std::fs::read(&exe_path)?;
        let digest = Sha256::digest(&data);
        Ok(hex(&digest))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
