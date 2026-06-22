use std::collections::HashMap;
use std::path::Path;

use crate::io::{CommandOutput, SystemIo};
use crate::IoError;

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Production [`SystemIo`] backed by the real OS.
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

    fn remove_path(&mut self, path: &Path) -> Result<(), IoError> {
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
        Ok(hex_sha256(&data))
    }

    fn sha256_process_exe(&self, pid: u32) -> Result<String, IoError> {
        let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| IoError(format!("read /proc/{pid}/exe: {e}")))?;
        let data = std::fs::read(&exe_path)?;
        Ok(hex_sha256(&data))
    }
}

/// In-memory mock [`SystemIo`] for tests.  All operations are deterministic and
/// no real filesystem or process interaction occurs.
#[derive(Default)]
pub struct MockSystemIo {
    pub files: HashMap<String, Vec<u8>>,
    pub file_hashes: HashMap<String, String>,
    pub process_hashes: HashMap<u32, String>,
    pub command_stdout: String,
    pub command_status: Option<i32>,
}

impl MockSystemIo {
    pub fn new() -> Self {
        Self {
            command_status: Some(0),
            ..Default::default()
        }
    }

    pub fn with_file(mut self, path: &str, content: &[u8]) -> Self {
        self.files.insert(path.to_string(), content.to_vec());
        self
    }

    pub fn with_file_hash(mut self, path: &str, hash: &str) -> Self {
        self.file_hashes.insert(path.to_string(), hash.to_string());
        self
    }

    pub fn with_process_hash(mut self, pid: u32, hash: &str) -> Self {
        self.process_hashes.insert(pid, hash.to_string());
        self
    }
}

impl SystemIo for MockSystemIo {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError> {
        self.files
            .get(&path.to_string_lossy().to_string())
            .cloned()
            .ok_or_else(|| IoError(format!("file not found: {}", path.display())))
    }

    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError> {
        self.files
            .insert(path.to_string_lossy().to_string(), data.to_vec());
        Ok(())
    }

    fn file_exists(&self, path: &Path) -> bool {
        self.files.contains_key(&path.to_string_lossy().to_string())
    }

    fn create_dir_all(&self, _path: &Path) -> Result<(), IoError> {
        Ok(())
    }

    fn remove_path(&mut self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().to_string();
        if self.files.remove(&key).is_some() {
            Ok(())
        } else {
            Err(IoError(format!("not found: {key}")))
        }
    }

    fn create_symlink(&self, _original: &Path, _link: &Path) -> Result<(), IoError> {
        Ok(())
    }

    fn run_command(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput, IoError> {
        Ok(CommandOutput {
            stdout: self.command_stdout.clone(),
            stderr: String::new(),
            status: self.command_status,
        })
    }

    fn spawn_detached(&mut self, _program: &str, _args: &[&str]) -> Result<u32, IoError> {
        Ok(12345)
    }

    fn sha256_file(&self, path: &Path) -> Result<String, IoError> {
        self.file_hashes
            .get(&path.to_string_lossy().to_string())
            .cloned()
            .ok_or_else(|| IoError("no hash".into()))
    }

    fn sha256_process_exe(&self, pid: u32) -> Result<String, IoError> {
        self.process_hashes
            .get(&pid)
            .cloned()
            .ok_or_else(|| IoError(format!("no hash for pid {pid}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_file_round_trip() {
        let mut mock = MockSystemIo::new().with_file("/a", b"hi");
        let data = mock.read_file(Path::new("/a")).unwrap();
        assert_eq!(data, b"hi");
        mock.write_file(Path::new("/b"), b"yo").unwrap();
        assert_eq!(mock.read_file(Path::new("/b")).unwrap(), b"yo");
    }

    #[test]
    fn mock_hash_lookup() {
        let mock = MockSystemIo::new()
            .with_file_hash("/x", "abc")
            .with_process_hash(42, "def");
        assert_eq!(mock.sha256_file(Path::new("/x")).unwrap(), "abc");
        assert_eq!(mock.sha256_process_exe(42).unwrap(), "def");
    }
}
