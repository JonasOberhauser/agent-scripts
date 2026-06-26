use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

    fn create_symlink(&mut self, original: &Path, link: &Path) -> Result<(), IoError> {
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

    fn spawn_independent(
        &mut self,
        program: &str,
        args: &[&str],
        stderr_to: Option<&Path>,
    ) -> Result<u32, IoError> {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(program);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .process_group(0);

        match stderr_to {
            Some(path) => {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| IoError(format!("open log {path:?}: {e}")))?;
                cmd.stdout(std::process::Stdio::from(f.try_clone().map_err(|e| IoError(e.to_string()))?))
                    .stderr(std::process::Stdio::from(f));
            }
            None => {
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
        }

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .map_err(|e| IoError(format!("spawn_independent {program}: {e}")))?;
        Ok(child.id())
    }

    fn run_interactive(&self, program: &str, args: &[&str]) -> Result<i32, IoError> {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .map_err(|e| IoError(format!("run {program}: {e}")))?;
        Ok(status.code().unwrap_or(-1))
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

    fn is_symlink(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    }

    fn is_dir(&self, path: &Path) -> bool {
        std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, IoError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            entries.push(entry?.path());
        }
        Ok(entries)
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, IoError> {
        Ok(std::fs::read_link(path)?)
    }

    fn rename_path(&mut self, from: &Path, to: &Path) -> Result<(), IoError> {
        std::fs::rename(from, to)?;
        Ok(())
    }

    fn try_unix_connect(&self, path: &Path) -> bool {
        std::os::unix::net::UnixStream::connect(path).is_ok()
    }

    fn unix_send_recv(&self, path: &Path, data: &[u8]) -> Result<Vec<u8>, IoError> {
        use std::io::{BufRead, BufReader, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| IoError(format!("connect {}: {e}", path.display())))?;
        stream.write_all(data)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        Ok(line.into_bytes())
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
    pub interactive_exit: i32,
    pub spawned: Vec<(String, Vec<String>)>,
    pub unix_connected: bool,
    pub unix_responses: std::cell::RefCell<std::collections::VecDeque<Vec<u8>>>,
    pub symlinks: std::collections::HashMap<String, String>,
}

impl MockSystemIo {
    pub fn new() -> Self {
        Self {
            command_status: Some(0),
            interactive_exit: 0,
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

    pub fn with_unix_response(self, response: &[u8]) -> Self {
        self.unix_responses.borrow_mut().push_back(response.to_vec());
        self
    }

    fn record_spawn(&mut self, program: &str, args: &[&str]) {
        self.spawned
            .push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));
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
        let removed_file = self.files.remove(&key).is_some();
        let removed_link = self.symlinks.remove(&key).is_some();
        if removed_file || removed_link {
            Ok(())
        } else {
            Err(IoError(format!("not found: {key}")))
        }
    }

    fn create_symlink(&mut self, original: &Path, link: &Path) -> Result<(), IoError> {
        self.symlinks
            .insert(link.to_string_lossy().to_string(), original.to_string_lossy().to_string());
        Ok(())
    }

    fn run_command(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput, IoError> {
        Ok(CommandOutput {
            stdout: self.command_stdout.clone(),
            stderr: String::new(),
            status: self.command_status,
        })
    }

    fn spawn_detached(&mut self, program: &str, args: &[&str]) -> Result<u32, IoError> {
        self.record_spawn(program, args);
        Ok(12345)
    }

    fn spawn_independent(
        &mut self,
        program: &str,
        args: &[&str],
        _stderr_to: Option<&Path>,
    ) -> Result<u32, IoError> {
        self.record_spawn(program, args);
        self.unix_connected = true;
        Ok(54321)
    }

    fn run_interactive(&self, _program: &str, _args: &[&str]) -> Result<i32, IoError> {
        Ok(self.interactive_exit)
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

    fn try_unix_connect(&self, _path: &Path) -> bool {
        self.unix_connected
    }

    fn unix_send_recv(&self, _path: &Path, _data: &[u8]) -> Result<Vec<u8>, IoError> {
        self.unix_responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| IoError("no queued unix response".into()))
    }

    fn is_symlink(&self, path: &Path) -> bool {
        self.symlinks
            .contains_key(&path.to_string_lossy().to_string())
    }

    fn is_dir(&self, path: &Path) -> bool {
        let prefix = format!("{}/", path.to_string_lossy());
        self.files.keys().any(|k| k.starts_with(&prefix))
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, IoError> {
        let prefix = format!("{}/", path.to_string_lossy());
        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for key in self.files.keys() {
            if let Some(rest) = key.strip_prefix(&prefix) {
                let component = match rest.find('/') {
                    Some(i) => &rest[..i],
                    None => rest,
                };
                let full = format!("{}{}", prefix, component);
                if seen.insert(full.clone()) {
                    entries.push(PathBuf::from(full));
                }
            }
        }
        Ok(entries)
    }

    fn rename_path(&mut self, from: &Path, to: &Path) -> Result<(), IoError> {
        let from_key = from.to_string_lossy().to_string();
        let to_key = to.to_string_lossy().to_string();
        if let Some(data) = self.files.remove(&from_key) {
            self.files.insert(to_key, data);
            Ok(())
        } else if let Some(target) = self.symlinks.remove(&from_key) {
            self.symlinks.insert(to_key, target);
            Ok(())
        } else {
            Err(IoError(format!("rename: source not found: {from_key}")))
        }
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, IoError> {
        let key = path.to_string_lossy().to_string();
        self.symlinks
            .get(&key)
            .map(|t| PathBuf::from(t))
            .ok_or_else(|| IoError(format!("not a symlink: {key}")))
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
