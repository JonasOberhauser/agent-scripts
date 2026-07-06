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
            .map_err(|e| IoError(format!(
                "read /proc/{pid}/exe: {e}. \
                 The process may be in a different PID namespace — \
                 use --pidns=host on the container, or '*' as the hash to skip verification"
            )))?;
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

    fn unix_send_recv_servatui(
        &self,
        path: &Path,
        proto_name: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, IoError> {
        use std::io::{BufRead, BufReader, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| IoError(format!("connect {}: {e}", path.display())))?;
        stream.write_all(proto_name.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.write_all(data)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        stream.write_all(b"null\n")?;
        stream.flush()?;
        Ok(line.into_bytes())
    }
}

/// In-memory mock [`SystemIo`] for tests.  All operations are deterministic and
/// no real filesystem or process interaction occurs.
///
/// ## Simulating real-world scenarios
///
/// The mock supports several mechanisms to test failure paths that occur in
/// production:
///
/// - **Stale state**: use `with_file` / `with_dir` to pre-populate leftover
///   files and directories from a "previous run".  `file_exists` checks both.
/// - **Busy paths**: `with_busy_path` makes `remove_path` return an error
///   (simulates a mounted FUSE filesystem — EBUSY).
/// - **Spawn failure**: `with_spawn_error` makes `spawn_independent` fail.
/// - **Per-command results**: `with_command_result` controls success/failure
///   of `run_command` per program name (e.g., simulate `fusermount`
///   succeeding while other commands fail).
/// - **Interactive call tracking**: `interactive_calls` records every
///   `run_interactive` invocation so tests can assert on argv.
#[derive(Default)]
pub struct MockSystemIo {
    pub files: HashMap<String, Vec<u8>>,
    pub dirs: std::collections::HashSet<String>,
    pub file_hashes: HashMap<String, String>,
    pub process_hashes: HashMap<u32, String>,
    pub command_stdout: String,
    pub command_status: Option<i32>,
    pub command_results: HashMap<String, Option<i32>>,
    pub interactive_exit: i32,
    pub interactive_calls: std::cell::RefCell<Vec<(String, Vec<String>)>>,
    pub spawned: Vec<(String, Vec<String>)>,
    pub spawn_error_msg: Option<String>,
    pub busy_paths: std::cell::RefCell<std::collections::HashSet<String>>,
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

    pub fn with_dir(mut self, path: &str) -> Self {
        self.dirs.insert(path.to_string());
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

    /// Make `remove_path(path)` fail with an error (simulates EBUSY on a
    /// mounted FUSE filesystem, or EPERM on a root-owned file).
    pub fn with_busy_path(mut self, path: &str) -> Self {
        self.busy_paths.get_mut().insert(path.to_string());
        self
    }

    /// Make `spawn_independent` fail with the given error message.
    pub fn with_spawn_error(mut self, msg: &str) -> Self {
        self.spawn_error_msg = Some(msg.to_string());
        self
    }

    /// Set a per-program exit status for `run_command`.  `Some(0)` = success,
    /// `Some(non-zero)` = failure, `None` = command not found.
    pub fn with_command_result(mut self, program: &str, status: Option<i32>) -> Self {
        self.command_results.insert(program.to_string(), status);
        self
    }

    fn record_spawn(&mut self, program: &str, args: &[&str]) {
        self.spawned
            .push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));
    }

    /// Check whether a spawn call included all of the given argument
    /// substrings.
    pub fn spawn_contains(&self, index: usize, needles: &[&str]) -> bool {
        let (_, args) = &self.spawned[index];
        needles.iter().all(|n| args.iter().any(|a| a == n))
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
        let key = path.to_string_lossy().to_string();
        self.files.contains_key(&key) || self.dirs.contains(&key)
    }

    fn create_dir_all(&self, _path: &Path) -> Result<(), IoError> {
        // In the mock, we don't need to actually create directories —
        // but we record the path so file_exists works.
        Ok(())
    }

    fn remove_path(&mut self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().to_string();
        if self.busy_paths.borrow().contains(&key) {
            return Err(IoError("Device or resource busy (os error 16)".into()));
        }
        let removed_file = self.files.remove(&key).is_some();
        let removed_link = self.symlinks.remove(&key).is_some();
        let removed_dir = self.dirs.remove(&key);
        if removed_file || removed_link || removed_dir {
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

    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, IoError> {
        let status = if let Some(s) = self.command_results.get(program) {
            *s
        } else {
            self.command_status
        };
        // Simulate: a successful unmount clears the busy state, just as
        // `fusermount -uz` frees the mount point in the real world.
        if status == Some(0) && args.iter().any(|a| *a == "-uz" || *a == "-l") {
            self.busy_paths.borrow_mut().clear();
        }
        Ok(CommandOutput {
            stdout: self.command_stdout.clone(),
            stderr: String::new(),
            status,
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
        if let Some(msg) = &self.spawn_error_msg {
            return Err(IoError(msg.clone()));
        }
        self.record_spawn(program, args);
        self.unix_connected = true;
        Ok(54321)
    }

    fn run_interactive(&self, program: &str, args: &[&str]) -> Result<i32, IoError> {
        self.interactive_calls.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
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

    fn unix_send_recv_servatui(
        &self,
        _path: &Path,
        _proto_name: &str,
        _data: &[u8],
    ) -> Result<Vec<u8>, IoError> {
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
        let path_str = path.to_string_lossy();
        if self.dirs.contains(&path_str.to_string()) {
            return true;
        }
        let prefix = format!("{}/", path_str.trim_end_matches('/'));
        self.files.keys().any(|k| k.starts_with(&prefix))
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, IoError> {
        let path_str = path.to_string_lossy();
        let prefix = format!("{}/", path_str.trim_end_matches('/'));
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
            .map(PathBuf::from)
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

    #[test]
    fn mock_busy_path_cannot_be_removed() {
        let mut mock = MockSystemIo::new()
            .with_dir("/mnt")
            .with_busy_path("/mnt");
        let result = mock.remove_path(Path::new("/mnt"));
        assert!(result.is_err(), "busy path should not be removable");
    }

    #[test]
    fn mock_spawn_failure() {
        let mut mock = MockSystemIo::new()
            .with_spawn_error("terminal required");
        let result = mock.spawn_independent("sudo", &[], None);
        assert!(result.is_err());
        assert!(mock.spawned.is_empty(), "failed spawn should not be recorded");
    }

    #[test]
    fn mock_per_command_results() {
        let mock = MockSystemIo::new()
            .with_command_result("fusermount", Some(0))
            .with_command_result("umount", None);
        let fm = mock.run_command("fusermount", &["-uz", "/mnt"]).unwrap();
        assert!(fm.success());
        let um = mock.run_command("umount", &["-l", "/mnt"]).unwrap();
        assert!(!um.success(), "None status = command not found");
    }

    #[test]
    fn mock_interactive_calls_recorded() {
        let mock = MockSystemIo::new();
        mock.run_interactive("sudo", &["-v"]).unwrap();
        let calls = mock.interactive_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "sudo");
        assert_eq!(calls[0].1, vec!["-v"]);
    }

    #[test]
    fn mock_file_and_dir_existence() {
        let mock = MockSystemIo::new()
            .with_file("/tmp/sock", b"x")
            .with_dir("/tmp/mnt");
        assert!(mock.file_exists(Path::new("/tmp/sock")));
        assert!(mock.file_exists(Path::new("/tmp/mnt")));
        assert!(!mock.file_exists(Path::new("/tmp/other")));
    }

    #[test]
    fn mock_spawn_contains_helper() {
        let mut mock = MockSystemIo::new();
        mock.spawn_independent("flatpak-spawn", &["--host", "sudo", "-n", "fuse-server"], None).unwrap();
        assert!(mock.spawn_contains(0, &["sudo", "-n"]));
        assert!(mock.spawn_contains(0, &["fuse-server"]));
        assert!(!mock.spawn_contains(0, &["--allow-other"]));
    }
}
