use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::io::{CommandOutput, PathState, SystemIo};
use crate::IoError;


/// One parsed /proc/<pid>/maps line: `Ok(Some((range, path)))` for a
/// file-backed mapping, `Ok(None)` for a pathless segment, `Err` when
/// the line does not match the documented 5-mandatory-field format
/// ("start-end perms offset dev inode [path..]").
///
/// Fields are positional by kernel contract — procfs has no headers to
/// name them by — but every mandatory field is validated to exist, and
/// the pathname is taken as the whole remainder of the line so paths
/// containing spaces survive intact.
/// Disambiguate why a /proc/<pid> inspection step failed, from the errno:
/// each cause has a different remediation, and the pending panel shows
/// this text to the human deciding the grant.
fn inspect_hint(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => "The process is invisible from this server's PID namespace \
                     (container guest without --pidns=host?) or has already exited.",
        PermissionDenied => "Permission denied: /proc ptrace checks failed \
                             (SELinux? daemon lacks CAP_SYS_PTRACE? uid mismatch?). \
                             On the host check `getenforce`, yama ptrace_scope, \
                             and run the daemon with CAP_SYS_PTRACE.",
        _ => "The process could not be inspected.",
    }
}

/// The map_files read (and its fallbacks) both failed: either the ptrace
/// permission above, or the mapped path does not resolve in the server's
/// mount namespace (paths from a container guest rootfs).
fn map_files_hint(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => "Mapped file unreachable in this mount namespace — a guest \
                     path that does not exist where the server runs.",
        PermissionDenied => "Following /proc/<pid>/map_files requires \
                             CAP_SYS_ADMIN or CAP_CHECKPOINT_RESTORE in the \
                             INITIAL user namespace (kernel fs/proc/base.c, \
                             proc_map_files_get_link) — not ptrace of the \
                             target, and not a rootless user namespace. Run \
                             the hashing process with one of those \
                             capabilities (e.g. setcap cap_checkpoint_restore+ep).",
        _ => "The mapped file could not be read.",
    }
}

/// Read the content of one mapping — DIRECTLY from the mapped inode, via
/// the procfs magic links. `/proc/<pid>/map_files/<range>` (and
/// `/proc/<pid>/exe` for the main binary) resolve to the exact inode the
/// process has mapped, even after the on-disk file was replaced or
/// unlinked. On-disk paths are NEVER consulted: re-reading a path can
/// race with a swap (TOCTOU) and hash content the process is not
/// actually running. If the magic link is unreadable, hashing fails
/// closed — one-shot grants still work; grant-forever refuses.
fn read_mapped_inode(pid: u32, range: &str, path: &Path) -> Result<Vec<u8>, IoError> {
    let src = if range.is_empty() {
        format!("/proc/{pid}/exe")
    } else {
        format!("/proc/{pid}/map_files/{range}")
    };
    std::fs::read(&src).map_err(|e| {
        IoError(format!(
            "read mapped {} via {src}: {e} — refusing to hash a package \
             with unreadable mappings (on-disk paths are never consulted: \
             they race with file swaps). {}",
            path.display(),
            map_files_hint(&e)
        ))
    })
}

fn parse_maps_line(line: &str) -> Result<Option<(String, PathBuf)>, String> {
    const BAD: fn(&str) -> String = |l| format!("malformed maps line: {l:?}");
    let mut fields = line.splitn(6, ' ');
    let range = fields.next().ok_or_else(|| BAD(line))?;
    let (start, end) = range.split_once('-').ok_or_else(|| BAD(line))?;
    if start.is_empty() || end.is_empty() {
        return Err(BAD(line));
    }
    // perms, offset, device, inode — all mandatory.
    let perms = fields.next().ok_or_else(|| BAD(line))?;
    if perms.len() != 4 {
        return Err(BAD(line));
    }
    let _offset = fields.next().ok_or_else(|| BAD(line))?; // offset
    let _dev = fields.next().ok_or_else(|| BAD(line))?; // dev:major:minor
    let inode = fields.next().ok_or_else(|| BAD(line))?;
    if inode.is_empty() || !inode.chars().all(|c| c.is_ascii_digit()) {
        return Err(BAD(line));
    }
    // Path is optional ([heap], [stack], [vvar]… have none); when
    // present it is the remainder — spaces included.
    match fields.next().map(str::trim) {
        Some(p) if p.starts_with('/') => Ok(Some((range.to_string(), PathBuf::from(p)))),
        Some(_) | None => Ok(None),
    }
}

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
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, IoError> {
        Ok(std::fs::canonicalize(path)?)
    }
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError> {
        Ok(std::fs::read(path)?)
    }

    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError> {
        std::fs::write(path, data)?;
        Ok(())
    }

    fn set_file_mode(&self, path: &Path, mode: u32) -> Result<(), IoError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn file_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn path_state(&self, path: &Path) -> PathState {
        match std::fs::metadata(path) {
            Ok(m) if m.is_dir() => PathState::Dir,
            Ok(_) => PathState::File,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PathState::Missing,
            // ENOTCONN, EBUSY, EIO, … — the name exists but stat fails.
            // A dead FUSE mount shows up exactly here.
            Err(e) => PathState::Unreachable(e.to_string()),
        }
    }

    fn mkdir(&self, path: &Path) -> Result<(), IoError> {
        std::fs::create_dir(path)?;
        Ok(())
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
        let _cmd = cmd
            .args(args)
            .stdin(std::process::Stdio::null())
            .process_group(0);

        match stderr_to {
            Some(path) => {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| IoError(format!("open log {path:?}: {e}")))?;
                let _cmd = cmd
                    .stdout(std::process::Stdio::from(f.try_clone().map_err(|e| IoError(e.to_string()))?))
                    .stderr(std::process::Stdio::from(f));
            }
            None => {
                let _cmd = cmd
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
        }

        fn child_setsid() -> std::io::Result<()> {
            // SAFETY: setsid(2) takes no pointers and has no memory-safety
            // preconditions; failure (already a process-group leader) is
            // reported via the return value, which pre_exec propagates.
            let _sid = unsafe { libc::setsid() };
            Ok(())
        }
        let cmd_mut = &mut cmd;
        let setsid_cb = child_setsid;
        // SAFETY: `pre_exec` runs the callback between fork(2) and
        // execve(2), where only async-signal-safe operations are allowed.
        // The callback above calls only setsid(2) and returns — no
        // allocation, no locks, no libc state; re-check its body when
        // editing it (nothing enforces this).
        let _cmd = unsafe { cmd_mut.pre_exec(setsid_cb) };
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

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    fn heal_terminal(&self) {
        use std::io::IsTerminal;
        use std::io::Write;
        if !std::io::stdout().is_terminal() {
            return;
        }
        // Raw mode first: stty sane restores line discipline and default
        // special chars on our stdin (the tty the child borrowed).
        let _ = std::process::Command::new("stty").arg("sane").status();
        // Then the escape-level modes stty knows nothing about: mouse
        // capture (incl. SGR 1006 — the dead-scroll-wheel culprit),
        // alternate screen, hidden cursor. Mirrors servatui's restore
        // sequence; keep in sync with its terminal_restore module.
        let mut out = std::io::stdout();
        let _ = out.write_all(servyi_servatui::TERMINAL_RESTORE_BYTES);
        let _ = out.flush();
    }

    fn sha256_file(&self, path: &Path) -> Result<String, IoError> {
        let data = std::fs::read(path)?;
        Ok(hex_sha256(&data))
    }

    fn sha256_process_package(&self, pid: u32) -> Result<String, IoError> {
        use sha2::{Digest, Sha256};
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| IoError(format!(
                "read /proc/{pid}/exe: {e}. {}", inspect_hint(&e)
            )))?;
        // Collect (mapping-range, path) pairs.  The range addresses the
        // exact mapped inode via /proc/<pid>/map_files/, which works
        // even when the on-disk path was replaced or unlinked
        // (deleted-but-mapped libraries are common after updates).
        let mut entries: Vec<(String, PathBuf)> = vec![(String::new(), exe)];
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| IoError(format!(
                "read /proc/{pid}/maps: {e}. {}", inspect_hint(&e)
            )))?;
        for line in maps.lines() {
            match parse_maps_line(line) {
                // Pathless segments ([heap], [stack], [vvar], …) are
                // legitimate — they carry no file content.
                Ok(None) => {}
                Ok(Some((range, path))) => {
                    if !entries.iter().any(|(_, p)| p == &path) {
                        entries.push((range, path));
                    }
                }
                // A malformed maps line is never silently skipped: the
                // format is load-bearing for the trust decision.
                Err(e) => return Err(IoError(format!("/proc/{pid}/maps: {e}"))),
            }
        }
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        let mut hasher = Sha256::new();
        for (range, path) in &entries {
            hasher.update(path.to_string_lossy().as_bytes());
            hasher.update(b"\0");
            // Read the actually-mapped inode (works after the on-disk
            // path was replaced or unlinked); fall back to the path.
            // FAIL CLOSED on unreadable mappings: a marker would make
            // any two unreadable libraries at the same path hash
            // identically — a library-swap attack vector.  A failed
            // hash leaves the pending without a package hash: one-shot
            // grants still work, grant-forever refuses to whitelist.
            let content = read_mapped_inode(pid, range, path)?;
            hasher.update((content.len() as u64).to_le_bytes());
            hasher.update(&content);
        }
        Ok(format!("{:x}", hasher.finalize()))
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
        let _n = reader.read_line(&mut line)?;
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
/// - **Command call tracking**: `command_calls` records every `run_command`
///   invocation so tests can assert on argv.
/// - **Argv-scoped command results**: `with_command_result_when` controls
///   `run_command` results per program **and** argument substring (e.g.,
///   fail only the `exec` probe while `stop`/`start` succeed), optionally
///   only for the first N matching calls (`with_command_result_when_n`).
#[derive(Default)]
pub struct CommandArgRule {
    /// Program name the rule applies to.
    pub program: String,
    /// Rule matches when any argument contains this substring.
    pub arg_contains: String,
    /// Exit status to return while the rule applies.
    pub status: Option<i32>,
    /// Matching calls left before the rule expires; `None` = unlimited.
    pub uses_left: std::cell::Cell<Option<usize>>,
}

/// In-memory mock of [`SystemIo`] for unit tests.
#[derive(Default)]
pub struct MockSystemIo {
    pub files: HashMap<String, Vec<u8>>,
    pub dirs: std::collections::HashSet<String>,
    pub file_hashes: HashMap<String, String>,
    pub process_hashes: HashMap<u32, String>,
    pub command_stdout: String,
    /// Stderr returned by every `run_command` call.  Real commands
    /// report their failure reason here (`stat: cannot statx '…':
    /// No such file or directory` etc.) — callers must be able to test
    /// their handling of that text.
    pub command_stderr: String,
    pub command_status: Option<i32>,
    pub command_results: HashMap<String, Option<i32>>,
    /// Argv-scoped command results: match when the program equals and any
    /// argument contains `arg_contains`.  `remaining` counts down; when it
    /// hits zero the rule stops applying (0 = unlimited).
    pub command_arg_results: std::cell::RefCell<Vec<CommandArgRule>>,
    pub interactive_exit: i32,
    pub interactive_calls: std::cell::RefCell<Vec<(String, Vec<String>)>>,
    pub command_calls: std::cell::RefCell<Vec<(String, Vec<String>)>>,
    pub sleeps: std::cell::RefCell<Vec<u64>>,
    pub created_dirs: std::cell::RefCell<Vec<String>>,
    pub heal_terminal_calls: std::cell::Cell<usize>,
    pub spawned: Vec<(String, Vec<String>)>,
    pub spawn_error_msg: Option<String>,
    pub busy_paths: std::cell::RefCell<std::collections::HashSet<String>>,
    /// Paths that model a **dead FUSE mount**: the daemon behind the mount
    /// died, so the kernel still holds the name but `stat()` fails
    /// (ENOTCONN/EBUSY) and `mkdir` returns EEXIST.
    ///
    /// HONESTY NOTE (per maintainer directive): this models an *assumed*
    /// real-world behavior, derived from the incident log
    /// (`create_dir_all` → "File exists (os error 17)" on
    /// /tmp/fuse-gatekeeper-mnt after a fused restart) plus kernel FUSE
    /// semantics — not from controlled observation. If real incidents show
    /// different error kinds (e.g. stat succeeding but readdir hanging),
    /// refine this model instead of writing around it.
    pub stale_mounts: std::cell::RefCell<std::collections::HashSet<String>>,
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
        let _prev = self.files.insert(path.to_string(), content.to_vec());
        self
    }

    pub fn with_dir(mut self, path: &str) -> Self {
        let _new = self.dirs.insert(path.to_string());
        self
    }

    pub fn with_file_hash(mut self, path: &str, hash: &str) -> Self {
        let _prev = self.file_hashes.insert(path.to_string(), hash.to_string());
        self
    }

    pub fn with_process_hash(mut self, pid: u32, hash: &str) -> Self {
        let _prev = self.process_hashes.insert(pid, hash.to_string());
        self
    }

    pub fn with_unix_response(self, response: &[u8]) -> Self {
        self.unix_responses.borrow_mut().push_back(response.to_vec());
        self
    }

    /// Make `remove_path(path)` fail with an error (simulates EBUSY on a
    /// mounted FUSE filesystem, or EPERM on a root-owned file).
    pub fn with_busy_path(mut self, path: &str) -> Self {
        let _new = self.busy_paths.get_mut().insert(path.to_string());
        self
    }

    /// Model `path` as a **dead FUSE mount**: the FUSE daemon died, the
    /// kernel still holds the name. `create_dir_all` then fails with
    /// EEXIST (mkdir says it exists, stat says it is not a directory —
    /// the exact incident signature from issue #23), and `remove_path`
    /// fails with EBUSY. A successful `fusermount -uz`/`umount -l` in
    /// `run_command` clears the state, as in the real world.
    ///
    /// See the honesty note on [`MockSystemIo::stale_mounts`].
    pub fn with_stale_mount(mut self, path: &str) -> Self {
        let _new = self.stale_mounts.get_mut().insert(path.to_string());
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
        let _prev = self.command_results.insert(program.to_string(), status);
        self
    }

    /// Set the stdout text every `run_command` call reports (e.g. a
    /// directory listing).
    pub fn with_command_stdout(mut self, stdout: &str) -> Self {
        self.command_stdout = stdout.to_string();
        self
    }

    /// Set the stderr text every `run_command` call reports — e.g.
    /// `stat: cannot statx '…': No such file or directory`.  Real
    /// commands carry their failure reason here; callers must be able
    /// to test their handling of that text.
    pub fn with_command_stderr(mut self, stderr: &str) -> Self {
        self.command_stderr = stderr.to_string();
        self
    }

    /// Fail/succeed `run_command` only for calls to `program` where some
    /// argument contains `arg_contains` (unlimited matches).
    pub fn with_command_result_when(
        self,
        program: &str,
        arg_contains: &str,
        status: Option<i32>,
    ) -> Self {
        self.command_arg_results.borrow_mut().push(CommandArgRule {
            program: program.to_string(),
            arg_contains: arg_contains.to_string(),
            status,
            uses_left: std::cell::Cell::new(None),
        });
        self
    }

    /// Like [`Self::with_command_result_when`], but the rule expires after `n`
    /// matching calls (later calls fall through to broader rules/defaults).
    pub fn with_command_result_when_n(
        self,
        program: &str,
        arg_contains: &str,
        status: Option<i32>,
        n: usize,
    ) -> Self {
        self.command_arg_results.borrow_mut().push(CommandArgRule {
            program: program.to_string(),
            arg_contains: arg_contains.to_string(),
            status,
            uses_left: std::cell::Cell::new(Some(n)),
        });
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
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, IoError> {
        // Models existence; the real impl additionally resolves
        // symlinks — that is exactly why normalization must go
        // through here rather than string work.
        let key = path.to_string_lossy().to_string();
        if self.files.contains_key(&key) || self.dirs.contains(&key) {
            Ok(path.to_path_buf())
        } else {
            Err(crate::error::IoError(format!(
                "canonicalize {}: no such file or directory",
                path.display()
            )))
        }
    }
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, IoError> {
        self.files
            .get(&path.to_string_lossy().to_string())
            .cloned()
            .ok_or_else(|| IoError(format!("file not found: {}", path.display())))
    }

    fn write_file(&mut self, path: &Path, data: &[u8]) -> Result<(), IoError> {
        let _prev = self
            .files
            .insert(path.to_string_lossy().to_string(), data.to_vec());
        Ok(())
    }

    fn set_file_mode(&self, _path: &Path, _mode: u32) -> Result<(), IoError> {
        Ok(())
    }

    fn file_exists(&self, path: &Path) -> bool {
        let key = path.to_string_lossy().to_string();
        self.files.contains_key(&key)
            || self.dirs.contains(&key)
            || self.created_dirs.borrow().contains(&key)
            || self.stale_mounts.borrow().contains(&key)
    }

    fn path_state(&self, path: &Path) -> PathState {
        let key = path.to_string_lossy().to_string();
        // Dead FUSE mount: the kernel holds the name, stat fails.
        // ENOTCONN is what a killed data daemon's mountpoint answers.
        if self.stale_mounts.borrow().contains(&key) {
            return PathState::Unreachable("Transport endpoint is not connected (os error 107)".into());
        }
        if self.dirs.contains(&key) || self.created_dirs.borrow().contains(&key) {
            return PathState::Dir;
        }
        if self.files.contains_key(&key) || self.symlinks.contains_key(&key) {
            return PathState::File;
        }
        PathState::Missing
    }

    fn mkdir(&self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().to_string();
        // mkdir(2): EEXIST whenever ANYTHING occupies the name — file,
        // directory, symlink, or mount. No tolerance, no recursion.
        if self.path_state(path) != PathState::Missing {
            return Err(IoError("File exists (os error 17)".into()));
        }
        self.created_dirs.borrow_mut().push(key);
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), IoError> {
        // Same algorithm std uses, expressed via the primitives: try to
        // create, and tolerate EEXIST only when the name really is a
        // directory. On a dead mount mkdir says EEXIST while path_state
        // says Unreachable, so the EEXIST error surfaces — the exact
        // "File exists (os error 17)" from issue #23.
        if let Err(e) = self.mkdir(path) {
            return match self.path_state(path) {
                PathState::Dir => Ok(()),
                _ => Err(e),
            };
        }
        Ok(())
    }

    fn remove_path(&mut self, path: &Path) -> Result<(), IoError> {
        let key = path.to_string_lossy().to_string();
        if self.stale_mounts.borrow().contains(&key) {
            // rmdir(2) on a mountpoint → EBUSY, same as a busy path.
            return Err(IoError("Device or resource busy (os error 16)".into()));
        }
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
        let _prev = self
            .symlinks
            .insert(link.to_string_lossy().to_string(), original.to_string_lossy().to_string());
        Ok(())
    }

    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, IoError> {
        self.command_calls.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        // Argv-scoped rules take precedence, most recently added first, and
        // expire once their countdown reaches zero (`None` = unlimited).
        let mut rule_status = None;
        {
            let rules = self.command_arg_results.borrow();
            if let Some(rule) = rules.iter().rev().find(|r| {
                r.program == program
                    && r.uses_left.get().is_none_or(|n| n > 0)
                    && args.iter().any(|a| a.contains(&r.arg_contains))
            }) {
                if let Some(n) = rule.uses_left.get() {
                    rule.uses_left.set(Some(n.saturating_sub(1)));
                }
                rule_status = Some(rule.status);
            }
        }
        let status = rule_status.unwrap_or(match self.command_results.get(program) {
            Some(s) => *s,
            None => self.command_status,
        });
        // Simulate: a successful unmount clears the busy state, just as
        // `fusermount -uz` frees the mount point in the real world.
        if status == Some(0) && args.iter().any(|a| *a == "-uz" || *a == "-l") {
            self.busy_paths.borrow_mut().clear();
            // A successful lazy unmount of a dead mount leaves the
            // mountpoint behind as a plain (empty) directory — record
            // exactly that world state. Assumption-based model — see
            // the honesty note on `stale_mounts`.
            let mut stale = self.stale_mounts.borrow_mut();
            let cleared: Vec<String> = stale
                .iter()
                .filter(|p| args.iter().any(|a| a == *p))
                .cloned()
                .collect();
            for p in cleared {
                let _removed = stale.remove(&p);
                self.created_dirs.borrow_mut().push(p);
            }
        }
        Ok(CommandOutput {
            stdout: self.command_stdout.clone(),
            stderr: self.command_stderr.clone(),
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

    fn sleep_ms(&self, ms: u64) {
        self.sleeps.borrow_mut().push(ms);
    }

    fn heal_terminal(&self) {
        self.heal_terminal_calls.set(self.heal_terminal_calls.get() + 1);
    }

    fn sha256_file(&self, path: &Path) -> Result<String, IoError> {
        self.file_hashes
            .get(&path.to_string_lossy().to_string())
            .cloned()
            .ok_or_else(|| IoError("no hash".into()))
    }

    fn sha256_process_package(&self, pid: u32) -> Result<String, IoError> {
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
            let _prev = self.files.insert(to_key, data);
            Ok(())
        } else if let Some(target) = self.symlinks.remove(&from_key) {
            let _prev = self.symlinks.insert(to_key, target);
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
    use super::{inspect_hint, map_files_hint, parse_maps_line};

    /// A dead pid fails closed AND names the procfs source it tried —
    /// no on-disk path is ever consulted (TOCTOU: paths race with swaps).
    #[test]
    fn dead_pid_error_names_the_procfs_source() {
        let io = super::RealSystemIo::new();
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let _status = child.wait().unwrap();
        let err = io.sha256_process_package(pid).unwrap_err();
        assert!(err.0.contains(&format!("/proc/{pid}/exe")), "{}", err.0);
        assert!(err.0.contains("PID namespace"), "{}", err.0);
    }

    /// The hints are the disambiguation surface shown in the pending
    /// panel: each errno class must name its distinct remediation.
    #[test]
    fn inspect_hints_disambiguate_by_errno() {
        let notfound = std::io::Error::from_raw_os_error(libc::ENOENT);
        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        let other = std::io::Error::from_raw_os_error(libc::EIO);

        assert!(inspect_hint(&notfound).contains("PID namespace"));
        assert!(inspect_hint(&notfound).contains("--pidns=host"));
        assert!(inspect_hint(&denied).contains("CAP_SYS_PTRACE"));
        assert!(inspect_hint(&denied).contains("SELinux"));
        assert!(inspect_hint(&other).contains("could not be inspected"));

        assert!(map_files_hint(&notfound).contains("mount namespace"));
        assert!(map_files_hint(&denied).contains("CAP_CHECKPOINT_RESTORE"));
        assert!(map_files_hint(&denied).contains("INITIAL user namespace"));
        assert!(map_files_hint(&other).contains("could not be read"));
    }

    #[test]
    fn parses_file_backed_mapping_with_spaced_path() {
        let (range, path) = parse_maps_line(
            "7f2a:1-7f2a:2 r--p 00000000 fd:01 123456 /opt/my libs/lib x.so",
        )
        .expect("valid line")
        .expect("file-backed");
        assert_eq!(range, "7f2a:1-7f2a:2");
        assert_eq!(path, std::path::PathBuf::from("/opt/my libs/lib x.so"));
    }

    #[test]
    fn parses_deleted_mapped_file() {
        let line = "7f0000000000-7f0000001000 r--p 00000000 fd:01 99 /usr/lib/x.so (deleted)";
        let (_, path) = parse_maps_line(line).unwrap().unwrap();
        assert_eq!(path, std::path::PathBuf::from("/usr/lib/x.so (deleted)"));
    }

    #[test]
    fn pathless_segments_are_none_not_errors() {
        for line in [
            "7ffd-7ffe rw-p 00000000 00:00 0 [heap]",
            "7ffd-7ffe rw-p 00000000 00:00 0 [stack]",
            "7ffd-7ffe r--p 00000000 00:00 0 [vvar]",
            "7ffd-7ffe rw-p 00000000 00:00 0",
        ] {
            assert!(parse_maps_line(line).unwrap().is_none(), "{line}");
        }
    }

    #[test]
    fn malformed_lines_fail_closed() {
        for line in [
            "",
            "noperms fd:01 1 /x",
            "7f00-7f01",
            "7f00-7f01 r--p",
            "7f00-7f01 r--p 0000",
            "7f00-7f01 r--p 0000 fd:01",
            "7f00-7f01 badlen! 0000 fd:01 1 /x",
            "-7f01 r--p 0000 fd:01 1 /x",
            "7f00- r--p 0000 fd:01 1 /x",
            "7f00-7f01 r--p 0000 fd:01 notanumber /x",
        ] {
            assert!(parse_maps_line(line).is_err(), "must fail closed: {line:?}");
        }
    }

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
        assert_eq!(mock.sha256_process_package(42).unwrap(), "def");
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
    fn mock_arg_scoped_rule_limited_and_unlimited() {
        use super::SystemIo;
        // Limited rule: fails exactly the first matching call, then expires.
        let mock = MockSystemIo::new().with_command_result_when_n(
            "podman",
            "exec",
            Some(1),
            1,
        );
        let first = mock.run_command("podman", &["exec", "c1", "stat", "/x"]).unwrap();
        assert!(!first.success(), "first matching call must fail");
        let second = mock.run_command("podman", &["exec", "c1", "stat", "/x"]).unwrap();
        assert!(second.success(), "expired rule must fall through to defaults");

        // Unlimited rule (uses_left = None): keeps applying.
        let mock = MockSystemIo::new().with_command_result_when("podman", "exec", Some(1));
        for _ in 0..3 {
            let r = mock.run_command("podman", &["exec", "c1", "stat", "/x"]).unwrap();
            assert!(!r.success());
        }
        // Non-matching argv unaffected.
        let other = mock.run_command("podman", &["start", "c1"]).unwrap();
        assert!(other.success());
    }

    #[test]
    fn mock_interactive_calls_recorded() {
        let mock = MockSystemIo::new();
        let _out = mock.run_interactive("sudo", &["-v"]).unwrap();
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
    fn mock_path_state_classifies_the_world() {
        let mock = MockSystemIo::new()
            .with_file("/tmp/f", b"x")
            .with_dir("/tmp/d")
            .with_stale_mount("/tmp/m");
        assert_eq!(mock.path_state(Path::new("/tmp/d")), PathState::Dir);
        assert_eq!(mock.path_state(Path::new("/tmp/f")), PathState::File);
        assert_eq!(mock.path_state(Path::new("/tmp/nothing")), PathState::Missing);
        match mock.path_state(Path::new("/tmp/m")) {
            PathState::Unreachable(why) => assert!(why.contains("os error 107"), "got: {why}"),
            other => panic!("dead mount must be Unreachable, got {other:?}"),
        }
    }

    #[test]
    fn mock_stale_mount_blocks_create_like_the_incident() {
        // The #23 signature: on a dead mount mkdir says EEXIST while
        // path_state says Unreachable, so create_dir_all surfaces
        // "File exists (os error 17)". The state is plain world
        // modeling; the error EMERGES from the primitive rules.
        let mut mock = MockSystemIo::new().with_stale_mount("/tmp/mnt");
        assert!(mock.file_exists(Path::new("/tmp/mnt")));
        let err = mock
            .create_dir_all(Path::new("/tmp/mnt"))
            .expect_err("dead mount must block create_dir_all");
        assert!(err.to_string().contains("os error 17"), "got: {err}");
        let rm = mock.remove_path(Path::new("/tmp/mnt"));
        assert!(rm.is_err(), "rmdir on a mountpoint must fail EBUSY");
    }

    #[test]
    fn mock_stale_mount_cleared_by_successful_lazy_unmount() {
        let mock = MockSystemIo::new().with_stale_mount("/tmp/mnt");
        mock.run_command("fusermount", &["-uz", "/tmp/mnt"]).unwrap();
        // After the lazy unmount the mountpoint remains as a plain dir.
        assert_eq!(mock.path_state(Path::new("/tmp/mnt")), PathState::Dir);
        mock.create_dir_all(Path::new("/tmp/mnt"))
            .expect("a plain dir satisfies create_dir_all");
    }

    #[test]
    fn mock_stale_mount_survives_failed_and_unrelated_unmounts() {
        let mock = MockSystemIo::new().with_stale_mount("/tmp/mnt");
        // Unmounting a DIFFERENT path succeeds but must not clear /tmp/mnt.
        mock.run_command("fusermount", &["-uz", "/tmp/other"]).unwrap();
        assert_eq!(
            mock.path_state(Path::new("/tmp/mnt")),
            PathState::Unreachable("Transport endpoint is not connected (os error 107)".into()),
            "unmounting a different path must not clear the stale mount"
        );
        // A FAILING unmount of the right path must not clear it either.
        let mut failing = MockSystemIo::new().with_stale_mount("/tmp/mnt");
        failing
            .command_results
            .insert("fusermount".into(), Some(1));
        failing.run_command("fusermount", &["-uz", "/tmp/mnt"]).unwrap();
        assert!(
            failing.create_dir_all(Path::new("/tmp/mnt")).is_err(),
            "a failed unmount must leave the stale mount in place"
        );
    }

    #[test]
    fn mock_file_blocks_create_dir_all() {
        // Real mkdir on an existing file name: EEXIST, is_dir false →
        // create_dir_all errors. (Previously the mock always succeeded,
        // hiding this failure mode.)
        let mock = MockSystemIo::new().with_file("/tmp/mnt", b"junk");
        assert_eq!(mock.path_state(Path::new("/tmp/mnt")), PathState::File);
        let err = mock
            .create_dir_all(Path::new("/tmp/mnt"))
            .expect_err("a file at the path must block create_dir_all");
        assert!(err.to_string().contains("os error 17"), "got: {err}");
    }

    #[test]
    fn mock_mkdir_only_on_missing() {
        let mock = MockSystemIo::new();
        mock.mkdir(Path::new("/tmp/new")).expect("free name: mkdir works");
        assert_eq!(mock.path_state(Path::new("/tmp/new")), PathState::Dir);
        let err = mock
            .mkdir(Path::new("/tmp/new"))
            .expect_err("second mkdir on the same name: EEXIST, unlike create_dir_all");
        assert!(err.to_string().contains("os error 17"), "got: {err}");
    }

    #[test]
    fn mock_spawn_contains_helper() {
        let mut mock = MockSystemIo::new();
        let _out = mock.spawn_independent("flatpak-spawn", &["--host", "sudo", "-n", "fuse-server"], None).unwrap();
        assert!(mock.spawn_contains(0, &["sudo", "-n"]));
        assert!(mock.spawn_contains(0, &["fuse-server"]));
    }
}
