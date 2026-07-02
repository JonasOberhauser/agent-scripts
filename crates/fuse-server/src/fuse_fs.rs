use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyStatfs, Request,
};
use fuse_protocol::SystemIo;
use tracing::{debug, warn};

use crate::state::{ReadOutcome, ServerState};

const ROOT_INO: u64 = 1;

/// TTL for kernel cache entries.  Set to zero so the kernel always
/// re-validates with the FUSE daemon.  This is essential because secrets
/// are added dynamically via the socket protocol — a positive TTL would
/// cause stale entries (file appears to not exist, or removed file still
/// resolves) for up to TTL seconds after a state change.
const TTL: Duration = Duration::ZERO;

/// The FUSE gatekeeper filesystem.  Shares `Arc<Mutex<ServerState>>` with the
/// socket server so CRUD commands take effect immediately.
pub struct GatekeeperFs<S: SystemIo> {
    state: std::sync::Arc<Mutex<ServerState>>,
    #[allow(dead_code)]
    io: S,
    next_inode: AtomicU64,
    /// inode → secret-name  (root inode 1 is absent from this map)
    inodes: Mutex<std::collections::HashMap<u64, String>>,
}

/// Result of a non-blocking read attempt.
#[derive(Debug)]
pub enum ReadResult {
    /// Content served immediately.
    Data(Vec<u8>),
    /// Hard error (ENOENT, etc).
    Error(i32),
    /// Read denied — a pending access was created.  The caller should
    /// spawn a thread to wait for a grant and then reply.
    Pending {
        pending_id: u64,
        name: String,
        pid: u32,
        offset: usize,
        size: u32,
        timeout: std::time::Duration,
    },
}

/// Result of a `statfs` query — exposed for unit testing.
#[derive(Debug, Clone, PartialEq)]
pub struct StatfsData {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

impl<S: SystemIo> GatekeeperFs<S> {
    pub fn new(state: std::sync::Arc<Mutex<ServerState>>, io: S) -> Self {
        Self {
            state,
            io,
            next_inode: AtomicU64::new(2),
            inodes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn assign_inode(&self, name: &str) -> u64 {
        let mut map = self.inodes.lock().expect("inode map mutex poisoned");
        if let Some(&ino) = map.iter().find(|(_, n)| n.as_str() == name).map(|(k, _)| k) {
            return ino;
        }
        let ino = self.next_inode.fetch_add(1, Ordering::SeqCst);
        map.insert(ino, name.to_string());
        ino
    }

    fn inode_name(&self, ino: u64) -> Option<String> {
        if ino == ROOT_INO {
            return None;
        }
        self.inodes.lock().expect("inode map mutex poisoned").get(&ino).cloned()
    }

    fn file_attr(&self, ino: u64, size: u64, uid: u32, gid: u32) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn dir_attr(&self, ino: u64, uid: u32, gid: u32) -> FileAttr {
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    // ── Core logic (testable without a live FUSE mount) ───────────

    /// Resolve a name in a directory to an inode + attributes.
    ///
    /// Returns `Err(ENOENT)` when the parent is not the root directory or
    /// the name does not correspond to a known secret.
    pub fn do_lookup(
        &self,
        uid: u32,
        gid: u32,
        parent: u64,
        name: &str,
    ) -> Result<(u64, FileAttr), i32> {
        if parent != ROOT_INO {
            return Err(libc::ENOENT);
        }
        let state = self.state.lock().expect("ServerState mutex poisoned");
        if let Some(rec) = state.secrets.get(name) {
            let ino = self.assign_inode(name);
            let attr = self.file_attr(ino, rec.content.len() as u64, uid, gid);
            Ok((ino, attr))
        } else {
            Err(libc::ENOENT)
        }
    }

    /// Get attributes for an inode.
    pub fn do_getattr(&self, uid: u32, gid: u32, ino: u64) -> Result<FileAttr, i32> {
        if ino == ROOT_INO {
            return Ok(self.dir_attr(ROOT_INO, uid, gid));
        }
        let name = match self.inode_name(ino) {
            Some(n) => n,
            None => return Err(libc::ENOENT),
        };
        let state = self.state.lock().expect("ServerState mutex poisoned");
        if let Some(rec) = state.secrets.get(&name) {
            Ok(self.file_attr(ino, rec.content.len() as u64, uid, gid))
        } else {
            Err(libc::ENOENT)
        }
    }

    /// Read data from a secret file, enforcing the one-read / hash-check
    /// gatekeeper policy.
    ///
    /// `pid` is the PID of the reading process (used for multi-chunk
    /// detection).  `pid_hash` is the SHA-256 of the calling process's
    /// executable, or `None` if it could not be determined.  Forward-only
    /// reads are enforced: re-reading already-served bytes is denied.
    /// Non-blocking read attempt.  Returns Data, Error, or Pending.
    /// When Pending, the caller should spawn a thread to wait for grant
    /// and send the reply asynchronously.
    pub fn try_read(
        &self,
        ino: u64,
        pid: u32,
        pid_hash: Option<&str>,
        offset: i64,
        size: u32,
    ) -> ReadResult {
        let name = match self.inode_name(ino) {
            Some(n) => n,
            None => return ReadResult::Error(libc::ENOENT),
        };

        let off = offset.max(0) as usize;

        let outcome = {
            let mut state = self.state.lock().expect("ServerState mutex poisoned");
            state.attempt_read(&name, pid, pid_hash, off, size as usize)
        };

        match outcome {
            ReadOutcome::Granted(content) => {
                let start = off.min(content.len());
                let end = (start + size as usize).min(content.len());
                ReadResult::Data(content[start..end].to_vec())
            }
            ReadOutcome::NotFound => ReadResult::Error(libc::ENOENT),
            ReadOutcome::AlreadyAccessed | ReadOutcome::HashMismatch { .. } => {
                let reason = match &outcome {
                    ReadOutcome::AlreadyAccessed => "exceeded access limit".to_string(),
                    ReadOutcome::HashMismatch { got, expected } => {
                        format!("hash mismatch: got {got}, expected {expected}")
                    }
                    _ => unreachable!(),
                };

                let (pending_id, timeout) = {
                    let mut state = self.state.lock().expect("ServerState mutex poisoned");
                    if state.pending_timeout.is_zero() {
                        warn!("Denied read of '{name}' by pid {pid}: {reason}");
                        return ReadResult::Error(libc::EACCES);
                    }
                    let id = state.create_pending(&name, pid, pid_hash, &reason);
                    let to = state.pending_timeout;
                    (id, to)
                };

                warn!(
                    "Access pending for '{name}' by pid {pid}: {reason} \
                     (id={pending_id}). Waiting up to {}s for grant...",
                    timeout.as_secs()
                );

                ReadResult::Pending {
                    pending_id,
                    name,
                    pid,
                    offset: off,
                    size,
                    timeout,
                }
            }
        }
    }

    /// Blocking read — for unit tests only.  Production uses Filesystem::read
    /// which spawns a thread for Pending results.
    pub fn do_read(
        &self,
        ino: u64,
        pid: u32,
        pid_hash: Option<&str>,
        offset: i64,
        size: u32,
    ) -> Result<Vec<u8>, i32> {
        match self.try_read(ino, pid, pid_hash, offset, size) {
            ReadResult::Data(data) => Ok(data),
            ReadResult::Error(e) => Err(e),
            ReadResult::Pending {
                pending_id,
                name,
                pid,
                offset,
                size,
                timeout,
            } => {
                let deadline = std::time::Instant::now() + timeout;
                loop {
                    if std::time::Instant::now() > deadline {
                        self.state
                            .lock()
                            .expect("ServerState mutex poisoned")
                            .remove_pending(pending_id);
                        warn!("Pending access {pending_id} timed out");
                        return Err(libc::EACCES);
                    }

                    let granted = {
                        let state = self.state.lock().expect("ServerState mutex poisoned");
                        state.is_pending_granted(pending_id)
                    };

                    if granted {
                        warn!("Pending access {pending_id} granted — serving '{name}'");
                        let content = {
                            let mut state = self.state.lock().expect("ServerState mutex poisoned");
                            state.force_grant_read(&name, pid, offset, size as usize)
                        };
                        self.state
                            .lock()
                            .expect("ServerState mutex poisoned")
                            .remove_pending(pending_id);

                        return match content {
                            Some(data) => {
                                let start = offset.min(data.len());
                                let end = (start + size as usize).min(data.len());
                                Ok(data[start..end].to_vec())
                            }
                            None => Err(libc::ENOENT),
                        };
                    }

                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }

    /// List all entries in the root directory.
    pub fn do_readdir(&self) -> Vec<(u64, FileType, String)> {
        let state = self.state.lock().expect("ServerState mutex poisoned");
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ROOT_INO, FileType::Directory, ".".to_string()),
            (ROOT_INO, FileType::Directory, "..".to_string()),
        ];
        for name in state.secrets.keys() {
            let ino = self.assign_inode(name);
            entries.push((ino, FileType::RegularFile, name.clone()));
        }
        entries
    }

    /// Filesystem statistics for `statfs`.
    pub fn do_statfs(&self) -> Result<StatfsData, i32> {
        let state = self.state.lock().expect("ServerState mutex poisoned");
        let total_size: usize = state.secrets.values().map(|r| r.content.len()).max().unwrap_or(0);
        let num_files = state.secrets.len() as u64;
        drop(state);

        Ok(StatfsData {
            blocks: (total_size as u64).div_ceil(512),
            bfree: 1_000_000,
            bavail: 1_000_000,
            files: num_files + 1,
            ffree: 1_000_000,
            bsize: 512,
            namelen: 255,
            frsize: 512,
        })
    }
}

impl<S: SystemIo> Filesystem for GatekeeperFs<S> {
    fn lookup(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        match self.do_lookup(req.uid(), req.gid(), parent, name_str) {
            Ok((_, attr)) => reply.entry(&TTL, &attr, 0),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.do_getattr(req.uid(), req.gid(), ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let pid = req.pid();

        // Look up the secret name on the main thread (fast, uses inode map).
        let name = match self.inode_name(ino) {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Spawn a thread for the entire read: hash computation (potentially
        // slow — reads /proc/{pid}/exe and hashes the binary), attempt_read,
        // and pending wait if needed.  This keeps the FUSE session responsive.
        let state = self.state.clone();
        std::thread::spawn(move || {
            let off = offset.max(0) as usize;

            // Compute process hash (slow — reads the binary file)
            let pid_hash = match fuse_protocol::RealSystemIo::new().sha256_process_exe(pid) {
                Ok(h) => Some(h),
                Err(e) => {
                    warn!("Could not hash /proc/{pid}/exe: {e}");
                    None
                }
            };

            // Try to read
            let outcome = {
                let mut s = state.lock().expect("ServerState mutex poisoned");
                s.attempt_read(&name, pid, pid_hash.as_deref(), off, size as usize)
            };

            match outcome {
                ReadOutcome::Granted(content) => {
                    debug!("Granted read of '{name}' to pid {pid}");
                    let start = off.min(content.len());
                    let end = (start + size as usize).min(content.len());
                    reply.data(&content[start..end]);
                }
                ReadOutcome::NotFound => reply.error(libc::ENOENT),
                ReadOutcome::AlreadyAccessed | ReadOutcome::HashMismatch { .. } => {
                    let reason = match &outcome {
                        ReadOutcome::AlreadyAccessed => "exceeded access limit".to_string(),
                        ReadOutcome::HashMismatch { got, expected } => {
                            format!("hash mismatch: got {got}, expected {expected}")
                        }
                        _ => unreachable!(),
                    };

                    let (pending_id, timeout) = {
                        let mut s = state.lock().expect("ServerState mutex poisoned");
                        if s.pending_timeout.is_zero() {
                            warn!("Denied read of '{name}' by pid {pid}: {reason}");
                            reply.error(libc::EACCES);
                            return;
                        }
                        let id = s.create_pending(&name, pid, pid_hash.as_deref(), &reason);
                        let to = s.pending_timeout;
                        (id, to)
                    };

                    warn!(
                        "Access pending for '{name}' by pid {pid}: {reason} \
                         (id={pending_id}). Waiting up to {}s for grant...",
                        timeout.as_secs()
                    );

                    let deadline = std::time::Instant::now() + timeout;
                    loop {
                        if std::time::Instant::now() > deadline {
                            state
                                .lock()
                                .expect("ServerState mutex poisoned")
                                .remove_pending(pending_id);
                            warn!("Pending access {pending_id} timed out");
                            reply.error(libc::EACCES);
                            return;
                        }

                        let granted = {
                            let s = state.lock().expect("ServerState mutex poisoned");
                            s.is_pending_granted(pending_id)
                        };

                        if granted {
                            warn!("Pending access {pending_id} granted — serving '{name}'");
                            let content = {
                                let mut s = state.lock().expect("ServerState mutex poisoned");
                                s.force_grant_read(&name, pid, off, size as usize)
                            };
                            state
                                .lock()
                                .expect("ServerState mutex poisoned")
                                .remove_pending(pending_id);

                            match content {
                                Some(data) => {
                                    let start = off.min(data.len());
                                    let end = (start + size as usize).min(data.len());
                                    reply.data(&data[start..end]);
                                }
                                None => reply.error(libc::ENOENT),
                            }
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        });
        // Return immediately — the thread handles everything.
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(libc::ENOTDIR);
            return;
        }
        let entries = self.do_readdir();
        let start = offset.max(0) as usize;
        for (i, (eino, kind, ename)) in entries.iter().enumerate().skip(start) {
            let buf_full = !reply.add(*eino, (i + 1) as i64, *kind, ename);
            if buf_full {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        match self.do_statfs() {
            Ok(s) => reply.statfs(
                s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.bsize, s.namelen, s.frsize,
            ),
            Err(e) => reply.error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::MockSystemIo;

    fn make_fs(secrets: &[(&str, &[u8], &str)]) -> GatekeeperFs<MockSystemIo> {
        let mut state = ServerState::new();
        state.pending_timeout = Duration::ZERO;
        for (name, content, hash) in secrets {
            state.add(*name, content.to_vec(), *hash);
        }
        let state = std::sync::Arc::new(std::sync::Mutex::new(state));
        GatekeeperFs::new(state, MockSystemIo::new())
    }

    // ── do_lookup tests ──────────────────────────────────────────

    #[test]
    fn lookup_non_root_parent_returns_enoent() {
        let fs = make_fs(&[("secret", b"data", "hash_a")]);
        let result = fs.do_lookup(0, 0, 999, "secret");
        assert_eq!(result, Err(libc::ENOENT));
    }

    #[test]
    fn lookup_existing_secret_returns_attr() {
        let fs = make_fs(&[("secret", b"hello world", "hash_a")]);
        let (ino, attr) = fs.do_lookup(0, 0, ROOT_INO, "secret").unwrap();
        assert!(ino >= 2);
        assert_eq!(attr.size, 11);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o444);
    }

    #[test]
    fn lookup_nonexistent_secret_returns_enoent() {
        let fs = make_fs(&[("secret", b"data", "hash_a")]);
        let result = fs.do_lookup(0, 0, ROOT_INO, "nope");
        assert_eq!(result, Err(libc::ENOENT));
    }

    #[test]
    fn lookup_assigns_stable_inode() {
        let fs = make_fs(&[("a", b"x", "h"), ("b", b"y", "h")]);
        let (ino1, _) = fs.do_lookup(0, 0, ROOT_INO, "a").unwrap();
        let (ino2, _) = fs.do_lookup(0, 0, ROOT_INO, "a").unwrap();
        assert_eq!(ino1, ino2, "same name should get same inode");
        let (ino3, _) = fs.do_lookup(0, 0, ROOT_INO, "b").unwrap();
        assert_ne!(ino2, ino3, "different names get different inodes");
    }

    #[test]
    fn lookup_non_root_parent_does_not_return_enonet() {
        // Regression: the original code returned libc::ENONET (error 64,
        // "Machine is not on the network") instead of libc::ENOENT
        // (error 2, "No such file or directory").
        let fs = make_fs(&[]);
        let err = fs.do_lookup(0, 0, 42, "anything").unwrap_err();
        assert_ne!(err, libc::ENONET, "must not return ENONET");
        assert_eq!(err, libc::ENOENT);
    }

    // ── do_getattr tests ─────────────────────────────────────────

    #[test]
    fn getattr_root_returns_directory() {
        let fs = make_fs(&[]);
        let attr = fs.do_getattr(0, 0, ROOT_INO).unwrap();
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn getattr_secret_returns_file() {
        let fs = make_fs(&[("s", b"ABCDEF", "h")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        let attr = fs.do_getattr(0, 0, ino).unwrap();
        assert_eq!(attr.size, 6);
        assert_eq!(attr.kind, FileType::RegularFile);
    }

    #[test]
    fn getattr_unknown_inode_returns_enoent() {
        let fs = make_fs(&[]);
        let result = fs.do_getattr(0, 0, 9999);
        assert_eq!(result, Err(libc::ENOENT));
    }

    // ── do_read tests ────────────────────────────────────────────

    #[test]
    fn read_with_correct_hash_grants_content() {
        let fs = make_fs(&[("s", b"TOPSECRET", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        let data = fs.do_read(ino, 100, Some("good_hash"), 0, 1024).unwrap();
        assert_eq!(data, b"TOPSECRET");
    }

    #[test]
    fn read_with_wrong_hash_denied() {
        let fs = make_fs(&[("s", b"TOPSECRET", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        let result = fs.do_read(ino, 100, Some("bad_hash"), 0, 1024);
        assert_eq!(result, Err(libc::EACCES));
    }

    #[test]
    fn read_with_unknown_hash_denied() {
        let fs = make_fs(&[("s", b"TOPSECRET", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        let result = fs.do_read(ino, 100, None, 0, 1024);
        assert_eq!(result, Err(libc::EACCES));
    }

    #[test]
    fn read_cross_pid_second_access_denied() {
        let fs = make_fs(&[("s", b"TOPSECRET", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        // PID 100 reads first
        let _ = fs.do_read(ino, 100, Some("good_hash"), 0, 1024).unwrap();
        // PID 200 denied
        let result = fs.do_read(ino, 200, Some("good_hash"), 0, 1024);
        assert_eq!(result, Err(libc::EACCES));
    }

    #[test]
    fn read_multi_chunk_same_pid_allowed() {
        let fs = make_fs(&[("s", b"0123456789ABCDEF", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        // Chunk 1: forward
        let d1 = fs.do_read(ino, 42, Some("good_hash"), 0, 4).unwrap();
        assert_eq!(d1, b"0123");
        // Chunk 2: forward
        let d2 = fs.do_read(ino, 42, Some("good_hash"), 4, 4).unwrap();
        assert_eq!(d2, b"4567");
        // Chunk 3: forward
        let d3 = fs.do_read(ino, 42, Some("good_hash"), 8, 4).unwrap();
        assert_eq!(d3, b"89AB");
    }

    #[test]
    fn read_backward_chunk_denied() {
        let fs = make_fs(&[("s", b"0123456789", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        // Read 0..4
        fs.do_read(ino, 42, Some("good_hash"), 0, 4).unwrap();
        // Re-read 0..4 — denied
        let result = fs.do_read(ino, 42, Some("good_hash"), 0, 4);
        assert_eq!(result, Err(libc::EACCES));
        // Read 2..6 — overlaps — denied
        let result = fs.do_read(ino, 42, Some("good_hash"), 2, 4);
        assert_eq!(result, Err(libc::EACCES));
        // Read 4..8 — forward — allowed
        let d = fs.do_read(ino, 42, Some("good_hash"), 4, 4).unwrap();
        assert_eq!(d, b"4567");
    }

    #[test]
    fn read_partial_with_offset() {
        let fs = make_fs(&[("s", b"0123456789", "good_hash")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        let data = fs.do_read(ino, 100, Some("good_hash"), 3, 4).unwrap();
        assert_eq!(data, b"3456");
    }

    #[test]
    fn read_unknown_inode_returns_enoent() {
        let fs = make_fs(&[]);
        let result = fs.do_read(9999, 100, Some("hash"), 0, 1024);
        assert_eq!(result, Err(libc::ENOENT));
    }

    #[test]
    fn read_resets_allow_reread() {
        let fs = make_fs(&[("s", b"DATA", "h")]);
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();
        // First read succeeds
        let _ = fs.do_read(ino, 100, Some("h"), 0, 1024).unwrap();
        // Different PID denied
        assert_eq!(fs.do_read(ino, 200, Some("h"), 0, 1024), Err(libc::EACCES));
        // Reset via shared state
        {
            let mut state = fs.state.lock().unwrap();
            state.reset(Some("s"));
        }
        // After reset, same PID can read again
        let data = fs.do_read(ino, 100, Some("h"), 0, 1024).unwrap();
        assert_eq!(data, b"DATA");
    }

    // ── do_readdir tests ─────────────────────────────────────────

    #[test]
    fn readdir_lists_all_secrets() {
        let fs = make_fs(&[("a", b"x", "h"), ("b", b"y", "h")]);
        let entries = fs.do_readdir();
        let names: Vec<&str> = entries.iter().map(|(_, _, n)| n.as_str()).collect();
        assert!(names.contains(&"."));
        assert!(names.contains(&".."));
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn readdir_empty_has_dot_dotdot() {
        let fs = make_fs(&[]);
        let entries = fs.do_readdir();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].2, ".");
        assert_eq!(entries[1].2, "..");
    }

    #[test]
    fn readdir_entries_are_regular_files() {
        let fs = make_fs(&[("s", b"data", "h")]);
        let entries = fs.do_readdir();
        let secret_entry = entries.iter().find(|(_, _, n)| n == "s").unwrap();
        assert_eq!(secret_entry.1, FileType::RegularFile);
    }

    // ── do_statfs tests ──────────────────────────────────────────

    #[test]
    fn statfs_returns_valid_data() {
        let fs = make_fs(&[("s", b"data", "h")]);
        let s = fs.do_statfs().unwrap();
        assert!(s.bsize > 0);
        assert!(s.namelen > 0);
        assert!(s.files >= 1, "files should include at least root");
    }

    #[test]
    fn statfs_empty_filesystem() {
        let fs = make_fs(&[]);
        let s = fs.do_statfs().unwrap();
        assert_eq!(s.files, 1, "just root inode");
        assert!(s.bfree > 0);
    }

    // ── dynamic add via shared state ─────────────────────────────

    #[test]
    fn dynamic_add_visible_after_lookup() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        let fs = GatekeeperFs::new(state.clone(), MockSystemIo::new());

        // Initially no secrets
        assert_eq!(fs.do_lookup(0, 0, ROOT_INO, "new"), Err(libc::ENOENT));

        // Add via shared state (simulates socket AddSecret)
        state.lock().unwrap().add("new", b"DATA".to_vec(), "hash");

        // Now visible
        let (ino, attr) = fs.do_lookup(0, 0, ROOT_INO, "new").unwrap();
        assert_eq!(attr.size, 4);
        let data = fs.do_read(ino, 100, Some("hash"), 0, 1024).unwrap();
        assert_eq!(data, b"DATA");
    }

    // ── pending access tests ─────────────────────────────────────

    #[test]
    fn pending_granted_serves_content() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        state.lock().unwrap().pending_timeout = Duration::from_secs(10);
        state.lock().unwrap().add("s", b"SECRET".to_vec(), "good_hash");
        let state_clone = state.clone();

        // Spawn a thread to grant the pending access after 200ms
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // Grant the first pending access
            let mut s = state_clone.lock().unwrap();
            if let Some(p) = s.pending.first() {
                let id = p.id;
                drop(s);
                state_clone.lock().unwrap().grant_pending(id);
            }
        });

        let fs = GatekeeperFs::new(state, MockSystemIo::new());
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();

        // This read has wrong hash → pending → granted by thread → succeeds
        let data = fs.do_read(ino, 42, Some("wrong_hash"), 0, 1024).unwrap();
        assert_eq!(data, b"SECRET");
    }

    #[test]
    fn pending_timeout_denies() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        state.lock().unwrap().pending_timeout = Duration::from_millis(100);
        state.lock().unwrap().add("s", b"SECRET".to_vec(), "good_hash");

        let fs = GatekeeperFs::new(state, MockSystemIo::new());
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();

        // Wrong hash → pending → no grant → timeout → EACCES
        let result = fs.do_read(ino, 42, Some("wrong_hash"), 0, 1024);
        assert_eq!(result, Err(libc::EACCES));
    }

    #[test]
    fn pending_creates_and_removes_entry() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        state.lock().unwrap().pending_timeout = Duration::from_millis(100);
        state.lock().unwrap().add("s", b"X".to_vec(), "h");

        let fs = GatekeeperFs::new(state.clone(), MockSystemIo::new());
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();

        // Trigger a pending (will timeout)
        let _ = fs.do_read(ino, 42, Some("wrong"), 0, 1024);

        // After timeout, pending should be cleaned up
        assert!(state.lock().unwrap().pending.is_empty());
    }

    // ── try_read non-blocking tests ──────────────────────────────

    #[test]
    fn try_read_returns_immediately_on_pending() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        state.lock().unwrap().pending_timeout = Duration::from_secs(60);
        state.lock().unwrap().add("s", b"DATA".to_vec(), "correct_hash");

        let fs = GatekeeperFs::new(state, MockSystemIo::new());
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();

        // Wrong hash → try_read should return Pending immediately
        let start = std::time::Instant::now();
        let result = fs.try_read(ino, 100, Some("wrong"), 0, 1024);
        let elapsed = start.elapsed();

        assert!(matches!(result, ReadResult::Pending { .. }));
        assert!(
            elapsed < Duration::from_millis(100),
            "try_read should return immediately, took {elapsed:?}"
        );
    }

    #[test]
    fn try_read_concurrent_after_pending() {
        // Verify that after a pending is created, try_read for a DIFFERENT
        // secret still works immediately (no blocking).
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        state.lock().unwrap().pending_timeout = Duration::from_secs(60);
        state.lock().unwrap().add("a", b"AAA".to_vec(), "hash_a");
        state.lock().unwrap().add("b", b"BBB".to_vec(), "hash_b");

        let fs = GatekeeperFs::new(state, MockSystemIo::new());
        let (ino_a, _) = fs.do_lookup(0, 0, ROOT_INO, "a").unwrap();
        let (ino_b, _) = fs.do_lookup(0, 0, ROOT_INO, "b").unwrap();

        // First read: wrong hash → pending (shouldn't block)
        let result_a = fs.try_read(ino_a, 100, Some("wrong"), 0, 1024);
        assert!(matches!(result_a, ReadResult::Pending { .. }));

        // Second read: correct hash → should succeed immediately
        // even though the first read is pending.
        let start = std::time::Instant::now();
        let result_b = fs.try_read(ino_b, 200, Some("hash_b"), 0, 1024);
        let elapsed = start.elapsed();

        assert!(matches!(result_b, ReadResult::Data(_)));
        assert!(
            elapsed < Duration::from_millis(100),
            "second try_read should return immediately, took {elapsed:?}"
        );
    }

    #[test]
    fn try_read_zero_timeout_returns_error_not_pending() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(ServerState::new()));
        state.lock().unwrap().pending_timeout = Duration::ZERO;
        state.lock().unwrap().add("s", b"DATA".to_vec(), "correct_hash");

        let fs = GatekeeperFs::new(state, MockSystemIo::new());
        let (ino, _) = fs.do_lookup(0, 0, ROOT_INO, "s").unwrap();

        // Wrong hash with zero timeout → Error, not Pending
        let result = fs.try_read(ino, 100, Some("wrong"), 0, 1024);
        assert!(matches!(result, ReadResult::Error(libc::EACCES)));
    }
}
