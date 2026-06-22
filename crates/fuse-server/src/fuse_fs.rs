use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    Request,
};
use fuse_protocol::SystemIo;
use tracing::{debug, warn};

use crate::state::{ReadOutcome, ServerState};

const ROOT_INO: u64 = 1;
const TTL: Duration = Duration::from_secs(1);

/// The FUSE gatekeeper filesystem.  Shares `Arc<Mutex<ServerState>>` with the
/// socket server so CRUD commands take effect immediately.
pub struct GatekeeperFs<S: SystemIo> {
    state: std::sync::Arc<Mutex<ServerState>>,
    io: S,
    next_inode: AtomicU64,
    /// inode → secret-name  (root inode 1 is absent from this map)
    inodes: Mutex<std::collections::HashMap<u64, String>>,
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
        let mut map = self.inodes.lock().unwrap();
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
        self.inodes.lock().unwrap().get(&ino).cloned()
    }

    fn file_attr(&self, ino: u64, size: u64, uid: u32, gid: u32) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: (size + 511) / 512,
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
}

impl<S: SystemIo> Filesystem for GatekeeperFs<S> {
    fn lookup(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: ReplyEntry,
    ) {
        if parent != ROOT_INO {
            reply.error(libc::ENONET);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let state = self.state.lock().unwrap();
        if let Some(rec) = state.secrets.get(name_str) {
            let ino = self.assign_inode(name_str);
            let attr = self.file_attr(ino, rec.content.len() as u64, req.uid(), req.gid());
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == ROOT_INO {
            reply.attr(&TTL, &self.dir_attr(ROOT_INO, req.uid(), req.gid()));
            return;
        }
        let name = match self.inode_name(ino) {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let state = self.state.lock().unwrap();
        if let Some(rec) = state.secrets.get(&name) {
            reply.attr(&TTL, &self.file_attr(ino, rec.content.len() as u64, req.uid(), req.gid()));
        } else {
            reply.error(libc::ENOENT);
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
        let name = match self.inode_name(ino) {
            Some(n) => n,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let pid = req.pid();
        let pid_hash = match self.io.sha256_process_exe(pid) {
            Ok(h) => Some(h),
            Err(e) => {
                warn!("Could not hash /proc/{pid}/exe: {e}");
                None
            }
        };

        let outcome = {
            let mut state = self.state.lock().unwrap();
            state.attempt_read(&name, pid_hash.as_deref())
        };

        match outcome {
            ReadOutcome::Granted(content) => {
                let start = offset.max(0) as usize;
                let end = (start + size as usize).min(content.len());
                debug!("Granted read of '{name}' to pid {pid}");
                reply.data(&content[start..end]);
            }
            ReadOutcome::AlreadyAccessed => {
                warn!("Denied second read of '{name}' by pid {pid}");
                reply.error(libc::EACCES);
            }
            ReadOutcome::HashMismatch { got, expected } => {
                warn!("Hash mismatch for '{name}' pid {pid}: got {got}, want {expected}");
                reply.error(libc::EACCES);
            }
            ReadOutcome::NotFound => {
                reply.error(libc::ENOENT);
            }
        }
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
        let state = self.state.lock().unwrap();
        let names: Vec<(u64, String, usize)> = state
            .secrets
            .iter()
            .map(|(name, rec)| (self.assign_inode(name), name.clone(), rec.content.len()))
            .collect();
        drop(state);

        let mut entries = vec![
            (ROOT_INO, FileType::Directory, ".".to_string()),
            (ROOT_INO, FileType::Directory, "..".to_string()),
        ];
        for (ino, name, _len) in &names {
            entries.push((*ino, FileType::RegularFile, name.clone()));
        }

        let start = offset.max(0) as usize;
        for (i, (eino, kind, ename)) in entries.iter().enumerate().skip(start) {
            let buf_full = !reply.add(*eino, (i + 1) as i64, *kind, &ename);
            if buf_full {
                break;
            }
        }
        reply.ok();
    }
}

/// Helper to expose just the inode-mapping logic for unit testing without a
/// real mount.
#[cfg(test)]
pub(crate) fn test_inode_roundtrip() {
    use fuse_protocol::RealSystemIo;
    let state = std::sync::Arc::new(Mutex::new(ServerState::new()));
    let fs = GatekeeperFs::new(state, RealSystemIo::new());
    let ino_a = fs.assign_inode("a");
    let ino_b = fs.assign_inode("b");
    assert_ne!(ino_a, ino_b);
    // Re-assigning "a" returns the same inode.
    assert_eq!(fs.assign_inode("a"), ino_a);
    assert_eq!(fs.inode_name(ino_a), Some("a".into()));
}
