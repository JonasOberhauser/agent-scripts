//! The data daemon's FUSE filesystem: content, metadata, and the
//! per-read delegation to the policy daemon.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuse_protocol::oracle::{OracleCommand, OracleReply, OracleRequest};
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, Request, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
};
use tracing::warn;

const ROOT_INO: u64 = 1;
const TTL: Duration = Duration::from_secs(1);

/// One served secret: the bytes (they live ONLY here) + mode.
#[derive(Clone)]
struct Content {
    bytes: Vec<u8>,
    mode: u32,
}

#[derive(Default)]
struct StoreInner {
    next_ino: u64,
    by_name: HashMap<String, u64>,
    by_ino: HashMap<u64, (String, Content)>,
}

/// Content store: name⇄inode bookkeeping plus the bytes.
#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<StoreInner>>);

impl Store {
    pub fn upsert(&self, name: &str, bytes: Vec<u8>, mode: u32) {
        let mut s = self.0.lock().unwrap();
        if let Some(&ino) = s.by_name.get(name) {
            s.by_ino.insert(ino, (name.to_string(), Content { bytes, mode }));
        } else {
            s.next_ino += 1;
            let ino = s.next_ino + ROOT_INO;
            s.by_name.insert(name.to_string(), ino);
            s.by_ino.insert(ino, (name.to_string(), Content { bytes, mode }));
        }
    }

    pub fn remove(&self, name: &str) {
        let mut s = self.0.lock().unwrap();
        if let Some(ino) = s.by_name.remove(name) {
            s.by_ino.remove(&ino);
        }
    }

    fn lookup(&self, ino: u64) -> Option<(String, Content)> {
        self.0.lock().unwrap().by_ino.get(&ino).cloned()
    }

    fn listing(&self) -> Vec<(u64, String, u32, usize)> {
        let s = self.0.lock().unwrap();
        let mut v: Vec<_> = s
            .by_ino
            .iter()
            .map(|(ino, (name, c))| (*ino, name.clone(), c.mode, c.bytes.len()))
            .collect();
        v.sort_by(|a, b| a.1.cmp(&b.1));
        v
    }

    fn read(&self, ino: u64, offset: usize, size: usize) -> Option<Vec<u8>> {
        let (_, c) = self.lookup(ino)?;
        let data = &c.bytes;
        if offset >= data.len() {
            return Some(Vec::new());
        }
        let end = (offset + size).min(data.len());
        Some(data[offset..end].to_vec())
    }
}

/// One blocking adjudication ask against the policy daemon.
pub fn ask_policy(socket: &str, name: &str, pid: u32, offset: u64, size: u32) -> Result<OracleReply, String> {
    let mut conn = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    conn.set_read_timeout(Some(Duration::from_secs(3600))).ok();
    let req = serde_json::to_string(&OracleRequest::Ask {
        name: name.into(),
        pid,
        offset,
        size,
    })
    .map_err(|e| e.to_string())?;
    conn.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

pub struct FusedFs {
    store: Store,
    oracle: String,
}

impl FusedFs {
    pub fn new(store: Store, oracle_socket: &str) -> Self {
        Self { store, oracle: oracle_socket.to_string() }
    }

    fn file_attr(&self, ino: u64, size: u64, uid: u32, gid: u32, mode: u32) -> FileAttr {
        // Read-only view: strip every write bit, whatever the source had.
        let ro = mode & 0o444;
        let now = std::time::SystemTime::now();
        #[allow(deprecated)]
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm: ro as u16,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn dir_attr(&self, ino: u64, uid: u32, gid: u32) -> FileAttr {
        let now = std::time::SystemTime::now();
        #[allow(deprecated)]
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for FusedFs {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), libc::c_int> {
        Ok(())
    }

    fn destroy(&mut self) {}

    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        if parent != ROOT_INO {
            reply.error(libc::ENOENT);
            return;
        }
        let name = name.to_string_lossy();
        let s = self.store.0.lock().unwrap();
        let Some(&ino) = s.by_name.get(name.as_ref()) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some((_, c)) = s.by_ino.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let size = c.bytes.len() as u64;
        let mode = c.mode;
        drop(s);
        let attr = self.file_attr(ino, size, req.uid(), req.gid(), mode);
        reply.entry(&TTL, &attr, 0);
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == ROOT_INO {
            reply.attr(&TTL, &self.dir_attr(ino, req.uid(), req.gid()));
            return;
        }
        match self.store.lookup(ino) {
            Some((_, c)) => {
                let attr = self.file_attr(ino, c.bytes.len() as u64, req.uid(), req.gid(), c.mode);
                reply.attr(&TTL, &attr);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, fuser::consts::FOPEN_DIRECT_IO);
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
        let Some((name, _)) = self.store.lookup(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let offset = offset.max(0) as u64;
        // Delegate the trust decision to the policy daemon; this call
        // may block while a pending waits for a grant — run it on its
        // own thread so the mount stays responsive.
        let oracle = self.oracle.clone();
        let store = self.store.clone();
        let pid = req.pid();
        std::thread::spawn(move || match ask_policy(&oracle, &name, pid, offset, size) {
            Ok(OracleReply::Allow) => match store.read(ino, offset as usize, size as usize) {
                Some(data) => reply.data(&data),
                None => reply.error(libc::ENOENT),
            },
            Ok(OracleReply::Deny { errno, reason }) => {
                warn!("policy daemon denied read of '{name}' by pid {pid}: {reason}");
                reply.error(errno);
            }
            Ok(other) => {
                warn!("policy daemon replied unexpectedly to read: {other:?}");
                reply.error(libc::EACCES);
            }
            Err(e) => {
                warn!("policy daemon unreachable for read of '{name}': {e}");
                reply.error(libc::EACCES);
            }
        });
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
            reply.error(libc::ENOENT);
            return;
        }
        // FUSE readdir contract: each entry carries the offset the NEXT
        // readdir call should start from — strictly increasing, never 0,
        // or the kernel re-reads from the start forever.
        let listing = self.store.listing();
        let all: Vec<(u64, FileType, String)> = vec![
            (ROOT_INO, FileType::Directory, ".".into()),
            (ROOT_INO, FileType::Directory, "..".into()),
        ]
        .into_iter()
        .chain(listing.into_iter().map(|(i, n, _, _)| (i, FileType::RegularFile, n)))
        .collect();
        for (idx, (e_ino, kind, name)) in all.into_iter().enumerate() {
            let next_offset = (idx + 1) as i64;
            let idx_off = idx as i64;
            if idx_off < offset {
                continue; // already served
            }
            if reply.add(e_ino, next_offset, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let listing = self.store.listing();
        let total: u64 = listing.iter().map(|(_, _, _, len)| *len as u64).sum();
        reply.statfs(
            1_000_000,
            1_000_000u64.saturating_sub(total.div_ceil(512)),
            1_000_000u64.saturating_sub(total.div_ceil(512)),
            listing.len() as u64 + 1,
            1_000_000,
            512,
            255,
            512,
        );
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Read-only view: every mutation is refused.
        reply.error(libc::EPERM);
    }

    fn fsync(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        reply.error(libc::EPERM);
    }
}

/// Maintain the CONTROL connection to the policy daemon: say hello,
/// then apply every Upsert/Remove it pushes. Reconnects on loss.
pub fn run_control_loop(store: Store, oracle_socket: String) {
    loop {
        if let Ok(conn) = UnixStream::connect(&oracle_socket) {
            let mut reader = BufReader::new(conn.try_clone().expect("clone control conn"));
            let mut w = conn;
            if writeln!(w, "{}", serde_json::to_string(&OracleRequest::Hello).unwrap()).is_err() {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let _ = w.flush();
            // Ok ack + snapshot commands arrive as lines.
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Ok(OracleCommand::Upsert { name, content, mode }) =
                            serde_json::from_str::<OracleCommand>(line.trim())
                        {
                            store.upsert(&name, content, mode);
                        } else if let Ok(OracleCommand::Remove { name }) =
                            serde_json::from_str::<OracleCommand>(line.trim())
                        {
                            store.remove(&name);
                        }
                        // anything else: Ok acks on the same stream
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(name: &str, bytes: &[u8], mode: u32) -> Store {
        let s = Store::default();
        s.upsert(name, bytes.to_vec(), mode);
        s
    }

    #[test]
    fn upsert_assigns_stable_inode_and_replace_keeps_it() {
        let s = store_with("a", b"one", 0o400);
        let ino1 = s.0.lock().unwrap().by_name["a"];
        s.upsert("a", b"longer bytes".to_vec(), 0o400);
        let ino2 = s.0.lock().unwrap().by_name["a"];
        assert_eq!(ino1, ino2, "replacement keeps the inode");
        assert_eq!(s.read(ino1, 0, 64).unwrap(), b"longer bytes");
    }

    #[test]
    fn remove_makes_lookup_fail() {
        let s = store_with("a", b"x", 0o400);
        let ino = s.0.lock().unwrap().by_name["a"];
        s.remove("a");
        assert!(s.lookup(ino).is_none());
    }

    #[test]
    fn read_clamps_offset_and_size() {
        let s = store_with("a", b"0123456789", 0o400);
        let ino = s.0.lock().unwrap().by_name["a"];
        assert_eq!(s.read(ino, 2, 3).unwrap(), b"234");
        assert_eq!(s.read(ino, 9, 100).unwrap(), b"9");
        assert_eq!(s.read(ino, 10, 5).unwrap(), b"");
        assert_eq!(s.read(ino, 100, 5).unwrap(), b"");
    }

    /// The ask framing round-trips against a live listener that acts
    /// like the policy daemon.
    #[test]
    fn ask_policy_frames_one_request_per_connection() {
        let dir = std::env::temp_dir().join(format!("fused-ask-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("o.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let p2 = path.clone();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let req: OracleRequest = serde_json::from_str(line.trim()).unwrap();
            let OracleRequest::Ask { name, pid, offset, size } = req else {
                panic!("expected an ask");
            };
            assert_eq!((name.as_str(), pid, offset, size), ("s.yaml", 7, 1, 4));
            conn.write_all(
                format!("{}\n", serde_json::to_string(&OracleReply::Allow).unwrap()).as_bytes(),
            )
            .unwrap();
        });
        let reply = ask_policy(p2.to_str().unwrap(), "s.yaml", 7, 1, 4).unwrap();
        assert_eq!(reply, OracleReply::Allow);
        server.join().unwrap();
    }
}
