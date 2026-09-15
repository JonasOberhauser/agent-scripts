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
    /// Implicit directory layer (issue #34): names are normalized
    /// host paths (`home/u/auth.json`); directories materialize from
    /// the path components and vanish when no name lives under them.
    /// Inodes come from a separate high range so they can never
    /// collide with file inodes (which count up from ROOT_INO).
    dir_by_path: HashMap<String, u64>,
    path_by_dir_ino: HashMap<u64, String>,
    next_dir_ino: u64,
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

    /// Stable inode for the implicit directory at `path` ("" = root).
    fn dir_ino(&self, path: &str) -> u64 {
        let mut s = self.0.lock().unwrap();
        if let Some(&ino) = s.dir_by_path.get(path) {
            return ino;
        }
        // Far away from file inodes (ROOT_INO + small counters) and
        // from 1 (root): count DOWN from u64::MAX/2.
        s.next_dir_ino += 1;
        let ino = DIR_INO_BASE - s.next_dir_ino;
        s.dir_by_path.insert(path.to_string(), ino);
        s.path_by_dir_ino.insert(ino, path.to_string());
        ino
    }

    /// Path of a directory inode, None for non-directories.
    fn dir_path(&self, ino: u64) -> Option<String> {
        self.0.lock().unwrap().path_by_dir_ino.get(&ino).cloned()
    }

    /// Resolve one lookup step under `prefix` ("" = root): a served
    /// file, an implicit directory, or nothing.
    fn child_of(&self, prefix: &str, name: &str) -> Option<Child> {
        let full = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let s = self.0.lock().unwrap();
        if s.by_name.contains_key(&full) {
            return Some(Child::File(s.by_name[&full]));
        }
        let is_dir = s
            .by_name
            .keys()
            .any(|n| n.len() > full.len() + 1 && n.starts_with(&full) && n.as_bytes()[full.len()] == b'/');
        drop(s);
        if is_dir {
            Some(Child::Dir(self.dir_ino(&full)))
        } else {
            None
        }
    }

    /// Entries of the directory at `prefix`: distinct next components
    /// with their kinds, sorted by name (readdir order stability).
    fn dir_children(&self, prefix: &str) -> Vec<(u64, bool, String)> {
        let s = self.0.lock().unwrap();
        // component -> (is_dir, file ino when !is_dir); collected
        // under the lock, dir inodes allocated after the release.
        let mut comps: std::collections::BTreeMap<String, (bool, Option<u64>)> =
            Default::default();
        for name in s.by_name.keys() {
            let rest = if prefix.is_empty() {
                name.as_str()
            } else if name.len() > prefix.len() + 1
                && name.starts_with(prefix)
                && name.as_bytes()[prefix.len()] == b'/'
            {
                &name[prefix.len() + 1..]
            } else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            match rest.find('/') {
                Some(i) => {
                    comps.insert(rest[..i].to_string(), (true, None));
                }
                None => {
                    comps.insert(rest.to_string(), (false, Some(s.by_name[name])));
                }
            }
        }
        let resolved: Vec<_> = comps.into_iter().map(|(c, v)| (c, v.0, v.1)).collect();
        drop(s);
        resolved
            .into_iter()
            .map(|(c, is_dir, file_ino)| {
                let full = if prefix.is_empty() {
                    c.clone()
                } else {
                    format!("{prefix}/{c}")
                };
                let ino = if is_dir { self.dir_ino(&full) } else { file_ino.unwrap() };
                (ino, is_dir, c)
            })
            .collect()
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

/// One resolved path component: a served file or an implicit
/// directory (issue #34 path-shaped names).
enum Child {
    File(u64),
    Dir(u64),
}

/// Implicit directory inodes count DOWN from here — far from file
/// inodes (small counters above ROOT_INO).
const DIR_INO_BASE: u64 = u64::MAX / 2;

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
        let prefix = if parent == ROOT_INO {
            String::new()
        } else {
            match self.store.dir_path(parent) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };
        let name = name.to_string_lossy();
        match self.store.child_of(&prefix, &name) {
            Some(Child::File(ino)) => {
                if let Some((_, c)) = self.store.lookup(ino) {
                    let attr =
                        self.file_attr(ino, c.bytes.len() as u64, req.uid(), req.gid(), c.mode);
                    reply.entry(&TTL, &attr, 0);
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Some(Child::Dir(ino)) => {
                reply.entry(&TTL, &self.dir_attr(ino, req.uid(), req.gid()), 0);
            }
            None => reply.error(libc::ENOENT),
        }
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
            None => {
                if self.store.dir_path(ino).is_some() {
                    reply.attr(&TTL, &self.dir_attr(ino, req.uid(), req.gid()));
                } else {
                    reply.error(libc::ENOENT);
                }
            }
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
        let prefix = if ino == ROOT_INO {
            String::new()
        } else {
            match self.store.dir_path(ino) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };
        // FUSE readdir contract: each entry carries the offset the NEXT
        // readdir call should start from — strictly increasing, never 0,
        // or the kernel re-reads from the start forever.
        let children = self.store.dir_children(&prefix);
        let all: Vec<(u64, FileType, String)> = vec![
            (ROOT_INO, FileType::Directory, ".".into()),
            (ROOT_INO, FileType::Directory, "..".into()),
        ]
        .into_iter()
        .chain(children.into_iter().map(|(i, is_dir, n)| {
            (i, if is_dir { FileType::Directory } else { FileType::RegularFile }, n)
        }))
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
/// Apply one oracle control line to the store. Returns whether the
/// line was understood. Unparsable lines are LOUD — silently dropping
/// them produced the PR #37 field report: an old fuse-server upserting
/// to a newer fused left an alive-but-empty mount with no diagnostic
/// anywhere.
fn apply_control_line(store: &Store, line: &str) -> bool {
    // The server's Hello ack ({"type":"ok"}) shares the stream with
    // commands — replies are not commands; consume silently.
    if serde_json::from_str::<OracleReply>(line.trim()).is_ok() {
        return false;
    }
    match serde_json::from_str::<OracleCommand>(line.trim()) {
        Ok(OracleCommand::Upsert { name, content, mode }) => {
            store.upsert(&name, content, mode);
            true
        }
        Ok(OracleCommand::Remove { name }) => {
            store.remove(&name);
            true
        }
        Err(e) => {
            warn!(
                "oracle control line not understood ({e}): {line:?} — version skew between \
                 fuse-server and fused? `cargo build --workspace` refreshes both"
            );
            false
        }
    }
}

pub fn run_control_loop(store: Store, oracle_socket: String) {
    loop {
        if let Ok(conn) = UnixStream::connect(&oracle_socket) {
            let mut reader = BufReader::new(conn.try_clone().expect("clone control conn"));
            let mut w = conn;
            if writeln!(w, "{}", serde_json::to_string(&OracleRequest::Hello {
                version: Some(fuse_protocol::VERSION.to_string()),
            }).unwrap()).is_err() {
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
                        apply_control_line(&store, &line);
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
    #[test]
    fn control_line_upsert_and_remove_apply() {
        let s = Store::default();
        assert!(apply_control_line(
            &s,
            r#"{"type":"upsert","name":"a","content":[104,105],"mode":420}"#
        ));
        let has = |s: &Store, n: &str| s.listing().iter().any(|(_, name, _, _)| name == n);
        assert!(has(&s, "a"), "upsert must land in the store");
        assert!(apply_control_line(&s, r#"{"type":"remove","name":"a"}"#));
        assert!(!has(&s, "a"), "remove must clear the store");
    }

    #[test]
    fn implicit_directories_materialize_from_path_names() {
        // Issue #34: names are normalized host paths; directories
        // derive from the components.
        let s = Store::default();
        s.upsert("home/u/auth.json", b"A".to_vec(), 0o400);
        s.upsert("home/u/keys/token", b"T".to_vec(), 0o400);
        s.upsert("other.txt", b"O".to_vec(), 0o400);

        let root = s.dir_children("");
        let names: Vec<&str> = root.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(names, ["home", "other.txt"], "root: one dir + one file");
        assert!(root[0].1, "home is a directory");
        assert!(!root[1].1, "other.txt is a file");

        let home = s.dir_children("home");
        assert_eq!(home.iter().map(|(_, _, n)| n.clone()).collect::<Vec<_>>(), ["u"]);
        let u = s.dir_children("home/u");
        let names: Vec<&str> = u.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(names, ["auth.json", "keys"], "mixed dir+file under u");

        // resolution matches the listing
        assert!(matches!(s.child_of("", "home"), Some(Child::Dir(_))));
        assert!(matches!(s.child_of("home/u", "auth.json"), Some(Child::File(_))));
        assert!(matches!(s.child_of("home/u/keys", "token"), Some(Child::File(_))));
        assert!(s.child_of("home", "auth.json").is_none(), "no such sibling");
    }

    #[test]
    fn directories_vanish_when_their_last_name_leaves() {
        let s = Store::default();
        s.upsert("a/b/c.txt", b"C".to_vec(), 0o400);
        assert!(matches!(s.child_of("a", "b"), Some(Child::Dir(_))));
        s.remove("a/b/c.txt");
        assert!(s.child_of("", "a").is_none(), "empty trees disappear");
    }

    #[test]
    fn control_line_replies_are_acks_not_garbage() {
        // The Hello ack shares the control stream with commands. It is
        // a REPLY — consuming it silently is correct; flagging it as a
        // parse failure would cry "version skew" on every healthy
        // connection (seen live while reproducing #39).
        let s = Store::default();
        assert!(!apply_control_line(&s, r#"{"type":"ok"}"#));
        let has = |s: &Store, n: &str| s.listing().iter().any(|(_, name, _, _)| name == n);
        assert!(!has(&s, "a"));
        // and a real command after an ack still applies
        assert!(apply_control_line(
            &s,
            r#"{"type":"upsert","name":"a","content":[104,105],"mode":420}"#
        ));
        assert!(has(&s, "a"));
    }

    #[test]
    fn control_line_upsert_without_mode_applies_default() {
        // Old policy daemons predate the mode field (see oracle.rs).
        let s = Store::default();
        assert!(apply_control_line(
            &s,
            r#"{"type":"upsert","name":"a","content":[1]}"#
        ));
        let has = |s: &Store| s.listing().iter().any(|(_, name, _, _)| name == "a");
        assert!(has(&s), "old-format upsert must NOT be dropped");
    }

    #[test]
    fn control_line_garbage_is_rejected_not_swallowed() {
        // The PR #37 failure mode: unparsable lines were silently
        // dropped, leaving an alive-but-empty mount. The handler must
        // report rejection so the caller (and the log) can surface it.
        let s = Store::default();
        apply_control_line(&s, r#"{"type":"upsert","name":"a","content":[1]}"#);
        assert!(!apply_control_line(&s, r#"{"type":"teleport","where":"mars"}"#));
        assert!(!apply_control_line(&s, "not json at all"));
        let has = |s: &Store| s.listing().iter().any(|(_, name, _, _)| name == "a");
        assert!(has(&s), "store must be untouched by garbage");
    }


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
