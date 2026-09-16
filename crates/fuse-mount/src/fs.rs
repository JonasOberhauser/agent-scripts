//! The data daemon's FUSE filesystem: content, metadata, and the
//! per-read delegation to the policy daemon.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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

// Directories are a DERIVED VIEW, not entities (review): the store
// keeps bookkeeping for files only — a directory is exactly "some
// served name lives under this path", its inode is DERIVED from the
// path (hash, top bit set: disjoint from the small file-inode
// counters), and it needs no lifecycle, no allocator, and no state
// that can drift from the name set.

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

    /// Inode of the implicit directory at `path` — a pure function of
    /// the path. Top bit set keeps it disjoint from file inodes
    /// (ROOT_INO + small counters).
    fn dir_ino(path: &Path) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut h);
        h.finish() | (1 << 63)
    }

    /// Every directory path currently implied by the served names —
    /// the PROPER prefixes of the flat name set (the names themselves
    /// are files), derived on demand.
    fn live_dir_paths(&self) -> Vec<PathBuf> {
        let s = self.0.lock().unwrap();
        let mut set = std::collections::BTreeSet::new();
        for name in s.by_name.keys() {
            let comps: Vec<_> = Path::new(name).components().collect();
            let mut p = PathBuf::new();
            for comp in comps.iter().take(comps.len().saturating_sub(1)) {
                p.push(comp);
                set.insert(p.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Path of a directory inode, None for non-directories. Derived:
    /// the (small) implied-prefix set is searched for the path that
    /// hashes to `ino` — no reverse map to maintain.
    fn dir_path(&self, ino: u64) -> Option<PathBuf> {
        self.live_dir_paths().into_iter().find(|p| Self::dir_ino(p) == ino)
    }

    /// Resolve one lookup step under `prefix` (empty = root): a served
    /// file, an implicit directory, or nothing. Component semantics
    /// come from the OS path library — `join` builds the child path,
    /// `strip_prefix` decides what lives under it.
    fn child_of(&self, prefix: &Path, name: &OsStr) -> Option<Child> {
        let full = prefix.join(name);
        let key = full.to_string_lossy().into_owned();
        let s = self.0.lock().unwrap();
        if let Some(&ino) = s.by_name.get(&key) {
            return Some(Child::File(ino));
        }
        // The directory exists iff some served name lives strictly
        // under it (a non-empty remainder after prefix stripping).
        let is_dir = s.by_name.keys().any(|n| {
            Path::new(n)
                .strip_prefix(&full)
                .is_ok_and(|rest| !rest.as_os_str().is_empty())
        });
        drop(s);
        if is_dir {
            Some(Child::Dir(Self::dir_ino(&full)))
        } else {
            None
        }
    }

    /// Entries of the directory at `prefix` (empty = root): distinct
    /// next components with their kinds, sorted by name (readdir order
    /// stability). Derived component-wise via the OS path library.
    fn dir_children(&self, prefix: &Path) -> Vec<(u64, bool, String)> {
        let s = self.0.lock().unwrap();
        // component -> (is_dir, file ino when !is_dir); collected
        // under the lock, dir inodes allocated after the release.
        let mut comps: std::collections::BTreeMap<String, (bool, Option<u64>)> =
            Default::default();
        for name in s.by_name.keys() {
            let Ok(rest) = Path::new(name).strip_prefix(prefix) else {
                continue;
            };
            let Some(first) = rest.components().next() else {
                continue;
            };
            let is_dir = rest.components().nth(1).is_some();
            let label = first.as_os_str().to_string_lossy().into_owned();
            if is_dir {
                comps.insert(label, (true, None));
            } else {
                comps.insert(label, (false, Some(s.by_name[name])));
            }
        }
        let resolved: Vec<_> = comps.into_iter().map(|(c, v)| (c, v.0, v.1)).collect();
        drop(s);
        resolved
            .into_iter()
            .map(|(c, is_dir, file_ino)| {
                let full = prefix.join(&c);
                let ino = if is_dir { Self::dir_ino(&full) } else { file_ino.unwrap() };
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
            PathBuf::new()
        } else {
            match self.store.dir_path(parent) {
                Some(p) => p,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };
        match self.store.child_of(&prefix, name) {
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
            PathBuf::new()
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


    #[test]
    fn dir_inode_is_a_pure_function_of_the_path() {
        // Review: directories are a derived view — no allocator state.
        // The inode is derived from the path (stable within the mount,
        // top bit set so it can never collide with the small file
        // inode counters).
        let a = Store::dir_ino(Path::new("home/u"));
        assert_eq!(a, Store::dir_ino(Path::new("home/u")));
        assert_ne!(a, Store::dir_ino(Path::new("home/v")));
        assert!(a & (1 << 63) != 0, "dir inodes live in the high range");
    }

    #[test]
    fn dir_paths_derive_from_the_served_name_set() {
        // The implied directory set is exactly the prefixes of the
        // served names — materializing on insert, vanishing on
        // remove, with no state of its own to drift.
        let s = Store::default();
        s.upsert("home/u/a.json", b"A".to_vec(), 0o400);
        s.upsert("home/u/keys/t.json", b"T".to_vec(), 0o400);
        assert_eq!(
            s.live_dir_paths(),
            vec![
                PathBuf::from("home"),
                PathBuf::from("home/u"),
                PathBuf::from("home/u/keys"),
            ]
        );
        s.remove("home/u/keys/t.json");
        assert_eq!(
            s.live_dir_paths(),
            vec![PathBuf::from("home"), PathBuf::from("home/u")]
        );
        // and every implied dir answers via its derived inode
        let u_ino = Store::dir_ino(Path::new("home/u"));
        assert_eq!(s.dir_path(u_ino), Some(PathBuf::from("home/u")));
        let gone = Store::dir_ino(Path::new("home/u/keys"));
        assert_eq!(s.dir_path(gone), None, "vanished with its last name");
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

        let root = s.dir_children(Path::new(""));
        let names: Vec<&str> = root.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(names, ["home", "other.txt"], "root: one dir + one file");
        assert!(root[0].1, "home is a directory");
        assert!(!root[1].1, "other.txt is a file");

        let home = s.dir_children(Path::new("home"));
        assert_eq!(home.iter().map(|(_, _, n)| n.clone()).collect::<Vec<_>>(), ["u"]);
        let u = s.dir_children(Path::new("home/u"));
        let names: Vec<&str> = u.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(names, ["auth.json", "keys"], "mixed dir+file under u");

        // resolution matches the listing
        assert!(matches!(s.child_of(Path::new(""), OsStr::new("home")), Some(Child::Dir(_))));
        assert!(matches!(s.child_of(Path::new("home/u"), OsStr::new("auth.json")), Some(Child::File(_))));
        assert!(matches!(s.child_of(Path::new("home/u/keys"), OsStr::new("token")), Some(Child::File(_))));
        assert!(s.child_of(Path::new("home"), OsStr::new("auth.json")).is_none(), "no such sibling");
    }

    #[test]
    fn directories_vanish_when_their_last_name_leaves() {
        let s = Store::default();
        s.upsert("a/b/c.txt", b"C".to_vec(), 0o400);
        assert!(matches!(s.child_of(Path::new("a"), OsStr::new("b")), Some(Child::Dir(_))));
        s.remove("a/b/c.txt");
        assert!(s.child_of(Path::new(""), OsStr::new("a")).is_none(), "empty trees disappear");
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
