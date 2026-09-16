//! The data daemon's FUSE filesystem: content, metadata, and the
//! per-read delegation to the policy daemon.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
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

/// One node of the mount tree: a served file (with its bytes) or an
/// implicit directory (with its children).
#[derive(Clone)]
enum Node {
    File(Content),
    Dir { children: std::collections::BTreeMap<String, u64> },
}

struct StoreInner {
    /// ONE increment-only counter for every node, files and
    /// directories alike.  The only invariants the FUSE ABI puts on
    /// inodes are: root is FUSE_ROOT_ID (1), live inodes identify at
    /// most one node each, and a number stays bound to its node while
    /// the kernel may still reference it.  A monotone counter satisfies
    /// all three trivially — numbers never repeat, so a path deleted
    /// and re-created gets a fresh inode and stale kernel references
    /// can never conflate nodes.
    next_ino: u64,
    by_path: HashMap<PathBuf, u64>,
    by_ino: HashMap<u64, (PathBuf, Node)>,
}

impl Default for StoreInner {
    fn default() -> Self {
        let mut s = Self {
            next_ino: ROOT_INO,
            by_path: HashMap::new(),
            by_ino: HashMap::new(),
        };
        s.by_path.insert(PathBuf::new(), ROOT_INO);
        s.by_ino.insert(
            ROOT_INO,
            (PathBuf::new(), Node::Dir { children: Default::default() }),
        );
        s
    }
}

/// Content store: the mount tree.  Files and directories are ordinary
/// entries in the same two maps and the same counter — no separate
/// machinery for either kind.
#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<StoreInner>>);

impl Store {
    pub fn upsert(&self, name: &str, bytes: Vec<u8>, mode: u32) {
        let mut s = self.0.lock().unwrap();
        let path = PathBuf::from(name);
        let comps: Vec<std::ffi::OsString> =
            path.components().map(|c| c.as_os_str().to_os_string()).collect();
        if comps.is_empty() {
            return;
        }
        // Walk (and materialize) the parent chain of implicit dirs.
        let mut prefix = PathBuf::new();
        let mut parent = ROOT_INO;
        for comp in comps.iter().take(comps.len() - 1) {
            prefix.push(comp);
            let existing = s.by_path.get(&prefix).copied();
            parent = match existing {
                Some(ino) => match &s.by_ino[&ino].1 {
                    Node::Dir { .. } => ino,
                    // A served FILE occupies the directory position —
                    // possible only via raw AddSecret with
                    // non-normalized names.  Fail safe: keep the
                    // shallower file, skip this name, say so.
                    Node::File(_) => {
                        warn!("cannot serve \"{name}\": \"{}\" is already a file",
                              prefix.display());
                        return;
                    }
                },
                None => {
                    s.next_ino += 1;
                    let ino = s.next_ino;
                    s.by_path.insert(prefix.clone(), ino);
                    s.by_ino.insert(
                        ino,
                        (prefix.clone(), Node::Dir { children: Default::default() }),
                    );
                    let Node::Dir { children } = &mut s.by_ino.get_mut(&parent).unwrap().1
                    else {
                        unreachable!("parent chain is directories by construction");
                    };
                    children.insert(comp.to_string_lossy().into_owned(), ino);
                    ino
                }
            };
        }
        let file_label = comps.last().unwrap().to_string_lossy().into_owned();
        match s.by_path.get(&path).copied() {
            Some(ino) => {
                // Live path: replace the content, KEEP the inode —
                // open fds and kernel caches stay coherent.
                s.by_ino.get_mut(&ino).unwrap().1 = Node::File(Content { bytes, mode });
            }
            None => {
                s.next_ino += 1;
                let ino = s.next_ino;
                s.by_path.insert(path.clone(), ino);
                s.by_ino.insert(ino, (path, Node::File(Content { bytes, mode })));
                let Node::Dir { children } = &mut s.by_ino.get_mut(&parent).unwrap().1
                else {
                    unreachable!("parent chain is directories by construction");
                };
                children.insert(file_label, ino);
            }
        }
    }

    pub fn remove(&self, name: &str) {
        let mut s = self.0.lock().unwrap();
        let path = PathBuf::from(name);
        let Some(ino) = s.by_path.get(&path).copied() else {
            return;
        };
        if !matches!(s.by_ino[&ino].1, Node::File(_)) {
            return;
        }
        let mut child_label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        s.by_path.remove(&path);
        s.by_ino.remove(&ino);
        // Unlink from the parent, then prune childless ancestors so
        // implicit directories vanish with their last name.
        let mut parent_path = path;
        loop {
            if !parent_path.pop() {
                break;
            }
            let Some(pino) = s.by_path.get(&parent_path).copied() else {
                break;
            };
            let now_empty = {
                let Node::Dir { children } = &mut s.by_ino.get_mut(&pino).unwrap().1 else {
                    break;
                };
                children.remove(&child_label);
                children.is_empty() && pino != ROOT_INO
            };
            if !now_empty {
                break;
            }
            s.by_path.remove(&parent_path);
            s.by_ino.remove(&pino);
            child_label = parent_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
        }
    }

    /// One lookup step: the child of directory `parent` named `name`,
    /// as (inode, is_dir).  O(1) — the parent's children map knows.
    fn child(&self, parent: u64, name: &OsStr) -> Option<(u64, bool)> {
        let s = self.0.lock().unwrap();
        let Node::Dir { children } = &s.by_ino.get(&parent)?.1 else {
            return None;
        };
        let &ino = children.get(&name.to_string_lossy().into_owned())?;
        let is_dir = matches!(s.by_ino.get(&ino)?.1, Node::Dir { .. });
        Some((ino, is_dir))
    }

    /// Entries of a directory for readdir: (inode, is_dir, name) in
    /// BTreeMap order (readdir order stability).
    fn dir_children(&self, dir: u64) -> Option<Vec<(u64, bool, String)>> {
        let s = self.0.lock().unwrap();
        let Node::Dir { children } = &s.by_ino.get(&dir)?.1 else {
            return None;
        };
        Some(
            children
                .iter()
                .map(|(name, &ino)| {
                    let is_dir = matches!(s.by_ino[&ino].1, Node::Dir { .. });
                    (ino, is_dir, name.clone())
                })
                .collect(),
        )
    }

    fn is_dir(&self, ino: u64) -> bool {
        matches!(
            self.0.lock().unwrap().by_ino.get(&ino).map(|(_, n)| n),
            Some(Node::Dir { .. })
        )
    }

    /// The parent directory of `ino` (None for root / unknown).
    fn parent_of(&self, ino: u64) -> Option<u64> {
        let s = self.0.lock().unwrap();
        let (path, node) = s.by_ino.get(&ino)?;
        if !matches!(node, Node::Dir { .. }) || path.as_os_str().is_empty() {
            return None;
        }
        let mut parent = path.clone();
        parent.pop();
        s.by_path.get(&parent).copied()
    }

    /// A served file by inode: its full (path-shaped) name for policy
    /// asks, and its content.
    fn file(&self, ino: u64) -> Option<(String, Content)> {
        let s = self.0.lock().unwrap();
        let (path, node) = s.by_ino.get(&ino)?;
        match node {
            Node::File(c) => Some((path.to_string_lossy().into_owned(), c.clone())),
            Node::Dir { .. } => None,
        }
    }

    /// Every served FILE as (inode, full name, mode, size) — sorted by
    /// name.  Directories are not listed.
    fn listing(&self) -> Vec<(u64, String, u32, usize)> {
        let s = self.0.lock().unwrap();
        let mut v: Vec<_> = s
            .by_ino
            .iter()
            .filter_map(|(ino, (path, node))| match node {
                Node::File(c) => Some((
                    *ino,
                    path.to_string_lossy().into_owned(),
                    c.mode,
                    c.bytes.len(),
                )),
                Node::Dir { .. } => None,
            })
            .collect();
        v.sort_by(|a, b| a.1.cmp(&b.1));
        v
    }

    fn read(&self, ino: u64, offset: usize, size: usize) -> Option<Vec<u8>> {
        let (_, c) = self.file(ino)?;
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
        match self.store.child(parent, name) {
            Some((ino, false)) => {
                if let Some((_, c)) = self.store.file(ino) {
                    let attr =
                        self.file_attr(ino, c.bytes.len() as u64, req.uid(), req.gid(), c.mode);
                    reply.entry(&TTL, &attr, 0);
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Some((ino, true)) => {
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
        if let Some((_, c)) = self.store.file(ino) {
            let attr = self.file_attr(ino, c.bytes.len() as u64, req.uid(), req.gid(), c.mode);
            reply.attr(&TTL, &attr);
        } else if self.store.is_dir(ino) {
            reply.attr(&TTL, &self.dir_attr(ino, req.uid(), req.gid()));
        } else {
            reply.error(libc::ENOENT);
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
        let Some((name, _)) = self.store.file(ino) else {
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
        // FUSE readdir contract: each entry carries the offset the NEXT
        // readdir call should start from — strictly increasing, never 0,
        // or the kernel re-reads from the start forever.
        let Some(children) = self.store.dir_children(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let dot_ino = ino;
        let dotdot_ino = self.store.parent_of(ino).unwrap_or(ino);
        let all: Vec<(u64, FileType, String)> = vec![
            (dot_ino, FileType::Directory, ".".into()),
            (dotdot_ino, FileType::Directory, "..".into()),
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
    use super::*;

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
        // derive from the components. Lookup goes parent-ino ->
        // children map: one step per component, exactly like the
        // kernel walks.
        let s = Store::default();
        s.upsert("home/u/auth.json", b"A".to_vec(), 0o400);
        s.upsert("home/u/keys/token", b"T".to_vec(), 0o400);
        s.upsert("other.txt", b"O".to_vec(), 0o400);

        let root = s.dir_children(ROOT_INO).unwrap();
        let names: Vec<&str> = root.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(names, ["home", "other.txt"], "root: one dir + one file");
        assert!(root[0].1, "home is a directory");
        assert!(!root[1].1, "other.txt is a file");

        let home = s.child(ROOT_INO, OsStr::new("home")).unwrap();
        assert!(home.1);
        let u = s.child(home.0, OsStr::new("u")).unwrap();
        let u_children = s.dir_children(u.0).unwrap();
        let names: Vec<&str> = u_children.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(names, ["auth.json", "keys"], "mixed dir+file under u");

        // resolution matches the listing
        let auth = s.child(u.0, OsStr::new("auth.json")).unwrap();
        assert!(!auth.1);
        let keys = s.child(u.0, OsStr::new("keys")).unwrap();
        assert!(keys.1);
        assert!(s.child(keys.0, OsStr::new("token")).is_some());
        assert!(s.child(home.0, OsStr::new("auth.json")).is_none(), "no such sibling");
        // the file answers by inode with its full path-shaped name
        let (name, c) = s.file(auth.0).unwrap();
        assert_eq!(name, "home/u/auth.json");
        assert_eq!(c.bytes, b"A".to_vec());
        // and the dir reports its parent
        assert_eq!(s.parent_of(u.0), Some(home.0));
    }

    #[test]
    fn directories_vanish_when_their_last_name_leaves() {
        let s = Store::default();
        s.upsert("a/b/c.txt", b"C".to_vec(), 0o400);
        let a = s.child(ROOT_INO, OsStr::new("a")).unwrap();
        assert!(s.child(a.0, OsStr::new("b")).is_some());
        s.remove("a/b/c.txt");
        assert!(s.child(ROOT_INO, OsStr::new("a")).is_none(), "empty trees disappear");
    }

    #[test]
    fn recreated_paths_get_fresh_inodes_and_live_ones_stay_unique() {
        // The FUSE inode contract: live numbers identify at most one
        // node each; a deleted-and-recreated path is a NEW node and
        // must get a NEW number (the counter never repeats, so stale
        // kernel references can never conflate nodes).
        let s = Store::default();
        s.upsert("k/a.txt", b"1".to_vec(), 0o400);
        let k1 = s.child(ROOT_INO, OsStr::new("k")).unwrap();
        let a1 = s.child(k1.0, OsStr::new("a.txt")).unwrap();
        s.remove("k/a.txt");
        s.upsert("k/a.txt", b"2".to_vec(), 0o400);
        let k2 = s.child(ROOT_INO, OsStr::new("k")).unwrap();
        let a2 = s.child(k2.0, OsStr::new("a.txt")).unwrap();
        assert_ne!(a1.0, a2.0, "recreated file: fresh inode");
        assert_ne!(k1.0, k2.0, "recreated (pruned + re-materialized) dir: fresh inode");

        // live uniqueness across files and directories alike:
        // listing() covers every live file, the vec adds the dirs
        s.upsert("k/b.txt", b"3".to_vec(), 0o400);
        let mut live: Vec<u64> = vec![ROOT_INO, k2.0];
        live.extend(s.listing().iter().map(|(ino, _, _, _)| *ino));
        let mut sorted = live.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(live.len(), sorted.len(), "every live inode is distinct");
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

    fn root_file(name: &str, bytes: &[u8], mode: u32) -> (Store, u64) {
        let s = Store::default();
        s.upsert(name, bytes.to_vec(), mode);
        let ino = s.child(ROOT_INO, OsStr::new(name)).expect("served").0;
        (s, ino)
    }

    #[test]
    fn replace_keeps_the_inode_of_a_live_file() {
        let (s, ino1) = root_file("a", b"one", 0o400);
        s.upsert("a", b"longer bytes".to_vec(), 0o400);
        let ino2 = s.child(ROOT_INO, OsStr::new("a")).expect("still served").0;
        assert_eq!(ino1, ino2, "replacement keeps the inode (open fds keep reading)");
        assert_eq!(s.read(ino1, 0, 64).unwrap(), b"longer bytes");
    }

    #[test]
    fn remove_makes_the_inode_unreachable() {
        let (s, ino) = root_file("a", b"x", 0o400);
        s.remove("a");
        assert!(s.file(ino).is_none());
        assert!(s.child(ROOT_INO, OsStr::new("a")).is_none());
    }

    #[test]
    fn read_clamps_offset_and_size() {
        let (s, ino) = root_file("a", b"0123456789", 0o400);
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
                format!("{}
", serde_json::to_string(&OracleReply::Allow).unwrap()).as_bytes(),
            )
            .unwrap();
        });
        let reply = ask_policy(p2.to_str().unwrap(), "s.yaml", 7, 1, 4).unwrap();
        assert_eq!(reply, OracleReply::Allow);
        server.join().unwrap();
    }
}
