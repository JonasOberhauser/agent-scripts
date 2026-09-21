//! The data daemon's FUSE filesystem (MR4 transparent reads): a
//! frozen, name-keyed tree of served secrets whose file identities
//! follow host incarnations, and content that exists only as host fds
//! handed over by the policy daemon at (adjudicated) open time.
//!
//! Identity model (issue #34 MR4):
//!   path → { current fino | children }   frozen tree; names are the
//!                                        identities policy keys
//!   fino → { kdev, kino, path }          change-detection state +
//!                                        by-ino address; allocated
//!                                        from a counter, refreshed
//!                                        when the host incarnation
//!                                        changes (ESTALE the old)
//!   fh   = fd                            the kernel fd table IS the
//!                                        map: open hands an fd via
//!                                        SCM_RIGHTS, reads pread it,
//!                                        release closes it. No
//!                                        snapshot bytes anywhere.

use std::collections::{BTreeMap, HashMap};
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

/// The fuse inode number (review: newtype pattern). Opaque to the
/// kernel and to the container — only ever minted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FuseIno(u64);

impl FuseIno {
    const ROOT: FuseIno = FuseIno(1);
}

const TTL: Duration = Duration::from_secs(1);

/// One frozen-tree node. Files carry their CURRENT fuse inode and the
/// mode fallback Serve brought; directories are pure structure (the
/// host listing is never consulted — no scouring).
enum Node {
    File {
        fino: FuseIno,
        mode: u32,
    },
    Dir {
        /// Child labels keyed by the OUTER (host) name.
        children: BTreeMap<String, ()>,
        /// Issue #47: the outer<->inner label bijection (review on
        /// #58: an off-the-shelf bimap, not two hand-rolled maps).
        /// Only the ROOT's map is consulted — the container view is
        /// flat.
        labels: bimap::BiBTreeMap<String, String>,
    },
}

/// The HOST identity a fuse inode was minted for (review: the struct
/// is the identity record, not the ino — the ino is the KEY): the
/// (device, inode) pair observed when it was minted, kept only to
/// DETECT incarnation change (stat now, compare), plus the path any
/// by-ino request needs as its address.
#[derive(Clone)]
struct FinoRecord {
    /// The host identity observed when this fino was minted, if any:
    /// a ghost (Serve without identity) has NONE — absence is Option,
    /// never an in-band (0,0) sentinel — until the first
    /// stat-on-lookup discovers one and mints a fresh fino.
    identity: Option<fuse_protocol::oracle::HostIdentity>,
    path: PathBuf,
}

struct StoreInner {
    /// ONE increment-only counter for every node. The only invariants
    /// the FUSE ABI puts on inodes are: root is FUSE_ROOT_ID, live
    /// inodes identify at most one node each, and a number stays bound
    /// to its node while the kernel may still reference it. A monotone
    /// counter satisfies all three trivially.
    next_fino: u64,
    /// The frozen tree, keyed by outer path ("" = root).
    tree: BTreeMap<PathBuf, Node>,
    identities: HashMap<FuseIno, FinoRecord>,
}

impl Default for StoreInner {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreInner {
    fn new() -> Self {
        Self {
            next_fino: FuseIno::ROOT.0,
            tree: BTreeMap::from([(
                PathBuf::new(),
                Node::Dir {
                    children: BTreeMap::new(),
                    labels: bimap::BiBTreeMap::new(),
                },
            )]),
            identities: HashMap::new(),
        }
    }
}

/// Mint a fresh fino for `path` with the observed host identity.
/// Numbers never repeat; a replaced incarnation gets a NEW number and
/// the old one keeps its entry (so by-ino access can distinguish
/// STALE from never-existed).
fn mint_fino(
    s: &mut StoreInner,
    path: &Path,
    identity: Option<fuse_protocol::oracle::HostIdentity>,
) -> FuseIno {
    s.next_fino += 1;
    let fino = FuseIno(s.next_fino);
    debug_assert!(
        !s.identities.contains_key(&fino),
        "fino {:?} already exists",
        fino
    );
    s.identities.insert(
        fino,
        FinoRecord { identity, path: path.to_path_buf() },
    );
    fino
}

#[derive(Clone, Default)]
pub struct Store(Arc<Mutex<StoreInner>>);

impl Store {
    /// A secret enters the frozen tree (MR4 Serve): no content — the
    /// current fino follows the host identity, allocating a fresh one
    /// when the incarnation changed since last Serve/stat.
    pub fn serve(&self, name: &str, inner: &str, mode: u32) {
        let mut s = self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug");
        let path = PathBuf::from(name);
        let comps: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .filter(|c| !c.is_empty())
            .collect();
        if comps.is_empty() {
            return;
        }
        // The TREE stays outer-keyed (policy and display speak outer;
        // the identity machinery walks outer paths). The CONTAINER
        // view is FLAT (review on #58): one directory, whole-path
        // hash labels — no shape to parallel, no per-level bijection,
        // no depth/fan-out leaking host layout.
        let mut prefix = PathBuf::new();
        for comp in comps.iter().take(comps.len() - 1) {
            match s.tree.get_mut(&prefix) {
                Some(Node::Dir { children, .. }) => {
                    children.insert(comp.clone(), ());
                }
                Some(Node::File { .. }) => {
                    warn!("cannot serve \"{name}\": \"{}\" is already a file", prefix.display());
                    return;
                }
                None => unreachable!("parent chain is directories by construction"),
            }
            prefix.push(comp);
            match s.tree.get(&prefix) {
                Some(Node::Dir { .. }) => {}
                Some(Node::File { .. }) => {
                    warn!("cannot serve \"{name}\": \"{}\" is already a file", prefix.display());
                    return;
                }
                None => {
                    s.tree.insert(
                        prefix.clone(),
                        Node::Dir {
                            children: BTreeMap::new(),
                            labels: bimap::BiBTreeMap::new(),
                        },
                    );
                }
            }
        }
        match s.tree.get(&path) {
            // Structure only: refresh the mode, leave the fino alone —
            // incarnation change is discovered LAZILY by the next
            // stat (lookup is authoritative; open verifies against the
            // recorded identity regardless).
            Some(Node::File { .. }) => {
                let Node::File { mode: m, .. } = s
                    .tree
                    .get_mut(&path)
                    .expect("checked File in the match arm directly above")
                else {
                    unreachable!("checked File above");
                };
                *m = mode;
            }
            Some(Node::Dir { .. }) => {
                // A directory already occupies the file's path (e.g.
                // "a/b" served, then "a"): refuse loudly, keep the
                // deeper structure — NEVER panic (review blocker on
                // #57: a data-daemon crash kills the mount).
                warn!("cannot serve \"{name}\": a directory already occupies that path");
                return;
            }
            None => {
                let fino = mint_fino(&mut s, &path, None);
                s.tree.insert(path.clone(), Node::File { fino, mode });
            }
        }
        // Flat container label: link the whole-path hash into the
        // ROOT's bijection — the only place inner names resolve.
        let last = &comps[comps.len() - 1];
        if let Some(Node::Dir { children, .. }) = s.tree.get_mut(&prefix) {
            children.insert(last.clone(), ());
        }
        if let Some(Node::Dir { labels, .. }) = s.tree.get_mut(Path::new("")) {
            let outer_full = comps.join("/");
            // A bimap is bijective by construction: insert removes the
            // previous pairing on BOTH sides (relabel is a rename),
            // and a conflicting inner label would evict the old
            // outer's binding — so check the collision FIRST, refuse.
            if let Some(existing_outer) = labels.get_by_right(inner) {
                if existing_outer != &outer_full {
                    warn!(
                        "anonymized label \"{inner}\" collides between \"{existing_outer}\" and \
                         \"{outer_full}\" — refusing the second name (never alias two secrets)"
                    );
                    return;
                }
            }
            labels.remove_by_left(&outer_full);
            labels.insert(outer_full, inner.to_string());
        }
    }

    /// Remove a secret: prune the tree node and its fino entry, then
    /// childless structural ancestors vanish with it.
    pub fn remove(&self, name: &str) {
        let mut s = self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug");
        let mut path = PathBuf::from(name);
        if !matches!(s.tree.get(&path), Some(Node::File { .. })) {
            return;
        }
        if let Some(Node::File { fino, .. }) = s.tree.remove(&path) {
            s.identities.remove(&fino);
        }
        while let Some(label) = path.file_name().map(|n| n.to_string_lossy().into_owned()) {
            if !path.pop() {
                break;
            }
            let now_empty = {
                let Some(Node::Dir { children, labels }) = s.tree.get_mut(&path) else {
                    break;
                };
                labels.remove_by_left(&label);
                children.remove(&label);
                children.is_empty() && !path.as_os_str().is_empty()
            };
            if !now_empty {
                break;
            }
            if let Some(Node::Dir { .. }) = s.tree.remove(&path) {
                // structural dirs hold no fino
            }
        }
    }

    /// Resolve one lookup step under `parent` (FuseIno::ROOT = root).
    fn child(&self, parent: FuseIno, label: &OsStr) -> Option<(FuseIno, bool)> {
        // FLAT container view: only the ROOT has inner-labeled
        // children (one whole-path hash per secret). Nested lookups
        // do not exist — the mount is a single directory.
        if parent != FuseIno::ROOT {
            return None;
        }
        let label = label.to_string_lossy().into_owned();
        let s = self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug");
        let Node::Dir { labels, .. } = s.tree.get(Path::new(""))? else {
            return None;
        };
        let outer_full = labels.get_by_right(&label)?;
        let ino = match s.tree.get(Path::new(outer_full.as_str()))? {
            Node::File { fino, .. } => *fino,
            _ => return None,
        };
        Some((ino, false))
    }

    /// The fino table entry (identity + address) for by-ino requests.
    fn fino_record(&self, ino: FuseIno) -> Option<FinoRecord> {
        self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug").identities.get(&ino).cloned()
    }

    /// Observe a fresh host identity for a path (from Stat at
    /// lookup/getattr): same incarnation keeps the fino; a changed one
    /// mints a new number (the caller then answers ESTALE for the old
    /// ino and the new number for fresh lookups).
    fn observe(
        &self,
        path: &Path,
        identity: fuse_protocol::oracle::HostIdentity,
    ) -> Option<FuseIno> {
        let mut s = self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug");
        let current = match s.tree.get(path)? {
            Node::File { fino, .. } => *fino,
            _ => return None,
        };
        if s.identities.get(&current)?.identity == Some(identity) {
            return Some(current);
        }
        let nf = mint_fino(&mut s, path, Some(identity));
        let Node::File { fino, .. } = s.tree.get_mut(path)? else {
            return None;
        };
        *fino = nf;
        Some(nf)
    }

    /// The Serve-time mode fallback for a file path.
    fn mode_of(&self, path: &Path) -> Option<u32> {
        match self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug").tree.get(path)? {
            Node::File { mode, .. } => Some(*mode),
            _ => None,
        }
    }

    /// Directory listing for readdir: (fino, is_dir, label) sorted.
    /// Dir children get their fino minted on demand — a freshly
    /// served tree must list completely without prior lookups.
    fn dir_children(&self, _dir: FuseIno) -> Option<Vec<(FuseIno, bool, String)>> {
        let s = self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug");
        let Node::Dir { labels, .. } = s.tree.get(Path::new(""))? else {
            return None;
        };
        let mut out = Vec::new();
        for (outer_full, inner) in labels.iter() {
            if let Some(Node::File { fino, .. }) = s.tree.get(Path::new(outer_full.as_str())) {
                out.push((*fino, false, inner.clone()));
            }
        }
        out.sort_by(|a, b| a.2.cmp(&b.2));
        Some(out)
    }


    /// Parent directory ino for readdir's `..`.
    fn parent_of(&self, ino: FuseIno) -> Option<FuseIno> {
        if ino == FuseIno::ROOT {
            return Some(FuseIno::ROOT);
        }
        let s = self.0.lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug");
        let path = &s.identities.get(&ino)?.path;
        let mut parent = path.clone();
        parent.pop();
        if parent.as_os_str().is_empty() {
            return Some(FuseIno::ROOT);
        }
        if let Some(Node::File { .. }) = s.tree.get(&parent) {
            return None;
        }
        // a dir's parent is a dir: reuse its fino if minted
        s.identities
            .iter()
            .find(|(_, id)| id.path == parent)
            .map(|(fino, _)| *fino)
            .or(Some(FuseIno::ROOT))
    }

    /// Count of served files (statfs).
    fn file_count(&self) -> usize {
        self.0
            .lock()
            .expect("store lock: never held across a panic — poisoning means a data-daemon bug")
            .tree
            .values()
            .filter(|n| matches!(n, Node::File { .. }))
            .count()
    }
}

// ── oracle clients ──────────────────────────────────────────────

fn send_line(sock: &str, line: &str) -> Result<UnixStream, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| e.to_string())?;
    writeln!(s, "{line}").map_err(|e| e.to_string())?;
    s.flush().map_err(|e| e.to_string())?;
    Ok(s)
}

/// Stat a secret by name: live identity + attrs, no adjudication.
pub fn stat_secret(socket: &str, name: &str) -> Result<OracleReply, String> {
    let s = send_line(
        socket,
        &serde_json::to_string(&OracleRequest::Stat { name: name.into() })
            .expect("serializing Stat: internal enum, infallible"),
    )?;
    // Metadata has no pending machinery to wait out — bound it tight.
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    let mut r = BufReader::new(s);
    r.read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

/// How long an open may wait for the policy daemon's reply.  Pendings
/// legitimately block an open for human-scale times (until grant or
/// expiry), so this is deliberately generous — but finite: a reply
/// that never comes (server thread died between reading the request
/// and answering, fd pass failed silently) must hang the reader no
/// longer than this, then surface as EIO.  Mirrors the 3600 s the
/// pre-MR4 `ask` path used.
const OPEN_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// Adjudicated open: on Allow the reply line arrives with the host fd
/// as SCM_RIGHTS ancillary data — returned as an owned descriptor.
pub fn open_secret(
    socket: &str,
    name: &str,
    pid: u32,
    kdev: fuse_protocol::oracle::KDev,
    kino: fuse_protocol::oracle::Kino,
) -> Result<(OracleReply, Option<std::os::fd::OwnedFd>), String> {
    open_secret_timeout(socket, name, pid, kdev, kino, OPEN_REPLY_TIMEOUT)
}

/// The test seam for [`open_secret`]: an explicit reply deadline.
fn open_secret_timeout(
    socket: &str,
    name: &str,
    pid: u32,
    kdev: fuse_protocol::oracle::KDev,
    kino: fuse_protocol::oracle::Kino,
    timeout: std::time::Duration,
) -> Result<(OracleReply, Option<std::os::fd::OwnedFd>), String> {
    use std::os::fd::OwnedFd;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let s = send_line(
        socket,
        &serde_json::to_string(&OracleRequest::Open { name: name.into(), pid, kdev, kino })
            .expect("serializing Open: internal enum, infallible"),
    )?;
    s.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 4096];
    let mut cmsg_buf = nix::cmsg_space!(libc::cmsghdr, std::os::unix::io::RawFd);
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    // SAFETY: recvmsg writes into the provided buffers only; the
    // kernel places received descriptors into duplicated fds.
    let msg =
        nix::sys::socket::recvmsg::<()>(s.as_raw_fd(), &mut iov, Some(&mut cmsg_buf), nix::sys::socket::MsgFlags::empty())
            .map_err(|e| e.to_string())?;
    let mut fd = None;
    let cmsgs = msg.cmsgs().map_err(|e| e.to_string())?;
    for c in cmsgs {
        if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = c {
            if let Some(&raw) = fds.first() {
                // SAFETY: the kernel created this descriptor for us in
                // recvmsg; taking ownership is the correct transfer.
                fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
    }
    let n = msg.bytes;
    let line = String::from_utf8_lossy(&buf[..n]).into_owned();
    let reply: OracleReply = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    Ok((reply, fd))
}

// ── filesystem ──────────────────────────────────────────────────

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
        let Some((fino, is_dir)) = self.store.child(FuseIno(parent), name) else {
            tracing::info!("lookup {:?}: no such tree child", name);
            reply.error(libc::ENOENT);
            return;
        };
        if is_dir {
            reply.entry(&TTL, &self.dir_attr(fino.0, req.uid(), req.gid()), 0);
            return;
        }
        // Files: live stat decides identity AND attrs.
        let Some(id) = self.store.fino_record(fino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let name = id.path.to_string_lossy().into_owned();
        match stat_secret(&self.oracle, &name) {
            Ok(OracleReply::StatOk { kdev, kino, size, mode, regular: true }) => {
                // Keep the fino for the same incarnation; a changed
                // host file mints a new number — fresh lookups (like
                // this one) answer the NEW identity.
                let observed =
                    fuse_protocol::oracle::HostIdentity { kdev, kino };
                tracing::info!(
                    "lookup {:?}: stat ok {:?} size={size} mode={mode:o} (recorded {:?})",
                    name, observed, id.identity
                );
                if let Some(nf) = self.store.observe(&id.path, observed) {
                    let attr = self.file_attr(nf.0, size, req.uid(), req.gid(), mode);
                    reply.entry(&TTL, &attr, 0);
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Ok(other) => {
                tracing::info!("lookup {:?}: stat said {other:?}", name);
                reply.error(libc::ENOENT);
            }
            Err(e) => {
                // Server unreachable: attrs cannot be fabricated —
                // fail loudly rather than serve stale metadata.
                warn!("lookup stat failed for {name}: {e}");
                reply.error(libc::EIO);
            }
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        if ino == FuseIno::ROOT.0 {
            reply.attr(&TTL, &self.dir_attr(ino, req.uid(), req.gid()));
            return;
        }
        let Some(id) = self.store.fino_record(FuseIno(ino)) else {
            reply.error(libc::ENOENT);
            return;
        };
        if self.store.mode_of(&id.path).is_some() {
            // A file. fstat after open is authoritative: the fd pins
            // its own incarnation.
            if let Some(fh) = fh {
                // SAFETY: fstat writes into the provided zeroed struct.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: fh is a live descriptor this daemon issued.
                if unsafe { libc::fstat(fh as i32, &mut st) } == 0 {
                    let attr = self.file_attr(
                        ino,
                        st.st_size as u64,
                        req.uid(),
                        req.gid(),
                        (st.st_mode & 0o777) as u32,
                    );
                    reply.attr(&TTL, &attr);
                    return;
                }
            }
            // Path stat: live attrs + incarnation check.
            let name = id.path.to_string_lossy().into_owned();
            match stat_secret(&self.oracle, &name) {
                Ok(OracleReply::StatOk { kdev, kino, size, mode, regular: true }) => {
                    let observed =
                        fuse_protocol::oracle::HostIdentity { kdev, kino };
                    if id.identity != Some(observed) {
                        // The file this ino was minted for is gone (or
                        // never known — a ghost): ESTALE re-resolves,
                        // and lookup's stat mints the real identity.
                        reply.error(libc::ESTALE);
                        return;
                    }
                    let attr = self.file_attr(ino, size, req.uid(), req.gid(), mode);
                    reply.attr(&TTL, &attr);
                }
                Ok(OracleReply::Gone | OracleReply::Stale) => reply.error(libc::ESTALE),
                Ok(_) => reply.error(libc::ENOENT),
                Err(_) => reply.error(libc::EIO),
            }
        } else {
            reply.attr(&TTL, &self.dir_attr(ino, req.uid(), req.gid()));
        }
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        // Read-only mount.
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            reply.error(libc::EACCES);
            return;
        }
        let Some(id) = self.store.fino_record(FuseIno(ino)) else {
            reply.error(libc::ENOENT);
            return;
        };
        if self.store.mode_of(&id.path).is_none() {
            reply.error(libc::EISDIR);
            return;
        }
        let name = id.path.to_string_lossy().into_owned();
        tracing::info!(
            "open {name}: ino={ino} pid={} recorded {:?}",
            req.pid(), id.identity
        );
        let Some(identity) = id.identity else {
            // A ghost fino (served without identity, never stat'ed):
            // the kernel skipped lookup via the dcache. Force the
            // re-resolve — the lookup stat will mint a real identity.
            reply.error(libc::ESTALE);
            return;
        };
        match open_secret(&self.oracle, &name, req.pid(), identity.kdev, identity.kino) {
            Ok((OracleReply::Allow, Some(fd))) => {
                use std::os::fd::AsRawFd;
                // fh = the fd number: the kernel fd table is the map.
                reply.opened(fd.as_raw_fd() as u64, fuser::consts::FOPEN_DIRECT_IO);
                // Intentionally NOT dropped: the fd's lifetime is the
                // fh's lifetime; RELEASE closes it.
                std::mem::forget(fd);
            }
            Ok((OracleReply::Allow, None)) => reply.error(libc::EIO),
            Ok((OracleReply::Deny { errno, .. }, _)) => reply.error(errno),
            Ok((OracleReply::Stale, _)) => reply.error(libc::ESTALE),
            Ok((OracleReply::Gone, _)) => reply.error(libc::ENOENT),
            Ok((other, _)) => {
                warn!("open {name}: unexpected reply {other:?}");
                reply.error(libc::EIO);
            }
            Err(e) => {
                warn!("open {name}: oracle transport failed: {e}");
                reply.error(libc::EIO);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        // fh IS the host fd: pread it. Fills exactly `size` bytes
        // except at EOF (the kernel substitutes zeroes otherwise).
        let mut out = vec![0u8; size as usize];
        let mut filled = 0usize;
        while filled < size as usize {
            // SAFETY: pread writes only into the remaining slice.
            let n = unsafe {
                libc::pread(
                    fh as i32,
                    out[filled..].as_mut_ptr() as *mut libc::c_void,
                    size as usize - filled,
                    offset + filled as i64,
                )
            };
            if n < 0 {
                reply.error(libc::EIO);
                return;
            }
            if n == 0 {
                break; // EOF
            }
            filled += n as usize;
        }
        out.truncate(filled);
        reply.data(&out);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // The kernel never uses an fh after RELEASE: closing the fd is
        // safe and its number may be recycled by a future open.
        // SAFETY: fh was issued by our open as a live fd.
        unsafe { libc::close(fh as i32) };
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(children) = self.store.dir_children(FuseIno(ino)) else {
            reply.error(libc::ENOENT);
            return;
        };
        let parent = self.store.parent_of(FuseIno(ino)).unwrap_or(FuseIno::ROOT);
        let all: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".into()),
            (parent.0, FileType::Directory, "..".into()),
        ]
        .into_iter()
        .chain(children.into_iter().map(|(i, d, n)| {
            (i.0, if d { FileType::Directory } else { FileType::RegularFile }, n)
        }))
        .collect();
        for (idx, (e_ino, kind, name)) in all.into_iter().enumerate() {
            let next_offset = (idx + 1) as i64;
            if (idx as i64) < offset {
                continue;
            }
            if reply.add(e_ino, next_offset, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        // Content sizes are live at open (no snapshots); only the
        // served-file count is known statically.
        let files = self.store.file_count() as u64 + 1;
        reply.statfs(1_000_000, 1_000_000, 1_000_000, files, 1_000_000, 512, 255, 512);
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

/// Apply one oracle control line to the store. Returns whether the
/// line was understood. Unparsable lines are LOUD — silently dropping
/// them produced the PR #37 field report: an old fuse-server upserting
/// to a newer fused left an alive-but-empty mount with no diagnostic
/// anywhere.
fn apply_control_line(store: &Store, line: &str) -> bool {
    // The Hello ack ({"type":"ok"}) shares the control stream with
    // commands — replies are not commands; consuming silently is
    // correct; flagging it as a parse failure would cry "version
    // skew" on every healthy connection (seen live in #39 triage).
    if serde_json::from_str::<OracleReply>(line.trim()).is_ok() {
        return false;
    }
    match serde_json::from_str::<OracleCommand>(line.trim()) {
        Ok(OracleCommand::Serve { name, inner, mode }) => {
            store.serve(&name, &inner, mode);
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

/// Maintain the CONTROL connection to the policy daemon: say hello,
/// then apply every Serve/Remove it pushes. Reconnects on loss.
/// Content sync no longer exists — Serve only shapes the frozen tree;
/// bytes reach readers as fds at open time.
pub fn run_control_loop(store: Store, oracle_socket: String) {
    loop {
        if let Ok(conn) = UnixStream::connect(&oracle_socket) {
            let mut reader = BufReader::new(conn.try_clone().expect("clone control conn"));
            let mut w = conn;
            if writeln!(
                w,
                "{}",
                serde_json::to_string(&OracleRequest::Hello {
                    version: Some(fuse_protocol::VERSION.to_string()),
                })
                .expect("serializing Hello: internal enum, infallible")
            )
            .is_err()
            {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let _ = w.flush();
            // Ok ack + Serve commands arrive as lines.
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        apply_control_line(&store, &line);
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
    fn container_speaks_inner_labels_only() {
        // Issue #47 + review on #58 (flat): the container view is ONE
        // directory of whole-path hashes; outer components never
        // resolve, nested lookups do not exist.
        let s = Store::default();
        s.serve("var/home/jonas/git.netrc", "ab12cd34ef56", 0o400);
        let (_f, is_dir) = s.child(FuseIno::ROOT, OsStr::new("ab12cd34ef56")).unwrap();
        assert!(!is_dir);
        assert!(s.child(FuseIno::ROOT, OsStr::new("var")).is_none());
        // readdir: flat inner labels only
        let root = s.dir_children(FuseIno::ROOT).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].2, "ab12cd34ef56");
    }

    #[test]
    fn inner_label_collision_is_refused() {
        // Same flat hash for two outers: the second name is refused,
        // the first keeps its mapping — never alias two secrets.
        let s = Store::default();
        s.serve("one", "dupe", 0o400);
        s.serve("two", "dupe", 0o400);
        let root = s.dir_children(FuseIno::ROOT).unwrap();
        assert_eq!(root.len(), 1, "collision refused, no aliasing: {root:?}");
    }

    #[test]
    fn nested_outer_paths_serve_flat() {
        let s = Store::default();
        s.serve("home/u/auth.json", "aa11", 0o400);
        s.serve("home/u/keys/token", "bb22", 0o400);
        let root = s.dir_children(FuseIno::ROOT).unwrap();
        let labels: Vec<&str> = root.iter().map(|(_, _, n)| n.as_str()).collect();
        assert_eq!(labels, ["aa11", "bb22"], "one flat directory");
        // both resolve
        assert!(s.child(FuseIno::ROOT, OsStr::new("aa11")).is_some());
        assert!(s.child(FuseIno::ROOT, OsStr::new("bb22")).is_some());
    }

    #[test]
    fn re_serve_with_a_new_label_relabels_without_fino_churn() {
        // Serve carries structure only: a new inner LABEL (e.g. salt
        // rotation) is a rename in the container view, not an
        // incarnation change — stat-on-lookup owns identity (see
        // observe_refreshes_identity_on_lookup).
        let s = Store::default();
        s.serve("a/x", "x1", 0o400);
        let x1 = s.child(FuseIno::ROOT, OsStr::new("x1")).unwrap().0;
        s.serve("a/x", "x2", 0o400);
        assert!(s.child(FuseIno::ROOT, OsStr::new("x1")).is_none(), "old label gone");
        let x2 = s.child(FuseIno::ROOT, OsStr::new("x2")).unwrap().0;
        assert_eq!(x1, x2, "relabel is not an incarnation change");
    }

    #[test]
    fn same_incarnation_keeps_its_fino() {
        let s = Store::default();
        s.serve("a/x", "x1", 0o400);
        s.serve("a/x", "x1", 0o400);
        let x1 = s.child(FuseIno::ROOT, OsStr::new("x1")).unwrap().0;
        let x2 = s.child(FuseIno::ROOT, OsStr::new("x1")).unwrap().0;
        assert_eq!(x1, x2, "no churn without an incarnation change");
    }

    #[test]
    fn observe_refreshes_identity_on_lookup() {
        let s = Store::default();
        s.serve("a/x", "x1", 0o400);
        let x1 = s.child(FuseIno::ROOT, OsStr::new("x1")).unwrap().0;
        // lookup observed a replaced file: new fino for the path
        let x2 = s.observe(Path::new("a/x"), fuse_protocol::oracle::HostIdentity {
            kdev: fuse_protocol::KDev(52),
            kino: fuse_protocol::Kino(777),
        }).unwrap();
        assert_ne!(x1, x2);
        let x3 = s.child(FuseIno::ROOT, OsStr::new("x1")).unwrap().0;
        assert_eq!(x2, x3, "the tree now answers the new identity");
    }

    #[test]
    fn remove_prunes_the_tree_and_childless_ancestors() {
        let s = Store::default();
        s.serve("a/b/c.txt", "c1", 0o400);
        assert_eq!(s.dir_children(FuseIno::ROOT).unwrap().len(), 1);
        s.remove("a/b/c.txt");
        assert!(s.dir_children(FuseIno::ROOT).unwrap().is_empty(), "empty trees vanish");
    }

    #[test]
    fn control_line_replies_are_acks_not_garbage() {
        // The Hello ack shares the control stream with commands. It is
        // a REPLY — consuming it silently is correct; flagging it as a
        // parse failure would cry "version skew" on every healthy
        // connection (seen live while reproducing #39).
        let s = Store::default();
        assert!(!apply_control_line(&s, r#"{"type":"ok"}"#));
    }

    #[test]
    fn finos_are_unique_and_monotone() {
        let s = Store::default();
        let mut seen: Vec<FuseIno> = Vec::new();
        for i in 0..6u64 {
            let name = format!("f{i}.txt");
            s.serve(&name, &name, 0o400);
            let f = s.child(FuseIno::ROOT, OsStr::new(&name)).unwrap().0;
            assert!(!seen.contains(&f), "fino repeated: {f:?}");
            if let Some(&max) = seen.iter().max() {
                assert!(f.0 > max.0);
            }
            seen.push(f);
        }
    }

    fn tmp_listener(tag: &str) -> std::os::unix::net::UnixListener {
        let dir = std::env::temp_dir().join(format!("fused-open-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("o.sock");
        let _ = std::fs::remove_file(&path);
        std::os::unix::net::UnixListener::bind(&path).unwrap()
    }

    #[test]
    fn open_secret_does_not_hang_when_no_reply_ever_comes() {
        // PR #48 review finding, reproduced: a reply that never comes
        // — the server thread dies between reading the request and
        // answering, or the SCM_RIGHTS sendmsg fails silently — used
        // to block the reader's open FOREVER (no read timeout on the
        // connection). A listener that accepts and reads but never
        // answers must yield an error within the deadline instead.
        let listener = tmp_listener("hang");
        let path = listener.local_addr().unwrap().as_pathname().unwrap().to_path_buf();
        // Accept, swallow the request, then never answer and never
        // close — the worst case.
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut line = String::new();
                let _ = std::io::BufRead::read_line(
                    &mut std::io::BufReader::new(&mut conn),
                    &mut line,
                );
                std::thread::sleep(std::time::Duration::from_secs(300));
            }
        });
        let start = std::time::Instant::now();
        let r = open_secret_timeout(
            path.to_str().unwrap(),
            "s.yaml",
            7,
            fuse_protocol::oracle::KDev(1),
            fuse_protocol::oracle::Kino(2),
            std::time::Duration::from_millis(200),
        );
        assert!(r.is_err(), "a lost reply must surface as an error, got: {r:?}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "the error must arrive at the deadline, not hang"
        );
    }

    #[test]
    fn open_secret_maps_eof_to_error_not_hang() {
        // The server closes after reading without answering (crashed
        // mid-adjudication): the empty reply must be an error, never a
        // hang — the production caller maps it to EIO.
        let listener = tmp_listener("eof");
        let path = listener.local_addr().unwrap().as_pathname().unwrap().to_path_buf();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut line = String::new();
                let _ = std::io::BufRead::read_line(
                    &mut std::io::BufReader::new(&mut conn),
                    &mut line,
                );
                drop(conn);
            }
        });
        let r = open_secret_timeout(
            path.to_str().unwrap(),
            "s.yaml",
            7,
            fuse_protocol::oracle::KDev(1),
            fuse_protocol::oracle::Kino(2),
            std::time::Duration::from_secs(5),
        );
        assert!(r.is_err(), "EOF with no reply line must be an error, got: {r:?}");
    }
}
