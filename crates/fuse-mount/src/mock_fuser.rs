//! The mock fuser: run (and fuzz) fused WITHOUT /dev/fuse.
//!
//! DI seam: `fuser::Session::from_fd` runs the REAL session machinery
//! — request parsing, dispatch, reply writing, the exact code the
//! kernel drives — over one end of a `SOCK_SEQPACKET` socketpair (the
//! packet boundary matches /dev/fuse's one-request-per-read
//! semantics). This module is the OTHER end: a userspace "kernel"
//! that accepts JSON-line operations on a control socket, encodes
//! them into genuine Linux FUSE wire requests, feeds them to the
//! session, and decodes the replies back to JSON.
//!
//! The wire types are `fuse_backend_rs::abi::fuse_abi` — the
//! maintained public mirror of `include/uapi/linux/fuse.h` (v7.31),
//! from the virtiofsd lineage; fuser keeps its own mirror private.
//! fuser is built with the `abi-7-9` feature so the layouts it
//! SERIALIZES match fbrs's full ones byte-for-byte on every struct
//! this module decodes (exact-length `ByteValued` decoding).
//!
//! This is the e2e substrate for environments without a FUSE device
//! (CI containers, the authoring sandbox, fuzz tiers): every layer
//! above the kernel is real — the fused binary process, its control
//! loop against the real oracle protocol, MR4 fd passing, one-read
//! adjudication, MR5 persistence.

use std::io::{BufRead, BufReader, Write};
use std::io::Read as _;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use fuse_backend_rs::abi::fuse_abi as abi;
use serde_json::{json, Value};

use crate::fs::FusedFs;

/// Decode an exact-length POD from a byte slice: copy into an ALIGNED
/// stack array first (vm-memory's `from_slice` needs both exact size
/// and alignment; reply buffers are `Vec<u8>`).
macro_rules! decode_pod {
    ($t:ty, $bytes:expr) => {{
        fn decode<T: vm_memory::ByteValued>(b: &[u8]) -> Option<T> {
            if b.len() != std::mem::size_of::<T>() {
                return None;
            }
            let mut tmp = vec![0u8; std::mem::size_of::<T>()];
            tmp.copy_from_slice(b);
            // The copy is heap-aligned (≥ the struct's alignment on
            // every platform we target); ByteValued::from_slice then
            // borrows it as the POD view.
            vm_memory::ByteValued::from_slice(&tmp).copied()
        }
        decode::<$t>($bytes)
    }};
}

/// Serialize a POD ABI value to bytes. vm-memory 0.17's
/// `ByteValued::as_bytes` is a &mut VolatileSlice (its writer-side
/// API); for plain serialization the POD contract — "any data is
/// valid for this type" — makes a byte-view cast sound.
fn pod_bytes<T: vm_memory::ByteValued>(v: &T) -> Vec<u8> {
    // SAFETY: ByteValued is only implemented for POD types whose any
    // bit pattern is valid; reading size_of::<T>() bytes at the value
    // is exactly its wire form (repr(C), field-declared padding).
    unsafe {
        std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>())
    }
    .to_vec()
}

/// One FUSE wire request: header + opcode-specific payload.
fn encode_request(
    opcode: abi::Opcode,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header = abi::InHeader {
        len: (std::mem::size_of::<abi::InHeader>() + payload.len()) as u32,
        opcode: opcode as u32,
        unique,
        nodeid,
        uid,
        gid,
        pid,
        padding: 0,
    };
    let mut buf = pod_bytes(&header);
    buf.extend_from_slice(payload);
    buf
}

/// Variable-length LOOKUP payload: the name, NUL-padded to 8.
fn encode_lookup_name(name: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(name.as_bytes());
    p.push(0);
    while !p.len().is_multiple_of(8) {
        p.push(0);
    }
    p
}

/// The userspace kernel. `sock` is the DRIVER-side handle to the
/// kernel channel (the socketpair end whose other end the fuser
/// SESSION thread — spawned in [`serve`] — owns and reads): every
/// write here becomes one request the session parses and dispatches
/// into the real `Filesystem` impl, and its reply frame (matched by
/// `unique`) arrives back on this socket.
struct MockKernel {
    sock: UnixStream,
    unique: u64,
    /// fhs issued to THIS driver by successful OPENs, not yet
    /// RELEASEd — the registry for the kernel-faithful cleanup the
    /// router position enables: on driver disconnect, the real
    /// kernel closes the dying process's files and RELEASEs each fh;
    /// the mock synthesizes the same frames (fh 0 — fuser's default
    /// opendir placeholder — is never tracked: it is not a real fd).
    open_fhs: Vec<u64>,
}

/// A decoded FUSE reply: `error != 0` carries the POSITIVE errno (the
/// wire carries -errno in out_header.error), else `data` is the
/// payload after the out_header.
struct WireReply {
    error: i32,
    unique: u64,
    data: Vec<u8>,
}

impl MockKernel {
    /// The dying-driver path: the real kernel closes the process's
    /// files and a RELEASE arrives for each outstanding fh — the
    /// paired host fd in fused gets closed instead of orphaned. Best
    /// effort: the session is alive (the channel is daemon-owned), so
    /// replies arrive; failures are logged, not fatal.
    fn driver_exit(&mut self) {
        for fh in std::mem::take(&mut self.open_fhs) {
            let payload = abi::ReleaseIn {
                fh,
                flags: 0,
                release_flags: 0,
                lock_owner: 0,
            };
            let res = self.request(
                abi::Opcode::Release,
                fuser::FUSE_ROOT_ID,
                0,
                0,
                0,
                &pod_bytes(&payload),
            );
            match res {
                Ok(r) if r.error != 0 => {
                    tracing::warn!("driver exit: RELEASE fh={fh} answered errno {}", r.error);
                }
                Err(e) => tracing::warn!("driver exit: RELEASE fh={fh}: {e}"),
                Ok(_) => {}
            }
        }
    }

    fn new(sock: UnixStream) -> Self {
        Self { sock, unique: 0, open_fhs: Vec::new() }
    }

    fn next_unique(&mut self) -> u64 {
        self.unique += 1;
        self.unique
    }

    fn request(
        &mut self,
        opcode: abi::Opcode,
        nodeid: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        payload: &[u8],
    ) -> Result<WireReply, String> {
        let unique = self.next_unique();
        let frame = encode_request(opcode, unique, nodeid, uid, gid, pid, payload);
        self.sock
            .write_all(&frame)
            .map_err(|e| format!("write wire request: {e}"))?;
        let mut buf = vec![0u8; 1 << 20];
        let n = self
            .sock
            .read(&mut buf)
            .map_err(|e| format!("read wire reply: {e}"))?;
        buf.truncate(n);
        if n < std::mem::size_of::<abi::OutHeader>() {
            return Err(format!("short reply frame: {n} bytes"));
        }
        let out = decode_pod!(abi::OutHeader, &buf[..std::mem::size_of::<abi::OutHeader>()])
            .ok_or_else(|| format!("bad out_header in {n}-byte frame"))?;
        let reply = WireReply {
            error: -out.error,
            unique: out.unique,
            data: buf[std::mem::size_of::<abi::OutHeader>()..].to_vec(),
        };
        if reply.unique != unique {
            return Err(format!(
                "reply unique {} != request {} (stream desync)",
                reply.unique, unique
            ));
        }
        Ok(reply)
    }

    /// FORGET is the one opcode the kernel never expects a reply to.
    fn forget(&mut self, nodeid: u64, count: u64) -> Result<(), String> {
        let unique = self.next_unique();
        let payload = abi::ForgetOne { nodeid, nlookup: count };
        let frame = encode_request(
            abi::Opcode::Forget,
            unique,
            nodeid,
            0,
            0,
            std::process::id(),
            &pod_bytes(&payload),
        );
        self.sock
            .write_all(&frame)
            .map_err(|e| format!("write FORGET: {e}"))?;
        Ok(())
    }
}

/// Caller credentials the kernel stamps on every request; drivers
/// may override them per line (fodder for the fuzz tier).
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Caller {
    uid: u32,
    gid: u32,
    pid: Option<u32>,
}

impl Caller {
    fn pid(&self) -> u32 {
        self.pid.unwrap_or_else(std::process::id)
    }
}

/// The driver protocol as an ADT (review on #76): each op is a
/// payload struct, and the enum gives it the wire semantics —
/// [`DriverOp::encode`] turns a variant into its FUSE frame payload
/// (per-variant, in one place), [`decode_reply`] turns the raw reply
/// back into the typed [`OpReply`] that matches the op.
#[derive(serde::Deserialize)]
struct Init;

#[derive(serde::Deserialize)]
struct Lookup {
    name: String,
    #[serde(default)]
    ino: u64,
}

#[derive(serde::Deserialize)]
struct Getattr {
    #[serde(default)]
    ino: u64,
    #[serde(default)]
    fh: Option<u64>,
}

#[derive(serde::Deserialize)]
struct Open {
    #[serde(default)]
    ino: u64,
    #[serde(default)]
    flags: u32,
}

#[derive(serde::Deserialize)]
struct Opendir {
    #[serde(default)]
    ino: u64,
}

#[derive(serde::Deserialize)]
struct Read {
    fh: u64,
    #[serde(default)]
    offset: i64,
    #[serde(default = "default_read_size")]
    size: u32,
}

#[derive(serde::Deserialize)]
struct Readdir {
    #[serde(default)]
    ino: u64,
    fh: u64,
    #[serde(default)]
    offset: i64,
    #[serde(default = "default_read_size")]
    size: u32,
}

#[derive(serde::Deserialize)]
struct Release {
    #[serde(default)]
    ino: u64,
    fh: u64,
}

#[derive(serde::Deserialize)]
struct Releasedir {
    #[serde(default)]
    ino: u64,
    fh: u64,
}

#[derive(serde::Deserialize)]
struct Flush {
    fh: u64,
}

#[derive(serde::Deserialize)]
struct Statfs {
    #[serde(default)]
    ino: u64,
}

#[derive(serde::Deserialize)]
struct Forget {
    #[serde(default)]
    ino: u64,
    #[serde(default = "default_one")]
    count: u64,
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum DriverOp {
    Init(Init),
    Lookup(Lookup),
    Getattr(Getattr),
    Open(Open),
    Opendir(Opendir),
    Read(Read),
    Readdir(Readdir),
    Release(Release),
    Releasedir(Releasedir),
    Flush(Flush),
    Statfs(Statfs),
    Forget(Forget),
}

fn default_one() -> u64 {
    1
}

fn default_read_size() -> u32 {
    4096
}

impl DriverOp {
    /// The kernel-side encoding of one op: opcode, target node, and
    /// the payload bytes — the per-variant match that makes the wire
    /// semantics live ON the ADT (review on #76).
    fn encode(&self) -> (abi::Opcode, u64, Vec<u8>) {
        let root = |ino: u64| if ino == 0 { fuser::FUSE_ROOT_ID } else { ino };
        match self {
            DriverOp::Init(_) => (
                abi::Opcode::Init,
                0,
                pod_bytes(&abi::InitIn {
                    major: 7,
                    minor: 8,
                    max_readahead: 128 * 1024,
                    flags: 0,
                }),
            ),
            DriverOp::Lookup(Lookup { name, ino }) => {
                (abi::Opcode::Lookup, root(*ino), encode_lookup_name(name))
            }
            DriverOp::Getattr(Getattr { ino, fh }) => (
                abi::Opcode::Getattr,
                root(*ino),
                pod_bytes(&abi::GetattrIn { flags: 0, dummy: 0, fh: fh.unwrap_or(0) }),
            ),
            DriverOp::Open(Open { ino, flags }) => (
                abi::Opcode::Open,
                root(*ino),
                pod_bytes(&abi::OpenIn { flags: *flags, fuse_flags: 0 }),
            ),
            DriverOp::Opendir(Opendir { ino }) => (
                abi::Opcode::Opendir,
                root(*ino),
                pod_bytes(&abi::OpenIn { flags: 0, fuse_flags: 0 }),
            ),
            DriverOp::Read(Read { fh, offset, size }) => (
                abi::Opcode::Read,
                fuser::FUSE_ROOT_ID,
                pod_bytes(&abi::ReadIn {
                    fh: *fh,
                    offset: *offset as u64,
                    size: *size,
                    read_flags: 0,
                    lock_owner: 0,
                    flags: 0,
                    padding: 0,
                }),
            ),
            DriverOp::Readdir(Readdir { ino, fh, offset, size }) => (
                abi::Opcode::Readdir,
                root(*ino),
                pod_bytes(&abi::ReadIn {
                    fh: *fh,
                    offset: *offset as u64,
                    size: *size,
                    read_flags: 0,
                    lock_owner: 0,
                    flags: 0,
                    padding: 0,
                }),
            ),
            DriverOp::Release(Release { ino, fh }) => (
                abi::Opcode::Release,
                root(*ino),
                pod_bytes(&abi::ReleaseIn { fh: *fh, flags: 0, release_flags: 0, lock_owner: 0 }),
            ),
            DriverOp::Releasedir(Releasedir { ino, fh }) => (
                abi::Opcode::Releasedir,
                root(*ino),
                pod_bytes(&abi::ReleaseIn { fh: *fh, flags: 0, release_flags: 0, lock_owner: 0 }),
            ),
            DriverOp::Flush(Flush { fh }) => (
                abi::Opcode::Flush,
                fuser::FUSE_ROOT_ID,
                pod_bytes(&abi::FlushIn { fh: *fh, unused: 0, padding: 0, lock_owner: 0 }),
            ),
            DriverOp::Statfs(Statfs { ino }) => (abi::Opcode::Statfs, root(*ino), Vec::new()),
            DriverOp::Forget(Forget { ino, count }) => (
                abi::Opcode::Forget,
                root(*ino),
                pod_bytes(&abi::ForgetOne { nodeid: root(*ino), nlookup: *count }),
            ),
        }
    }
}

/// The typed reply, one variant per op — the answer shape the ADT
/// promises (review on #76). `Ok` is the shapeless reply (release-like
/// ops answer nothing but success).
#[derive(serde::Serialize)]
#[serde(untagged)]
enum OpReply {
    Init { major: u32, minor: u32, max_write: u32, flags: u32 },
    Entry { nodeid: u64, generation: u64, attr: AttrJson },
    Attr(AttrJson),
    Open { fh: u64, flags: u32 },
    Read { len: usize, data_hex: String },
    Entries(Vec<(u64, u64, u32, String)>),
    Statfs { blocks: u64, bfree: u64, bavail: u64, files: u64, ffree: u64, bsize: u32, namelen: u32, frsize: u32 },
    Ok(usize),
    Errno { errno: i32, what: String },
}

#[derive(serde::Serialize)]
struct AttrJson {
    ino: u64,
    size: u64,
    mode: u32,
    nlink: u32,
}

fn attr_json(a: &abi::Attr) -> AttrJson {
    AttrJson { ino: a.ino, size: a.size, mode: a.mode, nlink: a.nlink }
}

fn errno_reply(errno: i32) -> OpReply {
    OpReply::Errno { errno, what: std::io::Error::from_raw_os_error(errno).to_string() }
}

/// The wire reply → the typed [`OpReply`] matching the op — decoding
/// is its OWN function, not interleaved with dispatch (review on #76).
fn decode_reply(op: &DriverOp, r: &WireReply) -> Result<OpReply, String> {
    if r.error != 0 {
        return Ok(errno_reply(r.error));
    }
    match op {
        DriverOp::Init(_) => {
            // The init reply's layout is feature-dependent on the
            // SERVING side (fuser compiles a subset); the prefix
            // major,minor,max_readahead,flags is ABI-stable since
            // 7.1, so read it directly.
            if r.data.len() < 16 {
                return Err("short init reply".into());
            }
            let g = |off: usize| u32::from_le_bytes(r.data[off..off + 4].try_into().unwrap_or([0; 4]));
            Ok(OpReply::Init {
                major: g(0),
                minor: g(4),
                max_write: g(12),
                flags: g(8),
            })
        }
        DriverOp::Lookup(_) => {
            let e = decode_pod!(abi::EntryOut, &r.data).ok_or("entry_out size mismatch")?;
            Ok(OpReply::Entry {
                nodeid: e.nodeid,
                generation: e.generation,
                attr: attr_json(&e.attr),
            })
        }
        DriverOp::Getattr(_) => {
            let a = decode_pod!(abi::AttrOut, &r.data).ok_or("attr_out size mismatch")?;
            Ok(OpReply::Attr(attr_json(&a.attr)))
        }
        DriverOp::Open(_) | DriverOp::Opendir(_) => {
            let o = decode_pod!(abi::OpenOut, &r.data).ok_or("open_out size mismatch")?;
            Ok(OpReply::Open { fh: o.fh, flags: o.open_flags })
        }
        DriverOp::Read(_) => {
            let hex: String = r.data.iter().map(|b| format!("{b:02x}")).collect();
            Ok(OpReply::Read { len: r.data.len(), data_hex: hex })
        }
        DriverOp::Readdir(_) => Ok(OpReply::Entries(dirents(&r.data))),
        DriverOp::Statfs(_) => {
            let s = decode_pod!(abi::StatfsOut, &r.data).ok_or("statfs_out size mismatch")?;
            Ok(OpReply::Statfs {
                blocks: s.st.blocks,
                bfree: s.st.bfree,
                bavail: s.st.bavail,
                files: s.st.files,
                ffree: s.st.ffree,
                bsize: s.st.bsize,
                namelen: s.st.namelen,
                frsize: s.st.frsize,
            })
        }
        DriverOp::Release(_) | DriverOp::Releasedir(_) | DriverOp::Flush(_)
        | DriverOp::Forget(_) => Ok(OpReply::Ok(0)),
    }
}

/// fuse_dirent stream → (ino, off, kind, name) tuples.
fn dirents(data: &[u8]) -> Vec<(u64, u64, u32, String)> {
    let hdr = std::mem::size_of::<abi::Dirent>();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + hdr <= data.len() {
        let Some(d) = decode_pod!(abi::Dirent, &data[off..off + hdr]) else {
            break;
        };
        let namelen = d.namelen as usize;
        if off + hdr + namelen > data.len() {
            break;
        }
        let name =
            String::from_utf8_lossy(&data[off + hdr..off + hdr + namelen]).into_owned();
        out.push((d.ino, d.off, d.type_, name));
        let entry_len = hdr + namelen;
        off += entry_len.div_ceil(8) * 8;
    }
    out
}

/// One driver line: the op plus overridable caller credentials.
#[derive(serde::Deserialize)]
struct DriverLine {
    #[serde(flatten)]
    op: DriverOp,
    #[serde(flatten)]
    caller: Caller,
}

/// Run one driver op: encode → wire → decode → JSON at the edge.
/// Dispatch owns nothing but orchestration and the fh registry.
fn run_op(k: &mut MockKernel, line: &DriverLine) -> Value {
    let uid = line.caller.uid;
    let gid = line.caller.gid;
    let pid = line.caller.pid();

    let res: Result<OpReply, String> = (|| {
        if let DriverOp::Forget(Forget { ino, count }) = &line.op {
            return k.forget(*ino, *count).map(|()| OpReply::Ok(0));
        }
        let (opcode, nodeid, payload) = line.op.encode();
        let wire = k.request(opcode, nodeid, uid, gid, pid, &payload)?;
        let reply = decode_reply(&line.op, &wire)?;
        // The registry: fhs this driver holds until RELEASE.
        if let (DriverOp::Open(_), OpReply::Open { fh, .. }) = (&line.op, &reply) {
            if *fh != 0 {
                k.open_fhs.push(*fh);
            }
        }
        if let DriverOp::Release(Release { fh, .. }) = &line.op {
            k.open_fhs.retain(|f| f != fh);
        }
        if let DriverOp::Releasedir(Releasedir { fh, .. }) = &line.op {
            k.open_fhs.retain(|f| f != fh);
        }
        Ok(reply)
    })();

    match res {
        Ok(reply) => serde_json::to_value(reply).unwrap_or_else(|_| json!({"encode": "reply"})),
        Err(e) => json!({ "transport": e }),
    }
}

/// Serve `fs` over the mock kernel; driver connections on `control`.
/// Blocks until the process is killed (same lifetime contract as
/// `fuser::mount2`).
///
/// Why TWO sockets (review on #76): the socketpair below is the
/// mock /dev/fuse — the KERNEL channel, owned by the session for its
/// entire lifetime. `control` is the DRIVER surface, which accepts
/// many connections over that lifetime (a driver hangs up; the next
/// reconnects — the session must NOT die with any one driver, the
/// same way /dev/fuse outlives every process reading the mount).
/// Between them sits the mock kernel: it translates JSON ops into
/// FUSE wire (different framing: lines vs SEQPACKET packets), stamps
/// caller credentials, and matches replies by unique. Handing the
/// session a driver connection directly would fuse the session's
/// lifetime to one driver AND force drivers to speak binary FUSE.
pub fn serve(fs: FusedFs, control: &Path) {
    let _ = std::fs::remove_file(control);
    let listener = match UnixListener::bind(control) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("mock fuser: cannot bind {}: {e}", control.display());
            std::process::exit(1);
        }
    };
    // The KERNEL channel (the mock /dev/fuse): SOCK_SEQPACKET preserves
    // the one-request-per-read framing /dev/fuse guarantees. fds[0]
    // is read by the session thread below for the process's lifetime;
    // fds[1] by the MockKernel this loop drives per driver connection.
    let mut fds = [0i32; 2];
    // SAFETY: socketpair(2) writes two fresh descriptors into fds; on
    // failure nothing is written.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) } != 0 {
        tracing::error!("mock fuser: socketpair failed");
        std::process::exit(1);
    }
    // SAFETY: fds[0] is a fresh, exclusively owned descriptor from
    // socketpair above; OwnedFd closes it on drop.
    let session_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: fds[1] likewise; the MockKernel socket owns it.
    let kernel_sock = unsafe { UnixStream::from_raw_fd(fds[1]) };

    std::thread::spawn(move || {
        let mut session =
            fuser::Session::from_fd(fs, session_fd, fuser::SessionACL::All);
        match session.run() {
            Ok(()) => tracing::info!("mock fuser: session ended cleanly"),
            Err(e) => tracing::error!("mock fuser: session error: {e}"),
        }
    });

    tracing::info!("mock fuser: serving driver ops at {}", control.display());
    for conn in listener.incoming().flatten() {
        let mut kernel = MockKernel::new(kernel_sock.try_clone().unwrap_or_else(|e| {
            tracing::error!("mock fuser: cannot clone kernel socket: {e}");
            std::process::exit(1);
        }));
        let Ok(reader) = conn.try_clone() else { continue };
        let mut writer = conn;
        let mut lines = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match lines.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let Ok(parsed) = serde_json::from_str::<DriverLine>(line.trim()) else {
                        let _ = writeln!(writer, "{}", json!({
                            "protocol": "send one JSON op per line; unknown ops and wrong field types do not parse"
                        }));
                        let _ = writer.flush();
                        continue;
                    };
                    let reply = run_op(&mut kernel, &parsed);
                    let _ = writeln!(writer, "{reply}");
                    let _ = writer.flush();
                }
            }
        }
        // Driver gone (EOF or transport error): the kernel-faithful
        // cleanup — RELEASE every fh this driver still holds, so the
        // paired host fds close instead of orphaning. OUTSIDE the op
        // loop: once per CONNECTION end, never mid-conversation (a
        // mid-loop insertion bug here once closed a just-opened
        // secret fd — EBADF on the next read).
        kernel.driver_exit();
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn header_frame_round_trips_through_the_abi() {
        let frame = encode_request(abi::Opcode::Statfs, 7, 5, 1, 2, 3, &[]);
        let h = decode_pod!(abi::InHeader, &frame).expect("exact-size header");
        assert_eq!(frame.len(), std::mem::size_of::<abi::InHeader>());
        assert_eq!(h.len as usize, frame.len());
        assert_eq!(h.opcode, abi::Opcode::Statfs as u32);
        assert_eq!(h.unique, 7);
        assert_eq!(h.nodeid, 5);
        assert_eq!(h.uid, 1);
        assert_eq!(h.gid, 2);
        assert_eq!(h.pid, 3);
        assert_eq!(h.padding, 0);
    }

    #[test]
    fn payloads_round_trip_through_the_abi() {
        let r = abi::ReadIn {
            fh: 9,
            offset: 4096,
            size: 128,
            read_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        let bytes = pod_bytes(&r);
        let back = decode_pod!(abi::ReadIn, &bytes).expect("read_in round trip");
        assert_eq!(back.fh, 9);
        assert_eq!(back.size, 128);
        // The ABI crate owns the layouts; we only assert OUR use of
        // them (round trip + frame composition), not offset tables.
        assert_eq!(
            bytes.len(),
            std::mem::size_of::<abi::ReadIn>(),
            "as_bytes covers the whole struct"
        );
    }

    #[test]
    fn lookup_name_is_nul_padded_to_8() {
        assert_eq!(encode_lookup_name("a").len(), 8);
        assert_eq!(encode_lookup_name("abcdefgh").len(), 16, "NUL + pad");
    }

    #[test]
    fn dirent_stream_walks_padded_entries() {
        // Two entries: "a" (1-byte name → padded to 32) and
        // "bcdefgh" (7 bytes → padded to 32; the kernel pads every
        // dirent to a multiple of 8 — so does this buffer).
        let hdr = std::mem::size_of::<abi::Dirent>();
        let mut d = pod_bytes(&abi::Dirent { ino: 11, off: 1, namelen: 1, type_: 4 });
        d.extend_from_slice(b"a");
        d.extend_from_slice(&[0u8; 7]);
        d.extend_from_slice(&pod_bytes(&abi::Dirent { ino: 12, off: 2, namelen: 7, type_: 4 }));
        d.extend_from_slice(b"bcdefgh");
        d.push(0);
        let v = dirents(&d);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].3, "a");
        assert_eq!(v[1].3, "bcdefgh");
        assert_eq!(hdr, 24);
    }
}
