//! The mock fuser: run (and fuzz) fused WITHOUT /dev/fuse.
//!
//! DI seam: `fuser::Session::from_fd` runs the REAL session machinery
//! — request parsing, dispatch, reply writing, the exact code the
//! kernel drives — over one end of a `SOCK_SEQPACKET` socketpair (the
//! packet boundary matches /dev/fuse's one-request-per-read
//! semantics). This module is the OTHER end: a userspace "kernel"
//! that accepts JSON-line operations on a control socket, encodes
//! them into genuine Linux FUSE wire requests (the layouts are
//! fuser's `ll::fuse_abi` structs, pinned by size assertions), feeds
//! them to the session, and decodes the replies back to JSON.
//!
//! This is the e2e substrate for environments without a FUSE device
//! (CI containers, the authoring sandbox, fuzz tiers): every layer
//! above the kernel is real — the fused binary process, its control
//! loop against the real oracle protocol, MR4 fd passing, one-read
//! adjudication, MR5 persistence. The `raw` op additionally lets a
//! driver speak hand-crafted wire bytes directly, so a later fuzz
//! tier can attack the parser itself.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use serde_json::{json, Value};

// Linux FUSE kernel UAPI (include/uapi/linux/fuse.h) — the stable
// wire contract the kernel itself speaks. fuser does not re-export
// its internal ABI tables, and it should not have to: the protocol
// below is the kernel's, not fuser's.
mod opcode {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
}

use crate::fs::FusedFs;

/// One FUSE wire request: header (40 bytes, little-endian) plus the
/// opcode-specific payload, name bytes NUL-padded to 8 where present.
fn encode_request(
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + payload.len());
    put_u32(&mut buf, (40 + payload.len()) as u32);
    put_u32(&mut buf, opcode);
    put_u64(&mut buf, unique);
    put_u64(&mut buf, nodeid);
    put_u32(&mut buf, uid);
    put_u32(&mut buf, gid);
    put_u32(&mut buf, pid);
    put_u32(&mut buf, 0); // padding
    buf.extend_from_slice(payload);
    buf
}

fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(b: &mut Vec<u8>, v: i64) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0; 4]))
}
fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap_or([0; 8]))
}
fn get_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0; 4]))
}
fn get_i64(b: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(b[off..off + 8].try_into().unwrap_or([0; 8]))
}

/// The userspace kernel: writes wire requests into the socketpair end
/// the fuser session reads from, and reads its reply frames back.
struct MockKernel {
    sock: UnixStream,
    unique: u64,
}

/// A decoded FUSE reply: `error != 0` carries the errno, else `data`
/// is the payload after the out_header.
struct WireReply {
    /// POSITIVE errno (the wire carries -errno in out_header.error).
    error: i32,
    unique: u64,
    data: Vec<u8>,
}

impl MockKernel {
    fn new(sock: UnixStream) -> Self {
        Self { sock, unique: 0 }
    }

    fn next_unique(&mut self) -> u64 {
        self.unique += 1;
        self.unique
    }

    fn request(
        &mut self,
        opcode: u32,
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
        if n < 16 {
            return Err(format!("short reply frame: {n} bytes"));
        }
        let reply = WireReply {
            error: -get_i32(&buf, 4),
            unique: get_u64(&buf, 8),
            data: buf[16..].to_vec(),
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
        let mut payload = Vec::with_capacity(16);
        put_u64(&mut payload, nodeid);
        put_u64(&mut payload, count);
        let frame =
            encode_request(opcode::FORGET, unique, nodeid, 0, 0, std::process::id(), &payload);
        self.sock
            .write_all(&frame)
            .map_err(|e| format!("write FORGET: {e}"))?;
        Ok(())
    }

    /// Hand-crafted bytes, straight onto the wire (parser-attack
    /// surface for the fuzz tier). `expect_reply`: some frames
    /// (FORGET-shaped ones) legitimately answer nothing.
    fn raw(&mut self, bytes: &[u8], expect_reply: bool) -> Result<WireReply, String> {
        self.sock
            .write_all(bytes)
            .map_err(|e| format!("write raw frame: {e}"))?;
        if !expect_reply {
            return Ok(WireReply { error: 0, unique: 0, data: Vec::new() });
        }
        let mut buf = vec![0u8; 1 << 20];
        let n = self
            .sock
            .read(&mut buf)
            .map_err(|e| format!("read raw reply: {e}"))?;
        buf.truncate(n);
        Ok(WireReply {
            error: -get_i32(&buf, 4),
            unique: get_u64(&buf, 8),
            data: buf[16..].to_vec(),
        })
    }
}

/// Decode `fuse_attr` as OUR fuser build serializes it (Linux,
/// default features — read from fuser's `fuse_attr_from_attr`): the
/// macOS-only crtime/flags and the abi-7-9 blksize tail are compiled
/// out, leaving ino,size,blocks,atime,mtime,ctime (6×u64),
/// atime/mtime/ctimensec (3×u32), mode,nlink,uid,gid (4×u32), rdev
/// (u32) — 80 bytes, mode at offset 60.
fn attr_to_json(a: &[u8]) -> Result<Value, i32> {
    if a.len() < 80 {
        return Err(libc::EIO);
    }
    Ok(json!({
        "ino": get_u64(a, 0),
        "size": get_u64(a, 8),
        "mode": get_u32(a, 60),
        "nlink": get_u32(a, 64),
    }))
}

fn entry_payload(data: &[u8]) -> Result<Value, i32> {
    // fuse_entry_out: nodeid,generation,entry_valid,attr_valid
    // (4×u64) + entry/attr_valid_nsec (2×u32) — attr at offset 40.
    if data.len() < 40 {
        return Err(libc::EIO);
    }
    Ok(json!({
        "nodeid": get_u64(data, 0),
        "generation": get_u64(data, 8),
        "attr": attr_to_json(&data[40..])?,
    }))
}

fn attr_payload(data: &[u8]) -> Result<Value, i32> {
    if data.len() < 16 {
        return Err(libc::EIO);
    }
    attr_to_json(&data[16..])
}

fn dirent_stream(data: &[u8]) -> Value {
    // fuse_dirent: ino u64, off i64, namelen u32, type u32, name…
    // padded to a multiple of 8.
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 24 <= data.len() {
        let namelen = get_u32(data, off + 16) as usize;
        if off + 24 + namelen > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[off + 24..off + 24 + namelen]).into_owned();
        out.push(json!({
            "ino": get_u64(data, off),
            "off": get_i64(data, off + 8),
            "kind": get_u32(data, off + 20),
            "name": name,
        }));
        let entry_len = 24 + namelen;
        off += entry_len.div_ceil(8) * 8;
    }
    Value::Array(out)
}

fn statfs_payload(data: &[u8]) -> Result<Value, i32> {
    // fuse_statfs_out is fuse_kstatfs directly: blocks,bfree,bavail,
    // files,ffree (5×u64) then bsize,namelen,frsize (3×u32) — the
    // fields read below end at 52; the full struct pads to 80.
    if data.len() < 52 {
        return Err(libc::EIO);
    }
    Ok(json!({
        "blocks": get_u64(data, 0),
        "bfree": get_u64(data, 8),
        "bavail": get_u64(data, 16),
        "files": get_u64(data, 24),
        "ffree": get_u64(data, 32),
        "bsize": get_u32(data, 40),
        "namelen": get_u32(data, 44),
        "frsize": get_u32(data, 48),
    }))
}

/// Run one driver op; answer with `{"ok":…}` or `{"errno":n,"what":…}`.
fn run_op(k: &mut MockKernel, op: &Value) -> Value {
    let name = op["op"].as_str().unwrap_or("");
    // The kernel stamps caller credentials on every request; the
    // driver may override them per-op (fodder for the fuzz tier).
    let uid = op["uid"].as_u64().unwrap_or(0) as u32;
    let gid = op["gid"].as_u64().unwrap_or(0) as u32;
    let pid = op["pid"].as_u64().unwrap_or(std::process::id() as u64) as u32;
    let nodeid = op["ino"].as_u64().unwrap_or(fuser::FUSE_ROOT_ID);

    let res: Result<Value, String> = (|| {
        macro_rules! wire {
            ($opcode:expr, $payload:expr) => {
                match k.request($opcode, nodeid, uid, gid, pid, $payload) {
                    Ok(r) if r.error != 0 => Ok(json!({
                        "errno": r.error,
                        "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                    })),
                    Ok(r) => Ok(json!({ "ok": r.data.len() })),
                    Err(e) => Err(e),
                }
            };
        }
        match name {
            "init" => {
                let mut p = Vec::new();
                put_u32(&mut p, 7); // FUSE_KERNEL_VERSION
                put_u32(&mut p, 8); // minor
                put_u32(&mut p, 128 * 1024);
                put_u32(&mut p, 0); // flags: none — let the session pick
                match k.request(opcode::INIT, 0, 0, 0, 0, &p) {
                    Ok(r) if r.error != 0 => Ok(json!({"errno": r.error})),
                    Ok(r) => {
                        if r.data.len() < 16 {
                            return Err("short init reply".into());
                        }
                        Ok(json!({
                            "major": get_u32(&r.data, 0),
                            "minor": get_u32(&r.data, 4),
                            "max_write": get_u32(&r.data, 12),
                            "flags": get_u32(&r.data, 8),
                        }))
                    }
                    Err(e) => Err(e),
                }
            }
            "lookup" => {
                let inner = op["name"].as_str().unwrap_or("");
                let mut p = Vec::new();
                p.extend_from_slice(inner.as_bytes());
                p.push(0);
                while p.len() % 8 != 0 {
                    p.push(0);
                }
                match k.request(opcode::LOOKUP, nodeid, uid, gid, pid, &p) {
                    Ok(r) if r.error != 0 => Ok(json!({
                        "errno": r.error,
                        "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                    })),
                    Ok(r) => entry_payload(&r.data)
                        .map_err(|e| format!("bad entry_out: {e}")),
                    Err(e) => Err(e),
                }
            }
            "getattr" => {
                let mut p = Vec::new();
                put_u32(&mut p, op["fh"].is_u64().into()); // FUSE_GETATTR_FH
                put_u32(&mut p, 0); // dummy
                put_u64(&mut p, op["fh"].as_u64().unwrap_or(0));
                match k.request(opcode::GETATTR, nodeid, uid, gid, pid, &p) {
                    Ok(r) if r.error != 0 => Ok(json!({
                        "errno": r.error,
                        "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                    })),
                    Ok(r) => attr_payload(&r.data)
                        .map_err(|e| format!("bad attr_out: {e}")),
                    Err(e) => Err(e),
                }
            }
            "open" | "opendir" => {
                let mut p = Vec::new();
                p.extend_from_slice(&(op["flags"].as_i64().unwrap_or(0) as u32).to_le_bytes());
                put_u32(&mut p, 0);
                let opcode = if name == "open" { opcode::OPEN } else { opcode::OPENDIR };
                match k.request(opcode, nodeid, uid, gid, pid, &p) {
                    Ok(r) if r.error != 0 => Ok(json!({
                        "errno": r.error,
                        "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                    })),
                    Ok(r) => {
                        if r.data.len() < 8 {
                            return Err("short open_out".into());
                        }
                        Ok(json!({"fh": get_u64(&r.data, 0), "flags": get_u32(&r.data, 8)}))
                    }
                    Err(e) => Err(e),
                }
            }
            "read" | "readdir" => {
                let mut p = Vec::new();
                put_u64(&mut p, op["fh"].as_u64().unwrap_or(0));
                put_i64(&mut p, op["offset"].as_i64().unwrap_or(0));
                put_u32(&mut p, op["size"].as_u64().unwrap_or(4096) as u32);
                put_u32(&mut p, 0); // read_flags
                put_u64(&mut p, 0); // lock_owner
                put_u32(&mut p, 0); // flags
                put_u32(&mut p, 0); // padding
                let opcode = if name == "read" { opcode::READ } else { opcode::READDIR };
                match k.request(opcode, nodeid, uid, gid, pid, &p) {
                    Ok(r) if r.error != 0 => Ok(json!({
                        "errno": r.error,
                        "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                    })),
                    Ok(r) => {
                        if name == "read" {
                            // Raw bytes, hex-encoded in the reply.
                            let hex: String = r.data.iter().map(|b| format!("{b:02x}")).collect();
                            Ok(json!({"len": r.data.len(), "data_hex": hex}))
                        } else {
                            Ok(json!({"entries": dirent_stream(&r.data)}))
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            "release" | "releasedir" => {
                let mut p = Vec::new();
                put_u64(&mut p, op["fh"].as_u64().unwrap_or(0));
                put_u32(&mut p, 0); // flags
                put_u32(&mut p, 0); // release_flags
                put_u64(&mut p, 0); // lock_owner
                let opcode =
                    if name == "release" { opcode::RELEASE } else { opcode::RELEASEDIR };
                wire!(opcode, &p)
            }
            "flush" => {
                let mut p = Vec::new();
                put_u64(&mut p, op["fh"].as_u64().unwrap_or(0));
                put_u32(&mut p, 0); // flags
                put_u32(&mut p, 0); // padding
                put_u64(&mut p, 0); // lock_owner
                wire!(opcode::FLUSH, &p)
            }
            "statfs" => match k.request(opcode::STATFS, nodeid, uid, gid, pid, &[]) {
                Ok(r) if r.error != 0 => Ok(json!({
                    "errno": r.error,
                    "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                })),
                Ok(r) => statfs_payload(&r.data).map_err(|e| format!("bad statfs_out: {e}")),
                Err(e) => Err(e),
            },
            "forget" => k
                .forget(nodeid, op["count"].as_u64().unwrap_or(1))
                .map(|()| json!({"ok": 0})),
            "raw" => {
                let bytes = hex_decode(op["bytes"].as_str().unwrap_or(""))?;
                let expect = op["expect_reply"].as_bool().unwrap_or(true);
                match k.raw(&bytes, expect) {
                    Ok(r) if r.error != 0 => Ok(json!({
                        "errno": r.error,
                        "what": std::io::Error::from_raw_os_error(r.error).to_string(),
                    })),
                    Ok(r) => {
                        let hex: String = r.data.iter().map(|b| format!("{b:02x}")).collect();
                        Ok(json!({"len": 16 + r.data.len(), "data_hex": hex}))
                    }
                    Err(e) => Err(e),
                }
            }
            other => Err(format!("unknown op {other:?}")),
        }
    })();

    match res {
        Ok(v) => v,
        Err(e) => json!({"transport": e}),
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("raw bytes must be hex".into());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| format!("bad hex: {e}"))
        })
        .collect()
}

/// Serve `fs` over the mock kernel; driver connections on `control`.
/// Blocks until the process is killed (same lifetime contract as
/// `fuser::mount2`).
pub fn serve(fs: FusedFs, control: &Path) {
    let _ = std::fs::remove_file(control);
    let listener = match UnixListener::bind(control) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("mock fuser: cannot bind {}: {e}", control.display());
            std::process::exit(1);
        }
    };
    // The session end of the channel: SOCK_SEQPACKET preserves the
    // one-request-per-read framing /dev/fuse guarantees on streams.
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
                    let Ok(op) = serde_json::from_str::<Value>(line.trim()) else {
                        let _ = writeln!(writer, "{}", json!({"protocol": "send JSON ops"}));
                        let _ = writer.flush();
                        continue;
                    };
                    let reply = run_op(&mut kernel, &op);
                    let _ = writeln!(writer, "{reply}");
                    let _ = writer.flush();
                }
            }
        }
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn header_encoder_matches_the_uapi() {
        // fuse_in_header: len, opcode, unique, nodeid, uid, gid, pid,
        // padding — 40 bytes total, all little-endian.
        let frame = encode_request(opcode::STATFS, 7, 5, 1, 2, 3, &[]);
        assert_eq!(frame.len(), 40);
        assert_eq!(get_u32(&frame, 0), 40);
        assert_eq!(get_u32(&frame, 4), opcode::STATFS);
        assert_eq!(get_u64(&frame, 8), 7);
        assert_eq!(get_u64(&frame, 16), 5);
        assert_eq!(get_u32(&frame, 24), 1);
        assert_eq!(get_u32(&frame, 28), 2);
        assert_eq!(get_u32(&frame, 32), 3);
        assert_eq!(get_u32(&frame, 36), 0);
    }

    #[test]
    fn dirent_stream_walks_padded_entries() {
        // Two entries: "a" (1-byte name → 24+1 → padded to 32) and
        // "bcdefgh" (7 bytes → 24+7 → padded to 32; the kernel pads
        // every dirent to a multiple of 8 — so does this buffer).
        let mut d = Vec::new();
        put_u64(&mut d, 11);
        put_i64(&mut d, 1);
        put_u32(&mut d, 1);
        put_u32(&mut d, 4);
        d.extend_from_slice(b"a");
        d.extend_from_slice(&[0u8; 7]);
        put_u64(&mut d, 12);
        put_i64(&mut d, 2);
        put_u32(&mut d, 7);
        put_u32(&mut d, 4);
        d.extend_from_slice(b"bcdefgh");
        d.push(0);
        let v = dirent_stream(&d);
        assert_eq!(v[0]["name"], "a");
        assert_eq!(v[1]["name"], "bcdefgh");
        assert_eq!(v.as_array().map(Vec::len), Some(2));
    }
}
