//! The typed driver client for the mock kernel — what tests, tools,
//! and fuzz tiers link to drive a `fused --mock-fuse` daemon.
//!
//! The driver speaks the kernel's own protocol (the stable Linux FUSE
//! UAPI, via `fuse_backend_rs::abi` types) — there is no house
//! protocol on top (review on #76: forward the UAPI, don't reinvent).
//! Each method is one request→reply pair, so the reply TYPE is bound
//! to the request at compile time — the marker-struct pairing the
//! review asked for, expressed as one method per op instead of a
//! runtime-paired decoder.

use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use fuse_backend_rs::abi::fuse_abi as abi;

use crate::mock_fuser::{pod_bytes, pod_decode};

const FRAME_BUF: usize = 1 << 20;

/// Caller credentials the kernel stamps on every request; the mock's
/// defaults are overridable per client (fodder for the fuzz tier).
#[derive(Clone, Copy)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl Default for Creds {
    fn default() -> Self {
        Self { uid: 0, gid: 0, pid: std::process::id() }
    }
}

/// A typed driver connection to a mock-kernel fused.
pub struct MockDriver {
    sock: UnixStream,
    unique: u64,
    pub creds: Creds,
}

/// A FUSE reply's error, as a positive errno.
#[derive(Debug)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", std::io::Error::from_raw_os_error(self.0))
    }
}

impl MockDriver {
    /// Connect to a fused running with `--mock-fuse <path>`. The
    /// control socket is SOCK_SEQPACKET (frames must survive the hop
    /// whole), so std's stream-only `UnixStream::connect` cannot be
    /// used — EPROTOTYPE.
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        // SAFETY: socket(2)/connect(2) on a caller-owned path; the fd
        // is wrapped in UnixStream on success and closed by it.
        let af_unix = libc::AF_UNIX;
        let seqpacket = libc::SOCK_SEQPACKET;
        let zero = 0;
        // SAFETY: socket(2) returns a fresh fd (or -1, checked).
        let fd = unsafe { libc::socket(af_unix, seqpacket, zero) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: zeroed sockaddr_un is a valid all-zero struct.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.len() >= addr.sun_path.len() {
            // SAFETY: close(2) on our own fd; the result only reports
            // double-close, which the ownership rules exclude.
            let _closed = unsafe { libc::close(fd) };
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "path too long"));
        }
        let dst = addr.sun_path.as_mut_ptr() as *mut u8;
        let src = bytes.as_ptr();
        let n = bytes.len();
        // SAFETY: &[u8] and &[c_char] have the same layout; the length
        // was bounds-checked above; one memcpy, no overlap.
        unsafe { std::ptr::copy(src, dst, n) };
        let p = &addr as *const _ as *const libc::sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: connect(2) on a caller-owned path with the
        // fully-initialized addr above.
        let rc = unsafe { libc::connect(fd, p, len) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: close(2) on our own fd; the result only reports
            // double-close, which the ownership rules exclude.
            let _closed = unsafe { libc::close(fd) };
            return Err(e);
        }
        // SAFETY: fd is a fresh connected descriptor owned from here;
        // UnixStream closes it on drop.
        let sock = unsafe { UnixStream::from_raw_fd(fd) };
        Ok(Self { sock, unique: 0, creds: Creds::default() })
    }

    fn next_unique(&mut self) -> u64 {
        self.unique += 1;
        self.unique
    }

    fn roundtrip(
        &mut self,
        opcode: abi::Opcode,
        nodeid: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, Errno> {
        let unique = self.next_unique();
        let header = abi::InHeader {
            len: (std::mem::size_of::<abi::InHeader>() + payload.len()) as u32,
            opcode: opcode as u32,
            unique,
            nodeid,
            uid: self.creds.uid,
            gid: self.creds.gid,
            pid: self.creds.pid,
            padding: 0,
        };
        let mut frame = pod_bytes(&header);
        frame.extend_from_slice(payload);
        self.sock
            .write_all(&frame)
            .map_err(|e| Errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
        let mut buf = vec![0u8; FRAME_BUF];
        let n = self
            .sock
            .read(&mut buf)
            .map_err(|e| Errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
        buf.truncate(n);
        let hdr = std::mem::size_of::<abi::OutHeader>();
        let out = pod_decode::<abi::OutHeader>(&buf[..hdr])
            .ok_or(Errno(libc::EIO))?;
        if out.unique != unique {
            return Err(Errno(libc::EIO)); // stream desync
        }
        if out.error != 0 {
            return Err(Errno(-out.error));
        }
        Ok(buf[hdr..].to_vec())
    }

    /// FUSE_INIT — the handshake every session expects first.
    pub fn init(&mut self) -> Result<abi::InitOut, Errno> {
        // The init reply's layout is feature-dependent on the SERVING
        // side (fuser compiles a subset); the prefix
        // major,minor,max_readahead,flags is ABI-stable since 7.1.
        let reply = self.roundtrip(
            abi::Opcode::Init,
            0,
            &pod_bytes(&abi::InitIn {
                major: 7,
                minor: 8,
                max_readahead: 128 * 1024,
                flags: 0,
            }),
        )?;
        if reply.len() < 16 {
            return Err(Errno(libc::EIO));
        }
        let g = |off: usize| u32::from_le_bytes(reply[off..off + 4].try_into().unwrap_or([0; 4]));
        Ok(abi::InitOut { major: g(0), minor: g(4), flags: g(8), ..Default::default() })
    }

    pub fn lookup(&mut self, name: &str) -> Result<abi::EntryOut, Errno> {
        let mut p = name.as_bytes().to_vec();
        p.push(0);
        while !p.len().is_multiple_of(8) {
            p.push(0);
        }
        let reply = self.roundtrip(abi::Opcode::Lookup, fuser::FUSE_ROOT_ID, &p)?;
        pod_decode::<abi::EntryOut>(&reply).ok_or(Errno(libc::EIO))
    }

    pub fn getattr(&mut self, ino: u64) -> Result<abi::AttrOut, Errno> {
        let reply = self.roundtrip(
            abi::Opcode::Getattr,
            ino,
            &pod_bytes(&abi::GetattrIn { flags: 0, dummy: 0, fh: 0 }),
        )?;
        pod_decode::<abi::AttrOut>(&reply).ok_or(Errno(libc::EIO))
    }

    pub fn open(&mut self, ino: u64) -> Result<abi::OpenOut, Errno> {
        let reply = self.roundtrip(
            abi::Opcode::Open,
            ino,
            &pod_bytes(&abi::OpenIn { flags: libc::O_RDONLY as u32, fuse_flags: 0 }),
        )?;
        pod_decode::<abi::OpenOut>(&reply).ok_or(Errno(libc::EIO))
    }

    pub fn opendir(&mut self, ino: u64) -> Result<abi::OpenOut, Errno> {
        let reply = self.roundtrip(
            abi::Opcode::Opendir,
            ino,
            &pod_bytes(&abi::OpenIn { flags: libc::O_RDONLY as u32, fuse_flags: 0 }),
        )?;
        pod_decode::<abi::OpenOut>(&reply).ok_or(Errno(libc::EIO))
    }

    pub fn read(&mut self, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        self.roundtrip(
            abi::Opcode::Read,
            fuser::FUSE_ROOT_ID,
            &pod_bytes(&abi::ReadIn {
                fh,
                offset,
                size,
                read_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            }),
        )
    }

    /// One READDIR burst, decoded to (dirent, name) pairs.
    pub fn readdir(&mut self, fh: u64, size: u32) -> Result<Vec<(abi::Dirent, String)>, Errno> {
        let data = self.roundtrip(
            abi::Opcode::Readdir,
            fuser::FUSE_ROOT_ID,
            &pod_bytes(&abi::ReadIn {
                fh,
                offset: 0,
                size,
                read_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            }),
        )?;
        let hdr = std::mem::size_of::<abi::Dirent>();
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + hdr <= data.len() {
            let Some(d) = pod_decode::<abi::Dirent>(&data[off..off + hdr]) else {
                break;
            };
            let namelen = d.namelen as usize;
            if off + hdr + namelen > data.len() {
                break;
            }
            let name =
                String::from_utf8_lossy(&data[off + hdr..off + hdr + namelen]).into_owned();
            out.push((d, name));
            off += (hdr + namelen).div_ceil(8) * 8;
        }
        Ok(out)
    }

    pub fn release(&mut self, ino: u64, fh: u64) -> Result<(), Errno> {
        self.roundtrip(
            abi::Opcode::Release,
            ino,
            &pod_bytes(&abi::ReleaseIn { fh, flags: 0, release_flags: 0, lock_owner: 0 }),
        )
        .map(|_| ())
    }

    pub fn releasedir(&mut self, ino: u64, fh: u64) -> Result<(), Errno> {
        self.roundtrip(
            abi::Opcode::Releasedir,
            ino,
            &pod_bytes(&abi::ReleaseIn { fh, flags: 0, release_flags: 0, lock_owner: 0 }),
        )
        .map(|_| ())
    }

    pub fn flush(&mut self, fh: u64) -> Result<(), Errno> {
        self.roundtrip(
            abi::Opcode::Flush,
            fuser::FUSE_ROOT_ID,
            &pod_bytes(&abi::FlushIn { fh, unused: 0, padding: 0, lock_owner: 0 }),
        )
        .map(|_| ())
    }

    pub fn statfs(&mut self) -> Result<abi::StatfsOut, Errno> {
        let reply = self.roundtrip(abi::Opcode::Statfs, fuser::FUSE_ROOT_ID, &[])?;
        pod_decode::<abi::StatfsOut>(&reply).ok_or(Errno(libc::EIO))
    }

    /// FORGET is oneway by the kernel contract — no reply is read.
    pub fn forget(&mut self, nodeid: u64, count: u64) -> std::io::Result<()> {
        let unique = self.next_unique();
        let header = abi::InHeader {
            len: (std::mem::size_of::<abi::InHeader>()
                + std::mem::size_of::<abi::ForgetOne>()) as u32,
            opcode: abi::Opcode::Forget as u32,
            unique,
            nodeid,
            uid: self.creds.uid,
            gid: self.creds.gid,
            pid: self.creds.pid,
            padding: 0,
        };
        let mut frame = pod_bytes(&header);
        frame.extend_from_slice(&pod_bytes(&abi::ForgetOne { nodeid, nlookup: count }));
        self.sock.write_all(&frame)
    }
}
