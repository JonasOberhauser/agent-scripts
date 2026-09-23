//! The mock fuser: run (and fuzz) fused WITHOUT /dev/fuse.
//!
//! DI seam: `fuser::Session::from_fd` runs the REAL session machinery
//! — request parsing, dispatch, reply writing, the exact code the
//! kernel drives — over one end of a `SOCK_SEQPACKET` socketpair (the
//! packet boundary matches /dev/fuse's one-request-per-read
//! semantics). This module is the other end: a userspace "kernel"
//! whose ONLY protocol is the kernel's own — the stable Linux FUSE
//! UAPI, forwarded verbatim. Driver connections on the control socket
//! (also SEQPACKET, so frames survive the hop) are bridged onto the
//! kernel channel frame-for-frame; nothing is translated, encoded, or
//! reinvented (review on #76: "since it is the kernel UAPI (stable!)
//! then just forward it").
//!
//! The one thing the router adds beyond forwarding is kernel-faithful
//! driver-exit cleanup: it OBSERVES the frames passing through (with
//! `fuse_backend_rs::abi` types) to track which fhs a driver holds,
//! and when a driver hangs up it synthesizes a RELEASE for each —
//! what the real kernel does when a process dies with files open.
//!
//! Why TWO sockets: the socketpair is the mock /dev/fuse — the KERNEL
//! channel, owned by the session for its entire lifetime. `control`
//! is the DRIVER surface, which accepts many connections over that
//! lifetime (a driver hangs up; the next reconnects — the session
//! must NOT die with any one driver, the same way /dev/fuse outlives
//! every process reading the mount; EOF on a driver connection is
//! permanent, so handing the session a driver connection directly
//! would fuse its lifetime to that driver).
//!
//! Every layer above the kernel is real — the fused process, its
//! control loop against the true oracle protocol, MR4 fd passing,
//! one-read adjudication. This is the e2e substrate for environments
//! without a FUSE device (CI containers, the sandbox, fuzz hosts).

use std::io::Read as _;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use fuse_backend_rs::abi::fuse_abi as abi;

use crate::fs::FusedFs;

const FRAME_BUF: usize = 1 << 20;

/// Serialize a POD ABI value to bytes. vm-memory 0.17's
/// `ByteValued::as_bytes` is a &mut VolatileSlice (its writer-side
/// API); for plain serialization the POD contract — "any data is
/// valid for this type" — makes a byte-view cast sound.
pub(crate) fn pod_bytes<T: vm_memory::ByteValued>(v: &T) -> Vec<u8> {
    // SAFETY: ByteValued is only implemented for POD types whose any
    // bit pattern is valid; reading size_of::<T>() bytes at the value
    // is exactly its wire form (repr(C), field-declared padding).
    unsafe {
        std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>())
    }
    .to_vec()
}

/// Decode an exact-length POD from a byte slice: copy into an ALIGNED
/// buffer first (vm-memory's `from_slice` needs both exact size and
/// alignment; frame buffers are `Vec<u8>`).
pub(crate) fn pod_decode<T: vm_memory::ByteValued>(b: &[u8]) -> Option<T> {
    if b.len() != std::mem::size_of::<T>() {
        return None;
    }
    let mut tmp = vec![0u8; std::mem::size_of::<T>()];
    tmp.copy_from_slice(b);
    vm_memory::ByteValued::from_slice(&tmp).copied()
}

/// One driver connection's bridge onto the kernel channel: forwards
/// frames verbatim, and observes enough of them (OPEN replies,
/// RELEASE requests) to run the kernel-faithful exit cleanup.
struct Bridge {
    kernel: UnixStream,
    /// The in-flight request (drivers are serial with the session:
    /// one request, one reply) — resolved by unique so fh tracking
    /// never guesses from frame lengths.
    pending: Option<(u64, u32)>,
    /// fhs issued to THIS driver by successful OPENs, not yet
    /// RELEASEd (fh 0 — fuser's default opendir placeholder — is
    /// never tracked: it is not a real fd).
    open_fhs: Vec<u64>,
}

impl Bridge {
    fn new(kernel: UnixStream) -> Self {
        Self { kernel, pending: None, open_fhs: Vec::new() }
    }

    /// Serve one driver until it hangs up. Requests are forwarded and
    /// replies forwarded back; FORGET frames legitimately have no
    /// reply (the kernel contract), everything else answers exactly
    /// one frame per request.
    fn run(&mut self, driver: &UnixStream) -> std::io::Result<()> {
        let mut reader = driver.try_clone()?;
        let mut writer = driver.try_clone()?;
        let mut frame = vec![0u8; FRAME_BUF];
        loop {
            let n = reader.read(&mut frame)?;
            if n == 0 {
                return Ok(()); // driver hung up
            }
            let request = &frame[..n];
            self.observe_request(request);
            self.kernel.write_all(request)?;
            if request_opcode(request) == Some(abi::Opcode::Forget as u32) {
                continue; // oneway by the kernel contract
            }
            let rn = self.kernel.read(&mut frame)?;
            if rn == 0 {
                return Ok(()); // session ended
            }
            let reply = &frame[..rn];
            self.observe_reply(reply);
            writer.write_all(reply)?;
        }
    }

    fn observe_request(&mut self, request: &[u8]) {
        let hdr = std::mem::size_of::<abi::InHeader>();
        let Some(h) = (request.len() >= hdr).then(|| pod_decode::<abi::InHeader>(&request[..hdr])).flatten() else {
            return;
        };
        self.pending = Some((h.unique, h.opcode));
        if h.opcode == abi::Opcode::Release as u32 {
            if let Some(r) = pod_decode::<abi::ReleaseIn>(&request[hdr..]) {
                self.open_fhs.retain(|f| *f != r.fh);
            }
        }
    }

    fn observe_reply(&mut self, reply: &[u8]) {
        let hdr = std::mem::size_of::<abi::OutHeader>();
        let Some(out) = (reply.len() >= hdr)
            .then(|| pod_decode::<abi::OutHeader>(&reply[..hdr]))
            .flatten()
        else {
            return;
        };
        if let Some((unique, opcode)) = self.pending.take() {
            if out.unique == unique
                && out.error == 0
                && matches!(abi::Opcode::from(opcode), abi::Opcode::Open | abi::Opcode::Opendir)
                && reply.len() == hdr + std::mem::size_of::<abi::OpenOut>()
            {
                if let Some(o) = pod_decode::<abi::OpenOut>(&reply[hdr..]) {
                    if o.fh != 0 {
                        self.open_fhs.push(o.fh);
                    }
                }
            }
        }
    }

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
            let header = abi::InHeader {
                len: (std::mem::size_of::<abi::InHeader>()
                    + std::mem::size_of::<abi::ReleaseIn>()) as u32,
                opcode: abi::Opcode::Release as u32,
                unique: u64::MAX - fh, // never collides with driver uniques
                nodeid: fuser::FUSE_ROOT_ID,
                uid: 0,
                gid: 0,
                pid: 0,
                padding: 0,
            };
            let mut frame = pod_bytes(&header);
            frame.extend_from_slice(&pod_bytes(&payload));
            match self.kernel.write_all(&frame).and_then(|()| {
                let mut buf = vec![0u8; FRAME_BUF];
                self.kernel.read(&mut buf).map(|_| ())
            }) {
                Ok(()) => {}
                Err(e) => tracing::warn!("driver exit: RELEASE fh={fh}: {e}"),
            }
        }
    }
}

fn request_opcode(frame: &[u8]) -> Option<u32> {
    let hdr = std::mem::size_of::<abi::InHeader>();
    if frame.len() < hdr {
        return None;
    }
    pod_decode::<abi::InHeader>(&frame[..hdr]).map(|h| h.opcode)
}

/// Serve `fs` over the mock kernel; driver connections on `control`.
/// Blocks until the process is killed (same lifetime contract as
/// `fuser::mount2`).
/// Bind a SOCK_SEQPACKET listener at `path` — std's UnixListener is
/// stream-only, and frames must survive the driver hop whole.
fn bind_seqpacket_listener(path: &Path) -> std::io::Result<OwnedFd> {
    // SAFETY: plain socket(2)/bind(2)/listen(2) on a path the caller
    // owns; the fd is wrapped in OwnedFd on success and closed by it.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.len() >= addr.sun_path.len() {
            libc::close(fd);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "path too long"));
        }
        addr.sun_path[..bytes.len()]
            .copy_from_slice(std::mem::transmute::<&[u8], &[libc::c_char]>(bytes));
        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        ) != 0
            || libc::listen(fd, 16) != 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

pub fn serve(fs: FusedFs, control: &Path) {
    let _ = std::fs::remove_file(control);
    let listener = match bind_seqpacket_listener(control) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("mock fuser: cannot bind {}: {e}", control.display());
            std::process::exit(1);
        }
    };
    // The KERNEL channel (the mock /dev/fuse): SOCK_SEQPACKET preserves
    // the one-request-per-read framing /dev/fuse guarantees. fds[0]
    // is read by the session thread below for the process's lifetime;
    // fds[1] by the Bridge this loop drives per driver connection.
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
    // SAFETY: fds[1] likewise; the Bridge socket owns it.
    let kernel_sock = unsafe { UnixStream::from_raw_fd(fds[1]) };

    std::thread::spawn(move || {
        let mut session =
            fuser::Session::from_fd(fs, session_fd, fuser::SessionACL::All);
        match session.run() {
            Ok(()) => tracing::info!("mock fuser: session ended cleanly"),
            Err(e) => tracing::error!("mock fuser: session error: {e}"),
        }
    });

    tracing::info!("mock fuser: forwarding FUSE frames at {}", control.display());
    loop {
        // SAFETY: accept(2) on the listener above; a fresh owned fd.
        let cfd = unsafe { libc::accept(listener.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            let e = std::io::Error::last_os_error();
            tracing::error!("mock fuser: accept failed: {e}");
            continue;
        }
        // SAFETY: cfd is a fresh accepted descriptor from the
        // listener above; UnixStream closes it on drop.
        let conn = unsafe { UnixStream::from_raw_fd(cfd) };
        let mut bridge = Bridge::new(kernel_sock.try_clone().unwrap_or_else(|e| {
            tracing::error!("mock fuser: cannot clone kernel socket: {e}");
            std::process::exit(1);
        }));
        let _ = bridge.run(&conn);
        // Driver gone (EOF or transport error): the kernel-faithful
        // cleanup — RELEASE every fh this driver still holds, so the
        // paired host fds close instead of orphaning.
        bridge.driver_exit();
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn pod_round_trips_through_the_abi() {
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
        assert_eq!(bytes.len(), std::mem::size_of::<abi::ReadIn>());
        let back = pod_decode::<abi::ReadIn>(&bytes).expect("round trip");
        assert_eq!(back.fh, 9);
        assert_eq!(back.size, 128);
    }

    #[test]
    fn short_and_long_slices_rejected() {
        let h = abi::OutHeader { len: 16, error: 0, unique: 4 };
        let b = pod_bytes(&h);
        assert!(pod_decode::<abi::OutHeader>(&b[..15]).is_none());
        assert!(pod_decode::<abi::OutHeader>(&b).is_some());
        // Longer-than-exact also rejected: callers slice to the frame.
        let mut long = b.clone();
        long.push(0);
        assert!(pod_decode::<abi::OutHeader>(&long).is_none());
    }

    #[test]
    fn request_opcode_reads_the_header() {
        let h = abi::InHeader {
            len: 40,
            opcode: abi::Opcode::Lookup as u32,
            unique: 1,
            nodeid: 1,
            uid: 0,
            gid: 0,
            pid: 2,
            padding: 0,
        };
        let mut frame = pod_bytes(&h);
        frame.extend_from_slice(&[0u8; 8]);
        assert_eq!(request_opcode(&frame), Some(abi::Opcode::Lookup as u32));
        assert_eq!(request_opcode(&frame[..39]), None);
    }
}
