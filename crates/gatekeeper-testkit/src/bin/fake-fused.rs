//! A stand-in data daemon for the supervision seam (#94): ignores its
//! argv, runs until SIGTERM (default disposition), exits 0. Lets
//! container tiers exercise the policy daemon's supervise/reap
//! lifecycle without a kernel FUSE mount.

fn main() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
