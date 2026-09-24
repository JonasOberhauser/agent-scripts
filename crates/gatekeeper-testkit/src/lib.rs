//! The gatekeeper testkit (issue #63): ONE way to build the file-
//! backed parts of a gatekeeper stack in tests.
//!
//! Six policy-side stack constructors existed across four test files
//! before this — three of them near-identical in-process oracle
//! environments. Every hand-rolled copy was another harness
//! generation drifting apart; the fixed-name ones collided under
//! parallel test binaries (a PID-derived name is identical for every
//! test in one binary). `lints/stack-lint` now flags hand-creation
//! (`stack_testkit_only`); this crate is the sanctioned minter.
//!
//! The step-1 surface (in-process policy stacks — the three
//! `oracle_env` copies' home turf):
//!
//! ```no_run
//! use std::time::Duration;
//! use gatekeeper_testkit::Stack;
//!
//! let stack = Stack::new("my-test")            // tag lease: unique per binary
//!     .pending_timeout(Duration::from_millis(150))
//!     .secret("s", b"CONTENT", "*")             // host file + registration
//!     .spawn_in_process();                      // real oracle wire, real state
//!
//! // every surface a tier needs:
//! let _socket = stack.oracle_socket();
//! let _state = stack.state();
//! let _hub = stack.hub();
//! let _scratch = stack.scratch("fuzz-host");    // per-stack, never shared tmp
//! ```
//!
//! ## Collision-proof naming
//!
//! Roots are `tempfile` random (mkdtemp-style) — two stacks cannot
//! share a root, so fixed names INSIDE a root are private by
//! construction; across test BINARIES, random roots make tag
//! repetition safe. Within one binary, [`Stack::new`] takes a
//! process-global tag lease — a duplicate panics naming the tag.
//!
//! ## What is deliberately NOT here (step 2, with the binary drivers)
//!
//! Kill points (`.kill_policy()`/`.respawn_policy()`/`.kill_data()/
//! .respawn_data()`) and `Driver::RealMount` belong to the real-
//! binary drivers (`Split` becomes a thin wrapper); the in-process
//! policy has no process to kill. Sequenced after #73 so the e2e
//! fuzz tier's stacks consolidate HERE rather than forking again.
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use fuse_server::oracle_service::{run_oracle_server, OracleHub};
use fuse_server::ServerState;

/// Default pending window for kit stacks: short (tests want fast
/// pend-outs), long enough for grant flows.
const DEFAULT_PENDING_TIMEOUT: Duration = Duration::from_secs(2);

/// A never-bound hashd socket path (the #69 seam for `from_state`
/// callers that build their own state): dead by construction —
/// nothing ever binds it, sharing it across stacks is harmless.
pub const DEAD_HASHD: &str = "/tmp/gatekeeper-testkit-hashd-dead.sock";

// ── tag leasing: uniqueness within one test binary ───────────────

fn leases() -> &'static Mutex<HashSet<String>> {
    static LEASES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Releases the tag lease on drop.
struct Lease(String);

impl Drop for Lease {
    fn drop(&mut self) {
        let _released = leases()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

fn take_lease(tag: &str) -> Lease {
    // Poison-recovering: a panicking test (e.g. the duplicate-lease
    // probe below) must not brick every later stack in the binary.
    let mut set = leases()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let duplicate = !set.insert(tag.to_string());
    // The guard is DROPPED before the abort — the lock must not be
    // held across it (the first version poisoned it and cascaded).
    if duplicate {
        unreachable!(
            "testkit: stack tag {tag:?} is already leased by another live stack in \
             this test binary — two tests colliding, or a stack not yet dropped. \
             Tags may repeat across binaries (random roots), never within one."
        );
    }
    Lease(tag.to_string())
}

// ── the builder ──────────────────────────────────────────────────

/// Builder for a gatekeeper test stack. See the crate docs.
#[derive(Debug, Clone)]
pub struct Stack {
    tag: String,
    pending_timeout: Duration,
    /// Arm MR5 write-through persistence to a store under the stack's
    /// root (off by default — hermetic stacks; #59).
    store: bool,
    /// The hashd seam (#69): a DEAD per-stack path by default — a
    /// production hashd on the host can never leak in. Pin a live
    /// stub socket with [`Stack::hashd_stub`].
    hashd_sock: Option<PathBuf>,
    secrets: Vec<SecretSpec>,
}

#[derive(Debug, Clone)]
struct SecretSpec {
    name: String,
    content: Vec<u8>,
    hash: String,
}

impl Stack {
    /// Begin a stack. The tag is leased process-globally: a duplicate
    /// `Stack::new(tag)` among LIVE stacks in one test binary panics
    /// (see the crate docs — the collision answer).
    ///
    /// # Panics
    /// Panics if `tag` is already leased by a live stack in this
    /// binary, or if the tag-lease lock was poisoned.
    pub fn new(tag: &str) -> Self {
        Self {
            tag: tag.to_string(),
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
            store: false,
            hashd_sock: None,
            secrets: Vec::new(),
        }
    }

    /// The pending window for asks that pend (default: 2s).
    #[must_use]
    pub fn pending_timeout(mut self, d: Duration) -> Self {
        self.pending_timeout = d;
        self
    }

    /// Arm MR5 persistence: mutations write through to a policy store
    /// under the stack's root. (Load-from-store on spawn is NOT
    /// implied — that is the restart flow's job, tested with a second
    /// stack pointed at the same store path.)
    #[must_use]
    pub fn store(mut self) -> Self {
        self.store = true;
        self
    }

    /// Pin a LIVE hashd socket (e.g. a test's stub listener). Default
    /// is a dead per-stack path — the #69 discipline.
    #[must_use]
    pub fn hashd_stub(mut self, sock: impl Into<PathBuf>) -> Self {
        self.hashd_sock = Some(sock.into());
        self
    }

    /// Register a secret: its host file is written under the stack's
    /// root and added to the policy state (but NOT served to any data
    /// daemon — call [`StackHandle::hub`]'s `serve` when your driver
    /// needs the push, keeping the oracle tests' explicit shape).
    #[must_use]
    pub fn secret(mut self, name: &str, content: &[u8], hash: &str) -> Self {
        self.secrets.push(SecretSpec {
            name: name.to_string(),
            content: content.to_vec(),
            hash: hash.to_string(),
        });
        self
    }

    /// Spawn a policy server around an EXISTING state (the low-level
    /// entry — the migration seam for harnesses that construct their
    /// own `ServerState`): fresh per-stack root, real oracle wire,
    /// socket bound under the root.
    ///
    /// # Panics
    /// Panics if the tag lease is duplicated or the oracle server
    /// never binds within 5s.
    pub fn from_state(tag: &str, state: Arc<ServerState>, hub: OracleHub) -> StackHandle {
        let lease = take_lease(tag);
        let root = tempfile::tempdir().expect("testkit: create stack root");
        let oracle = root.path().join("oracle.sock");
        let (s2, hub2, p2) = (Arc::clone(&state), hub.clone(), oracle.clone());
        let _server_thread = std::thread::spawn(move || {
            let _ = run_oracle_server(&p2, s2, hub2);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !oracle.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "testkit: oracle server never bound at {}",
                oracle.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        StackHandle {
            _lease: lease,
            _root: root,
            oracle,
            state,
            hub,
        }
    }

    /// Spawn the IN-PROCESS policy stack (step 1): a real
    /// `run_oracle_server` on a per-stack socket, a real
    /// [`ServerState`] — the same substrate the three `oracle_env`
    /// copies hand-rolled.
    ///
    /// # Panics
    /// Panics if the tag lease is duplicated, the oracle server never
    /// binds within 5s, or a lock is poisoned.
    pub fn spawn_in_process(self) -> StackHandle {
        let lease = take_lease(&self.tag);
        let root = tempfile::tempdir().expect("testkit: create stack root");
        let oracle = root.path().join("oracle.sock");

        let mut st = ServerState::new();
        st.hashd_sock = self
            .hashd_sock
            .unwrap_or_else(|| root.path().join("hashd-dead.sock"))
            .display()
            .to_string();
        st.pending_timeout = Mutex::new(self.pending_timeout);
        if self.store {
            st.policy_path = Some(root.path().join("policy.json"));
        }
        let state = Arc::new(st);
        for spec in &self.secrets {
            let host = root.path().join(format!("host-{}", spec.name));
            std::fs::write(&host, &spec.content).expect("testkit: write host file");
            state.add(&spec.name, &host, spec.content.len(), &spec.hash);
        }

        let hub = OracleHub::new();
        let (s2, hub2, p2) = (Arc::clone(&state), hub.clone(), oracle.clone());
        let _server_thread = std::thread::spawn(move || {
            let _ = run_oracle_server(&p2, s2, hub2);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !oracle.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "testkit: oracle server never bound at {}",
                oracle.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        StackHandle {
            _lease: lease,
            _root: root,
            oracle,
            state,
            hub,
        }
    }
}

/// A live stack: every surface a test tier needs. Dropping it tears
/// down (root removed, sockets with it) and releases the tag lease.
pub struct StackHandle {
    _lease: Lease,
    _root: tempfile::TempDir,
    oracle: PathBuf,
    state: Arc<ServerState>,
    hub: OracleHub,
}

impl StackHandle {
    /// The policy daemon's oracle socket (the real wire protocol).
    pub fn oracle_socket(&self) -> &Path {
        &self.oracle
    }

    /// The live policy state (the in-process daemon's own).
    pub fn state(&self) -> &Arc<ServerState> {
        &self.state
    }

    /// The oracle hub: `serve`/`remove` push to connected data
    /// daemons (the control channel).
    pub fn hub(&self) -> &OracleHub {
        &self.hub
    }

    /// A per-stack scratch path (replaces `std::env::temp_dir()` —
    /// shared-temp fixed names collide across parallel test binaries;
    /// `stack_testkit_only` flags them).
    pub fn scratch(&self, name: &str) -> PathBuf {
        self._root.path().join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuse_protocol::oracle::OracleReply;

    #[test]
    fn stack_serves_the_real_oracle_wire() {
        let stack = Stack::new("kit-smoke")
            .secret("s", b"CONTENT", "*")
            .spawn_in_process();
        let reply = fuse_server::oracle_service::ask(stack.oracle_socket(), "s", 4242, 0, 7)
            .expect("ask over the real wire");
        assert_eq!(reply, OracleReply::Allow);
    }

    #[test]
    fn duplicate_live_tags_panic_and_release_on_drop() {
        let a = Stack::new("kit-lease").spawn_in_process();
        let dup = std::panic::catch_unwind(|| {
            let _b = Stack::new("kit-lease").spawn_in_process();
        });
        assert!(dup.is_err(), "a duplicate LIVE tag must panic");
        drop(a);
        // The lease died with the stack: re-taking is fine.
        let _c = Stack::new("kit-lease").spawn_in_process();
    }

    #[test]
    fn hashd_seam_is_dead_by_default_and_state_is_live() {
        let stack = Stack::new("kit-seam").spawn_in_process();
        let state = stack.state();
        assert!(
            state.hashd_sock.ends_with("hashd-dead.sock"),
            "the #69 seam: dead per-stack path, never ambient"
        );
        assert!(stack.oracle_socket().exists());
        let scratch = stack.scratch("host.bin");
        assert!(scratch.starts_with(stack.scratch(".").parent().unwrap()));
    }

    #[test]
    fn store_option_arms_persistence_under_the_root() {
        let stack = Stack::new("kit-store").store().secret("s", b"X", "*").spawn_in_process();
        let path = stack.state().policy_path.clone();
        let path = path.expect("store() arms the policy path");
        assert!(path.ends_with("policy.json"));
    }
}
