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
//! let stack = Stack::new()                       // identity minted internally
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

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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

// ── stack identity: minted, never user-supplied ─────────────────
//
// (review on #82: uniqueness by CONSTRUCTION, not by hoping a
// duplicate-tag check does not fire.) Stacks carry a process-global
// monotonic id; combined with tempfile-random roots, two stacks
// cannot share a root, an id, or anything derived from them — there
// is nothing to check at runtime.
type StateBuild = Box<dyn FnOnce(&Path) -> ServerState + Send>;

fn next_id() -> u64 {
    static IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ── the builder ──────────────────────────────────────────────────

/// Builder for a gatekeeper test stack. See the crate docs.
pub struct Stack {
    id: u64,
    pending_timeout: Duration,
    /// Arm MR5 write-through persistence to a store under the stack's
    /// root (off by default — hermetic stacks; #59).
    store: bool,
    /// The hashd seam (#69): a DEAD per-stack path by default — a
    /// production hashd on the host can never leak in. Pin a live
    /// stub socket with [`Stack::hashd_stub`].
    hashd_sock: Option<PathBuf>,
    /// Harnesses that build their OWN `ServerState`: built WITH the
    /// stack's root in hand, so every file-backed choice (the hashd
    /// seam, the store) derives under the private root instead of a
    /// shared convention path (review on #82).
    custom_state: Option<StateBuild>,
    secrets: Vec<SecretSpec>,
}

#[derive(Debug, Clone)]
struct SecretSpec {
    name: String,
    content: Vec<u8>,
    hash: String,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    /// Begin a stack. Identity is minted internally (monotonic id +
    /// random root) — callers never name stacks, so duplicates are
    /// impossible by construction, not detected at runtime (review
    /// on #82).
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: next_id(),
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
            store: false,
            hashd_sock: None,
            custom_state: None,
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
    /// is a dead path under the stack's own root — the #69
    /// discipline, private by construction (no fixed convention
    /// path something else could bind; review on #82).
    #[must_use]
    pub fn hashd_stub(mut self, sock: impl Into<PathBuf>) -> Self {
        self.hashd_sock = Some(sock.into());
        self
    }

    /// Build the policy state yourself — WITH the stack's root in
    /// hand, so every file-backed choice (the hashd seam, the store)
    /// derives under the private root. Replaces `from_state`: the
    /// root is minted before the state exists, which is what makes
    /// the default dead seam private BY CONSTRUCTION rather than by
    /// a "nothing ever binds this fixed path" hope (review on #82).
    #[must_use]
    pub fn state_from(
        mut self,
        build: impl FnOnce(&Path) -> ServerState + Send + 'static,
    ) -> Self {
        self.custom_state = Some(Box::new(build));
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

    /// Spawn the IN-PROCESS policy stack: a real `run_oracle_server`
    /// on a per-stack socket, a real [`ServerState`] — the substrate
    /// the hand-rolled oracle-env copies used to duplicate.
    ///
    /// The root is minted FIRST; the state (custom or built) derives
    /// every file-backed path under it.
    ///
    /// # Panics
    /// Panics if the oracle server never binds within 5s.
    pub fn spawn_in_process(self) -> StackHandle {
        let root = tempfile::tempdir().expect("testkit: create stack root");
        let oracle = root.path().join("oracle.sock");
        let dead_hashd = root.path().join("hashd-dead.sock").display().to_string();

        let state = match self.custom_state {
            Some(build) => {
                let mut st = build(root.path());
                if st.hashd_sock == fuse_server::ServerState::new().hashd_sock {
                    // The builder left the AMBIENT default (/run/fuse-
                    // hashd.sock) — refuse it: the #69 discipline is a
                    // kit invariant, and the ambient socket may host a
                    // production hashd on this machine.
                    st.hashd_sock = dead_hashd;
                }
                st
            }
            None => {
                let mut st = ServerState::new();
                st.hashd_sock = self
                    .hashd_sock
                    .map(|p| p.display().to_string())
                    .unwrap_or(dead_hashd);
                st.pending_timeout = Mutex::new(self.pending_timeout);
                if self.store {
                    st.policy_path = Some(root.path().join("policy.json"));
                }
                st
            }
        };
        let state = Arc::new(state);
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
            id: self.id,
            _root: root,
            oracle,
            state,
            hub,
        }
    }
}

/// A live stack: every surface a test tier needs. Dropping it tears
/// down (root removed, sockets with it).
pub struct StackHandle {
    id: u64,
    _root: tempfile::TempDir,
    oracle: PathBuf,
    state: Arc<ServerState>,
    hub: OracleHub,
}

impl StackHandle {
    /// The stack's minted id (informational — logs, diagnostics).
    pub fn id(&self) -> u64 {
        self.id
    }

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
        let stack = Stack::new()
            .secret("s", b"CONTENT", "*")
            .spawn_in_process();
        let reply = fuse_server::oracle_service::ask(stack.oracle_socket(), "s", 4242, 0, 7)
            .expect("ask over the real wire");
        assert_eq!(reply, OracleReply::Allow);
    }

    #[test]
    fn ids_are_minted_monotonic_and_unique() {
        // Duplication avoidance BY CONSTRUCTION (review on #82): ids
        // are minted, never named by callers — two stacks cannot
        // share one, and there is no runtime check to fire.
        let a = Stack::new();
        let b = Stack::new();
        assert_ne!(a.id, b.id);
        let ha = a.spawn_in_process();
        let hb = Stack::new().spawn_in_process();
        assert_ne!(ha.id(), hb.id());
    }

    #[test]
    fn hashd_seam_is_dead_under_the_private_root_by_default() {
        let stack = Stack::new().spawn_in_process();
        let seam = &stack.state().hashd_sock;
        let seam_path = std::path::Path::new(seam);
        let root = stack.scratch("x").parent().unwrap().to_path_buf();
        assert!(
            seam_path.starts_with(&root) && seam.ends_with("hashd-dead.sock"),
            "the #69 seam: a dead path under the stack's OWN random \
             root — private by construction, never a fixed convention \
             path something else could bind (review on #82): {seam}"
        );
    }

    #[test]
    fn custom_states_derive_paths_from_the_handed_root() {
        // state_from gives the builder the root: file-backed choices
        // derive under it; an ambient-default hashd seam is REFUSED
        // and replaced by the root-private dead path.
        let stack = Stack::new()
            .state_from(|_root| ServerState::new())
            .spawn_in_process();
        let seam = &stack.state().hashd_sock;
        assert!(
            seam.ends_with("hashd-dead.sock"),
            "custom states keep the #69 discipline: {seam}"
        );
    }

    #[test]
    fn store_option_arms_persistence_under_the_root() {
        let stack = Stack::new().store().secret("s", b"X", "*").spawn_in_process();
        let path = stack.state().policy_path.clone();
        let path = path.expect("store() arms the policy path");
        assert!(path.ends_with("policy.json"));
    }
}
