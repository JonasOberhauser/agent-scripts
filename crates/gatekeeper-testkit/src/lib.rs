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
//! ## The binary driver (step 2 — `Driver::RealMount`)
//!
//! [`Stack::spawn_real_mount`] brings up the REAL daemons —
//! `fuse-server` + `fused` as child processes on a kernel FUSE mount,
//! all under the stack's root — with #68's kill points as handle
//! methods (`kill_policy`/`kill_data`, store-only and
//! secrets-re-registration policy respawns, `respawn_data`). The
//! spawn waits carry the diagnostics the old hand-rolled harness
//! accumulated; `fuse_e2e`'s `Split` is a thin wrapper of
//! [`RealMountStack`].
//!
//! ## Stubs (step 2a — the hashd seam and raw rendezvous)
//!
//! [`Stack::live_hashd_stub`] pins a LIVE kit-spawned hashd stub to
//! the state's seam (the #69 discipline: the kit binds, under the
//! stack's root); the standalone [`spawn_hashd_stub`] serves tiers
//! that drive their own daemons; [`StubSocket`] mints a bound raw
//! rendezvous for tests whose SUT speaks the other end (the hostile
//! fake-daemon fuzz tier).
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuse_protocol::io::SystemIo as _;
use fuse_server::oracle_service::{run_oracle_server, OracleHub};
use fuse_server::ServerState;

mod mock_fuse;
pub mod supervised;
use supervised::SupervisedStack;

/// Crate-internal connect-wait shared by the binary tiers (the
/// diagnostics live in real_mount's copy; this one keeps the
/// message minimal for the supervision tier).
pub(crate) fn wait_connect_pub(path: &std::path::Path, what: &str, root: &std::path::Path) {
    crate::real_mount::wait_connect_pub(path, what, root);
}
pub use mock_fuse::{mock_fuse_available, MockFuseStack};
mod real_mount;
pub use real_mount::{bin, real_mount_available, Driver, RealMountStack};
use real_mount::dump_logs_under;

/// Default pending window for kit stacks: short (tests want fast
/// pend-outs), long enough for grant flows.
const DEFAULT_PENDING_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Minted at `new()` — the FIRST thing that exists, so stubs and
    /// custom states can derive from it before anything spawns.
    pub(crate) root: tempfile::TempDir,
    pub(crate) pending_timeout: Duration,
    /// Arm MR5 write-through persistence to a store under the stack's
    /// root (off by default — hermetic stacks; #59).
    store: bool,
    /// A LIVE kit-spawned hashd stub pinned to the state's seam
    /// (overrides the dead default; #69 discipline: the kit binds).
    pub(crate) live_hashd: Option<HashdReply>,
    /// Harnesses that build their OWN `ServerState`: built WITH the
    /// stack's root in hand, so every file-backed choice (the hashd
    /// seam, the store) derives under the private root instead of a
    /// shared convention path (review on #82).
    custom_state: Option<StateBuild>,
    pub(crate) secrets: Vec<SecretSpec>,
    /// Which driver `spawn()` brings up (the #63 axis). `None`
    /// (default) is the in-process policy; `RealMount` is the real
    /// binaries + kernel mount.
    driver: Driver,
    /// Substitute data daemon for the binary tiers (#94 seam):
    /// passed to fuse-server as `--fused-binary`. Defaults to the
    /// kit's `fake-fused` on the [`Driver::Supervised`] tier; also
    /// honored by [`Driver::RealMount`].
    pub(crate) fused_binary: Option<PathBuf>,
}

/// What a kit hashd stub answers on the wire (`hash {pid}` → reply).
#[derive(Debug, Clone)]
pub enum HashdReply {
    /// `ok {hash}` for every well-formed request — a canned package
    /// hash (the pending-remediation shape).
    Canned(String),
    /// The locally-computed package hash of the asked pid (the
    /// production shape: the policy daemon never hashes by itself).
    Compute,
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
    /// Begin a stack. The random root is minted HERE — the first
    /// thing that exists — and identity is minted internally
    /// (monotonic id + random root), so callers never name stacks and
    /// duplicates are impossible by construction, not detected at
    /// runtime (review on #82).
    ///
    /// # Panics
    /// Panics if the random root cannot be created (mkdtemp failure).
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: next_id(),
            root: tempfile::tempdir().expect("testkit: mint stack root"),
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
            store: false,
            live_hashd: None,
            custom_state: None,
            secrets: Vec::new(),
            driver: Driver::None,
            fused_binary: None,
        }
    }

    /// Pick the driver `spawn()` brings up: [`Driver::None`] (the
    /// in-process policy tier) or [`Driver::RealMount`] (the real
    /// `fuse-server` + `fused` binaries and a kernel FUSE mount —
    /// kill points and all, see [`RealMountStack`]).
    #[must_use]
    pub fn driver(mut self, d: Driver) -> Self {
        self.driver = d;
        self
    }

    /// Substitute the data daemon for the binary tiers (#94): passed
    /// to `fuse-server` as `--fused-binary`. The
    /// [`Driver::Supervised`] tier defaults to the kit's `fake-fused`.
    #[must_use]
    pub fn fused_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.fused_binary = Some(path.into());
        self
    }

    /// Spawn the SUPERVISION tier (#94): the real policy daemon
    /// supervising a substituted data daemon — no kernel FUSE, runs
    /// in every container. See [`SupervisedStack`].
    ///
    /// # Panics
    /// Panics if the policy daemon never answers.
    pub fn spawn_supervised(self) -> SupervisedStack {
        SupervisedStack::spawn(self)
    }

    /// Spawn per the configured [`Driver`]: the in-process policy
    /// stack, the mock-fuse split, or the real-mount binary tier.
    pub fn spawn(self) -> SpawnedStack {
        match self.driver {
            Driver::None => SpawnedStack::InProcess(self.spawn_in_process()),
            Driver::MockFuse => SpawnedStack::MockFuse(self.spawn_mock_fuse()),
            Driver::RealMount => SpawnedStack::RealMount(self.spawn_real_mount()),
            Driver::Supervised => SpawnedStack::Supervised(self.spawn_supervised()),
        }
    }

    /// Spawn the MOCK-FUSE split: the in-process policy daemon plus
    /// the real `fused` binary on `--mock-fuse`, its mock control
    /// socket under the stack's root (see [`MockFuseStack`]) — the
    /// everywhere-tier, no `/dev/fuse` needed.
    ///
    /// # Panics
    /// Panics if the fused binary cannot be spawned or never binds
    /// its control socket within 10s.
    pub fn spawn_mock_fuse(self) -> MockFuseStack {
        MockFuseStack::spawn(self)
    }

    /// Spawn the REAL-binary tier: `fuse-server` + `fused` children
    /// and a kernel FUSE mount under the stack's root, with #68's
    /// kill points as handle methods. Requires `/dev/fuse` and
    /// `fusermount3` (see [`real_mount_available`]).
    ///
    /// The policy store is ALWAYS armed on this tier (the inner
    /// names' salt lands in it, and the respawn kill points load
    /// through it); `state_from` is meaningless here (a binary owns
    /// its state) and is ignored.
    ///
    /// # Panics
    /// Panics if the daemons never come up (with their logs
    /// attached), or the binaries cannot be spawned.
    pub fn spawn_real_mount(self) -> RealMountStack {
        RealMountStack::spawn(self)
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

    /// Pin a LIVE kit-spawned hashd stub to the state's seam: the kit
    /// binds it under the stack's root and answers the hashd wire —
    /// the #69 discipline with the bind owned by the kit, never the
    /// test (review on #82). Default is the dead seam.
    #[must_use]
    pub fn live_hashd_stub(mut self, reply: HashdReply) -> Self {
        self.live_hashd = Some(reply);
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
    /// The state (custom or built) derives every file-backed path
    /// under the root minted at [`Stack::new`]; a live hashd stub,
    /// if requested, is bound BEFORE the state exists so the seam can
    /// point at it.
    ///
    /// # Panics
    /// Panics if the oracle server never binds within 5s.
    pub fn spawn_in_process(self) -> StackHandle {
        let root = self.root;
        let oracle = root.path().join("oracle.sock");
        let dead_hashd = root.path().join("hashd-dead.sock").display().to_string();
        let hashd = self.live_hashd.map(|reply| {
            let path = root.path().join("hashd.sock");
            bind_hashd_wire(&path, reply);
            HashdStub { _root: None, path }
        });

        let state = match self.custom_state {
            Some(build) => {
                let mut st = build(root.path());
                if st.hashd_sock == fuse_server::ServerState::new().hashd_sock {
                    // The builder left the AMBIENT default (/run/fuse-
                    // hashd.sock) — refuse it: the #69 discipline is a
                    // kit invariant, and the ambient socket may host a
                    // production hashd on this machine. The seam falls
                    // back to the kit's dead path (or the live stub).
                    st.hashd_sock = hashd
                        .as_ref()
                        .map(|h| h.path.display().to_string())
                        .unwrap_or(dead_hashd);
                }
                st
            }
            None => {
                let mut st = ServerState::new();
                st.hashd_sock = hashd
                    .as_ref()
                    .map(|h| h.path.display().to_string())
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
            hashd,
        }
    }
}

/// A live stub socket bound by the kit: the accept thread answers the
/// hashd wire until the process ends; the socket file is RAII-
/// reclaimed with the root that owns it.
#[must_use = "dropping the stub unlinks its socket"]
pub struct HashdStub {
    /// `None` when the socket lives under a stack root the
    /// `StackHandle` already owns.
    pub(crate) _root: Option<tempfile::TempDir>,
    pub(crate) path: PathBuf,
}

impl HashdStub {
    /// The bound socket path (the seam to pin into a state or an env
    /// var).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Spawn a LIVE hashd stub on its own kit-minted root (the stand-
/// alone form of [`Stack::live_hashd_stub`] for tiers that drive
/// their own daemons and only need the seam filled). The kit binds
/// the socket; the accept thread answers `hash {pid}` per `reply`
/// until process exit.
///
/// # Panics
/// Panics if the root or the socket bind fails.
pub fn spawn_hashd_stub(reply: HashdReply) -> HashdStub {
    let root = tempfile::tempdir().expect("testkit: mint hashd stub root");
    let path = root.path().join("hashd.sock");
    bind_hashd_wire(&path, reply);
    HashdStub { _root: Some(root), path }
}

/// A kit-minted RAW rendezvous: the kit binds, the test's own accept
/// loop speaks whatever protocol it is testing (the hostile
/// fake-daemon tier's primitive — its behavior IS the subject under
/// test, so only the rendezvous is kit business).
#[must_use = "dropping the stub unlinks its socket"]
pub struct StubSocket {
    _root: tempfile::TempDir,
    path: PathBuf,
    listener: UnixListener,
}

impl StubSocket {
    /// Bind `{label}.sock` under a fresh kit root.
    ///
    /// # Panics
    /// Panics if the root or the socket bind fails.
    pub fn bind(label: &str) -> Self {
        let root = tempfile::tempdir().expect("testkit: mint stub-socket root");
        let path = root.path().join(format!("{label}.sock"));
        let listener = UnixListener::bind(&path).expect("testkit: bind stub socket");
        Self { _root: root, path, listener }
    }

    /// The bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The bound listener — hand it to the test's accept thread. The
    /// socket file stays RAII-reclaimed through the root.
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// A scratch path under the same private root (state files and
    /// other per-stub artifacts — never the shared temp dir).
    #[must_use]
    pub fn scratch(&self, name: &str) -> PathBuf {
        self._root.path().join(name)
    }
}

pub(crate) fn bind_hashd_wire(path: &Path, reply: HashdReply) {
    let listener = UnixListener::bind(path).expect("testkit: bind hashd stub");
    // The wire thread runs until process exit (a deleted-path listener
    // accepts nothing new); the handle is deliberately discarded.
    let _wire = std::thread::spawn(move || serve_hashd_wire(listener, reply));
}

/// The one hashd wire shape every stub spoke by hand before the kit
/// owned it: one `hash {pid}` line in, one reply line out.
fn serve_hashd_wire(listener: UnixListener, reply: HashdReply) {
    for conn in listener.incoming().flatten() {
        let Ok(clone) = conn.try_clone() else { continue };
        let mut reader = BufReader::new(clone);
        let mut stream = conn;
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        // request grammar: WORD pid — plain split; replies are the
        // helper's JSON wire (serde-shaped strings, one line)
        let mut words = line.trim().split(' ');
        let out = match (
            &reply,
            words.next(),
            words.next().and_then(|p| p.parse::<u32>().ok()),
        ) {
            (HashdReply::Canned(hash), Some("hash"), Some(_)) => {
                format!("{{\"ok\":\"{hash}\"}}\n")
            }
            (HashdReply::Compute, Some("hash"), Some(pid)) => {
                match fuse_protocol::RealSystemIo::new().sha256_process_package(pid) {
                    Ok(h) => format!("{{\"ok\":\"{h}\"}}\n"),
                    Err(e) => format!(
                        "{{\"error\":{{\"kind\":\"gone\",\"message\":{}}}}}\n",
                        serde_json::to_string(&e.to_string()).unwrap_or_default()
                    ),
                }
            }
            (_, _, _) => "{\"error\":{\"kind\":\"generic\",\"message\":\"malformed request\"}}\n"
                .to_string(),
        };
        let _ = stream.write_all(out.as_bytes());
        let _ = stream.flush();
    }
}

/// One question, one answer — used by kit tests to speak the wire.
#[cfg(test)]
fn ask_hashd(path: &Path, pid: u32) -> String {
    let mut s = UnixStream::connect(path).expect("connect to hashd stub");
    std::io::Write::write_all(&mut s, format!("hash {pid}\n").as_bytes()).expect("write");
    let mut line = String::new();
    let _n = BufReader::new(s).read_line(&mut line).expect("read");
    line
}

/// What [`Stack::spawn`] returns per the configured [`Driver`].
pub enum SpawnedStack {
    /// The in-process policy tier.
    InProcess(StackHandle),
    /// The mock-fuse split tier (real fused, mocked kernel end).
    MockFuse(MockFuseStack),
    /// The real-binary mount tier.
    RealMount(RealMountStack),
    /// The supervision tier (#94): real policy daemon + substituted
    /// data daemon, no kernel FUSE.
    Supervised(SupervisedStack),
}

/// A live stack: every surface a test tier needs. Dropping it tears
/// down (root removed, sockets with it).
pub struct StackHandle {
    id: u64,
    _root: tempfile::TempDir,
    oracle: PathBuf,
    state: Arc<ServerState>,
    hub: OracleHub,
    hashd: Option<HashdStub>,
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

    /// The live kit hashd stub's socket, when the stack was built with
    /// [`Stack::live_hashd_stub`] — the seam the state is pinned to.
    pub fn hashd_socket(&self) -> Option<&Path> {
        self.hashd.as_ref().map(|h| h.path())
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

    /// Tail every daemon log under the stack's root.
    pub fn dump_logs(&self, what: &str) -> String {
        dump_logs_under(self._root.path(), what)
    }
}

// Tests may hand-parse output/protocol lines: sanctioned by policy
// (test + allow), NOT available to production code.
#[cfg(test)]
#[allow(unknown_lints)]
#[allow(custom_parser)]
#[allow(clippy::panic)]
mod supervised_tests {
    use crate::{Driver, Stack};

    /// The supervision tier comes up everywhere (no /dev/fuse): the
    /// policy daemon answers and the SUBSTITUTED daemon is alive
    /// carrying the stack's mount point (#94 seam).
    #[test]
    fn supervision_tier_spawns_the_substituted_daemon() {
        let stack = Stack::new().driver(Driver::Supervised).spawn();
        let mut sup = match stack {
            crate::SpawnedStack::Supervised(s) => s,
            _ => panic!("driver mismatch"),
        };
        assert!(
            std::os::unix::net::UnixStream::connect(sup.socket()).is_ok(),
            "policy daemon answers on the cmd socket"
        );
        let daemons = sup.daemon_pids();
        assert!(
            !daemons.is_empty(),
            "the substituted data daemon is alive under supervision"
        );
        sup.kill_policy();
        // give the (currently nonexistent) reaping a moment — #93 F2
        // will tighten this into the reaping assertion.
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

// Tests may hand-parse output/protocol lines: sanctioned by policy
// (test + allow), NOT available to production code. unknown_lints:
// the custom_parser lint exists only under the servyi driver.
#[cfg(test)]
#[allow(unknown_lints)]
#[allow(custom_parser)]
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

    #[test]
    fn live_hashd_stub_is_pinned_and_speaks_the_wire() {
        let stack = Stack::new()
            .live_hashd_stub(HashdReply::Canned("b".repeat(64)))
            .spawn_in_process();
        let seam = &stack.state().hashd_sock;
        let stub_path =
            stack.hashd_socket().expect("live stub socket exposed").to_path_buf();
        assert_eq!(seam, &stub_path.display().to_string(),
            "the seam points at the kit-bound stub");
        assert!(stub_path.ends_with("hashd.sock"));
        assert_eq!(
            ask_hashd(&stub_path, 7),
            format!("{{\"ok\":\"{}\"}}\n", "b".repeat(64))
        );
    }

    #[test]
    fn standalone_hashd_stub_answers_canned_and_malformed() {
        let stub = spawn_hashd_stub(HashdReply::Canned("c".repeat(64)));
        assert_eq!(
            ask_hashd(stub.path(), 42),
            format!("{{\"ok\":\"{}\"}}\n", "c".repeat(64))
        );
        let mut s = UnixStream::connect(stub.path()).expect("connect");
        std::io::Write::write_all(&mut s, b"garbage\n").expect("write");
        let mut line = String::new();
        let _n = BufReader::new(s).read_line(&mut line).expect("read");
        assert_eq!(
            line,
            "{\"error\":{\"kind\":\"generic\",\"message\":\"malformed request\"}}\n"
        );
    }

    #[test]
    fn stub_socket_binds_and_serves_one_roundtrip() {
        let stub = StubSocket::bind("fake-daemon");
        let listener = stub.listener().try_clone().expect("clone listener");
        let path = stub.path().to_path_buf();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut line = String::new();
            let _n = BufReader::new(&mut conn).read_line(&mut line).expect("read");
            let _ = conn.write_all(b"hostile\n");
        });
        let mut c = UnixStream::connect(&path).expect("connect");
        c.write_all(b"status\n").expect("write");
        let mut line = String::new();
        let _n = BufReader::new(&mut c).read_line(&mut line).expect("read");
        assert_eq!(line, "hostile\n");
        server.join().expect("server thread");
        let state_file = stub.scratch("state.json");
        assert!(state_file.starts_with(stub._root.path()));
    }
}
