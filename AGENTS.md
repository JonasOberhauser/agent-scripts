# AGENTS.md

## Versioning

The workspace version in `Cargo.toml` (`[workspace.package] version`) is the
**protocol version** shared between `fuse-client` and `fuse-server`. Both
crates use `version.workspace = true` and access it at runtime via
`fuse_protocol::VERSION`.

The version follows semantic versioning:
- **Major**: incompatible protocol changes (commands removed/renamed)
- **Minor**: new features, new commands, behavior changes
- **Patch**: bug fixes with no protocol impact

Bump **minor** only when the protocol changes; other changes to
client/server still bump the **patch** version so builds stay
distinguishable. The version handshake ignores the patch component and
compares only major & minor — patch releases never force a restart of
the long-running shared server.

On startup, `fuse-client` sends `GetVersion` to the running server. If the
versions differ, the client offers to restart the server:
1. Reads `/tmp/fuse-gatekeeper-state.json` (written by the orchestrator)
2. Kills the old server, starts the new one with the same configuration
3. Re-adds all secrets from the state file's host paths
4. If the state file is missing or unreadable: offers a clean reset

## Build & Test

```sh
cargo build                              # build all crates
cargo test                               # run all tests
cargo test -p fuse-server                # fuse-server only (unit)
cargo clippy --workspace                 # zero warnings required
```

The workspace has six crates: `fuse-protocol`, `fuse-server`, `fuse-client`, `run-agent`, `hashd`, `fuse-mount`.

## Architecture

- **fuse-server**: POLICY daemon — trust decisions (one-read, package hashes via hashd, pendings, grants), the servatui command socket, and the oracle endpoint the data daemon connects to. Holds NO secret bytes — secrets register by host PATH, and content reaches readers only as descriptors handed to the data daemon at open time (transparent reads). Mounts
  at `/tmp/fuse-gatekeeper-mnt`, listens on `/tmp/fuse-gatekeeper.sock`. Enforces
  one adjudicated OPEN per read cycle: binary-hash verification, pendings and the
  one-read counter all run at open; the open is answered with a host fd passed
  as SCM_RIGHTS.
- **run-agent** (orchestrator): Spawns/reuses the fuse-server, registers secret
  host paths via socket, launches a podman/docker container with symlinks pointing
  into `/fuse`.
- **fuse-client**: CLI to send CRUD commands (status, reset, add, remove) to the
  socket server.
- **fuse-protocol**: Shared types, `SystemIo` trait, `RealSystemIo` /
  `MockSystemIo` implementations.
- **fuse-mount** (`fused`): DATA daemon — holds the FUSE mount; every OPEN is adjudicated by the policy daemon, which answers with a host fd (SCM_RIGHTS); reads are plain preads of that descriptor and store NO content. Either half alone is useless; the mount survives policy restarts.
- **hashd**: optional socket-activated helper (`pid → sha256 of its loaded
  package`) so the unprivileged fuse-server can hash readers for
  grant-forever; needs CAP_CHECKPOINT_RESTORE in the initial user
  namespace (kernel `fs/proc/base.c` gate on `/proc/<pid>/map_files`).
  Not deployed by default: without it the lookup fails and grant-forever
  answers with a bare not-supported message (the reason only goes to the
  server log). Protocol: `fuse_protocol::hashd`; units in `crates/hashd`.

## Threat Model

Goal: **containment** — a confused, overly eager actor inside the agent
container must not spread secrets to the outside world. The gate
provides anonymized container-view names (issue #47: the container
sees only per-install salted hashes of the path components — the salt
comes from `/dev/urandom`, is persisted in the policy store, and the
server refuses rather than degrade to a guessable one; host-side
status, grants and pendings stay in clear names),
one-read semantics (one adjudicated OPEN per read cycle;
within an open, reads are re-preads of the same descriptor — same-bytes
re-reads carry no new information, but an in-place host rewrite of the
same inode DOES stream new bytes into an already-adjudicated open:
accepted), package identity (`map_files` inodes,
fail-closed), pendings with manual grants, and grant-forever as a
convenience tier.

Limits every contributor must know:

- the container sees the FLAT anonymized view (one directory, one
  whole-path salted hash per secret — #47/#58): no host layout, depth,
  or fan-out leaks; what remains visible is the NUMBER of secrets and
  their sizes and modes; losing the policy store (corrupt-aside fresh
  start) loses the salt and rotates every inner name until the next
  run-agent re-links.
- grant-forever authorizes a package **class**, not the verified
  instance: whoever can later execute the same executable + libraries
  inherits the access.
- Full container compromise (env/argv/DNS/trust-store control) is out
  of scope; a credentialed client under that control can be coerced.
  Mitigations belong in the consuming binary: closed-mouth,
  operation-restricted, `PR_SET_DUMPABLE=0`, compiled-in leaf-key
  pinning (HTTPS against an attacker-owned CA store is no protection),
  or keeping the credentialed client outside the container entirely.
- Package hashing is file-backed identity; anonymous executable pages
  (JIT) are outside the hash by construction.

**Persistence (MR5)** — approvals, permitted hashes with provenance,
and one-read access state live in the daemon-owned policy store
(`$FUSE_GATEKEEPER_POLICY`, else `$XDG_STATE_HOME/gatekeeper/policy.json`,
`0600`): loaded once at startup before any socket accepts,
write-through on every mutation (never a shutdown flush — `kill -9`
has no hook). Operational consequences:

- **Killing the daemons no longer resets approvals** — what used to be
  an implicit reset (kill the gatekeeper, budgets come back) is gone;
  access state persists. Treat "restart to clear a grant" as dead.
- The CLI is the editor, restart is the reload; hand-edits are the
  stop-daemon → edit → start escape hatch, never concurrent.
- Corruption fails SAFE: unparsable stores are renamed aside and the
  daemon starts fresh (affected reads pend again); UNREADABLE stores
  refuse to arm persistence — nothing overwrites a store the daemon
  could not read until a human looks.
- Host files missing at load become ghosts: policy intact, opens
  ENOENT until the file returns or a re-add joins the hash set.

Do not weaken these properties without updating this section.

## Testing Philosophy

### Mocks must simulate real-world scenarios, not just happy paths

Mocks exist to test logic quickly without external dependencies, but they are
**useless if they abstract away the failure surface**. Every mock must reflect
how the real system actually behaves — including error paths, stale state,
permission issues, and edge cases that occur in production.

When writing or modifying mocks:

1. **Simulate stale state.** Tests must cover scenarios where a previous run
   left behind stale files, sockets, or mount points. Pre-populate the mock's
   filesystem with leftover artifacts and verify that cleanup logic handles
   them. A test that always starts from clean state proves nothing about
   recovery.

2. **Simulate failure modes.** `spawn_independent` should not always return
   `Ok`. Add scenarios where the spawned process crashes, the socket never
   appears, or bind fails with `EADDRINUSE`. The orchestrator must handle
   these gracefully.

3. **Validate program input where possible.** If the real command is
   `sudo -n fuse-server --allow-other`, the mock should let tests assert that
   the correct flags are present (or absent). Record the full argv and provide
   assertions on its contents — don't just accept whatever is passed.

4. **Test negative paths.** For every "X succeeds" test, write a corresponding
   "X fails" test: wrong hash denied, second read from different PID denied,
   backward chunk read denied, stale socket removed, root-owned file cleaned
   up. If the code has an `if` or `match` arm, there must be a test for it.

5. **Encode correct expectations, not the current behavior.** A test that
   asserts buggy behavior "passes" but is worthless. Before writing a test,
   ask: "Is this the *desired* behavior, or am I just mirroring the
   implementation?" If the implementation is wrong, fix both.

### Understanding real system behavior

Before mocking a system interaction, **understand how the real system behaves**.
Do not guess. The agent should:

- **Interact with real commands** to observe behavior firsthand. Run `man
  sudo`, `fusermount --help`, `podman run --help`, `stat -f /tmp`, etc. to
  understand flags, error codes, and edge cases.

- **Read manuals and documentation.** `man` pages, `--help` output, and
  upstream docs (e.g., kernel FUSE docs, podman man pages) are authoritative
  sources for understanding error codes, permission requirements, and
  namespace behavior.

- **Search forums and issue trackers.** When behavior is surprising (e.g.,
  FUSE bind mounts into containers, rootless podman UID mapping, sudo without
  a terminal), search GitHub issues, Stack Overflow, and mailing lists. Others
  have hit the same walls.

- **Test real behavior when possible.** If `/dev/fuse` is available, run the
  e2e tests to verify the FUSE filesystem actually works through the kernel.
  If podman is available, verify that container UID mapping behaves as
  expected. Real interaction reveals bugs that mocks never will.

### What mocks cannot cover (and what to do about it)

| Concern | Mock limitation | Mitigation |
|---|---|---|
| FUSE kernel behavior | MockSystemIo doesn't mount | `do_*` methods extract logic for unit testing; `tests/fuse_e2e.rs` tests real mounts |
| Process spawning | Mock returns fake PID, always succeeds | Assert argv contents in mock; test error paths with configurable failures |
| File ownership/permissions | Mock has no real permissions | Test stale-state recovery logic; document permission requirements |
| Container UID mapping | Mock doesn't run containers | Document rootless podman behavior; test `allow_other` flag logic |
| Stale state from previous runs | Mock starts clean | Pre-populate mock state to simulate leftovers |

When a bug is found in production that tests missed, **add a test that would
have caught it** before fixing the bug. This ensures the regression is
permanently guarded against.

**Read the test run, don't just see it green.** Before running, state the
expected test COUNT derived from what you changed (n new tests → old + n).
After running — locally or in CI — verify the number and that the new test
NAMES actually appear. A silently no-op'd patch (missed conflict hunk,
failed string replace, empty commit) otherwise hides as "still green, one
test short". A green run you didn't count is a green run you didn't check.
