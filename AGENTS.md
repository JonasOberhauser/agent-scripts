# AGENTS.md

## Versioning

The workspace version in `Cargo.toml` (`[workspace.package] version`) is the
**protocol version** shared between `fuse-client` and `fuse-server`. Both
crates use `version.workspace = true` and access it at runtime via
`fuse_protocol::VERSION`.

**Increment the minor version for every build** that changes either the client
or the server. This ensures the client detects version mismatches and can offer
to restart the server.

The version follows semantic versioning:
- **Major**: incompatible protocol changes (commands removed/renamed)
- **Minor**: new features, new commands, behavior changes
- **Patch**: bug fixes with no protocol impact

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
cargo test -p fuse-server                # fuse-server only (unit + e2e)
cargo test -p fuse-server --test fuse_e2e -- --include-ignored  # e2e (needs /dev/fuse)
cargo clippy --workspace                 # zero warnings required
```

The workspace has four crates: `fuse-protocol`, `fuse-server`, `fuse-client`, `run-agent`.

## Architecture

- **fuse-server**: FUSE gatekeeper filesystem + Unix socket CRUD server. Mounts
  at `/tmp/fuse-gatekeeper-mnt`, listens on `/tmp/fuse-gatekeeper.sock`. Enforces
  one-read-per-secret with binary-hash verification and forward-only multi-chunk
  reads.
- **run-agent** (orchestrator): Spawns/reuses the fuse-server, loads secrets via
  socket, launches a podman/docker container with symlinks pointing into `/fuse`.
- **fuse-client**: CLI to send CRUD commands (status, reset, add, remove) to the
  socket server.
- **fuse-protocol**: Shared types, `SystemIo` trait, `RealSystemIo` /
  `MockSystemIo` implementations.

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
