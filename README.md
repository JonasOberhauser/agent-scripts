# Agent Scripts (Rust)

A secure agent orchestration system that gates access to secret configuration
files via a FUSE filesystem. Only an approved binary (identified by SHA-256)
can read the secret, and only **once** per access cycle — a client can reset
the counter to allow the next agent.

## Architecture

```
┌──────────────── HOST ────────────────┐
│                                       │
│  run-agent ──► fuse-server ◄── fuse-client
│                   │    ▲               │
│          FUSE mount│    │ Unix socket  │
│                   ▼    │               │
│              fuse_mnt/                 │
│              secrets.yaml              │
│                   ▲                    │
│                   │bind-mount (ro)     │
│ ──────────────────┼────────────────────│
│              CONTAINER                 │
│              /fuse/secrets.yaml        │
│              (symlink from config/)    │
│              agent binary reads it     │
└─────────────────────────────────────────┘
```

| Crate | Binary | Role |
|-------|--------|------|
| `fuse-protocol` | — | Shared types, `IoProvider<I,O>` trait, `SystemIo`, `Transport` |
| `fuse-server` | `fuse-server` | FUSE gatekeeper filesystem + Unix socket CRUD server |
| `fuse-client` | `fuse-client` | CLI that sends commands to the server (reset, status, ...) |
| `run-agent` | `run-agent` | Orchestrator: starts server, launches container, auto-resets |

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt install libfuse3-dev fuse3 pkg-config

# You also need docker or podman for run-agent.
```

Rust 1.75+ (toolchain included via `rustup`).

## Build

```bash
cargo build --release
# Binaries land in target/release/{fuse-server,fuse-client,run-agent}
```

Run tests:

```bash
cargo test
```

## Quick Start

### Option A — One command (run-agent does everything)

```bash
# 1. Compute the SHA-256 of the binary you want to allow
sha256sum $(which goose)
# e.g. 9f86d081884c7d65...

# 2. Run (secret is passed as HOST:CONTAINER)
./target/release/run-agent \
    9f86d081884c7d65... \
    goose \
    --secret ~/prod-config.yaml:/root/.config/goose/production.yaml
```

`run-agent` will:
1. Spawn (or reuse) the shared `fuse-server`, loading the secret gated by the hash
2. Ensure a **persistent container** exists (named `agentbox-<hash>`, derived
   from the current directory; it stays alive between sessions)
3. `exec` into it: a setup script symlinks the secrets, then runs your command
   — with no extra arguments you get an **interactive bash shell**
4. **Pre-flight every secret** on both sides before the exec:
   - *host*: the source file must exist and the FUSE mount must answer a
     `stat` within 3s — a stale/dead mount aborts with unmount instructions
     instead of wedging the session.
   - *container*: `stat /fuse/<secret>` is probed via `exec` (with its own
     `timeout`); a stale bind — e.g. a box created before a host remount —
     is healed by a **stop/start** of the container, which re-applies the
     `-v` binds against the current mount and preserves all container data.
     Containers that exist but are stopped are `start`ed (never recreated).
5. On exit, **auto-reset** the one-read counter via `fuse-client`

Use `'*'` as the checksum to skip binary verification (simplest for manual
logins; real hashes need `--pidns-host` so the server can read `/proc/<pid>/exe`).

Lifecycle:
```bash
run-agent ... --restart-container   # recreate the box fresh
run-agent --stop                    # stop and remove it
```

### Option B — Manual step-by-step

**1. Start the FUSE server:**

```bash
mkdir -p fuse_mnt

./target/release/fuse-server \
    --mount-point fuse_mnt \
    --socket /tmp/fuse-gatekeeper.sock \
    --secret secrets.yaml:/path/to/secrets.yaml:9f86d081884c7d65... \
    --allow-other
```

Format: `--secret <NAME>:<FILE_PATH>:<SHA256_OF_ALLOWED_BINARY>`

**2. (In another terminal) Inspect / manage via the client:**

```bash
# Check which secrets are mounted and their read counts
./target/release/fuse-client --socket /tmp/fuse-gatekeeper.sock status

# List all secrets
./target/release/fuse-client list-mounts

# Reset the counter so another agent can read
./target/release/fuse-client reset --name secrets.yaml

# Reset all secrets at once
./target/release/fuse-client reset-all

# Dynamically add a new secret
./target/release/fuse-client add-secret token.yaml \
    --file /path/to/token.yaml \
    --hash abc123...

# Remove a secret
./target/release/fuse-client remove-secret token.yaml

# Rotate the allowed binary hash
./target/release/fuse-client rotate-hash secrets.yaml --hash newhash...
```

**3. Run your container** (mount `fuse_mnt` at `/fuse` read-only):

```bash
docker run -it --rm \
    -v "$(pwd)/fuse_mnt:/fuse:ro" \
    -v "$(pwd)/config:/root/.config/goose:slave,Z" \
    agentbox
```

Inside the container, the agent binary reads `~/.config/goose/secrets.yaml`,
which symlinks to `/fuse/secrets.yaml`. The FUSE server checks the binary's
SHA-256 and serves the content exactly **once**.

## How the gatekeeper works

1. **Binary hash check** — when a process reads the mounted file, the server
   hashes `/proc/<pid>/exe` and compares it to the allowed hash. Mismatch →
   `EACCES`.

2. **One-shot counter** — after a successful read, the counter increments to 1.
   Any further read attempt → `EACCES`.

3. **Reset** — `fuse-client reset` (or `run-agent` automatically on container
   exit) zeroes the counter, allowing the next agent to read.

## run-agent options

```
run-agent [OPTIONS] <BINARY_CHECKSUM> <AGENT_SUBFOLDER> [CONTAINER_ARGS]...

Arguments:
  <BINARY_CHECKSUM>    SHA-256 of the allowed agent binary, or '*' to skip
                       binary verification
  <AGENT_SUBFOLDER>    Guest subfolder under ~/.config/ (e.g. `goose`)
  [CONTAINER_ARGS]...  Command to run in the container; none = interactive bash

Options:
      --secret <HOST:CONTAINER>     Secret to serve through FUSE (repeatable).
                                    Directories are mapped recursively.
      --fuse-server <PATH>          Path to fuse-server binary [default: fuse-server,
                                    resolved next to run-agent first]
      --socket <PATH>               Unix socket [default: /tmp/fuse-gatekeeper.sock]
                                    [env: FUSE_GATEKEEPER_SOCKET]
      --mount-point <PATH>          FUSE mount point [default: /tmp/fuse-gatekeeper-mnt]
      --sudo                        Run fuse-server under sudo (implies --allow-other)
      --allow-other                 Let other UIDs read the mount (rootful runtimes)
      --pidns-host                  Share the host PID namespace (needed for real
                                    binary-hash verification)
      --runtime <RUNTIME>           Container runtime: auto, docker or podman [default: auto]
      --runtime-wrapper <CMD>       Wrap the runtime call (e.g. "flatpak-spawn --host")
      --image <NAME>                Container image name [default: agentbox]
      --memory <LIMIT>              Container memory limit [default: 224G]
      --cpus <N>                    Container CPU limit [default: 90]
      --log-level <LEVEL>           fuse-server log level [default: info]
      --stop                        Stop and remove the persistent container, then exit
      --restart-container           Recreate the persistent container from scratch
```

## Project layout

```
agents/
├── Cargo.toml                 # workspace root
├── crates/
│   ├── fuse-protocol/         # shared types + IoProvider<I,O> trait
│   ├── fuse-server/           # FUSE filesystem + socket server
│   ├── fuse-client/           # CLI client
│   └── run-agent/             # orchestrator
├── Dockerfile                 # agentbox container image
└── run-agent.sh               # original bash version (kept for reference)
```
