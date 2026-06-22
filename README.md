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

# 2. Run
./target/release/run-agent \
    9f86d081884c7d65... \
    production.yaml \
    goose
```

`run-agent` will:
1. Spawn `fuse-server` (mounting the secret, gated by the hash)
2. Symlink the config file into the container's config dir
3. Launch the container (docker or podman, detected automatically)
4. On container exit, **auto-reset** the counter via `fuse-client`
5. Clean up the symlink

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
run-agent [OPTIONS] <BINARY_CHECKSUM> <HOST_CONFIG_FILE> <AGENT_SUBFOLDER> [CONTAINER_ARGS]...

Arguments:
  <BINARY_CHECKSUM>    SHA-256 of the allowed agent binary
  <HOST_CONFIG_FILE>   Host path to the secret config file
  <AGENT_SUBFOLDER>    Guest subfolder under ~/.config/ (e.g. `goose`)

Options:
      --fuse-server <PATH>   Path to fuse-server binary [default: fuse-server]
      --image <NAME>         Container image name [default: agentbox]
      --memory <LIMIT>       Container memory limit [default: 224G]
      --cpus <N>             Container CPU limit [default: 90]
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
