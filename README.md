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
| `fuse-server` | `fuse-server` | POLICY daemon: decisions, pendings, grants, servatui command socket |
| `fuse-mount` | `fused` | DATA daemon: secret bytes + FUSE mount; asks the policy daemon per read |
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

> **Package hashing (grant-forever) needs capabilities.** Following
> `/proc/<pid>/map_files` — the only TOCTOU-safe source for a reader's
> loaded package — requires `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE`
> in the *initial* user namespace (kernel `fs/proc/base.c`). Neither
> ptrace rights nor a rootless user namespace suffice, and file
> capabilities (`setcap`) only work where the launching session's
> capability BOUNDING set contains the cap (many user sessions trim it).
> The reliable least-privilege deployment is a system-level unit — the
> bounding set descends full from PID 1:
>
> ```ini
> [Service]
> User=youruser
> AmbientCapabilities=CAP_CHECKPOINT_RESTORE
> CapabilityBoundingSet=CAP_CHECKPOINT_RESTORE
> ExecStart=/path/to/fuse-server ...
> ```
>
> (Launching under `sudo`/root also works — real root holds
> `CAP_SYS_ADMIN`.) With the capability in place, grant-forever can
> whitelist observed package hashes.

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

## Package hashing — optional hashd helper

Reader package hashes (the input to grant-forever) require following
`/proc/<pid>/map_files`, which demands `CAP_SYS_ADMIN` or
`CAP_CHECKPOINT_RESTORE` in the *initial* user namespace — more
privilege than the deliberately-unprivileged fuse-server may hold.
The server delegates to the optional `hashd` helper over
`/run/fuse-hashd.sock`; with no hashd deployed the lookup fails and
grant-forever names the fix:

```text
fuse-client grant-forever 7
Error: pending access 7 has no package hash — hashd unreachable — No such file or directory (os error 2). (Re)start hashd now:
  sudo install -m 755 <build-dir>/hashd /usr/local/bin/hashd
  sudo systemctl stop fuse-hashd.service 2>/dev/null; sudo systemctl reset-failed fuse-hashd.service 2>/dev/null
  sudo systemd-run --unit=fuse-hashd /usr/local/bin/hashd --socket /run/fuse-hashd.sock
Or install it permanently (one-time, root):
  sudo install -m 755 target/{debug,release}/hashd /usr/local/bin/hashd
  sudo install -m 644 crates/hashd/fuse-hashd.socket crates/hashd/fuse-hashd.service /etc/systemd/system/
  sudo systemctl daemon-reload && sudo systemctl enable --now fuse-hashd.socket
```

(The commands work in every state — hashd down, running but
unreachable, or a failed unit still occupying the name. Install before
`systemd-run`: on SELinux-enforcing systems a service cannot execute
binaries from `$HOME` — it fails with 203/EXEC.)

Deploying the helper (root once at install; systemd owns the socket,
the service carries exactly one capability; no polkit):

```sh
sudo install -m 644 crates/hashd/fuse-hashd.socket crates/hashd/fuse-hashd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now fuse-hashd.socket
```

The technical reason for a missing hash only goes to the server log.

## Threat model

The gate's goal is **containment**: a confused, overly eager actor
inside the agent container must not spread secrets to the outside
world. It provides:

- one-read-per-secret with binary-hash verification; every other
  reader pends for manual approval
- package identity — the executable plus every mapped library, read
  through `/proc/<pid>/map_files` (the mapped inodes, never on-disk
  paths, failing closed on anything unreadable)
- two grant tiers: one-shot manual grants (strict) and
  grant-forever (convenience)

What it deliberately does **not** provide:

- **instance authorization** — grant-forever whitelists a package
  *class*, not the verified process: whoever can later execute the
  same executable + libraries inherits the access
- **defense against full container compromise** — an actor
  controlling env, argv, DNS and the trust stores can coerce any
  credentialed client; that tier is mitigated in the consuming
  binary (below), not in the gate
- **memory identity** — JIT-generated (anonymous executable) pages
  are outside the hash by construction; the hash is a *package*
  identity

## Using a forever-granted secret securely

A binary that gets grant-forever should be built to:

1. **Be closed-mouth**: the secret never appears on stdout/stderr,
   in logs, in verbose output, or in error paths.
2. **Restrict its operations**: confine what it does *with* the
   credential — otherwise the actor drives a confused deputy that
   acts as you.
3. **Harden its memory**: `prctl(PR_SET_DUMPABLE, 0)` at startup (as
   ssh-agent does) — blocks core dumps and `/proc/<pid>/mem` even
   for same-uid attackers. The flag resets on `execve`: set it
   yourself, re-set after exec.
4. **Pin the peer**: verify the destination's leaf public key
   (compiled in), ignore environment-overridable CA paths
   (`SSL_CERT_FILE` and friends), hard-fail on certificate change,
   never fall back to plain HTTP. HTTPS alone is **not** sufficient —
   with container control the actor owns the trust store, and a fake
   endpoint receives the credentials as Basic auth after its own TLS
   termination.
5. **Strongest form**: keep the credentialed client outside the
   compromisable container — a host-side proxy performing approved
   actions on the container's behalf, so the secret never enters the
   container at all.

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
