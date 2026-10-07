#!/usr/bin/env bash
# fgk54.sh — validate the stale-mount world model against a REAL killed fused (issue #54).
#
# What the orchestrator's mock assumes (real_io.rs, PathState model):
#   claim 1: after fused dies (kill -9), the mountpoint stays behind as a
#            dead mount — stat fails with ENOTCONN, mkdir fails with EEXIST
#   claim 2: fusermount -uz (lazy unmount) succeeds on that dead mount
#   claim 3: after the lazy unmount, the mountpoint is a plain directory
#            (normal owner/perms, usable) — the mock's PathState::Dir
#
# This script runs the real daemons, kills them in the crash order
# (policy first so nothing respawns fused, then fused itself), observes
# the kernel's actual answers at each step, and prints a summary table.
#
# Usage:   ./fgk54.sh [path-to-agent-scripts-repo]
#          (default repo: ~/projects/agent-scripts, or $PWD if it looks
#           like the repo)
# Output:  everything goes to ./fgk54-<timestamp>/ next to your cwd —
#          report.log (all observations), server.log, fused.log,
#          policy.json — keep or delete that folder when done.

set -u  # unset variables are bugs — but NOT -e: failed stat/mount are the
        # very observations we want to record, they must not abort the run

# ── 0. Locate the repo and the built binaries ──────────────────────────
REPO="${1:-}"
if [ -z "$REPO" ]; then
    if [ -d "$HOME/projects/agent-scripts/crates/fuse-server" ]; then
        REPO="$HOME/projects/agent-scripts"
    elif [ -d "$PWD/crates/fuse-server" ]; then
        REPO="$PWD"
    else
        echo "usage: $0 [path-to-agent-scripts-repo]" >&2; exit 2
    fi
fi
SRV="$REPO/target/debug/fuse-server"
FUSED="$REPO/target/debug/fused"
echo "cargo clean (stale cross-environment artifacts are the known trap)..."
(cd "$REPO" && cargo clean) || exit 2
echo "building fuse-server + fused + fuse-client from a clean target..."
(cd "$REPO" && cargo build -p fuse-server -p fuse-mount -p fuse-client) || exit 2

# ── 1. One scratch folder per run, in the directory you ran me from ────
TS="$(date +%Y%m%d-%H%M%S)"
W="$PWD/fgk54-$TS"
mkdir -p "$W/run"          # sockets
MNT="$W/mnt"               # the FUSE mountpoint
mkdir -p "$MNT"
LOG="$W/report.log"
head -c 4096 /dev/urandom > "$W/secret.bin"   # the one secret we serve

# Every line the script produces from here on goes to the terminal AND
# report.log — nothing is only-on-screen.
exec > >(tee -a "$LOG") 2>&1

echo "== fgk54: stale-mount world validation (issue #54) =="
echo "time:        $(date -Is)"
echo "repo:        $REPO"
echo "workdir:     $W"
echo "kernel:      $(uname -r)"
echo "uid:         $(id -u) ($(id -un))"
echo "fusermount:  $(command -v fusermount3 || echo none) $(command -v fusermount || echo none)"
echo

# probe NAME CMD... — run one observation, always show exit code + output
probe() {
    local what="$1"; shift
    echo "--- $what"
    local out rc
    out="$("$@" 2>&1 </dev/null)"; rc=$?
    echo "    \$ $*"
    echo "    -> exit $rc: ${out:-<no output>}"
}

# ── 2. Start the policy daemon (fuse-server) ───────────────────────────
# Same shape the e2e harness uses: own sockets, own policy store, one
# --secret, nothing global. All daemon output to files in $W.
FUSE_GATEKEEPER_POLICY="$W/policy.json" \
RUST_LOG="fuse_server=info,fuse_mount=info" \
"$SRV" \
    --socket "$W/run/cmd.sock" \
    --oracle-socket "$W/run/oracle.sock" \
    --pending-timeout 5 \
    --log-path "$W/server.log" \
    --secret "s:$W/secret.bin:aa" \
    > "$W/server.stdout" 2>&1 &
POLICY_PID=$!
echo "policy daemon pid $POLICY_PID"

# Wait for the command socket to answer. fuse-client 'version' prints
# "(server not running)" via its offline fallback while dead, so we
# poll until that string disappears.
FC="$REPO/target/debug/fuse-client"
for i in $(seq 1 100); do
    if "$FC" --socket "$W/run/cmd.sock" version </dev/null 2>/dev/null | grep -q "not running"; then
        sleep 0.1
    else
        break
    fi
done
probe "cmd socket alive (fuse-client version)" \
    "$FC" --socket "$W/run/cmd.sock" version

# ── 3. Start the data daemon (fused) and wait for the mount ────────────
RUST_LOG=info "$FUSED" \
    --mount-point "$MNT" \
    --oracle-socket "$W/run/oracle.sock" \
    > "$W/fused.log" 2>&1 &
FUSED_PID=$!
echo "data daemon pid $FUSED_PID"

# The mount is up when stat -f reports the FUSE fs — plain `ls` would
# succeed on the pre-mount directory and observe the wrong world.
for i in $(seq 1 300); do
    if stat -f -c %T "$MNT" 2>/dev/null | grep -q fuse; then break; fi
    sleep 0.1
done

# ── 4. Observation A: the HEALTHY world (baseline) ─────────────────────
echo
echo "===== A. healthy stack (baseline) ====="
probe "mount listed in /proc/mounts" grep " $MNT " /proc/mounts
probe "stat -f mountpoint (fs type alive)" stat -f -c "type=%t fstype=%T" "$MNT"
probe "ls -ld mountpoint" ls -ld "$MNT"
probe "readdir" ls -la "$MNT"
INNER="$(ls "$MNT" 2>/dev/null | head -n1)"
echo "inner (anonymized) name served: ${INNER:-<none>}"
if [ -n "$INNER" ]; then
    probe "read first 16 bytes of the served secret" \
        sh -c "head -c 16 '$MNT/$INNER' | od -An -tx1"
fi

# ── 5. THE CRASH: policy first (nobody left to respawn fused), then fused
echo
echo "===== B. kill -9 both daemons (policy first, then fused) ====="
kill -9 "$POLICY_PID" 2>/dev/null; echo "kill -9 policy ($POLICY_PID): rc=$?"
sleep 1
# fused must still be alive with a dead policy: the mount outlives it.
probe "mount still alive after policy kill" stat -f -c "type=%t fstype=%T" "$MNT"
kill -9 "$FUSED_PID" 2>/dev/null; echo "kill -9 fused ($FUSED_PID): rc=$?"
sleep 2

# ── 6. Observation B: the KILLED world — what the kernel really left ───
echo
echo "===== C. stale mount after fused kill -9 ====="
probe "stat -f mountpoint (expect ENOTCONN if dead-mount)" stat -f "$MNT"
probe "stat mountpoint inode (owner/perms of the dir)" stat -c "mode=%A owner=%U:%G" "$MNT"
probe "ls -ld mountpoint" ls -ld "$MNT"
probe "readdir on dead mount" ls "$MNT"
probe "raw mkdir(2) on dead mount (Rust create_dir_all's first call; mock claims EEXIST 17)" mkdir "$MNT"
probe "mkdir -p same path (GNU coreutils stats FIRST — different algorithm)" mkdir -p "$MNT"
probe "mount still in /proc/mounts?" grep " $MNT " /proc/mounts

# ── 7. The recovery the orchestrator performs: lazy unmount ────────────
echo
echo "===== D. recovery: lazy unmount ====="
for tool in "fusermount3 -uz" "fusermount -uz" "umount -l"; do
    # try each until one succeeds — exactly the orchestrator's order
    echo "--- try: $tool $MNT"
    $tool "$MNT"
    echo "    -> exit $?"
    if grep -q " $MNT " /proc/mounts; then
        echo "    (still listed in /proc/mounts — trying next tool)"
    else
        echo "    (no longer in /proc/mounts — mount gone)"
        break
    fi
done

# ── 8. Observation C: what remains after the lazy unmount ──────────────
echo
echo "===== E. mountpoint after lazy unmount (the mock's PathState::Dir claim) ====="
probe "stat -f (plain dir answers with the parent fs)" stat -f -c "fstype=%T" "$MNT"
probe "stat inode (owner/perms — plain user dir? root 0700?)" stat -c "mode=%A owner=%U:%G" "$MNT"
probe "ls -ld" ls -ld "$MNT"
probe "readdir works now?" ls -la "$MNT"
probe "rmdir + mkdir (fully usable as a fresh mountpoint?)" sh -c "rmdir '$MNT' && mkdir '$MNT' && echo recreated-ok"
probe "left in /proc/mounts?" grep " $MNT " /proc/mounts

# ── 9. Summary — the three claims, with what your kernel actually said ─
echo
echo "===== summary (paste this back with report.log if asked) ====="
echo "claim 1 (dead mount: stat ENOTCONN / mkdir EEXIST): see sections C"
echo "claim 2 (fusermount -uz succeeds on the dead mount): see section D"
echo "claim 3 (afterwards: plain usable directory):        see section E"
echo "logs and scratch: $W"
