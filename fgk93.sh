#!/usr/bin/env bash
# fgk93.sh — diagnose `fuse-client restart` (issue #93) on the real host.
#
# Three suspects from the code audit; this run discriminates them:
#   S1  the SIGTERM'd policy server ORPHANS its supervised fused (the
#       stored-for-reaping child is never reaped — no reaping code
#       exists), leaking one fused per restart.
#   S2  the respawned server inherits the CLIENT's environment, not the
#       orchestrator's — a stack running with FUSE_GATEKEEPER_POLICY
#       (run-agent always sets it) respawns on the DEFAULT store:
#       grants lost, salt rotated, every container-visible inner name
#       changed => "a broken configuration".
#   S3  mount/socket cleanup races (stale mount blocking the new fused).
#
# The stack here deliberately uses a NON-default policy store — that is
# the probe for S2. Nothing global is touched except, if S2 fires, a
# freshly-created default store at ~/.local/state/gatekeeper/ (reported).
#
# Usage:  ./fgk93.sh [repo]     Logs to ./fgk93-<ts>/ next to your cwd.

set -u

REPO="${1:-}"
if [ -z "$REPO" ]; then
    if [ -d "$HOME/projects/agent-scripts/workspace/crates/fuse-server" ]; then
        REPO="$HOME/projects/agent-scripts/workspace"
    elif [ -d "$PWD/crates/fuse-server" ]; then
        REPO="$PWD"
    else
        echo "usage: $0 [path-to-agent-scripts-workspace]" >&2; exit 2
    fi
fi

TS="$(date +%Y%m%d-%H%M%S)"
W="$PWD/fgk93-$TS"
LOG="$W/report.log"
mkdir -p "$W/run"
exec > >(tee -a "$LOG") 2>&1

echo "== fgk93: restart diagnosis (issue #93) $(date -Is) =="
echo "repo: $REPO   workdir: $W   kernel: $(uname -r)  uid: $(id -un)"

# 0. clean build — cross-environment artifacts in a shared target dir
#    are the known trap; a clean build guarantees intent.
echo "-- cargo clean + build (server, fused, client)..."
(cd "$REPO" && cargo clean && cargo build -p fuse-server -p fuse-mount -p fuse-client) || exit 2
SRV="$REPO/target/debug/fuse-server"
FUSED="$REPO/target/debug/fused"
FC="$REPO/target/debug/fuse-client"

MNT="$W/mnt"; mkdir -p "$MNT"
POLICY="$W/policy.json"          # NON-default on purpose (S2 probe)
STATE="$W/state.json"            # what run-agent would have written
SOCK="$W/run/cmd.sock"; ORACLE="$W/run/oracle.sock"
SECRET="$W/secret.bin"; head -c 4096 /dev/urandom > "$SECRET"

echo "-- starting stack (policy store: $POLICY — deliberately non-default)..."

# 1. spawn the policy daemon exactly like a real stack: own sockets,
#    own policy store via env, supervised fused via --mount-point,
#    three-word --secret.
FUSE_GATEKEEPER_POLICY="$POLICY" RUST_LOG=info \
"$SRV" --socket "$SOCK" --oracle-socket "$ORACLE" \
      --mount-point "$MNT" --log-path "$W/server.log" \
      --secret s "$SECRET" 4d1863212d8e6c1ad12d7b1f2f2b3a5c9e0f1a2b3c4d5e6f708192a3b4c5d6e7f \
      > "$W/server.stdout" 2>&1 &
SRV_PID=$!

# mount is up when stat -f reports fuse (never `ls` — it succeeds on
# the pre-mount dir; the #54 lesson)
for i in $(seq 1 300); do
    stat -f -c %T "$MNT" 2>/dev/null | grep -q fuse && break
    sleep 0.1
done
stat -f -c %T "$MNT" | grep -q fuse || { echo "FATAL: mount never came up"; tail -5 "$W/server.log"; exit 1; }

# 2. the state file, field-for-field like run-agent's orchestrator
cat > "$STATE" <<EOF
{
  "version": "0.33.0",
  "server_pid": $SRV_PID,
  "server_binary": "$SRV",
  "mount_point": "$MNT",
  "socket": "$SOCK",
  "log_level": "info",
  "pending_timeout": 10,
  "runtime_wrapper": null,
  "oracle_socket": "$ORACLE",
  "secrets": [
    { "fuse_name": "s", "host_path": "$SECRET",
      "hash": "4d1863212d8e6c1ad12d7b1f2f2b3a5c9e0f1a2b3c4d5e6f708192a3b4c5d6e7f" }
  ]
}
EOF

snapshot() {
    local tag="$1"
    echo "--- snapshot: $tag"
    echo "    server pids:      $(pgrep -f "$SRV --socket $SOCK" | tr '\n' ' ')"
    echo "    fused pids:       $(pgrep -f "$FUSED --mount-point $MNT" | tr '\n' ' ')"
    echo "    mount listed:     $(grep -c " $MNT " /proc/mounts)"
    echo "    stat -f:          $(stat -f -c %T "$MNT" 2>&1)"
    echo "    readdir:          $(ls "$MNT" 2>&1 | tr '\n' ' ')"
    echo "    scratch policy:   $( [ -f "$POLICY" ] && python3 -c "import json;print(' '.join(json.load(open('$POLICY')).get('secrets',{}).keys()))" 2>/dev/null || echo missing)"
    echo "    default store:    $HOME/.local/state/gatekeeper/policy.json $([ -f "$HOME/.local/state/gatekeeper/policy.json" ] && echo EXISTS || echo absent)"
    echo "    cmd socket alive: $("$FC" --socket "$SOCK" version </dev/null 2>/dev/null | head -1)"
    echo "    inner names:      $(python3 -c "import json;print(' '.join(s.get('inner','?') for s in json.load(open('$POLICY')).get('secrets',[])))" 2>/dev/null)"
}

snapshot "before restart"
INNER_BEFORE=$(python3 -c "import json;print(' '.join(s.get('inner','?') for s in json.load(open('$POLICY')).get('secrets',[])))" 2>/dev/null)
FUSED_BEFORE=$(pgrep -f "$FUSED --mount-point $MNT" | wc -l)

# 3. THE RESTART — the client reads the stack from the state file
echo
echo "===== running: fuse-client restart ====="
FUSE_GATEKEEPER_STATE="$STATE" timeout 120 "$FC" --socket "$SOCK" restart </dev/null
echo "restart exit: $?  (elapsed shown above if slow)"
echo

sleep 3
snapshot "after restart #1"
INNER_AFTER=$(python3 -c "import json;print(' '.join(s.get('inner','?') for s in json.load(open('$POLICY')).get('secrets',[])))" 2>/dev/null)
FUSED_AFTER=$(pgrep -f "$FUSED --mount-point $MNT" | wc -l)

echo
echo "===== verdicts ====="
echo "S1 orphaned fused per restart: before=$FUSED_BEFORE after=$FUSED_AFTER $([ "$FUSED_AFTER" -gt "$FUSED_BEFORE" ] && echo '<< LEAK CONFIRMED' || echo '(no leak)')"
if [ -f "$HOME/.local/state/gatekeeper/policy.json" ]; then
    echo "S2 default store EXISTS after restart: $HOME/.local/state/gatekeeper/policy.json << ENV LOSS CONFIRMED (respawn ignored the stack's FUSE_GATEKEEPER_POLICY)"
else
    echo "S2 default store absent — respawn used the stack's own policy (no env loss)"
fi
if [ "$INNER_BEFORE" = "$INNER_AFTER" ] && [ -n "$INNER_BEFORE" ]; then
    echo "inner names stable: $INNER_BEFORE"
else
    echo "inner names CHANGED: '$INNER_BEFORE' -> '$INNER_AFTER' << container symlinks all break"
fi
echo "S3 mount after restart: $(stat -f -c %T "$MNT" 2>&1) / listed=$(grep -c " $MNT " /proc/mounts)"

# 4. a second restart doubles the evidence (S1 accumulates)
echo
echo "===== running: restart #2 (leak accumulation check) ====="
FUSE_GATEKEEPER_STATE="$STATE" timeout 120 "$FC" --socket "$SOCK" restart </dev/null
sleep 3
echo "fused pids after restart #2: $(pgrep -f "$FUSED --mount-point $MNT" | tr '\n' ' ') (was $FUSED_AFTER)"
snapshot "after restart #2"

echo
echo "===== all logs ====="
for f in "$W"/server.log "$W"/server.stdout "$W"/fuse-gatekeeper-client.log; do
    [ -f "$f" ] && { echo "--- $f (tail)"; tail -25 "$f"; }
done
echo "full logs: $W"
echo "== done $(date -Is) =="
