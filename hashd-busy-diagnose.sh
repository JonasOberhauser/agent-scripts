#!/usr/bin/env bash
# hashd-busy-diagnose.sh — why does ask() classify BUSY?
# Busy means: hashd accepted the connection but answered NOTHING within
# 500ms (the client's read timeout). This script measures, on YOUR host:
#   1. which protocol generation the running hashd speaks (old text vs JSON)
#   2. how long a REAL hash of a real process takes
#   3. what the new client library would classify
# Everything logs to ./hashd-diag-<timestamp>/report.log.

set -u

TS="$(date +%Y%m%d-%H%M%S)"
W="$PWD/hashd-diag-$TS"
mkdir -p "$W"
LOG="$W/report.log"
exec > >(tee -a "$LOG") 2>&1

SOCK="${1:-/run/fuse-hashd.sock}"

echo "== hashd busy diagnosis $(date -Is) =="
echo "socket: $SOCK"
echo "kernel: $(uname -r)  uid: $(id -u)"
echo

probe() {
    echo "--- $*"
    echo "    \$ $*"
    "$@"
    echo "    -> exit $?"
}

# 1. What is running, and which generation is it?
echo "===== 1. the running hashd ====="
pgrep -a hashd || echo "(no hashd process found)"
echo
probe "status request (protocol generation)" \
    sh -c "printf 'status\\n' | timeout 2 socat - UNIX-CONNECT:'$SOCK' | head -c 120; echo"
echo "(JSON {\"status\":...} = NEW; 'status privileged follows...' = OLD)"
echo

# 2. Time a REAL hash of a real, representative process: this shell's
#    parent-ish python if present, else init. Pick a real reader-like
#    pid: the biggest node/python/go process you have running.
echo "===== 2. real hash timing ====="
CAND="$(pgrep -n -f 'node|python|goose|agent' || pgrep -n bash || echo 1)"
echo "hashing pid $CAND ($(tr -d '\0' < /proc/$CAND/comm 2>/dev/null || echo '?'))"
python3 - "$SOCK" "$CAND" <<'PY'
import socket, sys, time
sock, pid = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX); s.settimeout(10)
s.connect(sock)
t0 = time.time()
s.sendall(("hash %s\n" % pid).encode())
chunks = b''
try:
    while True:
        d = s.recv(4096)
        if not d: break
        chunks += d
except Exception as e:
    print("RECV FAILED after %.0f ms: %s" % ((time.time()-t0)*1000, e))
dt = (time.time()-t0)*1000
print("hash took %.0f ms  (client timeout: 500 ms)" % dt)
print("reply[:120]: %r" % chunks[:120])
print()
if dt > 500:
    print("VERDICT-CANDIDATE: hashing alone exceeds the 500 ms ask() read")
    print("timeout -> every ask classifies Busy regardless of health.")
PY
echo

# 3. The sizes behind that timing: what a reader of this scale maps.
echo "===== 3. how much file-backed memory the target maps ====="
awk '$6 ~ /^\// {print $6}' /proc/$CAND/maps 2>/dev/null | sort -u | \
    xargs -r stat -c '%s %n' 2>/dev/null | sort -rn | head -8
TOTAL=$(awk '$6 ~ /^\// {print $6}' /proc/$CAND/maps 2>/dev/null | sort -u | \
    xargs -r stat -c '%s' 2>/dev/null | paste -sd+ | bc 2>/dev/null)
echo "unique file-backed bytes total: ${TOTAL:-?}"
echo
echo "logs: $W"
