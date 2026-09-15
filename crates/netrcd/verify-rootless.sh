#!/usr/bin/env bash
# Rootless netrcd verification — run AFTER deploy-rootless.sh.
# Everything here is plain podman: no sudo, no systemd-run.
#   sh crates/netrcd/verify-rootless.sh
# Prediction: 6/6 PASS with SELinux enforcing.
# Logged to ~/.local/share/netrcd/verify.log.
set -u

BASE=${NETRCD_ROOT:-$HOME/.local/share/netrcd}
MCS=${NETRCD_MCS:-s0:c100,c200}
IMG=localhost/netrcd:latest
PASS=0; FAIL=0

mkdir -p "$BASE"
LOG="$BASE/verify.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== netrcd verify $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

ck() { # ck <desc> <want_ok:0|1> <cmd...>
  desc=$1; want_ok=$2; shift 2
  out=$("$@" 2>&1); rc=$?
  if { [ "$rc" -eq 0 ] && [ "$want_ok" -eq 0 ]; } || { [ "$rc" -ne 0 ] && [ "$want_ok" -eq 1 ]; }; then
    PASS=$((PASS+1)); echo "PASS  $desc"
  else
    FAIL=$((FAIL+1)); echo "FAIL  $desc (rc=$rc: $(echo "$out" | head -2))"
  fi
}

run_nrq() { # run_nrq <method> <machine> <path>
  podman run --rm --security-opt label=level=$MCS \
    -v $BASE/socket:/netrcd:Z $IMG \
    env NETRCD_SOCK=/netrcd/netrcd.sock nrq "$1" "$2" "$3"
}

echo "== connect through the MCS-pinned boundary =="
ck "boundary: GET /user reaches the pinned API (Bearer injected)" 0 \
  run_nrq GET api.github.com /user
ck "boundary: login field present in /user" 0 \
  sh -c "$(command -v podman) run --rm --security-opt label=level=$MCS -v $BASE/socket:/netrcd:Z $IMG env NETRCD_SOCK=/netrcd/netrcd.sock nrq GET api.github.com /user | grep -q '\"login\"'"

echo "== refusals (policy enforced daemon-side) =="
ck "unmatched path refused" 1 run_nrq GET api.github.com /not-allowed
ck "method mismatch refused (DELETE /user)" 1 run_nrq DELETE api.github.com /user
ck "unknown machine refused" 1 run_nrq GET evil.example.com /x

echo "== credential isolation =="
ck "client container holds no credential file" 0 \
  sh -c "! $(command -v podman) run --rm --security-opt label=level=$MCS -v $BASE/socket:/netrcd:Z $IMG sh -c 'test -e /etc/netrcd/netrc || grep -rq password /netrcd'"

echo
echo "VERDICT: $PASS pass, $FAIL fail"
[ "$FAIL" -eq 0 ] && echo "ROOTLESS: OK" || { echo "ROOTLESS: FAILED"; exit 1; }
