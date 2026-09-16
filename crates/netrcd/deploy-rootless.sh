#!/usr/bin/env bash
# Rootless netrcd deployment — no sudo anywhere.
#   cd <repo root>
#   ./crates/netrcd/deploy-rootless.sh [path-to-netrc]
# Defaults the credential source to ~/secrets/agent/github.netrc.
# A COPY is placed under ~/.local/share/netrcd/creds (never relabel
# the original); client containers only ever see the socket dir.
# Everything is logged to ~/.local/share/netrcd/deploy.log.
set -euo pipefail

NETRC_SRC=${1:-$HOME/secrets/agent/github.netrc}
BASE=${NETRCD_ROOT:-$HOME/.local/share/netrcd}
MCS=${NETRCD_MCS:-s0:c100,c200}
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)

mkdir -p "$BASE"
LOG="$BASE/deploy.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== netrcd deploy $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "log: $LOG"

[ -r "$NETRC_SRC" ] || { echo "credential not readable: $NETRC_SRC"; exit 1; }

mkdir -p "$BASE/socket/profiles.d" "$BASE/socket/config.d" "$BASE/creds"
install -m 600 "$NETRC_SRC" "$BASE/creds/netrc"

# Starter policy: api.github.com GET /user and /rate_limit, SPKI-pinned
# (the pair validated live against the real endpoint). Empty dirs
# would have the daemon refuse everything — confusing first contact.
if [ ! -e "$BASE/socket/profiles.d/api.github.com.toml" ]; then
cat > "$BASE/socket/profiles.d/api.github.com.toml" <<'EOF'
[[machine]]
name = "api.github.com"
auth = "bearer"
pins = [
  "sha256//ZSagvDzjltLkewXEBuDxIzpW/dpVw1Juvvmd0hhkzdY=",
  "sha256//S2LUIbq4yUg5w+MYbj5LZOWAZAzaeNGJ9rTTc4GjvBQ=",
]
EOF
cat > "$BASE/socket/config.d/api.github.com.toml" <<'EOF'
[[machine]]
name = "api.github.com"
rate = "30/min"

  [[machine.allow]]
  method = "GET"
  url = '/user'

  [[machine.allow]]
  method = "GET"
  url = '/rate_limit'
EOF
fi

echo "--- image build (first run takes several minutes) ---"
if ! podman build -f "$ROOT/crates/netrcd/Containerfile" -t localhost/netrcd:latest "$ROOT"; then
  echo "IMAGE BUILD FAILED — full output preserved in $LOG"
  exit 1
fi

mkdir -p "$HOME/.config/containers/systemd"
install -m 644 "$ROOT/crates/netrcd/quadlet/netrcd.container" \
  "$HOME/.config/containers/systemd/netrcd.container"

systemctl --user daemon-reload
if ! systemctl --user enable --now netrcd.service; then
  echo "UNIT FAILED TO START — diagnostics:"
  systemctl --user status netrcd.service || true
  journalctl --user -u netrcd.service -n 50 --no-pager || true
  echo "full log: $LOG"
  exit 1
fi

echo
echo "deployed (level $MCS). client recipe:"
echo "  podman run --rm --security-opt label=level=$MCS \\"
echo "    -v $BASE/socket:/netrcd:Z localhost/netrcd:latest \\"
echo "    env NETRCD_SOCK=/netrcd/netrcd.sock nrq GET api.github.com /user"
echo "verify with: sh $ROOT/crates/netrcd/verify-rootless.sh"
