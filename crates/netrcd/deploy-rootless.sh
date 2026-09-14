#!/bin/sh
# Rootless netrcd deployment — no sudo anywhere.
#   cd <repo root>
#   ./crates/netrcd/deploy-rootless.sh [path-to-netrc]
# Defaults the credential source to ~/secrets/agent/github.netrc.
# A COPY is placed under ~/.local/share/netrcd/creds (never relabel
# the original); client containers only ever see the socket dir.
set -eu

NETRC_SRC=${1:-$HOME/secrets/agent/github.netrc}
BASE=${NETRCD_ROOT:-$HOME/.local/share/netrcd}
MCS=${NETRCD_MCS:-s0:c100,c200}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)

[ -r "$NETRC_SRC" ] || { echo "credential not readable: $NETRC_SRC" >&2; exit 1; }

mkdir -p "$BASE/socket/profiles.d" "$BASE/socket/config.d" "$BASE/creds"
install -m 600 "$NETRC_SRC" "$BASE/creds/netrc"

podman build -f "$ROOT/crates/netrcd/Containerfile" -t localhost/netrcd:latest "$ROOT"

mkdir -p "$HOME/.config/containers/systemd"
install -m 644 "$ROOT/crates/netrcd/quadlet/netrcd.container" \
  "$HOME/.config/containers/systemd/netrcd.container"

systemctl --user daemon-reload
systemctl --user enable --now netrcd.service

echo
echo "deployed (level $MCS). client recipe:"
echo "  podman run --rm --security-opt label=level=$MCS \\"
echo "    -v $BASE/socket:/netrcd:Z localhost/netrcd:latest \\"
echo "    env NETRCD_SOCK=/netrcd/netrcd.sock nrq GET api.github.com /user"
