#!/bin/bash
# Triage for the #[ignore]-gated run-agent e2e suites on this host.
# Collects environment, CLI-parse probes, manual repro of the failing
# flows, and the test runs themselves into a timestamped log next to
# this script. Read-only: builds nothing, fixes nothing.
#
# Usage: sh crates/run-agent/tests/triage_ignored.sh

set -u
DIR=$(cd "$(dirname "$0")" && pwd)
LOG="$DIR/triage_ignored_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee "$LOG") 2>&1

WORK=$(mktemp -d /tmp/fuse-triage.XXXXXX)
BIN="$DIR/../../../target/debug/run-agent"

section() { printf '\n══════ %s ══════\n' "$1"; }
info()    { printf '%s\n' "$*"; }
verdict() { printf '\n*** VERDICT: %s\n' "$1"; }

section "header"
info "date:      $(date -Is)"
info "host:      $(uname -a)"
info "script:    $0"
info "log:       $LOG"
info "workdir:   $WORK"

section "environment"
command -v podman >/dev/null 2>&1 && podman --version || info "podman: NOT FOUND"
[ -e /dev/fuse ] && info "/dev/fuse: present" || info "/dev/fuse: MISSING"
if [ -n "${TOOLBOX_PATH:-}" ] || [ -n "${container:-}" ]; then
  info "toolbox/container detected: TOOLBOX_PATH=${TOOLBOX_PATH:-} container=${container:-}"
else
  info "toolbox/container: none detected"
fi
unshare --user --map-root-user true >/dev/null 2>&1 && info "userns: works" || info "userns: BLOCKED"
if [ -z "${BIN#}" ] && [ ! -x "$BIN" ]; then :; fi
if [ ! -x "$BIN" ]; then
  verdict "run-agent binary missing at $BIN — run: cargo build -p run-agent"
  exit 1
fi
info "run-agent: $($BIN --version 2>/dev/null || echo 'no --version')"

section "cli-surface"
$BIN --help 2>&1 | sed -n '1,8p'
info "--- flags the failing tests rely on:"
for f in --yes --image --socket --mount-point --runtime; do
  if $BIN --help 2>&1 | grep -q -- "$f"; then info "  $f: declared"; else info "  $f: NOT DECLARED"; fi
done
USAGE=$($BIN --help 2>&1 | grep -m1 '^Usage:')
info "usage line: $USAGE"
POSITIONALS=$(printf '%s\n' "$USAGE" | grep -o '<[A-Z_]*>' | grep -cv CONTAINER_ARGS)
info "leading positionals (excluding CONTAINER_ARGS): $POSITIONALS"

section "cli-parse probe: does --socket reach the config under the tests' argv shape"
PROBE_SOCK="$WORK/probe-stale.sock"
: > "$PROBE_SOCK"
RUST_LOG=info timeout 15 "$BIN" '*' probe-agent \
  --runtime podman \
  --socket "$PROBE_SOCK" \
  --mount-point "$WORK/probe-mnt" \
  --yes 2>&1 | sed 's/^/  /'
if RUST_LOG=info timeout 15 "$BIN" '*' probe-agent \
    --runtime podman --socket "$PROBE_SOCK" --yes 2>&1 \
    | grep -q "Removing stale socket at $PROBE_SOCK"; then
  info "RESULT: --socket honored (flag parsing OK under this argv shape)"
elif RUST_LOG=info timeout 15 "$BIN" '*' probe-agent \
    --runtime podman --socket "$PROBE_SOCK" --yes 2>&1 \
    | grep -q "fuse-gatekeeper.sock"; then
  info "RESULT: --socket SWALLOWED — run-agent used the DEFAULT socket."
  info "This is the smoking gun: flags after the two positionals land in"
  info "container_args (trailing var-arg), never in the option parser."
else
  info "RESULT: inconclusive (no socket lines in output)"
fi

section "podman store isolation setup (mirrors e2e_empty_os)"
STORE="$WORK/store"; RUNROOT="$WORK/runroot"; HOMEDIR="$WORK/home"
mkdir -p "$STORE" "$RUNROOT" "$HOMEDIR/.config/containers" "$WORK/xdr"
chmod 700 "$WORK/xdr"
cat > "$WORK/storage.conf" <<EOF
[storage]
driver = "overlay"
runroot = "$RUNROOT"
graphroot = "$STORE"
EOF
ENVRUN="env HOME=$HOMEDIR XDG_CONFIG_HOME=$HOMEDIR/.config XDG_CACHE_HOME=$HOMEDIR/.cache XDG_DATA_HOME=$HOMEDIR/.local/share XDG_RUNTIME_DIR=$WORK/xdr CONTAINERS_STORAGE_CONF=$WORK/storage.conf"

section "repro A: fully-qualified image flow (e2e_fully_qualified_image_creates_container_on_empty_os)"
info "--- pre-pull the fq image into the isolated store:"
$ENVRUN timeout 300 podman pull -q quay.io/libpod/alpine:latest && info "pull: OK" || info "pull: FAILED"
info "--- run-agent with --image (tests' argv shape, HEADLINE flags FIRST as control):"
RUST_LOG=error $ENVRUN timeout 120 "$BIN" fq-agent \
  --image quay.io/libpod/alpine:latest \
  --runtime podman --memory 512M --cpus 1 2>&1 | sed 's/^/  /'
info "--- run-agent with --image (tests' EXACT argv shape: two positionals then flags):"
RUST_LOG=error $ENVRUN timeout 120 "$BIN" '*' fq-agent \
  --runtime podman --memory 512M --cpus 1 \
  --image quay.io/libpod/alpine:latest 2>&1 | sed 's/^/  /'
info "--- images in isolated store:"
$ENVRUN podman images --format '{{.Repository}}:{{.Tag}}' 2>&1 | sed 's/^/  /'

section "repro B: auto-build flow (e2e_auto_build_creates_image_and_container)"
info "--- with --yes directly after the subfolder (control):"
RUST_LOG=error $ENVRUN timeout 300 "$BIN" auto-agent --yes \
  --runtime podman --memory 512M --cpus 1 2>&1 | sed 's/^/  /'
info "--- with --yes in the tests' position (trailing, after other flags):"
RUST_LOG=error $ENVRUN timeout 300 "$BIN" '*' auto-agent \
  --runtime podman --memory 512M --cpus 1 --yes 2>&1 | sed 's/^/  /'
info "--- images in isolated store after repro B:"
$ENVRUN podman images --format '{{.Repository}}:{{.Tag}}' 2>&1 | sed 's/^/  /'

section "the ignored suites themselves"
if command -v podman >/dev/null 2>&1 && [ -e /dev/fuse ]; then
  info "--- e2e_empty_os:"
  (cd "$DIR/../.." && cargo test -p run-agent --test e2e_empty_os -- --ignored --nocapture 2>&1) | tail -25 | sed 's/^/  /'
  info "--- e2e_stub_fuse:"
  (cd "$DIR/../.." && cargo test -p run-agent --test e2e_stub_fuse -- --ignored --nocapture 2>&1) | tail -25 | sed 's/^/  /'
else
  info "skipped: needs podman on PATH and /dev/fuse"
fi

section "verdict"
if grep -q "SWALLOWED" "$LOG"; then
  verdict "CLI/argv mismatch. The tests pass the OLD two-positional shape ('*' subfolder flags...) but the CLI now has ONE positional + trailing container_args: every flag lands in container_args, so --image/--yes/--socket never configure the run. Fix the test harnesses' argv (drop the leading '*' placeholder, put flags after the single subfolder) or the CLI contract."
elif grep -q "auto-build did not produce" "$LOG"; then
  verdict "Flags parse, but the auto-build itself fails — inspect repro B output above (build error, registry egress, embedded-Dockerfile materialization)."
elif grep -q "fully-qualified image was not created" "$LOG"; then
  verdict "Flags parse, but the fq flow fails — inspect repro A output above."
else
  verdict "No known failure signature captured — read the log sections above; environment may differ from both known modes."
fi
info "full log: $LOG"
rm -rf "$WORK"
