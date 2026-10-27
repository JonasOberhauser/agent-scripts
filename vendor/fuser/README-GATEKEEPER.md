# Vendored fuser 0.15.1 (one-patch fork)

Upstream: https://github.com/cberner/fuser (MIT), crates.io 0.15.1,
pinned by sha256 of the .crate when vendored.

## The delta (the ONLY change)

`Session::from_fd_resumed(filesystem, fd, acl, proto_major, proto_minor)`
in `src/session.rs` — like `from_fd`, but marks the session initialized
with the given protocol version. Rationale (#103, connection takeover):
the kernel sends `FUSE_INIT` exactly once per connection, so resuming a
session onto a live (already-initialized) connection with stock
`from_fd` leaves `initialized == false` and the dispatch loop answers
every request with `EIO` ("Ignoring FUSE operation before init"). The
resumed daemon's first INIT never comes; the constructor must accept
the negotiated version from the takeover payload instead.

Upstreamable as-is (a `takeover`/`resume` constructor is a known ask for
connection handoff). Re-track upstream when a release carries an
equivalent.
