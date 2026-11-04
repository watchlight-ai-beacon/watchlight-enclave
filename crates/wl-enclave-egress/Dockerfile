# Image for the egress guard.
#
# Two stages so the shipped image carries the binary and nothing else: no
# compiler, no source, no package manager. The guard sits in the agent's data
# path, so what is in its image is part of its attack surface.
#
# Tags rather than digests here to keep the example buildable on any
# architecture; pin by digest in CI, where reproducibility matters more than
# convenience.
FROM rust:1-slim-bookworm AS build

WORKDIR /src
# Copy the manifests first so dependency compilation caches independently of
# source edits.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# --locked: build exactly the dependency versions in Cargo.lock. A guard whose
# dependency tree can drift at build time is not one you can reason about.
RUN cargo build --release --locked

FROM debian:bookworm-slim

# Nothing is installed here, deliberately. The guard never terminates TLS, so
# it never validates a certificate and has no use for a CA bundle; it needs
# only libc, for the resolver that turns a hostname into the address netguard
# then validates. Leaving the package manager unused keeps the runtime image
# to the binary and its loader.

COPY --from=build /src/target/release/wl-enclave-egress /usr/local/bin/wl-enclave-egress

# Unprivileged. The guard never needs to write anywhere but its record file,
# which is bind-mounted in.
USER 65532:65532

# No init shim: the binary runs as PID 1 and installs its own SIGTERM handler,
# so a stop signal drains open tunnels instead of truncating the record file.

ENTRYPOINT ["/usr/local/bin/wl-enclave-egress"]
