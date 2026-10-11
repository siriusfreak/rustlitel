# syntax=docker/dockerfile:1
#
# Relay image. The relay now makes outbound HTTPS to Keycloak for OIDC, which
# pulls reqwest + rustls + aws-lc-rs — the latter needs cmake and a C compiler,
# so this is a glibc (debian) build on distroless/cc rather than musl/static.
# Only the relay crate is built; the agent crate is never compiled here.
#
# Built via `make image` -> $(REGISTRY)/$(IMAGE):latest (set in Makefile.local;
# linux/amd64; buildkit registry export).

FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Build identifier baked into relay + agent (see crates/proto/build.rs). Passed
# from `make image` (the git short SHA), so the agent's self-update can tell the
# deployed build from what a connected agent already runs. The build context has
# no .git, hence the explicit arg.
ARG RUSTLITEL_BUILD_ID=docker
ENV RUSTLITEL_BUILD_ID=${RUSTLITEL_BUILD_ID}
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Cache the cargo registry and target dir across builds so an incremental change
# (e.g. UI tweaks in the relay) recompiles only the relay crate. The target dir
# is a cache mount, so copy the binary out before the stage ends.
# Build the relay AND the Linux agent (glibc) in one go; the macOS and Windows
# agent binaries are cross-built out-of-band and dropped into dist/.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p rustlitel-relay -p rustlitel-agent && \
    cp target/release/rustlitel-relay /rustlitel-relay && \
    cp target/release/rustlitel-agent /rustlitel-agent-linux

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /rustlitel-relay /rustlitel-relay
# Stock agent binaries to download / bake one-click installers from:
# Linux (built above), macOS + Windows (dist/, cross-built out-of-band).
COPY --from=build /rustlitel-agent-linux /srv/agents/rustlitel-agent-linux
COPY dist/ /srv/agents/
# Compiled egui/WASM UI bundle (built out-of-band by `make ui` into
# crates/ui/dist; served from RUSTLITEL_UI_DIR, default /srv/ui).
COPY crates/ui/dist/ /srv/ui/
EXPOSE 8080
ENTRYPOINT ["/rustlitel-relay"]
