# rustlitel — build & dev helpers.

# Real deployment targets (registry, image name, relay URL, code-signing cert
# location) are kept out of version control. Put your own in an untracked
# Makefile.local, e.g.:
#   REGISTRY    = registry.example.com
#   IMAGE       = rustlitel
#   RELAY_URL   = https://relay.example.com
#   CODESIGN    = op://vault/rustlitel-codesign
#   UPDATE_PUBKEY         = <base64 ed25519 pubkey from `make update-keygen`>
#   UPDATE_SIGNING_KEY_REF = op://vault/rustlitel-update-signing/private
# The defaults below are placeholders so the repo exposes no real hosts.
-include Makefile.local

REGISTRY  ?= registry.example.com
IMAGE     ?= rustlitel
RELAY_URL ?= https://relay.example.com
CODESIGN  ?= op://vault/rustlitel-codesign
CARGO     ?= cargo

# Self-update signing. UPDATE_PUBKEY is baked into the agent/relay; the matching
# private key (UPDATE_SIGNING_KEY_REF, a 1Password ref) stays offline and signs
# release binaries via `make sign-agents`. Empty UPDATE_PUBKEY => agents refuse
# to self-update (fail closed) until you generate a key with `make update-keygen`.
UPDATE_PUBKEY          ?=
UPDATE_SIGNING_KEY_REF ?= op://vault/rustlitel-update-signing/private

# One build id + monotonic epoch for the whole release (image + agents + sigs),
# so a self-updating agent converges and only ever moves to a strictly newer
# build. Use the same commit for `image`, `agent-windows` and `sign-agents`.
BUILD_ID    := $(shell git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)
BUILD_EPOCH := $(shell git log -1 --format=%ct 2>/dev/null || date +%s)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  build            cargo build --release (relay + agent, this host)"
	@echo "  test             cargo test"
	@echo "  ui               build the egui/WASM UI bundle (needs trunk + wasm target)"
	@echo "  image            build + push the relay image to the private registry"
	@echo "  agent-windows    cross-build the Windows agent .exe (needs the target + linker)"
	@echo "  update-keygen    generate the ed25519 self-update signing key (one-time)"
	@echo "  sign-agents      ed25519-sign the dist/ agent binaries for self-update"
	@echo "  run-relay        run the relay locally (needs RUSTLITEL_OPERATOR_TOKEN, RUSTLITEL_AGENT_TOKEN)"
	@echo "  run-agent        run the agent locally (needs RUSTLITEL_RELAY, RUSTLITEL_AGENT_TOKEN)"
	@echo "  gen-tokens       print two fresh random tokens"

.PHONY: build
build:
	$(CARGO) build --release

.PHONY: test
test:
	$(CARGO) test

# Build + push the relay image. linux/amd64 for the k8s nodes; buildkit registry
# exporter. After this, roll out the relay Deployment in your cluster.
# Build the egui/WASM UI bundle into crates/ui/dist (served by the relay from
# RUSTLITEL_UI_DIR). Needs: `rustup target add wasm32-unknown-unknown` and `trunk`
# (brew install trunk). The relay compiles without it; the image needs it.
.PHONY: ui
ui:
	cd crates/ui && trunk build --release
	@echo "-> crates/ui/dist"

# RUSTLITEL_BUILD_ID (git short SHA) is baked into the relay + agent so the agent's
# self-update can distinguish the deployed build from what it already runs.
# Same commit -> same id -> cargo cache hit; a new commit -> agents update.
# Depends on `ui` so the image always bundles a fresh UI build.
.PHONY: image
image: ui
	docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
	  --build-arg RUSTLITEL_BUILD_ID=$(BUILD_ID) \
	  --build-arg RUSTLITEL_BUILD_EPOCH=$(BUILD_EPOCH) \
	  --build-arg RUSTLITEL_UPDATE_PUBKEY=$(UPDATE_PUBKEY) \
	  -t $(REGISTRY)/$(IMAGE):latest \
	  -t $(REGISTRY)/$(IMAGE):$$(date +%Y%m%d) \
	  --output type=registry .

# Windows agent. Prefer CI (.github/workflows/build.yml, MSVC) for release
# binaries; this target cross-compiles from a Unix host and needs:
#   rustup target add x86_64-pc-windows-gnu   + the mingw-w64 linker.
# Bake the same RUSTLITEL_BUILD_ID (git short SHA) the relay image uses, so a Windows
# agent that self-updates to this bundled binary converges (its baked id then
# equals the relay's) instead of re-updating forever. Build from the same commit
# you `make image` from.
.PHONY: agent-windows
agent-windows:
	RUSTLITEL_BUILD_ID=$(BUILD_ID) \
	RUSTLITEL_BUILD_EPOCH=$(BUILD_EPOCH) \
	RUSTLITEL_UPDATE_PUBKEY=$(UPDATE_PUBKEY) \
	  $(CARGO) build --release -p rustlitel-agent --target x86_64-pc-windows-gnu
	@echo "-> target/x86_64-pc-windows-gnu/release/rustlitel-agent.exe"

# One-time: generate the ed25519 self-update signing key. Store the PRIVATE key
# in 1Password at UPDATE_SIGNING_KEY_REF and put UPDATE_PUBKEY in Makefile.local.
.PHONY: update-keygen
update-keygen:
	$(CARGO) run --release -q -p rustlitel-update-sign -- keygen

# ed25519-sign the staged agent binaries for self-update, writing
# dist/<binary>.sig.json next to each (the relay serves these from /srv/agents,
# and the agent verifies the signature against the baked UPDATE_PUBKEY before
# swapping). Signs whichever of the stock binaries are present in dist/. Run
# from the same commit as `image`/`agent-windows` so BUILD_ID/BUILD_EPOCH match
# the baked values. The private key is read from 1Password, never stored.
.PHONY: sign-agents
sign-agents:
	@test -n "$(UPDATE_PUBKEY)" || { echo "UPDATE_PUBKEY is empty — run 'make update-keygen' and set it in Makefile.local"; exit 1; }
	@key="$$(op read '$(UPDATE_SIGNING_KEY_REF)')"; \
	for f in dist/rustlitel-agent-windows.exe dist/rustlitel-agent-linux dist/rustlitel-agent-macos; do \
	  [ -f "$$f" ] || continue; \
	  RUSTLITEL_UPDATE_SIGNING_KEY="$$key" \
	    $(CARGO) run --release -q -p rustlitel-update-sign -- \
	    sign --version "$(BUILD_ID)" --build-epoch "$(BUILD_EPOCH)" "$$f"; \
	done

# Authenticode-sign the bundled Windows agent with the code-signing cert stored
# in 1Password (set CODESIGN in Makefile.local), with an RFC3161 timestamp. Run
# after staging dist/rustlitel-agent-windows.exe, before `image`. For the
# signature to be *trusted*, deploy the cert ($(CODESIGN)/certificate) to
# Trusted Publisher + Root on target machines via GPO/Intune — the installer
# does not self-install a root cert by design.
.PHONY: sign-windows-agent
sign-windows-agent:
	@tmp=$$(mktemp -d); trap 'rm -rf $$tmp' EXIT; \
	op read '$(CODESIGN)/private_key'  > $$tmp/key.pem; \
	op read '$(CODESIGN)/certificate' > $$tmp/cert.pem; \
	osslsigncode sign -certs $$tmp/cert.pem -key $$tmp/key.pem -n "rustlitel agent" \
	  -i $(RELAY_URL) -h sha256 -t http://timestamp.digicert.com \
	  -in dist/rustlitel-agent-windows.exe -out $$tmp/signed.exe \
	&& mv $$tmp/signed.exe dist/rustlitel-agent-windows.exe \
	&& echo "signed dist/rustlitel-agent-windows.exe"

.PHONY: run-relay
run-relay:
	$(CARGO) run --release -p rustlitel-relay

.PHONY: run-agent
run-agent:
	$(CARGO) run --release -p rustlitel-agent -- --allow-remote

.PHONY: gen-tokens
gen-tokens:
	@echo "RUSTLITEL_OPERATOR_TOKEN=$$(openssl rand -hex 24)"
	@echo "RUSTLITEL_AGENT_TOKEN=$$(openssl rand -hex 24)"
