# rustlitel — build & dev helpers.

# Real deployment targets (registry, image name, relay URL, code-signing cert
# location) are kept out of version control. Put your own in an untracked
# Makefile.local, e.g.:
#   REGISTRY    = registry.example.com
#   IMAGE       = rustlitel
#   RELAY_URL   = https://relay.example.com
#   CODESIGN    = op://vault/rustlitel-codesign
# The defaults below are placeholders so the repo exposes no real hosts.
-include Makefile.local

REGISTRY  ?= registry.example.com
IMAGE     ?= rustlitel
RELAY_URL ?= https://relay.example.com
CODESIGN  ?= op://vault/rustlitel-codesign
CARGO     ?= cargo

.PHONY: help
help:
	@echo "Targets:"
	@echo "  build            cargo build --release (relay + agent, this host)"
	@echo "  test             cargo test"
	@echo "  ui               build the egui/WASM UI bundle (needs trunk + wasm target)"
	@echo "  image            build + push the relay image to the private registry"
	@echo "  agent-windows    cross-build the Windows agent .exe (needs the target + linker)"
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
	  --build-arg RUSTLITEL_BUILD_ID=$$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S) \
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
	RUSTLITEL_BUILD_ID=$$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S) \
	  $(CARGO) build --release -p rustlitel-agent --target x86_64-pc-windows-gnu
	@echo "-> target/x86_64-pc-windows-gnu/release/rustlitel-agent.exe"

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
