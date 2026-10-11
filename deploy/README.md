# Deploy

The relay is a single stateless container behind a TLS reverse proxy /
ingress. There's nothing to persist — it keeps only in-memory maps, so one
replica is enough. The only requirements are:

* a container registry you can push to;
* an HTTPS endpoint that terminates TLS and proxies to the relay, with
  **WebSocket upgrades** allowed and generous read/write timeouts (sessions are
  long-lived `wss://` connections);
* two secrets — an operator token and an agent token (must differ) — injected
  as environment variables.

Set your own registry, image name, relay URL and code-signing cert location in
an untracked `Makefile.local` (see the `Makefile` header); the committed
defaults are placeholders.

## Build + push the image

```bash
make image           # -> $(REGISTRY)/$(IMAGE):latest   (from Makefile.local)
```

The image bundles the relay, the Linux agent, the macOS/Windows agents staged
into `dist/` (see `make agent-windows` + `make sign-windows-agent`), and the
compiled web UI (`make ui`).

## Run the relay

Run the image behind your ingress with at least:

```
RUSTLITEL_OPERATOR_TOKEN   # web login / Bearer token
RUSTLITEL_AGENT_TOKEN      # agent enrollment token (must differ)
RUSTLITEL_PUBLIC_ORIGIN    # https://<your-relay-host>   (enables Origin checks)
RUSTLITEL_LISTEN_ADDR      # 0.0.0.0:8080
```

See the env table in the top-level `README.md` for the rest (session TTL, exec
caps, OIDC). After a code change: rebuild + push the image and roll out /
restart the relay in your platform.

Keep the operator and agent tokens in your secret store and inject them at
runtime; don't bake them into the image.

## Enroll a machine

On the target (Windows: elevated PowerShell), with the agent binary:

```powershell
rustlitel-agent-windows.exe install --relay wss://<your-relay-host> --token <AGENT_TOKEN>
```

Accept the consent dialog → it installs an auto-start service. The machine then
appears in the web UI at `https://<your-relay-host>`.
