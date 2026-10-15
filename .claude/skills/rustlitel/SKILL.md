---
name: rustlitel
description: Operate the rustlitel remote-shell relay to inspect and fix a machine behind NAT/CGNAT (Windows, macOS, or Linux) through its agent — list connected agents and run shell commands non-interactively with the `rustlitel` CLI (or the relay's POST /api/exec), in a diagnose → fix → verify loop. Use whenever the user wants to check, debug, inspect, or fix a remote machine / their Windows box / an agent through rustlitel, run a command on a remote host via the relay, restart a service or clean up a machine remotely, or see which machines are currently connected. The relay and agents are the user's own infrastructure; every command runs on their real (production) machine, so treat it accordingly.
---

# Operate rustlitel

rustlitel reaches a machine that has **no public IP** through a relay the user
hosts. The target runs an agent that *dials out* to the relay; you drive it from
here. The core primitive is non-interactive **`exec`**: one command in,
`stdout` / `stderr` / exit code out — perfect for a tight
**diagnose → fix → verify** loop from a Claude session.

## Setup (once)

- CLI binary is `rustlitel`. If it isn't on PATH, build it from this repo:
  `cargo build --release -p rustlitel-cli` → use `target/release/rustlitel`, or
  `cargo install --path crates/cli`.
- Sign in: `rustlitel login` — Keycloak device flow; it prints a URL + code to
  approve in a browser, then caches tokens and refreshes them automatically.
  The relay URL is saved after login; otherwise pass `--relay https://<host>`
  or set `RUSTLITEL_RELAY`.
- Confirm: `rustlitel whoami`.

## Core workflow

1. **See what's connected:**
   ```bash
   rustlitel agents
   ```
   Each row is an `agent_id` you address. An agent with remote access enabled
   accepts commands; one with it disabled is listed but declines everything
   (the user must have started/installed it with remote access on).

2. **Run a command** — the main primitive:
   ```bash
   rustlitel exec <agent> <command...>
   # e.g.
   rustlitel exec win-box "Get-Service Spooler | Restart-Service; Get-Service Spooler"
   ```
   - `--shell powershell|cmd|pwsh` (Windows) / `bash|sh|zsh` (Unix); defaults
     per the agent's OS.
   - `--timeout <secs>`: hard wall-clock limit (the agent kills the process when
     it elapses).
   - You get `stdout`, `stderr`, and the exit code back. **Read the result
     before deciding the next step.**

3. **Loop:** run a diagnostic → read the structured output → decide → run the
   fix → run a verification command to confirm it worked. One command at a time;
   don't chain blind multi-step commands when a diagnostic between them would
   tell you whether to continue.

## HTTP API (scripts, or when the CLI isn't set up)

```bash
curl -s https://<host>/api/exec \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"agent":"win-box","command":"...","shell":"powershell","timeout_secs":60}'
# -> {"exit_code":0,"stdout":"...","stderr":"...","truncated":false,"error":null}
```
`GET /api/agents` (same Bearer) lists agents. The operator token is the user's —
never echo it into logs, transcripts, or commits.

## Interactive terminal

`exec` is for discrete, scriptable commands. When something genuinely needs a
live TTY (an interactive installer, a pager, `top`), point the user at the web
UI at `https://<host>` — it has an in-browser terminal with selection/copy.

## Safety

- Commands run on the user's **real machine** — treat it like production.
- **Confirm before anything destructive or hard to reverse:** deleting files,
  uninstalling software, formatting, registry edits, stopping or removing the
  agent, and firewall/network changes.
- **Never** run a command that could cut off remote access — disabling the agent
  service, or blocking/mis-routing the relay host — without explicit, specific
  confirmation. If you lock out the agent, there is no second channel in.
- Default to read-only diagnostics first; show what you found and the fix you
  propose before applying it, unless the user has said to just fix it.

## Related

- Cleaning up / de-bloating a Windows machine (disk, apps, Appx, telemetry,
  services, visual effects): the `windows-cleanup` skill next to this one.
