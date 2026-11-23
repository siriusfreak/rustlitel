---
name: rustlitel
description: Operate the rustlitel remote-shell relay to inspect and fix a machine behind NAT/CGNAT (Windows, macOS, or Linux) through its agent — list connected agents, run shell commands non-interactively, take screenshots of a Windows machine's screen, a monitor, a single window, or another logged-on (RDP) session, and manage its windows (list, focus, minimize, maximize, restore, move/resize, close) with the `rustlitel` CLI (or the relay's POST /api/exec and /api/desktop), in a diagnose → fix → verify loop. Use whenever the user wants to check, debug, inspect, see, or fix a remote machine / their Windows box / an agent through rustlitel, look at what is on its screen, bring a window to the front or close it, run a command on a remote host via the relay, restart a service or clean up a machine remotely, download the rustlitel CLI, or see which machines are currently connected. The relay and agents are the user's own infrastructure; every command runs on their real (production) machine, so treat it accordingly.
---

# Operate rustlitel

rustlitel reaches a machine that has **no public IP** through a relay the user
hosts (here: `https://remote.siriusfrk.ru`). The target runs an agent that
*dials out* to the relay; you drive it from here. Two primitives:

- **`exec`**: one command in, `stdout` / `stderr` / exit code out.
- **desktop** (Windows agents): screenshots and window management in a
  logged-on user's session.

Both fit a tight **diagnose → fix → verify** loop; a screenshot is often the
fastest way to see what a person on the other end is looking at.

## Setup (once)

1. **Get the CLI from the relay** (public page, the binary holds no secret):
   `https://remote.siriusfrk.ru/cli` lists the builds with SHA-256.
   ```bash
   # macOS (universal arm64 + x86_64)
   curl -fLo rustlitel https://remote.siriusfrk.ru/cli/rustlitel-macos && chmod +x rustlitel && xattr -c rustlitel
   # Linux x86-64 (static)
   curl -fLo rustlitel https://remote.siriusfrk.ru/cli/rustlitel-linux-amd64 && chmod +x rustlitel
   # Windows (PowerShell)
   Invoke-WebRequest https://remote.siriusfrk.ru/cli/rustlitel-windows-amd64.exe -OutFile rustlitel.exe
   ```
   Or build it from this repo: `cargo build --release -p rustlitel-cli` →
   `target/release/rustlitel`.
2. **Sign in:** `rustlitel --relay https://remote.siriusfrk.ru login` — Keycloak
   device flow: it prints a URL + code that **the user** approves in a browser
   (realm role `rustlitel`). Tokens are cached and refreshed; the relay URL is
   remembered. Show the URL/code to the user and wait; never try to log in for them.
3. Confirm: `rustlitel whoami`.

## See what's connected

```bash
rustlitel agents
```
Each row is an `agent_id` you address. `REMOTE no` = the agent declines
everything (the user must enable remote access on that machine).

## Run a command

```bash
rustlitel exec <agent> <command...>
rustlitel exec win-box "Get-Service Spooler | Restart-Service; Get-Service Spooler"
```
- `--shell powershell|cmd|pwsh` (Windows) / `bash|sh|zsh` (Unix); per-OS default.
- `--timeout <secs>`: hard wall-clock limit, the process tree is killed after it.
- The exit code of `rustlitel exec` is the command's. Read the output before the
  next step; one command at a time, a diagnostic between steps.

## Screenshots (Windows agents)

```bash
rustlitel screenshot <agent>                          # all monitors -> <agent>-<time>.png
rustlitel screenshot <agent> -o screen.png
rustlitel screenshot <agent> --monitor 0              # one monitor (index from `windows`)
rustlitel screenshot <agent> --title "Notepad" -o np.png   # one window, even if covered
rustlitel screenshot <agent> --format jpeg --quality 70 --max-width 1600 -o s.jpg
```
- **To look at it yourself**, save to a file and open it with the Read tool.
  Prefer `--format jpeg --max-width 1600` for that: a full multi-monitor PNG is
  several MB and wastes context.
- A window target is `--hwnd`, `--title`, `--process` and/or `--pid`
  (title/process are case-insensitive substrings) and must match exactly one
  window; on ambiguity the error lists the candidates with their hwnd.
- A minimized window can't be captured: `window restore` it first.
- A full-screen capture follows the input desktop, so a lock screen or a UAC
  prompt shows up as such.

### Other sessions (RDP, a second user)

```bash
rustlitel sessions <agent>                            # ID, user, state, which is console/default
rustlitel screenshot <agent> --session 3 -o rdp.png   # that session's screen
rustlitel screenshot <agent> --all-sessions           # one file per logged-on session (-s<id>)
```
By default the agent acts in the console session if someone is logged on there,
else the active RDP session. `windows` and `window` take `--session` too.
A **disconnected** session (`state disconnected`) is not drawn by Windows: its
screenshot comes back black or stale and the CLI prints a warning.

## Manage windows (Windows agents)

```bash
rustlitel windows <agent>              # HWND, PID, PROCESS, POSITION, SIZE, STATE (fg/min/max), TITLE
rustlitel windows <agent> --all        # include hidden / untitled / tool windows
rustlitel windows <agent> --json       # full JSON, plus the monitor layout
rustlitel window <agent> focus    --title "Excel"
rustlitel window <agent> minimize --hwnd 0x1a2b3c
rustlitel window <agent> maximize --process notepad.exe
rustlitel window <agent> restore  --pid 4242
rustlitel window <agent> move     --title "Notepad" --x 0 --y 0 --width 1200 --height 800
rustlitel window <agent> close    --title "Notepad"
```
- After an action the CLI prints the window's new row; check it (and take a
  screenshot when it matters) instead of assuming it worked.
- `focus` can be refused by Windows while someone is actively using the machine;
  the CLI says so.
- `close` sends WM_CLOSE: the app may ask to save and stay open ("still open").
  Take a screenshot to see the dialog. **Confirm with the user before closing
  anything** that may hold unsaved work; never force-kill a process to "close" it
  without asking.

## HTTP API (scripts, or when the CLI isn't set up)

```bash
# Bearer: the CLI's cached Keycloak access token, or the operator token
curl -s $RELAY/api/agents -H "Authorization: Bearer $TOKEN"
curl -s $RELAY/api/exec -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"agent":"win-box","command":"...","shell":"powershell","timeout_secs":60}'
# -> {"exit_code":0,"stdout":"...","stderr":"...","truncated":false,"error":null}
curl -s $RELAY/api/desktop -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"agent":"win-box","action":"screenshot","format":"jpeg","session":3}' | jq -r .data | base64 -d > s.jpg
```
Desktop actions: `sessions`, `list_windows` (`all`), `screenshot` (`window`
target object, `monitor`, `format`, `quality`, `max_width`), `window` (`op`,
`target` `{hwnd|title|process|pid}`, `x`/`y`/`width`/`height` for move); every
request may carry `session` and `timeout_secs`. Answers are `{"ok":true,…}` or
`{"ok":false,"error":…}`. A 501 means the agent runs a build without desktop
commands (it self-updates after a relay rollout). Never echo a token into logs,
transcripts, or commits.

## Interactive terminal

When something genuinely needs a live TTY (an interactive installer, `top`),
point the user at the web UI at `https://remote.siriusfrk.ru`.

## Safety

- Commands and window actions run on the user's **real machine**, often while a
  person is using it — treat it like production. Moving, minimizing or closing
  windows under someone's hands is disruptive: say what you are about to do.
- Screenshots can show private content (mail, documents, passwords on screen).
  Take them for the task at hand, don't keep or share them beyond it.
- **Confirm before anything destructive or hard to reverse:** closing windows
  with possible unsaved work, deleting files, uninstalling software, registry
  edits, stopping or removing the agent, firewall/network changes.
- **Never** run a command that could cut off remote access — disabling the agent
  service, or blocking/mis-routing the relay host — without explicit, specific
  confirmation. If you lock out the agent, there is no second channel in.
- Default to read-only diagnostics (a `windows` list, a screenshot) first.

## Related

- Cleaning up / de-bloating a Windows machine: the `windows-cleanup` skill next
  to this one.
