---
name: windows-cleanup
description: Clean up and de-bloat a Windows 10 / Windows 11 machine reached through a rustlitel agent — free disk space (Windows.old, temp, component store), uninstall unwanted Win32 programs (incl. per-user installs), remove Microsoft consumer Appx apps (Xbox, Skype, Cortana, Zune, OneDrive…), switch off telemetry / ads / "suggested apps" / Copilot / Recall / Widgets, disable useless services and scheduled tasks, set visual effects for performance, update outdated browsers. Use whenever the user asks to clean, de-bloat, speed up, "remove Microsoft crap", turn off telemetry, or free space on a Windows box behind rustlitel. Builds on the `rustlitel` skill (how to run commands); read that first.
---

# Clean up a Windows 10 / 11 machine via rustlitel

Everything here runs through `rustlitel exec <agent> '<powershell>'` (see the
`rustlitel` skill). The agent runs as **SYSTEM in session 0** — most of the
traps below come from that. Long tables (registry values, Appx names, tasks)
live in [reference.md](reference.md); this file is the workflow and the traps.

## Workflow

1. **Inventory first, read-only.** OS + build, disks, biggest folders, installed
   programs (machine *and* per-user), Appx packages, who is logged on
   (`quser`). Commands in [reference.md § Inventory](reference.md#inventory).
2. **Show the user what you found and what you propose**, as a table: item,
   size/why, recommendation. Ask what the machine is *for* — a box that only
   serves catalogs over RDP can lose far more than a daily desktop.
3. **Apply in small batches**, each followed by a verification command. One
   batch = one kind of change (uninstall / Appx / policies / services / tasks).
4. **Reboot** at the end — ask first: it kicks RDP users off. Several changes
   (visual effects, some policies, pending file deletes, Appx folder cleanup)
   only land after reboot / re-logon.
5. Leave **no residue**: one-off scheduled tasks, scripts in `C:\ProgramData`,
   `StateFlags` registry values you set for cleanmgr — remove them.

## Never touch (security / updates)

Do not disable, even when a "debloat" list says so:

- Microsoft Defender (real-time, cloud-delivered protection, sample submission
  can be set to "never send" but leave protection on), SmartScreen.
- Windows Update and its services (`wuauserv`, `UsoSvc`, `BITS`, `DoSvc` may be
  limited, not disabled), automatic root certificate / CRL updates.
- UAC, firewall, BitLocker, Windows Security Center.
- `Microsoft.WindowsStore`, `Microsoft.DesktopAppInstaller` (winget), VCLibs /
  .NET / UI.Xaml frameworks, codecs (HEIF/VP9/WebMedia/Webp), Edge and
  `Microsoft.MicrosoftEdge.Stable` / WebView2 — removing these breaks other apps.
- Specifically (Microsoft's own "do not" list in the Restricted Traffic
  baseline): `SystemCertificates\AuthRoot DisableRootAutoUpdate`, Defender
  `Spynet` (`SpyNetReporting`/`SubmitSamplesConsent`) and signature-update
  fallback, `EnableSmartScreen=0` / Edge `SmartScreenEnabled=0`, any
  `WindowsUpdate` server/`DoNotConnectToWindowsUpdateInternetLocations`
  redirection, EdgeUpdate `UpdateDefault=0`, `wlidsvc` disabled (blocks feature
  updates), W32Time off, licensing (`NoGenTicket`, License Manager).
- Anything the machine's actual job needs. Ask about obscure runtimes before
  removing them: old Java, Adobe AIR, Access DB engine, VC++ redists are often
  required by line-of-business / catalog software.

## Confirm before (hard to undo)

- Deleting `C:\Windows.old` — it is the only way back to the previous Windows
  version (10 days after an upgrade). Check `CreationTime`; if the upgrade was
  today, say so.
- Uninstalling programs, removing Appx packages for all users, deleting user
  data folders. Move/keep user artefacts (e.g. a torrent client's `.torrent`
  files) into the user's Documents instead of deleting them.
- Disabling services the user may rely on (Windows Search indexer — Start
  search gets slower; SysMain; print spooler only if no printing).
- Reboots.

## Traps when working as SYSTEM through the agent

- **Output encoding.** Russian Windows prints cp866 garbage. Start every
  command with `[Console]::OutputEncoding=[Text.Encoding]::UTF8;`.
- **Quoting.** The CLI takes the command in bash single quotes. Inside it use
  only double quotes for PowerShell strings. `''` does **not** escape a single
  quote in bash — it ends and restarts the string. Need a single quote inside a
  WMI filter? Use `$q=[char]39` or a backtick-escaped double quote
  (`-Filter "Name=`"WerSvc`""`). For `Start-Process -ArgumentList` pass an
  array: `@("-L","-o","C:\x.iso","https://…")`.
- **HKCU is SYSTEM's hive.** Per-user settings go to
  `HKU:\<SID>\…` (map it: `New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS`).
  Get the SID from `Win32_UserProfile` (non-special). Per-user installs (uTorrent,
  OneDrive, WinDirStat…) are registered under `HKU:\<SID>\…\Uninstall`.
- **The user's hive is only in `HKU` while they are logged on.** After a
  reboot (or for an absent user) load it: `reg.exe load "HKU\u_tmp"
  "C:\Users\<user>\NTUSER.DAT"`, write under `Registry::HKEY_USERS\u_tmp\…`,
  then `[GC]::Collect(); [GC]::WaitForPendingFinalizers(); reg.exe unload
  "HKU\u_tmp"`. Don't load it while the user is logged on (it is already at
  `HKU\<SID>`). `New-Item` under a missing `HKU:\<SID>` fails with "The
  parameter is incorrect".
- **Uninstallers hang in session 0.** Inno Setup / NSIS uninstallers that pop a
  dialog (AOMEI feedback window, Revo prompts) wait forever on an invisible
  window, even with `/VERYSILENT /SUPPRESSMSGBOXES`. Always `WaitForExit(timeout)`.
  If they hang: kill them and rerun **in the logged-on user's session** with a
  one-off scheduled task (principal = that user, `LogonType Interactive`,
  `RunLevel Highest`), then delete the task. This also is the right way for
  per-user uninstallers (OneDrive `OneDriveSetup.exe /uninstall`), which as
  SYSTEM clean SYSTEM's profile, not the user's. Running a task as the user
  needs the user's explicit OK — it counts as persistence.
- **`ScheduledTasks` module can be broken** after an in-place upgrade
  (`Get-ScheduledTask` → "file not found", `Register-ScheduledTask` silently
  works anyway). Use `schtasks.exe /change /tn "<path>" /disable` for tasks.
- **cleanmgr `/sagerun` never exits** as SYSTEM (invisible final dialog). Poll
  for the result (folder gone, free space), then `Stop-Process cleanmgr` and
  remove the `StateFlagsNNNN` values you set.
- **Locked files** (shell extensions loaded in `explorer.exe`): schedule delete
  on reboot with `MoveFileEx(path, [NullString]::Value, 4)` — plain `$null`
  becomes `""` and the call fails.
- **Running app processes survive Appx removal** (Skype kept running in the
  tray). After removing packages, kill processes whose path is under
  `C:\Program Files\WindowsApps\<removed package>`.
- **Long jobs.** `exec` has a wall-clock limit. Start long things detached
  (`Start-Process … -PassThru`) and poll in a loop inside one `exec`
  (`do { Start-Sleep 15 } until (…)`), keeping the loop under `--timeout`.
- **Downloads.** Old PowerShell defaults to TLS 1.0:
  `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`
  or use `curl.exe` (present on Win10 1803+). Only download from the vendor's
  official source and verify: Authenticode (`Get-AuthenticodeSignature`, check
  the signer) or a SHA-256 you verified elsewhere (e.g. PGP-checked on the
  Mac). Abort on mismatch. Never fetch installers from random mirrors.
- **Machines in Russia:** Cloudflare-fronted hosts may stall after ~16–24 KB
  (ISP throttling); Microsoft blocks ISO downloads from RU IPs. Download via a
  non-RU host instead of waiting.

## What to do, in order

Details, exact keys and lists: [reference.md](reference.md).

1. **Disk** — `Windows.old` (after confirming), cleanmgr categories, `DISM
   /Online /Cleanup-Image /StartComponentCleanup`, temp folders, old
   `SoftwareDistribution\Download`. Report free space before/after.
2. **Win32 programs** — cracked/repacked utilities, duplicate tools (ISO
   mounters: Windows mounts ISO itself), torrent clients, OneDrive if unused.
   Update, don't keep, frozen browsers (Chrome 109 = last Win7 build; old
   Google Update won't move it — install the signed enterprise MSI over it).
3. **Appx** — remove consumer apps for all users **and** deprovision them so
   new profiles don't get them back.
4. **Policies** — telemetry to the lowest level, consumer features/suggested
   apps off, ads/tips/Spotlight suggestions off, web search & Cortana off,
   activity history, input personalisation, feedback prompts, Game DVR,
   background apps; Windows 11 extras: Copilot, Recall, Widgets, Chat/Teams,
   Start "Recommended". On **Pro** many CloudContent policies
   (`DisableWindowsConsumerFeatures`, Spotlight, `DisableSoftLanding`) are
   ignored — the per-user ContentDeliveryManager values do the work there, and
   `AllowTelemetry=0` acts as 1 (Required).
5. **Services** — telemetry (`DiagTrack`, `dmwappushservice`), WER (`WerSvc`),
   Xbox (`XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`, `XboxGipSvc`),
   `MapsBroker`, `RetailDemo`; on server-like/RDP-only VMs also `WSearch`, `SysMain`.
6. **Scheduled tasks** — Application Experience, CEIP, Feedback\Siuf, WER
   QueueReporting, Maps, Device Information, XblGameSave.
   `KernelCeipTask` is TrustedInstaller-protected; leave it.
7. **Visual effects** — "best performance" for the user, keep font smoothing.
8. **Reboot** (ask), then re-run the verification block.

## Sources

- Microsoft: [Manage connections from Windows 10 and Windows 11 OS components to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
  (Restricted Traffic Limited Functionality baseline; written for Enterprise — check edition support per policy),
  [Configure Windows diagnostic data](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization),
  Policy CSPs: [Experience](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience),
  [WindowsAI](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai),
  [Start](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start),
  [NewsAndInterests](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests),
  [System](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system).
- Community (telemetry scheduled tasks, Appx lists): Chris Titus WinUtil
  (github.com/ChrisTitusTech/winutil), Win10-Initial-Setup-Script. Not
  authoritative — task names verified on a real Win10 22H2 box (CATALOGS,
  2026-10-15).
