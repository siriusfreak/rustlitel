# windows-cleanup — reference

All snippets are PowerShell 5.1 bodies for `rustlitel exec <agent> '<…>'`
(bash single quotes outside, only double quotes inside). Prefix each with
`[Console]::OutputEncoding=[Text.Encoding]::UTF8;`.

Helpers used below:

```powershell
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
function S($p,$n,$v,$t="DWord") { if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }; Set-ItemProperty -Path $p -Name $n -Value $v -Type $t }
# per-user root of the interactive user (not SYSTEM's HKCU):
$sid = (Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -like "C:\Users\*" } | Sort-Object LastUseTime -Descending | Select-Object -First 1).SID
$u = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion"
```

## Inventory

```powershell
$v = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"; "$($v.ProductName) $($v.DisplayVersion) build $($v.CurrentBuild).$($v.UBR)"   # Win11 still says "Windows 10" in ProductName — use CurrentBuild >= 22000
Get-PSDrive -PSProvider FileSystem | Format-Table Name,@{n="FreeGB";e={[math]::Round($_.Free/1GB,1)}},@{n="UsedGB";e={[math]::Round($_.Used/1GB,1)}}
quser                                   # who is logged on (RDP sessions too)
Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object { "$($_.SID) $($_.LocalPath)" }
# biggest top-level folders (slow on big disks — give it --timeout 590)
function Size($p) { $s=0; Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { $s += $_.Length }; [math]::Round($s/1GB,1) }
Get-ChildItem C:\ -Force -Directory | ForEach-Object { [pscustomobject]@{GB=Size $_.FullName; Path=$_.FullName} } | Sort-Object GB -Descending | Format-Table -AutoSize | Out-String
# installed programs: machine + every user hive
$paths = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21-[\d-]+$" } | ForEach-Object { $paths += "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  Select-Object DisplayName,DisplayVersion,Publisher,@{n="MB";e={[math]::Round($_.EstimatedSize/1024)}},InstallDate,UninstallString,QuietUninstallString | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 300
# Appx: installed for anyone / provisioned for new users
Get-AppxPackage -AllUsers | Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne "System" } | ForEach-Object Name | Sort-Object -Unique
Get-AppxProvisionedPackage -Online | ForEach-Object DisplayName | Sort-Object
```

## Disk

| What | How | Note |
|---|---|---|
| `C:\Windows.old` | cleanmgr category `Previous Installations` | removes rollback; confirm |
| Upgrade leftovers | categories `Windows Upgrade Log Files`, `Temporary Setup Files`, `Setup Log Files` | |
| Update cache | category `Update Cleanup`, then `Dism /Online /Cleanup-Image /StartComponentCleanup` | DISM can take 10–30 min |
| Temp | category `Temporary Files`; `C:\Windows\Temp\*`, `$env:SystemRoot\SoftwareDistribution\Download\*` (stop `wuauserv` first) | |
| Dumps | `C:\Windows\MEMORY.DMP`, `C:\Windows\Minidump` | |

cleanmgr as SYSTEM (never exits by itself — poll, then kill):

```powershell
$base="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
Get-ChildItem $base | ForEach-Object { Remove-ItemProperty $_.PSPath -Name StateFlags0099 -ErrorAction SilentlyContinue }
foreach ($c in "Previous Installations") { S "$base\$c" StateFlags0099 2 }      # add more category names as needed
Start-Process cleanmgr.exe -ArgumentList "/sagerun:99"
# later, in a separate exec: poll Test-Path C:\Windows.old / free space; when done:
Stop-Process -Name cleanmgr -Force; Get-ChildItem $base | ForEach-Object { Remove-ItemProperty $_.PSPath -Name StateFlags0099 -ErrorAction SilentlyContinue }
```

## Win32 uninstall

- Inno Setup (`unins000.exe`): `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`.
- NSIS (`Uninstall.exe`, `uninst.exe`): `/S`.
- MSI (`MsiExec.exe /X{GUID}`): `msiexec /x {GUID} /qn /norestart`.
- Always `$p = Start-Process … -PassThru; $p.WaitForExit(120000)`; on timeout
  see "Uninstallers hang in session 0" in SKILL.md.
- Per-user installs: as SYSTEM the uninstaller cleans SYSTEM's profile. Either
  run it in the user's session (one-off task, with the user's OK) or remove by
  hand: stop process → `HKU:\<SID>\…\Run` values → `HKU:\<SID>\…\Uninstall\<key>` →
  file associations under `HKU:\<SID>\Software\Classes` (only keys whose
  `shell\open\command` points at the app) → firewall rules (`Get-NetFirewallRule
  | Where-Object DisplayName -match <app> | Remove-NetFirewallRule`) → shortcuts
  (Desktop, Start Menu, Public Desktop) → `%APPDATA%`/`%LOCALAPPDATA%` folder.
- Locked leftover files → delete on reboot:

```powershell
Add-Type -Namespace W -Name K -MemberDefinition "[DllImport(`"kernel32.dll`", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a, string b, int f);"
[W.K]::MoveFileEx("C:\path\locked.dll", [NullString]::Value, 4)   # files first, then their folders
```

One-off task in the user's session (needs the user's OK; delete afterwards):

```powershell
$a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\job.ps1"
$p = New-ScheduledTaskPrincipal -UserId "<HOST>\<user>" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "job-once" -Action $a -Principal $p -Force | Out-Null; Start-ScheduledTask -TaskName "job-once"
# job.ps1 writes progress to C:\ProgramData\job.log; poll it; then:
schtasks.exe /delete /tn job-once /f; Remove-Item C:\ProgramData\job.ps1, C:\ProgramData\job.log
```

Browsers: Chrome 109 is the last Windows 7 build and its old updater won't
upgrade after an in-place Win10 upgrade. Install over it (profile is kept):

```powershell
$f="$env:TEMP\chrome.msi"; & curl.exe -sSL -o $f "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
$s=Get-AuthenticodeSignature $f; if ($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "O=Google LLC") { throw "bad signature" }
Start-Process msiexec.exe -ArgumentList "/i","`"$f`"","/qn","/norestart" -Wait; Remove-Item $f
```

## Appx

Remove for all users **and** deprovision (otherwise new profiles get them back):

```powershell
$ProgressPreference="SilentlyContinue"
foreach ($n in $remove) {
  Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $n | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null }
  Get-AppxPackage -AllUsers -Name $n | ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers }
}
# then kill processes still running from removed packages:
Get-Process | Where-Object { $_.Path -match "WindowsApps\\(Microsoft\.SkypeApp|Microsoft\.Xbox|…)" } | Stop-Process -Force
```

Consumer apps safe to remove (Win10 22H2 / Win11):

- Communication/social: `Microsoft.SkypeApp`, `microsoft.windowscommunicationsapps`
  (Mail & Calendar), `Microsoft.People`, `Microsoft.YourPhone` (Phone Link),
  `MicrosoftTeams` / `MSTeams` (Win11 consumer Teams), `Microsoft.OutlookForWindows` (new Outlook)
- Assistant/AI: `Microsoft.549981C3F5F10` (Cortana), `Microsoft.Copilot`, `Microsoft.Windows.Ai.Copilot.Provider`
- Xbox/games: `Microsoft.XboxApp`, `Microsoft.GamingApp`, `Microsoft.Xbox.TCUI`,
  `Microsoft.XboxGameOverlay`, `Microsoft.XboxGamingOverlay`,
  `Microsoft.XboxIdentityProvider`, `Microsoft.XboxSpeechToTextOverlay`,
  `Microsoft.MicrosoftSolitaireCollection`
- Media: `Microsoft.ZuneMusic` (Groove / Media Player), `Microsoft.ZuneVideo` (Films & TV), `Clipchamp.Clipchamp`
- Bing/news: `Microsoft.BingWeather`, `Microsoft.BingNews`, `Microsoft.BingSearch`, `Microsoft.WindowsMaps`, `Microsoft.Wallet`
- Office promos: `Microsoft.MicrosoftOfficeHub`, `Microsoft.Office.OneNote`, `Microsoft.Todos`, `Microsoft.PowerAutomateDesktop`
- Help/tips: `Microsoft.GetHelp`, `Microsoft.Getstarted`, `Microsoft.WindowsFeedbackHub`, `Microsoft.Windows.DevHome`
- 3D/MR: `Microsoft.Microsoft3DViewer`, `Microsoft.MixedReality.Portal`, `Microsoft.MSPaint` (Paint 3D on Win10 — classic `mspaint.exe` stays)
- Optional by use: `Microsoft.WindowsCamera`, `Microsoft.WindowsAlarms`, `Microsoft.WindowsSoundRecorder`, `Microsoft.MicrosoftStickyNotes`, `Microsoft.ScreenSketch`, `Microsoft.Windows.Photos`, `Microsoft.WindowsCalculator`
- Third-party OEM/promo installs (`*.Yandex.Music`, `king.com.*`, `SpotifyAB.*`, …) — remove on single-purpose machines.

Keep: `Microsoft.WindowsStore`, `Microsoft.StorePurchaseApp`, `Microsoft.DesktopAppInstaller`,
`Microsoft.MicrosoftEdge.Stable`, `Microsoft.VCLibs.*`, `Microsoft.UI.Xaml.*`,
`Microsoft.NET.*`, `Microsoft.HEIFImageExtension`, `Microsoft.VP9VideoExtensions`,
`Microsoft.WebMediaExtensions`, `Microsoft.WebpImageExtension`, `Microsoft.SecHealthUI`,
`Microsoft.WindowsTerminal`, `Microsoft.WindowsNotepad`, `Microsoft.Paint` (Win11 Paint).

OneDrive (Win32, per-user): `%LOCALAPPDATA%\Microsoft\OneDrive\<ver>\OneDriveSetup.exe /uninstall`
in the user's session; prevent reinstall for new users by removing
`OneDriveSetup` from `HKU\.DEFAULT` / default-profile Run, and policy
`HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive DisableFileSyncNGSC=1`.

## Policies (machine, HKLM)

`$pol = "HKLM:\SOFTWARE\Policies\Microsoft"`

| Area | Key | Value = data |
|---|---|---|
| Diagnostic data | `$pol\Windows\DataCollection` | `AllowTelemetry=0` (0 = off only on Enterprise/Education/Server; on Pro it equals 1 = Required — the lowest Pro allows) |
| | same | `DisableOneSettingsDownloads=1` (MS: apps using OneSettings may stop working), `DoNotShowFeedbackNotifications=1`, `LimitDiagnosticLogCollection=1`, `LimitDumpCollection=1` |
| CEIP | `$pol\SQMClient\Windows` | `CEIPEnable=0` |
| App telemetry/inventory | `$pol\Windows\AppCompat` | `AITEnable=0`, `DisableInventory=1`, `DisableUAR=1` |
| Error reporting | `$pol\Windows\Windows Error Reporting` | `Disabled=1` (+ `HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting Disabled=1`) |
| Activity history | `$pol\Windows\System` | `PublishUserActivities=0`, `UploadUserActivities=0`, `EnableActivityFeed=0` |
| Input/handwriting | `$pol\InputPersonalization` | `AllowInputPersonalization=0`; `$pol\Windows\TabletPC PreventHandwritingDataSharing=1`; `$pol\Windows\HandwritingErrorReports PreventHandwritingErrorReports=1` |
| Advertising ID | `$pol\Windows\AdvertisingInfo` | `DisabledByGroupPolicy=1` |
| Consumer features (auto-installed "suggested" apps) | `$pol\Windows\CloudContent` | `DisableWindowsConsumerFeatures=1`, `DisableSoftLanding=1`, `DisableCloudOptimizedContent=1` — **Enterprise/Education only** (Experience CSP ❌ Pro); on Pro rely on the per-user ContentDeliveryManager values below |
| Cortana / web in Start search | `$pol\Windows\Windows Search` | `AllowCortana=0`, `AllowSearchToUseLocation=0`, `DisableWebSearch=1`, `ConnectedSearchUseWeb=0` |
| News & interests (Win10 taskbar) | `$pol\Windows\Windows Feeds` | `EnableFeeds=0` |
| Widgets (Win11 21H2+, Pro+) | `HKLM:\SOFTWARE\Policies\Microsoft\Dsh` | `AllowNewsAndInterests=0` (whole widgets experience incl. taskbar) |
| Find My Device | `$pol\FindMyDevice` | `AllowFindMyDevice=0` |
| Cross-device "continue experiences" | `$pol\Windows\System` | `EnableCdp=0` |
| MSRT reporting | `$pol\MRT` | `DontReportInfectionInformation=1` (MSRT itself keeps running) |
| Location | `$pol\Windows\LocationAndSensors` | `DisableLocation=1` (only if nothing needs location); per-app: `$pol\Windows\AppPrivacy LetAppsAccessLocation=2` |
| Offline maps | `$pol\Windows\Maps` | `AutoDownloadAndUpdateMapData=0`, `AllowUntriggeredNetworkTrafficOnSettingsPage=0` |
| Messaging cloud sync | `$pol\Windows\Messaging` | `AllowMessageSync=0` |
| Game DVR | `$pol\Windows\GameDVR` | `AllowGameDVR=0` |
| Background apps | `$pol\Windows\AppPrivacy` | `LetAppsRunInBackground=2` (force deny; MS: Cortana/Search may misbehave) |
| Advertising ID | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo` | `Enabled=0` (together with the policy above) |
| Store auto-update of apps | `$pol\WindowsStore` | `AutoDownload=2` (off — then update Store apps by hand). Do **not** use `DisableStoreApps` or `…\WindowsStore\WindowsUpdate AutoDownload=5` |
| Copilot (Win11, legacy sidebar) | `HKU:\<SID>\Software\Policies\Microsoft\Windows\WindowsCopilot` (**user** policy, deprecated) | `TurnOffWindowsCopilot=1` — doesn't affect the new Copilot *app*: remove Appx `Microsoft.Copilot`. `RemoveMicrosoftCopilotApp` (24H2+) is Enterprise/Education and has conditions |
| Recall (Win11 24H2 KB5055627+, Pro+) | `$pol\Windows\WindowsAI` | `AllowRecallEnablement=0` (removes Recall bits, needs restart), `DisableAIDataAnalysis=1` (deletes snapshots; also as user policy) |
| Paint AI (Win11) | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint` | `DisableCocreator=1`, `DisableGenerativeFill=1`, `DisableImageCreator=1` |
| Start "Recommended" (Win11 22H2+, Pro+) | `$pol\Windows\Explorer` (HKLM and/or user) | `HideRecommendedSection=1`, `HideRecommendedPersonalizedSites=1` |
| Chat/Teams icon (Win11, Pro+) | `$pol\Windows\Windows Chat` | `ChatIcon=3` (Disabled — the only option that sticks after first sign-in; value name per ADMX, verify on the build) |
| OneDrive | `$pol\Windows\OneDrive` | `DisableFileSyncNGSC=1`; `HKLM:\SOFTWARE\Microsoft\OneDrive PreventNetworkTrafficPreUserSignIn=1` |
| Delivery Optimization (optional) | `$pol\Windows\DeliveryOptimization` | `DODownloadMode=99` (simple mode, no P2P; Windows Update keeps working) |

## Per-user (HKU:\<SID>)

| Key (under `$u` = `…\Software\Microsoft\Windows\CurrentVersion`) | Values |
|---|---|
| `$u\ContentDeliveryManager` | `ContentDeliveryAllowed`, `SilentInstalledAppsEnabled`, `SystemPaneSuggestionsEnabled`, `SoftLandingEnabled`, `OemPreInstalledAppsEnabled`, `PreInstalledAppsEnabled`, `SubscribedContent-338388Enabled`, `-338389Enabled`, `-353694Enabled`, `-353696Enabled`, `-310093Enabled` = 0 |
| `$u\Search` | `BingSearchEnabled=0`, `CortanaConsent=0` |
| `$u\AdvertisingInfo` | `Enabled=0` |
| `$u\Privacy` | `TailoredExperiencesWithDiagnosticDataEnabled=0` |
| `$u\BackgroundAccessApplications` | `GlobalUserDisabled=1` |
| `$u\GameDVR` | `AppCaptureEnabled=0`; `HKU:\<SID>\System\GameConfigStore GameDVR_Enabled=0` |
| `$u\Explorer\Advanced` | `ShowSyncProviderNotifications=0` (OneDrive ads in Explorer); Win11: `Start_IrisRecommendations=0` (tips/new apps in Start), `TaskbarMn=0` (Chat), `TaskbarDa=0` (Widgets button — may be ACL-protected, the Dsh policy is the reliable way) |
| `HKU:\<SID>\Software\Microsoft\Siuf\Rules` | `NumberOfSIUFInPeriod=0` (feedback prompts) |
| `HKU:\<SID>\Software\Microsoft\InputPersonalization` | `RestrictImplicitInkCollection=1`, `RestrictImplicitTextCollection=1` |
| `HKU:\<SID>\Software\Microsoft\Personalization\Settings` | `AcceptedPrivacyPolicy=0` |
| `HKU:\<SID>\Software\Microsoft\Siuf\Rules` | also `PeriodInNanoSeconds=0` (QWORD) |
| `HKU:\<SID>\Software\Policies\Microsoft\Windows\CloudContent` | `DisableTailoredExperiencesWithDiagnosticData=1` (this one is a **user** policy; Pro+); `DisableWindowsSpotlightFeatures=1` (Enterprise/Education) |
| `HKU:\<SID>\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy` | `HasAccepted=0` (online speech recognition) |
| `HKU:\<SID>\Control Panel\International\User Profile` | `HttpAcceptLanguageOptOut=1` |

`…\Feeds ShellFeedsTaskbarViewMode` is hash-protected on recent builds — use the
`EnableFeeds` policy instead.

## Services

Disable (`Stop-Service -Force; Set-Service -StartupType Disabled`):

| Service | What |
|---|---|
| `DiagTrack` | Connected User Experiences and Telemetry |
| `dmwappushservice` | WAP push routing (telemetry) |
| `WerSvc` | Windows Error Reporting |
| `XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`, `XboxGipSvc` | Xbox |
| `MapsBroker` | Downloaded maps manager |
| `RetailDemo` | Retail demo mode |
| `WSearch` | Search indexer — only on RDP/server-like VMs (Start search gets slow) |
| `SysMain` | Superfetch — on VMs / SSD-less hosts |
| `Fax` | if present and unused |

Verify: `(Get-WmiObject Win32_Service -Filter "Name=`"X`"").StartMode`.

## Scheduled tasks (`schtasks.exe /change /tn "<path>" /disable`)

```
\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
\Microsoft\Windows\Application Experience\ProgramDataUpdater
\Microsoft\Windows\Application Experience\StartupAppTask
\Microsoft\Windows\Application Experience\PcaPatchDbTask
\Microsoft\Windows\Autochk\Proxy
\Microsoft\Windows\Customer Experience Improvement Program\Consolidator
\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector
\Microsoft\Windows\Feedback\Siuf\DmClient
\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload
\Microsoft\Windows\Windows Error Reporting\QueueReporting
\Microsoft\Windows\Maps\MapsUpdateTask
\Microsoft\Windows\Maps\MapsToastTask
\Microsoft\Windows\CloudExperienceHost\CreateObjectTask
\Microsoft\Windows\Device Information\Device
\Microsoft\Windows\Device Information\Device User
\Microsoft\XblGameSave\XblGameSaveTask
```

`…\KernelCeipTask` is protected (TrustedInstaller) — ignore the error. A task
that doesn't exist on a build returns an error — report "absent", not failure.

## Visual effects ("best performance", keep font smoothing)

```powershell
S "$u\Explorer\VisualEffects" VisualFXSetting 2
S "HKU:\$sid\Control Panel\Desktop" UserPreferencesMask ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) Binary
S "HKU:\$sid\Control Panel\Desktop" DragFullWindows "0" String
S "HKU:\$sid\Control Panel\Desktop" FontSmoothing "2" String
S "HKU:\$sid\Control Panel\Desktop\WindowMetrics" MinAnimate "0" String
S "$u\Explorer\Advanced" TaskbarAnimations 0; S "$u\Explorer\Advanced" ListviewAlphaSelect 0; S "$u\Explorer\Advanced" ListviewShadow 0; S "$u\Explorer\Advanced" IconsOnly 1
S "HKU:\$sid\Software\Microsoft\Windows\DWM" EnableAeroPeek 0
S "$u\Themes\Personalize" EnableTransparency 0
```

Applies at the user's next logon.

## Verify (after reboot)

```powershell
"free C: {0:N1} GB" -f ((Get-PSDrive C).Free/1GB)
Get-AppxPackage -AllUsers | Where-Object { $remove -contains $_.Name } | ForEach-Object Name     # expect nothing
Get-AppxProvisionedPackage -Online | Where-Object { $remove -contains $_.DisplayName }           # expect nothing
"DiagTrack","dmwappushservice","WerSvc" | ForEach-Object { "$_ " + (Get-WmiObject Win32_Service -Filter "Name=`"$_`"").StartMode }
schtasks.exe /query /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /fo list | Select-String "Status|Состояние"
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection").AllowTelemetry
```
