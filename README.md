# Endpoint Engineering

Scripts, payloads, and reference artifacts for endpoint management engineering —
Microsoft Intune, Windows Autopilot, and Microsoft Graph.

Everything here is written to be readable and reusable on its own: every script
still runs when copied out of the repository alone, and each unit of work
carries its own README, its prerequisites, and the permissions it needs.
The repo grows one tested artifact at a time rather than in bulk.

## Repository structure

Content is organised by domain and platform, not by file type. A script lives
with the payload, detection logic, and documentation that belong to it.

| Path | Contains |
| --- | --- |
| `Templates/` | Starting points for new scripts and artifacts. |
| `Templates/Remediation/` | Detection and remediation script pair for Intune remediation packages, and the optional TimeGuard block that limits how often heavy work runs. |
| `Tools/` | Repository maintenance: the script that runs every CI check, the identifier and secret scanner, and the git hook that runs the scan. |
| `Intune/Windows/` | Artifacts that run on a device or are deployed to one: remediations, platform scripts, configuration profiles, applications, compliance policies. |
| `Intune/Windows/Autopilot/` | Hardware hash handling, deployment profiles, Enrollment Status Page configuration. |
| `Intune/Windows/PolicySource/` | Tracing a policy setting on the device to the GPO or MDM setting behind it. |
| `Intune/Windows/Remediations/` | Remediation packages: a detection and remediation script pair per folder. |
| `Graph/` | Admin-side tooling run from a workstation against a tenant through Microsoft Graph, whatever workload it touches. |
| `Graph/Autopilot/` | Registering and reporting on Windows Autopilot device identities. |
| `Graph/Configuration/` | Backup and reporting over Intune configuration objects. |
| `Graph/Devices/` | Managed device reporting and inventory, and cleanup of stale Entra device objects. |
| `Graph/Groups/` | Group membership changes: resolving device names to object IDs and adding them to groups. |
| `Standalone/` | Scripts that run on their own: text and log handling, local diagnostics, one-off utilities. No Intune delivery, no Graph. |
| `Standalone/Packaging/` | Preparing Intune Win32 apps: what an installer holds, and what it writes when it runs. |

Folders are created by the first file that belongs in them, so not every path
above exists yet.

### Where a new script goes

The deciding question is what a script acts on and where it runs — not which
API it happens to call. Nearly everything admin-side uses Graph, so "uses Graph"
would sort almost the whole repo into one folder.

| If it... | It belongs in |
| --- | --- |
| runs on a managed device, or is deployed to one by Intune | `Intune/<Platform>/` |
| is run by you, from a workstation, against the tenant | `Graph/` |
| runs by itself, touching neither Intune nor a tenant | `Standalone/` |
| acts on this repository rather than a tenant or a device | `Tools/` |
| is a starting point rather than a finished thing | `Templates/` |

If a script fits none of these, that is worth a pause rather than a new folder.

## Scripts by area

| Area | Script | Purpose |
| --- | --- | --- |
| Graph / Autopilot | [`Import-AutopilotDeviceIdentity.ps1`](Graph/Autopilot/Import-AutopilotDeviceIdentity.ps1) | Registers devices with Windows Autopilot from a hardware hash CSV. |
| Graph / Configuration | [`Backup-IntuneConfiguration.ps1`](Graph/Configuration/Backup-IntuneConfiguration.ps1) | Read-only backup of remediations, platform scripts, configuration profiles, compliance policies and Windows update policies. |
| Graph / Devices | [`Get-BitLockerKeyEscrowReport.ps1`](Graph/Devices/Get-BitLockerKeyEscrowReport.ps1) | For every Windows device, whether Entra ID holds its BitLocker recovery key: the authoritative check behind the BitLockerKeyEscrow package. Never reads a key. |
| Graph / Devices | [`Get-ManagedDeviceInventory.ps1`](Graph/Devices/Get-ManagedDeviceInventory.ps1) | Every Intune managed device in the tenant, filterable, with optional CSV export. |
| Graph / Devices | [`Remove-StaleEntraDevice.ps1`](Graph/Devices/Remove-StaleEntraDevice.ps1) | Finds stale Entra device objects, disables them, and deletes them after a grace period. One explicit stage per run, report by default; deletion cannot be undone. |
| Graph / Groups | [`Add-GroupDeviceMember.ps1`](Graph/Groups/Add-GroupDeviceMember.ps1) | Resolves device names to Entra object IDs, filtered by join type and recent activity, and adds them to a group or writes the portal's bulk import CSV. |
| Intune / Windows / Autopilot | [`Get-AutopilotHardwareHash.ps1`](Intune/Windows/Autopilot/Get-AutopilotHardwareHash.ps1) | Collects the Autopilot hardware hash on a device during OOBE, offline, with no modules. |
| Intune / Windows / PolicySource | [`Get-PolicySource.ps1`](Intune/Windows/PolicySource/Get-PolicySource.ps1) | For each policy setting on a device: the GPO or MDM setting behind it, conflicts, and GPO settings Intune overrides that RSoP does not show. Offline, read-only. |
| Intune / Windows / Remediations | [`BitLockerKeyEscrow/`](Intune/Windows/Remediations/BitLockerKeyEscrow/) | Finds BitLocker recovery passwords with no evidence of backup to Entra ID, and backs them up, confirmed by Windows' own event. Never reads a password. |
| Intune / Windows / Remediations | [`ComponentRepairSource/`](Intune/Windows/Remediations/ComponentRepairSource/) | Detection only: where DISM would get repair files on each device, listing the devices where it has none. |
| Intune / Windows / Remediations | [`SystemFileHealth/`](Intune/Windows/Remediations/SystemFileHealth/) | Finds and repairs corrupt system files: SFC, and DISM only when SFC cannot finish. TimeGuard limits the heavy scans. |
| Standalone / Packaging | [`Get-InstallerInfo.ps1`](Standalone/Packaging/Get-InstallerInfo.ps1) | Reads what an Intune Win32 app needs from an MSI, an EXE installer or an `.intunewin` package: codes, install context, silent switches, and suggested commands and detection. |
| Standalone / Packaging | [`Get-UninstallEntry.ps1`](Standalone/Packaging/Get-UninstallEntry.ps1) | Reads the Uninstall registry entries, compares them before and after a test install, and suggests the Intune detection rule, uninstall command and install behavior for each. |
| Standalone | [`Invoke-TextScrub.ps1`](Standalone/Invoke-TextScrub.ps1) | Shares only what the reader needs: replaces identifiers in logs and text with consistent placeholders, and restores them. |

## Working in this repo

```powershell
# Once per clone: enable the pre-commit scan for tenant identifiers and secrets.
.\Tools\Install-GitHook.ps1

# Before pushing: every check CI runs, run the way CI runs it. From pwsh on
# Windows this covers both editions. -InstallModule installs the pinned module
# versions on the first run; Windows PowerShell keeps its own modules, so the
# first run installs into both.
.\Tools\Invoke-RepositoryCheck.ps1 -InstallModule
.\Tools\Invoke-RepositoryCheck.ps1

# A subset, for a quick look before committing.
.\Tools\Invoke-RepositoryCheck.ps1 -Check Analyzer, Scan

# One script's tests while working on it.
Invoke-Pester -Path .\Standalone\Packaging\Get-InstallerInfo.Tests.ps1 -Output Detailed
```

New work starts from a template — `Templates/Script-Template.ps1` for tooling
run against a tenant, `Templates/Remediation/` for scripts that run on a device.
[`Templates/README.md`](Templates/README.md) explains which applies.

## Quality gates

Every check lives in [`Tools/Invoke-RepositoryCheck.ps1`](Tools/Invoke-RepositoryCheck.ps1).
`.github/workflows/ci.yml` runs it on every push and pull request, one check per
step, and every step runs even after one fails, so a single run shows every
failure:

| Check | What it enforces | Runs in CI on |
| --- | --- | --- |
| PSScriptAnalyzer | ParseError, Error and Warning findings fail the build, using `PSScriptAnalyzerSettings.psd1`. | Linux, PowerShell 7 |
| Windows PowerShell 5.1 compatibility | Scripts that declare `#Requires -Version 5.1` are checked against it with `PSScriptAnalyzerSettings.WindowsPowerShell.psd1`, and parsed by the 5.1 parser. Everything else is free to use PowerShell 7. | Linux, PowerShell 7; Windows, 5.1 parser |
| Sensitive content scan | No tenant identifiers or credential material, with matched values masked so the log stays safe to publish. | Linux |
| Folder READMEs | Every folder documents itself. | Linux |
| Pester | Every `*.Tests.ps1` passes under PowerShell 7, and the tests that declare 5.1 pass under Windows PowerShell 5.1 too. Among them: every copied block — the Graph module check, the Graph helpers, TimeGuard, the remediation test harness — matches its canonical copy, no script under `Graph/` declares a module with `#Requires`, which would cost it its exit code under `pwsh -File`, and every remediation detection script exits `2`, never `1`, when it fails. | Linux and Windows, PowerShell 7; Windows, 5.1 |

Tests of Windows-only scripts skip on Linux, so the Windows run under
PowerShell 7 is the one that exercises them there. Pester always runs with
`$ErrorActionPreference = 'Stop'`, as GitHub's PowerShell shells start every
step, so a test that fails only in CI fails locally too.

Every tool CI installs is pinned, so a result changes only with a commit.
PSScriptAnalyzer, Pester and `Microsoft.Graph.Authentication` are held to exact
versions in `$PinnedModule` in the check script; raise one there after running
the checks locally against the new release. Actions are pinned by commit, with
the release in a comment, and [`.github/dependabot.yml`](.github/dependabot.yml)
proposes updates to them monthly as pull requests that CI checks first.

Conventions the checks are derived from — naming, error handling, required
documentation, and the rule against committing real tenant identifiers — are in
[CLAUDE.md](CLAUDE.md).

Claude Code sessions in this repo are held to
[`.claude/settings.json`](.claude/settings.json), which only restricts. It blocks
force-pushes, changes to the GitHub repository's settings, unmasked scanner
output, and reads of secret files, and it asks before reading tenant exports,
pushing, or merging a pull request. Personal allow rules belong in the
git-ignored `.claude/settings.local.json`.

## Licence and usage

Released under the MIT License (see [LICENSE.md](LICENSE.md)). You may use,
modify and redistribute these scripts, including commercially, provided the
copyright and licence notice are kept.

This is a personal project, developed in my own time from public
documentation. It is not affiliated with or endorsed by Microsoft or any
employer of the author.

The scripts change device and tenant configuration. Anything that writes at
scale defaults to report-only or -WhatIf. Test in a non-production tenant
first. No warranty; see LICENSE.md.
