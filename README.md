# ![Endpoint Engineering](.github/banner.svg)

[![CI](https://github.com/Zenpachi-alt/endpoint-engineering/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Zenpachi-alt/endpoint-engineering/actions/workflows/ci.yml)

PowerShell for Microsoft Intune, Windows Autopilot and Microsoft Graph: tooling
run against a tenant, scripts that run on managed Windows devices, and utilities
for the work in between.

Every tool stands on its own. Nothing it needs lives elsewhere in the
repository, so a script copied out alone still runs, and each one documents its
prerequisites, the permissions it needs, and what it changes. Nothing in it is
specific to one tenant. The repository grows one tool at a time, and CI checks
every one of them.

## Scripts

Grouped by where they run. Each name links to its documentation: prerequisites,
permissions, examples, and exit codes. The script sits beside it.

### Run against a tenant

From a workstation, through Microsoft Graph, with the
`Microsoft.Graph.Authentication` module. Read-only unless the description says
otherwise, and anything that writes supports `-WhatIf`.

| Name | What it does |
| --- | --- |
| [`Import-AutopilotDeviceIdentity.ps1`](Graph/Autopilot/README.md#import-autopilotdeviceidentityps1) | Registers devices with Windows Autopilot from a hardware hash CSV. |
| [`Backup-IntuneConfiguration.ps1`](Graph/Configuration/README.md#backup-intuneconfigurationps1) | Read-only backup of remediations, platform scripts, configuration profiles, compliance policies and Windows update policies. |
| [`Get-BitLockerKeyEscrowReport.ps1`](Graph/Devices/README.md#get-bitlockerkeyescrowreportps1) | For every Windows device, whether Entra ID holds its BitLocker recovery key: the authoritative check behind the BitLockerKeyEscrow package. Never reads a key. |
| [`Get-ManagedDeviceInventory.ps1`](Graph/Devices/README.md#get-manageddeviceinventoryps1) | Every Intune managed device in the tenant, filterable, with optional CSV export. |
| [`Remove-StaleEntraDevice.ps1`](Graph/Devices/README.md#remove-staleentradeviceps1) | Finds stale Entra device objects, disables them, and deletes them after a grace period. One explicit stage per run, report by default; deletion cannot be undone. |
| [`Add-GroupDeviceMember.ps1`](Graph/Groups/README.md#add-groupdevicememberps1) | Resolves device names to Entra object IDs, filtered by join type and recent activity, and adds them to a group or writes the portal's bulk import CSV. |

### Run on a device

Windows PowerShell 5.1 and no modules, because that is all a device can be
assumed to have. Remediation packages are delivered by Intune; the other tools
are run by a technician on the device itself.

| Name | What it does |
| --- | --- |
| [`Get-AutopilotHardwareHash.ps1`](Intune/Windows/Autopilot/README.md#get-autopilothardwarehashps1) | Collects the Autopilot hardware hash during OOBE, offline, with no modules. A `.cmd` beside it launches it from a USB key. |
| [`Get-PolicySource.ps1`](Intune/Windows/PolicySource/README.md#get-policysourceps1) | For each policy setting on a device: the GPO or MDM setting behind it, conflicts, and GPO settings Intune overrides that RSoP does not show. Offline, read-only. |
| [`BitLockerKeyEscrow/`](Intune/Windows/Remediations/BitLockerKeyEscrow/) | Remediation package. Finds BitLocker recovery passwords with no evidence of backup to Entra ID, and backs them up, confirmed by Windows' own event. Never reads a password. |
| [`ComponentRepairSource/`](Intune/Windows/Remediations/ComponentRepairSource/) | Remediation package, detection only. Where DISM would get repair files on each device, listing the devices where it has none. |
| [`SystemFileHealth/`](Intune/Windows/Remediations/SystemFileHealth/) | Remediation package. Finds and repairs corrupt system files: SFC, and DISM only when SFC cannot finish. TimeGuard limits the heavy scans. |

### Run on their own

Utilities that run by themselves, on a workstation or a device, and touch neither
Intune nor a tenant.

| Name | What it does |
| --- | --- |
| [`Get-InstallerInfo.ps1`](Standalone/Packaging/README.md#get-installerinfops1) | Reads what an Intune Win32 app needs from an MSI, an EXE installer or an `.intunewin` package: codes, install context, silent switches, and suggested commands and detection. |
| [`Get-UninstallEntry.ps1`](Standalone/Packaging/README.md#get-uninstallentryps1) | Reads the Uninstall registry entries, compares them before and after a test install, and suggests the Intune detection rule, uninstall command and install behavior for each. |
| [`Invoke-TextScrub.ps1`](Standalone/README.md#invoke-textscrubps1) | Shares only what the reader needs: replaces identifiers in logs and text with consistent placeholders, and restores them. |

## Using a script

1. **Read its documentation first.** It lists what the script needs (PowerShell
   version, modules, Graph scopes, role, licensing) and what it changes.
2. **Unblock a downloaded file.** A script downloaded through a browser, or
   extracted from a downloaded ZIP, is marked as coming from the internet.
   Under the `RemoteSigned` execution policy PowerShell will not run it unless it
   is signed, and these scripts are not. Review it, then:

   ```powershell
   Unblock-File -Path .\Get-ManagedDeviceInventory.ps1
   ```

3. **Ask it for help.** Every script carries comment-based help with its
   parameters, examples and notes:

   ```powershell
   Get-Help .\Get-ManagedDeviceInventory.ps1 -Full
   ```

4. **Rehearse before you change anything.** Run anything that writes with
   `-WhatIf` first, and against a test tenant or test device before production.

## Repository layout

Content is organised by where it runs and what it acts on, never by file type.
A script lives in one folder with its tests, any launcher, and the README that
documents it.

| Folder | Holds |
| --- | --- |
| [`Graph/`](Graph/) | Scripts you run from a workstation against a tenant, whatever workload they touch. |
| [`Intune/`](Intune/) | Scripts that run on a managed device, or that Intune deploys to one, by platform. Only `Windows/` exists so far. |
| [`Standalone/`](Standalone/) | Scripts that run by themselves and touch neither Intune nor a tenant. |
| [`Templates/`](Templates/) | Starting points for new work, and the canonical copies of the blocks scripts share. |
| [`Tools/`](Tools/) | Scripts that act on this repository: the checks CI runs, the identifier and secret scanner, and the git hook. |

The deciding question for a new script is what it acts on and where it runs,
not which API it calls. Nearly everything admin-side uses Graph, so "uses Graph"
would sort almost the whole repository into one folder. If a script fits none
of these, that is worth a pause rather than a new folder.

Code that several scripts need, such as the Graph sign-in, retry and paging
helpers, is copied into each of them rather than loaded from a shared file, and
a test fails while any copy differs from its canonical one in `Templates/`.

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

New work starts from a template: `Templates/Script-Template.ps1` for tooling
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
| Pester | Every `*.Tests.ps1` passes under PowerShell 7, and the tests that declare 5.1 pass under Windows PowerShell 5.1 too. | Linux and Windows, PowerShell 7; Windows, 5.1 |

Besides each script's own behaviour, the tests hold the rules the repository
depends on:

- every copied block (the Graph module check, the Graph helpers, TimeGuard, the
  remediation test harness) matches its canonical copy;
- no script under `Graph/` declares a module with `#Requires`, which would cost
  it its exit code under `pwsh -File`;
- every remediation detection script exits `2`, never `1`, when it fails, so a
  broken check can never start a repair.

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

Conventions the checks are derived from (naming, error handling, required
documentation, and the rule against committing real tenant identifiers) are in
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

The scripts change device and tenant configuration. Test them before
production. No warranty; see LICENSE.md.
