# Endpoint Engineering

Scripts, payloads, and reference artifacts for endpoint management engineering —
Microsoft Intune, Windows Autopilot, and Microsoft Graph.

Everything here is written to be readable and reusable on its own: each unit of
work carries its own README, its prerequisites, and the permissions it needs.
The repo grows one tested artifact at a time rather than in bulk.

## Repository structure

Content is organised by domain and platform, not by file type. A script lives
with the payload, detection logic, and documentation that belong to it.

| Path | Contains |
| --- | --- |
| `Templates/` | Starting points for new scripts and artifacts. |
| `Templates/Remediation/` | Detection and remediation script pair for Intune remediation packages, and the optional TimeGuard block that limits how often heavy work runs. |
| `Tools/` | Repository maintenance: the identifier and secret scanner, and the git hook that runs it. |
| `Intune/Windows/` | Artifacts that run on a device or are deployed to one: remediations, platform scripts, configuration profiles, applications, compliance policies. |
| `Intune/Windows/Autopilot/` | Hardware hash handling, deployment profiles, Enrollment Status Page configuration. |
| `Intune/Windows/Remediations/` | Remediation packages: a detection and remediation script pair per folder. |
| `Graph/` | Admin-side tooling run from a workstation against a tenant through Microsoft Graph, whatever workload it touches. |
| `Graph/Autopilot/` | Registering and reporting on Windows Autopilot device identities. |
| `Graph/Configuration/` | Backup and reporting over Intune configuration objects. |
| `Graph/Devices/` | Managed device reporting and inventory. |
| `Standalone/` | Scripts that run on their own: text and log handling, local diagnostics, one-off utilities. No Intune delivery, no Graph. |

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
| Graph / Configuration | [`Backup-IntuneConfiguration.ps1`](Graph/Configuration/Backup-IntuneConfiguration.ps1) | Read-only backup of remediations, platform scripts, configuration profiles and compliance policies. |
| Graph / Devices | [`Get-ManagedDeviceInventory.ps1`](Graph/Devices/Get-ManagedDeviceInventory.ps1) | Every Intune managed device in the tenant, filterable, with optional CSV export. |
| Intune / Windows / Autopilot | [`Get-AutopilotHardwareHash.ps1`](Intune/Windows/Autopilot/Get-AutopilotHardwareHash.ps1) | Collects the Autopilot hardware hash on a device during OOBE, offline, with no modules. |
| Intune / Windows / Remediations | [`ComponentRepairSource/`](Intune/Windows/Remediations/ComponentRepairSource/) | Detection only: where DISM would get repair files on each device, listing the devices where it has none. |
| Intune / Windows / Remediations | [`SystemFileHealth/`](Intune/Windows/Remediations/SystemFileHealth/) | Finds and repairs corrupt system files: SFC, and DISM only when SFC cannot finish. TimeGuard limits the heavy scans. |
| Standalone | [`Invoke-TextScrub.ps1`](Standalone/Invoke-TextScrub.ps1) | Shares only what the reader needs: replaces identifiers in logs and text with consistent placeholders, and restores them. |

## Working in this repo

```powershell
# Once per machine: the only dependency for the checks below.
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

# Once per clone: enable the pre-commit scan for tenant identifiers and secrets.
.\Tools\Install-GitHook.ps1

# Any time: check the working tree by hand.
.\Tools\Test-SensitiveContent.ps1

# Before pushing: the same analysis CI runs.
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1

# Tests, where a script has them (Pester 5.5 or later).
Invoke-Pester -Path . -Output Detailed

# Scripts that declare #Requires -Version 5.1 are additionally held to it.
Invoke-ScriptAnalyzer -Path .\Templates\Remediation -Recurse `
    -Settings .\PSScriptAnalyzerSettings.WindowsPowerShell.psd1
```

New work starts from a template — `Templates/Script-Template.ps1` for tooling
run against a tenant, `Templates/Remediation/` for scripts that run on a device.
[`Templates/README.md`](Templates/README.md) explains which applies.

## Quality gates

`.github/workflows/ci.yml` runs on every push and pull request:

| Check | What it enforces |
| --- | --- |
| PSScriptAnalyzer | ParseError, Error and Warning findings fail the build, using `PSScriptAnalyzerSettings.psd1`. |
| Pester | Every `*.Tests.ps1` in the repository runs, and a failing test fails the build. |
| Windows PowerShell 5.1 compatibility | Scripts that declare `#Requires -Version 5.1` are checked against it, and parsed by the 5.1 parser on a Windows runner. Everything else is free to use PowerShell 7. |
| Sensitive content scan | No tenant identifiers or credential material, with matched values masked so the log stays safe to publish. |
| Folder READMEs | Every folder documents itself. |

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
