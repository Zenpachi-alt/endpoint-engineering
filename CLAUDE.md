# Repository conventions

Personal endpoint-management engineering repo: Microsoft Intune, Windows
Autopilot, Microsoft Graph. Public-facing — assume every file is read by someone
outside my organisation.

## General

- **Never commit real identifiers.** No tenant IDs, object/policy/app GUIDs,
  UPNs, email addresses, internal hostnames, domain names, IP addresses, device
  serials, keys, or secrets — including in examples, comments, and sample output.
  Use obvious placeholders: `<TenantId>`, `<GroupId>`, `user@contoso.com`,
  `00000000-0000-0000-0000-000000000000`.
- **Organise by domain and platform, never by file type.** A script, its payload,
  its detection counterpart, and its README are one unit in one folder. Route by
  what a script acts on and where it runs, not by which API it calls — nearly
  everything admin-side uses Graph, so "uses Graph" sorts nothing. Runs on a
  managed device or is deployed to one → `Intune/<Platform>/`. Run by a person
  from a workstation against the tenant → `Graph/`. Runs by itself, touching
  neither Intune nor a tenant → `Standalone/`. Acts on this repository →
  `Tools/`.
- **Every script is self-contained.** A single file copied out of this
  repository runs on its own: no script dot-sources, imports or calls another
  file from the repository. A launcher beside its own script, such as the
  Autopilot `.cmd`, is part of that unit rather than a dependency. Code that
  several scripts need is copied into each of them and kept identical by a
  test, never loaded from a shared file at run time. The one exception is
  `Tools/Invoke-RepositoryCheck.ps1`, which exists to run this repository's
  own scanner and tests, and so runs only inside a clone.
- **`Standalone/` is not a junk drawer.** A script goes there because it is
  genuinely self-contained, not because deciding was hard. Anything that would
  be delivered through Intune or would talk to Graph belongs in the folder that
  says so. Once `Standalone/` holds work that clusters around a subject, split
  that cluster into its own folder rather than letting the pile grow.
- **No empty folders.** A folder is created by the first real file that belongs
  in it.
- **Every folder has a `README.md`** stating what it contains and how it is used.
  Tool configuration folders are exempt: `.github/`, because GitHub treats
  `.github/README.md` as a repository README (the workflows are documented in
  the root `README.md` instead), plus `.claude/` and `.vscode/`. CI enforces the
  rule and skips exactly those folders.
- **Every script documents its prerequisites and required permissions** — modules,
  licensing, API permissions, and the role needed to run it.
- **Every script opens with the SPDX header**, before `#Requires` (below the
  shebang in a shell script):

  ```
  # SPDX-FileCopyrightText: 2026 Tomasz Pietryka
  # SPDX-License-Identifier: MIT
  # Source: https://github.com/Zenpachi-alt/endpoint-engineering
  ```

  Single files get copied out of repositories and lose their context. The
  licence identifier alone names a licence with no holder, MIT asks that the
  copyright notice travel with copies, and the source line is how a stray copy
  leads back to the full licence and to a version that may have been fixed
  since. The URL points at the repository root, not a file, so it survives
  files being moved or renamed.
- **Error handling is mandatory.** No silent failures. Every failure surfaces an
  actionable message, and scripts that can fail exit non-zero.
- Folders are PascalCase. Scripts are `Verb-Noun.ps1`. Supporting files take the
  name of the script or unit they belong to.

## PowerShell

- Approved verb-noun naming (`Get-Verb`), PascalCase parameters,
  `[CmdletBinding()]` on every script.
- `SupportsShouldProcess` on anything that writes, changes, or deletes — and
  actually gate the change behind `$PSCmdlet.ShouldProcess()`.
- Typed, validated parameters. Use `Mandatory`, `ValidateSet`,
  `ValidateNotNullOrEmpty`, `ValidatePattern`, `ValidateScript` rather than
  discovering bad input halfway through a run.
- `try`/`catch`/`finally` with `-ErrorAction Stop` on every cmdlet inside a
  `try`. Never use `SilentlyContinue` to hide an error.
- `Write-Error`, `Write-Warning`, `Write-Verbose`, `Write-Output`. No bare
  `Write-Host` for errors, and never for data on the pipeline.
- Microsoft Graph PowerShell SDK or direct Graph REST (`Invoke-MgGraphRequest`)
  only. **Never MSOnline or AzureAD** — both are deprecated.
- Never name a function after a command or alias that a loaded module exports.
  An alias beats a function of the same name, silently: the Graph SDK exports
  `Invoke-GraphRequest` as an alias of `Invoke-MgGraphRequest`.
- Request the narrowest Graph scopes that work, and verify the granted scopes
  after connecting rather than assuming consent succeeded.
- Comment-based help is required and must declare, under `.NOTES`:
  - `PowerShell` — the version the script targets, matching its `#Requires` line
  - `Graph scopes` — every scope the script requests
  - `Admin consent` — required or not
  - `Licensing` — e.g. Microsoft Intune Plan 1, Microsoft Entra ID P1/P2
  - `Modules` — every module the script depends on

## Admin-side and endpoint-side scripts

The two run in different worlds and are written to different rules. Start from
the matching template; `Templates/README.md` compares them.

**Admin-side** — run by a person against a tenant: Graph queries, bulk
operations, reporting. Start from `Templates/Script-Template.ps1`. **PowerShell
7 is fine and often better** — use it where 5.1 is limiting, and say so.
Authenticates, verifies granted scopes, and defaults to report-only or
`-WhatIf` for anything that writes at scale. Irreversible actions (wipe, retire,
delete, Autopilot deregistration) are called out in the help.

The Graph plumbing — signing in and verifying scopes, retrying throttled and
failed requests, following every page — is the `#region Graph helpers` block
of `Templates/Script-Template.ps1`, carried verbatim by every script under
`Graph/`. Use it rather than calling `Connect-MgGraph` or looping over
`Invoke-MgGraphRequest` by hand. Change it only in the template, paste the
whole region over every copy, and run Pester:
`Templates/Script-Template.Tests.ps1` fails while any copy differs, and names
the first line that does. Script-specific code stays outside the region.

The same scripts carry the template's `#region Graph module` block, by the
same rule, and it is the only thing that loads `Microsoft.Graph.Authentication`.
**Never declare a module with `#Requires -Modules` in a script under
`Graph/`**: a module PowerShell loads that way can cost the script its exit
code, so that `pwsh -File` reports `0` whatever the script exits with. The
main `catch` reports with
`Write-Error -Exception $_.Exception -Message "..." -ErrorAction Continue` and
then `exit 1`. Never give `-Message` together with `-ErrorRecord`: `Write-Error`
fails instead of reporting. The template's tests check both, and
`Templates/README.md` has the reasons. Where a script can fail before it signs
in, its tests start it with `-File` in a child process and assert the exit
code and the message, because a test of the main block never runs its `catch`.

**Endpoint-side** — run by the Intune management extension on a managed device.
Start from `Templates/Remediation/`. **Windows PowerShell 5.1 only**, because
that is what ships with Windows; PowerShell 7 has to be deployed separately and
cannot be assumed on a device. No module dependencies, SYSTEM context unless
stated otherwise, logging to a file under
`%ProgramData%\EndpointEngineering\Logs`, and meaningful exit codes. Detection
scripts must exit `1` and only `1` for "issue found"; any other non-zero code
must mean "the detection failed", so a broken script never triggers a
remediation fleet-wide. Remediation scripts verify the change before reporting
success.

Every remediation package has a `<Noun>.Tests.ps1` that runs its scripts
through the `#region Remediation test harness` block of
`Templates/Remediation/ExampleSetting.Tests.ps1`, with stand-ins for whatever
touches the device, and asserts the exit code and output line of every path.
The harness and the TimeGuard region follow the same rule as the Graph
helpers: change the canonical copy, paste the whole region over every copy,
and run Pester, which fails while any copy differs.

**Declare the version honestly.** `#Requires -Version` is the contract, and CI
reads it: a script that declares `5.1` is checked for Windows PowerShell
compatibility and parsed by the 5.1 parser; everything else is analysed against
PowerShell 7 and may use 7-only syntax. Raise the declaration to `7.0` when a
script genuinely needs it rather than writing 5.1-compatible code out of habit.

## Encoding and line endings

- `.gitattributes` normalises line endings; do not fight it in an editor.
- `.editorconfig` sets 4-space indentation and a 100-column guide.
- Scripts are UTF-8 and **ASCII-only in content**. Intune rejects a BOM when
  script signature enforcement is on, and Windows PowerShell 5.1 misreads
  non-ASCII characters in a UTF-8 file without a BOM. Staying ASCII removes the
  problem: no smart quotes, no dashes, no accented characters in scripts.

## Before committing

1. `Tools/Install-GitHook.ps1` once per clone — the pre-commit hook runs the
   identifier and secret scan against staged content.
2. `Tools/Invoke-RepositoryCheck.ps1` under `pwsh` on Windows — every check CI
   runs, the same way CI runs it: PSScriptAnalyzer (CI fails on ParseError,
   Error and Warning), Windows PowerShell 5.1 compatibility, the identifier and
   secret scan, folder READMEs, and Pester, then the 5.1 parser and the 5.1
   tests in `powershell.exe`. `-Check` runs a subset. The first run in each
   edition needs `-InstallModule`, because Windows PowerShell and PowerShell 7
   keep separate modules.

When a script has tests (`<Script>.Tests.ps1` beside it), build
identifier-shaped test values at run time so the test file passes the scanner
too. The tests of a script that declares `#Requires -Version 5.1` declare it
too, and must pass under `powershell.exe` as well as `pwsh`. Pester runs them
with `$ErrorActionPreference = 'Stop'`, as GitHub's PowerShell shells start
every CI step, so a test must not depend on a gentler preference.

CI (`.github/workflows/ci.yml`) runs the same script, one check per step and
every step even after one fails: on Linux under PowerShell 7, and on Windows
under Windows PowerShell 5.1 and PowerShell 7. Tests of Windows-only scripts
skip on Linux, so the Windows run under PowerShell 7 is their only one there.
The hook is a convenience; CI is the gate.

CI pins every tool it installs: module versions in `$PinnedModule` in
`Tools/Invoke-RepositoryCheck.ps1`, actions by commit SHA with the release in a
comment. Never loosen a pin to a minimum version or a moving tag. Raise a
module version only after the checks pass locally against it.

The scanner matches shapes, not meaning. Design-level identifiers that survive
scrubbing — distinctive policy, app, group or script names, naming conventions,
custom OMA-URIs — still need a human read before anything is published.
