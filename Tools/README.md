# Tools

Repository maintenance scripts. These are not endpoint or tenant tooling — they
operate on this repository itself.

| Script | Purpose |
| --- | --- |
| `Invoke-RepositoryCheck.ps1` | Runs every check CI runs, the way CI runs it, and pins the module versions CI uses. |
| `Invoke-RepositoryCheck.Tests.ps1` | Pester tests for it, against small repositories built in TestDrive. |
| `Test-SensitiveContent.ps1` | Scans files or staged content for tenant identifiers and credential material. |
| `Install-GitHook.ps1` | Points `core.hooksPath` at `Tools/Hooks`, enabling the pre-commit scan in this clone. |
| `Hooks/pre-commit` | Runs the scan against staged content and blocks the commit on a finding. |

## Setting up a clone

```powershell
.\Tools\Install-GitHook.ps1
```

Git does not clone hooks, so this runs once per clone. Undo it with
`-Uninstall`.

## Running the checks

`Invoke-RepositoryCheck.ps1` holds every check, and CI does nothing but call
it, one check per step. Running it locally is running CI.

```powershell
# Everything CI runs. From pwsh on Windows this includes the Windows
# PowerShell 5.1 parser and tests, started in powershell.exe.
.\Tools\Invoke-RepositoryCheck.ps1

# The first time in each edition: install the pinned module versions.
.\Tools\Invoke-RepositoryCheck.ps1 -InstallModule

# A subset.
.\Tools\Invoke-RepositoryCheck.ps1 -Check Analyzer, Compatibility, Scan, Readme
```

| Check | Runs |
| --- | --- |
| `Analyzer` | PSScriptAnalyzer over every script, with `PSScriptAnalyzerSettings.psd1`. PowerShell 7 only. |
| `Compatibility` | PSScriptAnalyzer with `PSScriptAnalyzerSettings.WindowsPowerShell.psd1` over every script that declares `#Requires -Version 5.1`. PowerShell 7 only. |
| `Scan` | `Test-SensitiveContent.ps1` over the working tree, values masked. |
| `Readme` | Every folder has a `README.md`, except `.git`, `.github`, `.claude` and `.vscode` at the root. |
| `Pester` | Every test under PowerShell 7; under Windows PowerShell, the tests that declare 5.1. |
| `Parse` | The Windows PowerShell 5.1 parser over every script that declares 5.1. Windows PowerShell only. |
| `WindowsPowerShell` | From PowerShell 7 on Windows, `Parse` and `Pester` again in `powershell.exe`. |

Every selected check runs even when an earlier one fails, and the summary at
the end gives each result. The exit code is `0` when all passed and `1`
otherwise, including when a check could not run.

Pester runs with `$ErrorActionPreference = 'Stop'`, because GitHub's PowerShell
shells start every CI step with it. A test that only passed under a gentler
preference would pass locally and fail in CI.

The module versions live in `$PinnedModule`. Each check imports exactly that
version and stops with the install command when it is missing. `-Strict`, which
CI passes, also fails the run when the Graph helper tests would load a
`Microsoft.Graph.Authentication` other than the pinned one: they import the
highest version installed, so a newer copy would silently replace the pin.
Locally that is a warning.

## Running the scan by hand

```powershell
# Everything in the working tree
.\Tools\Test-SensitiveContent.ps1

# Only what is staged for the next commit
.\Tools\Test-SensitiveContent.ps1 -Staged

# Show the matched values instead of masking them (local use only)
.\Tools\Test-SensitiveContent.ps1 -ShowMatch
```

Exit codes: `0` clean, `1` findings, `2` the scan itself failed.

## What it looks for

| Rule | Severity | Flags |
| --- | --- | --- |
| `PrivateKey` | Error | PEM private key blocks. |
| `BearerToken` | Error | JWTs. |
| `ProviderToken` | Error | GitHub and Slack style access tokens. |
| `HardCodedSecret` | Error | `password = "..."`, `client_secret = "..."` and similar literals. |
| `Guid` | Warning | Tenant, object, policy and app IDs. |
| `EmailOrUpn` | Warning | Addresses and UPNs outside the fictitious domains. |
| `TenantDomain` | Warning | `*.onmicrosoft.com` other than `contoso`. |
| `Url` | Warning | URLs pointing at anything but public documentation and package sources. |
| `UncPath` | Warning | `\\server\share` paths naming a real host. | <!-- sensitive-content:allow -->
| `IPAddress` | Warning | Addresses outside loopback and the RFC 5737 documentation ranges. |

Known-fictitious values pass: all-zero or single-character GUIDs, well-known
Microsoft application IDs, `contoso`/`fabrikam`/`adatum`/`example` domains, the
reserved `.example`, `.invalid` and `.test` TLDs, and dotted quads that are
really version numbers.

Matched values are masked in output by default, so a finding can be pasted into
a CI log or an issue without publishing the identifier it reports.

## Handling a false positive

Three options, in order of preference:

1. Replace the value with a placeholder. Usually the finding is correct.
2. End the line with `# sensitive-content:allow` when the value must stay and is
   genuinely safe.
3. Pass `-AllowPattern '<regex>'` for a pattern that recurs across the repo, and
   add it to the `Scan` check in `Invoke-RepositoryCheck.ps1` if it should
   apply everywhere, CI included.

`git commit --no-verify` skips the hook entirely. CI runs the same scan, so a
skipped hook surfaces on the next push rather than disappearing.

## Limits

The scanner matches shapes, not meaning. It cannot recognise a distinctive
policy name, an internal naming convention, a custom OMA-URI, or a screenshot.
Those need a human read before anything is published.
