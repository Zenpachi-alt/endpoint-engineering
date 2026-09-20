# Templates

Starting points for new work. Nothing here is deployed as-is; each template is
copied into the domain folder it belongs to and renamed after the thing it does.

| Template | Use for |
| --- | --- |
| `Script-Template.ps1` | Admin-side tooling run by a person against a tenant: Graph queries, bulk operations, reporting. |
| `Remediation/` | Endpoint-side script pairs run by the Intune management extension on a device. |

## Which one to start from

The two halves of this repo have different constraints, and mixing them up
produces scripts that fail on the device or ask for permissions they do not
need.

| | `Script-Template.ps1` | `Remediation/` |
| --- | --- | --- |
| Runs | On an admin workstation, as a person | On a managed device, as SYSTEM |
| PowerShell | 7 where it helps; 5.1 when nothing is lost | Windows PowerShell 5.1 only — it is what ships with Windows |
| Modules | Microsoft Graph SDK | None |
| Authenticates | Yes, and verifies granted scopes | No |
| Parameters | Mandatory, supplied by the caller | All defaulted; Intune passes none |
| Reports through | Console output and CSV/JSON reports | Exit code, one STDOUT line, log file |
| Destructive actions | Gated behind `ShouldProcess`, report-only by default | Gated behind `ShouldProcess`, verified after the change |

## Declaring the PowerShell version

`#Requires -Version` is what CI reads. A script declaring `5.1` is checked for
Windows PowerShell compatibility and parsed by the 5.1 parser; anything else is
analysed against PowerShell 7 and may use 7-only syntax — ternaries, `??`,
`&&`, parallel `ForEach-Object`. Raise the declaration when the script needs it;
do not write 5.1-compatible code out of habit in tooling that will only ever run
on a workstation.

## Before committing a script built from a template

- The SPDX header is the first thing in the file, above `#Requires`.
- Comment-based help is filled in, including `.NOTES` with Graph scopes, admin
  consent, licensing, and modules.
- No real tenant identifiers anywhere — including examples, comments, and sample
  output. Run `Tools/Test-SensitiveContent.ps1` if you are unsure.
- Every failure path produces an actionable message and a non-zero exit code.
- The folder the script lives in has its own `README.md`.
