# Templates

Starting points for new work. Nothing here is deployed as-is; each template is
copied into the domain folder it belongs to and renamed after the thing it does.

| Template | Use for |
| --- | --- |
| `Script-Template.ps1` | Admin-side tooling run by a person against a tenant: Graph queries, bulk operations, reporting. Holds the master copy of the Graph helpers. |
| `Script-Template.Tests.ps1` | Tests for the Graph helpers, and the check that every copy under `Graph/` matches the template's. |
| `Remediation/` | Endpoint-side script pairs run by the Intune management extension on a device, the optional TimeGuard block for packages with heavy checks, and the test harness every package's tests carry. |

## Which one to start from

The two halves of this repo have different constraints, and mixing them up
produces scripts that fail on the device or ask for permissions they do not
need.

| | `Script-Template.ps1` | `Remediation/` |
| --- | --- | --- |
| Runs | On an admin workstation, as a person | On a managed device, as SYSTEM |
| PowerShell | 7 where it helps; 5.1 when nothing is lost | Windows PowerShell 5.1 only — it is what ships with Windows |
| Modules | Microsoft Graph SDK | None |
| Authenticates | Yes, through `Connect-GraphSession`, which verifies granted scopes | No |
| Parameters | Mandatory, supplied by the caller | All defaulted; Intune passes none |
| Reports through | Console output and CSV/JSON reports | Exit code, one STDOUT line, log file |
| Destructive actions | Gated behind `ShouldProcess`, report-only by default | Gated behind `ShouldProcess`, verified after the change |

## The Graph helpers region

`Script-Template.ps1` carries a `#region Graph helpers` block, and every script
under `Graph/` carries an identical copy of it. The template's copy is the
master. The region holds the plumbing every admin-side script needs and none
should write twice:

| Function | Does |
| --- | --- |
| `Connect-GraphSession` | Reuses a session that already holds the scopes, signs in when none does, and verifies consent either way. Accepts broader scopes the script lists as alternatives. Never replaces an app-only session. Returns whether it signed in, so the script disconnects only what it opened. |
| `Invoke-GraphRequestWithRetry` | Sends one GET or POST. Retries 429 and 5xx, and a GET that got no response at all, honouring `Retry-After`. A POST is resent only after 429 or 503, so an object is never created twice. Failures carry the HTTP status in `Exception.Data['StatusCode']`. |
| `Get-GraphCollection` | Follows `@odata.nextLink` to the last page and returns a `List`, even when empty. |

The Graph SDK retries 429, 503 and 504 by itself, three times, and then throws,
even with `-SkipHttpErrorCheck`. A loop around it never sees a 429, which is
what the earlier per-script loops did. The helpers switch the SDK's retry off
for each request and restore it afterwards, so their own loop is the only one
and `-MaximumAttempt` means what it says.

The region is copied rather than loaded from a shared file so that each script
still runs when copied out on its own. The copies cannot drift apart:
`Script-Template.Tests.ps1` fails while any copy differs from the template's,
and names the first line that does. To change a helper, edit the template,
paste the whole region over every copy, and run Pester.

The tests also exercise the helpers against stand-ins for the SDK, under both
Windows PowerShell 5.1 and PowerShell 7, and — where
`Microsoft.Graph.Authentication` is installed — against the real SDK and a
local server that throttles and pages. CI runs them under both, and installs
the module for the PowerShell 7 run, so the real-SDK tests always run there.

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
- A script under `Graph/` keeps the Graph helpers region exactly as the template
  has it. Code of its own goes outside the region.
- The folder the script lives in has its own `README.md`.
