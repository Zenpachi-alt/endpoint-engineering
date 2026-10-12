# Templates

Starting points for new work. Nothing here is deployed as-is; each template is
copied into the domain folder it belongs to and renamed after the thing it does.

| Template | Use for |
| --- | --- |
| `Script-Template.ps1` | Admin-side tooling run by a person against a tenant: Graph queries, bulk operations, reporting. Holds the master copies of the Graph module region and the Graph helpers. |
| `Script-Template.Tests.ps1` | Tests for the Graph helpers, the check that every copy of both regions under `Graph/` matches the template's, the checks that a script reports a failure and keeps its exit code, and the check that `-WhatIf` and `-Confirm` stay out of the module as it loads. |
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
| `Connect-GraphSession` | Reuses a session that already holds the scopes, signs in when none does, and verifies consent either way. Accepts broader scopes the script lists as alternatives. Never replaces an app-only session. Shows a device code sign-in's code while the sign-in waits for it. Returns whether it signed in, so the script disconnects only what it opened. |
| `Invoke-GraphRequestWithRetry` | Sends one GET, POST, PATCH or DELETE. Retries 429 and 5xx, and a GET that got no response at all, honouring `Retry-After`. A POST, PATCH or DELETE is resent only after 429 or 503, so a change is never made twice. Failures carry the HTTP status in `Exception.Data['StatusCode']`. |
| `Get-GraphCollection` | Follows `@odata.nextLink` to the last page and returns a `List`, even when empty. |

The Graph SDK retries 429, 503 and 504 by itself, three times, and then throws,
even with `-SkipHttpErrorCheck`. A loop around it never sees a 429, which is
what the earlier per-script loops did. The helpers switch the SDK's retry off
for each request and restore it afterwards, so their own loop is the only one
and `-MaximumAttempt` means what it says.

The helpers hand the SDK every `https://graph.microsoft.com` URI as a path
relative to that host, and the SDK sends it to the same address. Given an
absolute URI, `Invoke-MgGraphRequest` swaps the session's cloud environment for
one with no sign-in endpoint, and keeps the swap. Changing the retry setting
makes the SDK rebuild its HTTP client, and a session signed in as a user, or
with a certificate or secret, then fails every request after the first with
`Invalid URI: The format of the URI could not be determined.` The real-SDK
tests below cannot show this: they sign in with an access token, which needs no
sign-in endpoint. The stand-in tests check the path the SDK is given instead.

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

## Failure and exit codes

A script built from `Script-Template.ps1` exits `0` when it succeeds and `1`
when it fails, with the reason on the error stream. The code is the same
however the script is started: from a session, where the caller reads
`$LASTEXITCODE`, or with `pwsh -File`, as a scheduled task starts it. Two
things keep that true, and `Script-Template.Tests.ps1` checks both in the
template and in every script under `Graph/`.

**The script loads the Graph module itself.** `Script-Template.ps1` carries a
`#region Graph module` block that imports `Microsoft.Graph.Authentication`, or
says what to install and exits `1`. Every script under `Graph/` carries an
identical copy, kept identical by the same test as the helpers. No script
declares the module with `#Requires -Modules`. PowerShell loads a module
declared that way before the script starts, and when the module runs code of
its own while it loads, as the Graph module does, a script started with `-File`
reports `0` whatever it exits with. That was seen on Windows PowerShell 5.1
and PowerShell 7.6, and only with `-File`: read from a session, the code was
right.

**The main `catch` reports, then exits.** It is
`Write-Error -Exception $_.Exception -Message "..." -ErrorAction Continue`
followed by `exit 1`. `-Message` cannot be given with `-ErrorRecord`: the two
belong to different parameter sets, so `Write-Error` fails with an error of
its own and the reason is never shown. Without `-ErrorAction Continue`, the
script's `$ErrorActionPreference = 'Stop'` stops it at that line, and `exit`
never sets the code.

A script may exit with other codes for outcomes a caller should tell apart,
and documents them in its README, as `Graph/Configuration` does.

Neither mistake shows in the tests of a script's main block, which run the
body of its `try` and never its `catch`. So where a script can fail before it
signs in, its tests also start it as a file in a child process and assert the
exit code and the message. Those tests need the module, and are skipped where
it is not installed for the PowerShell that runs them.

## -WhatIf and -Confirm while the module loads

A script started with `-File` runs in the global scope, which is where a module
looks up preferences it does not set itself. So the script's `-WhatIf` and
`-Confirm` reach the code `Microsoft.Graph.Authentication` runs while it loads,
including its `Update-TypeData` calls. Under `-WhatIf`, each call printed a
What-if line ahead of the script's own (fifteen with version 2.41.0) and left
the type data unregistered. Under `-Confirm`, each call asked, and a run with
`-NonInteractive` could not load the module at all. That was seen on Windows
PowerShell 5.1 and PowerShell 7.6, and only with `-File`.

The Graph module region therefore switches both off for the import and
restores them in its `finally`, so they govern everything after it as before.
Setting them in a child scope would not help, because the module never looks
there. `Script-Template.Tests.ps1` runs the region as a file under each
switch.

## The device code prompt

`Connect-MgGraph -UseDeviceCode` writes the code, and the address to enter it
at, to the output stream, as data, rather than to the console. That is in the
SDK's source for versions 2.31.0 and 2.41.0, and was seen on a live run with
2.41.0. Discarded with `$null =`, as `Connect-GraphSession` once did, the code
never shows, and the sign-in waits until the SDK gives up after 120 seconds.

`Connect-GraphSession` passes each line `Connect-MgGraph` writes to
`Write-Information -InformationAction Continue`, through the pipeline. A
pipeline hands a line on the moment it is written, so the code shows while the
sign-in waits for it, and the function still returns only whether it signed
in. Collecting the output first and writing it afterwards would show the code
only once the sign-in had ended, which without the code it never does.

The stand-in `Connect-MgGraph` in `Script-Template.Tests.ps1` writes a prompt
the same way, and a test fails unless the prompt is shown before the stand-in
returns. It fails against both mistakes above.

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
- Every failure path produces an actionable message and a non-zero exit code,
  and the main `catch` keeps the template's `Write-Error` and `exit 1`.
- A script under `Graph/` keeps the Graph module and Graph helpers regions
  exactly as the template has them, and declares no module with `#Requires`.
  Code of its own goes outside the regions.
- The folder the script lives in has its own `README.md`.
