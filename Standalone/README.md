# Standalone

Scripts that run by themselves on a workstation or device and touch neither
Intune nor a tenant: text and log handling, diagnostics, one-off utilities.
Anything delivered through Intune belongs in `Intune/`, and anything that talks
to Graph belongs in `Graph/`.

| Script | Purpose |
| --- | --- |
| `Invoke-TextScrub.ps1` | Replaces identifying values in text with consistent placeholders, and puts them back. |
| `Invoke-TextScrub.Tests.ps1` | Pester tests for it. CI runs them on every push. |

## Invoke-TextScrub.ps1

Scrubs a log, an export, a script or the clipboard before it leaves the device,
for a support case, a forum post, or an AI assistant. Every distinct value gets
a stable placeholder, so the result still reads coherently, and `-Restore` puts
the real values back into whatever comes back.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 7.0 or later. A workstation utility, never deployed through Intune, so not held to 5.1 |
| Modules | None |
| Graph scopes | None |
| Admin consent | Not applicable |
| Licensing | None |
| Role | None. Runs as the signed-in user |
| Platform | Written for Windows. On Linux, `-Clipboard` needs `xclip` |

### Examples

```powershell
# Once: a template config to fill in with your domains, host name patterns and terms
.\Invoke-TextScrub.ps1 -NewConfig

# See what would be replaced, and with what, writing nothing
.\Invoke-TextScrub.ps1 -Path .\IntuneManagementExtension.log -ReportOnly |
    Format-Table Category, Original, Placeholder, Occurrences

# Scrub files; each becomes <name>.scrubbed<ext>
.\Invoke-TextScrub.ps1 -Path .\export.csv, .\error.txt -OutputDirectory C:\Temp\Out

# Scrub the clipboard in place, ready to paste
.\Invoke-TextScrub.ps1 -Clipboard

# Put the real values back into an answer
.\Invoke-TextScrub.ps1 -Path .\Answer.ps1 -Restore
```

### What it replaces

| Category | Example placeholder | Restorable |
| --- | --- | --- |
| Private keys, JWTs, bearer tokens, `password=` style values | `[REDACTED-JWT]`, `[REDACTED]` | No, never stored |
| E-mail addresses and UPNs | `user001@example.com` | Yes |
| GUIDs | `00000000-0000-0000-0000-000000000001` | Yes |
| SIDs, MAC addresses, SHA-1 thumbprints | `S-1-5-21-0-0-0-1001`, `00-00-5E-00-53-01`, `THUMBPRINT-001` | Yes |
| Tenant names in `*.onmicrosoft.com`, `*.sharepoint.com` | `tenant001` | Yes |
| Configured domains, and every host under them | `corp001.example`, `host001.corp001.example` | Yes |
| UNC server names, user profile folders | `SERVER-001`, `C:\Users\USER-001` | Yes |
| Host name patterns, literal terms, extra patterns from config | `DEVICE-001`, `TERM-001`, `SERIAL-001` | Yes |
| ServiceNow-style record numbers | `INC0000001` | Yes |
| IPv4 addresses | `192.0.2.1` | Yes |

Placeholders come from values reserved for documentation (RFC 2606 domains,
RFC 5737 addresses, the RFC 7042 MAC block), so they cannot collide with
anything real. Well-known Microsoft application IDs, such as Microsoft Graph's,
are left readable. The machine name, the signed-in user name and the logon
domain are added to the literal terms unless `-SkipLocalIdentity` is used.

Scrubbing is idempotent: scrubbing scrubbed text changes nothing, and a later
step never rewrites an earlier step's placeholder.

### config.json and map.json stay on the device

Both live in `-DataDirectory`, by default `%LOCALAPPDATA%\TextScrub`.

| File | Holds |
| --- | --- |
| `config.json` | Your domains, host name patterns and literal terms: real values once filled in |
| `map.json` | Every real value and its placeholder. `-Restore` reads it; without it, earlier output cannot be restored |
| `scrub.log` | File names and counts only. Never a value |

The script warns when either file sits inside a git working tree. The map is
saved before any output is written, and replaced atomically, so a failed run
cannot leave behind output that has no map to restore it from.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | The run failed. Nothing is written after the failure |
| `2` | Output was written, but a value already in the map is still in it |

Exit code `2` usually means a value inside a longer token, such as a configured
term `Acme` inside `Acmecorp`, which the word boundaries skip. The warning gives
the line and the placeholder, never the value, because console output is
exactly what gets pasted. The check is a deliberate substring search, so a
short or common term, `user` for example, also matches inside ordinary words
such as `Users`. Keep literal terms distinctive.

### Limits

Regular expressions cannot recognise a person's name in free text, a street
address, or anything the config does not describe. **Read the output before it
leaves the device.**

- IPv6 addresses are not recognised.
- Four-part version numbers match the IPv4 pattern. Use `-SkipIPv4` for text
  full of them.
- MAC and IPv4 placeholders come from documentation ranges holding 256 and 762
  values. A map that needs more stops with an error rather than reusing a
  placeholder; use a separate `-DataDirectory`.
- An 8 MB log with 100,000 identifiers takes under 20 seconds to scrub and a
  few seconds to restore.

### Tests

```powershell
Install-Module Pester -Scope CurrentUser -SkipPublisherCheck   # once; Pester 5.5 or later
Invoke-Pester -Path .\Standalone -Output Detailed
```

The tests build every identifier-shaped value at run time, random GUIDs and a
JWT assembled from parts, so the test file passes
`Tools/Test-SensitiveContent.ps1` like any other file.
