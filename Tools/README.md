# Tools

Repository maintenance scripts. These are not endpoint or tenant tooling — they
operate on this repository itself.

| Script | Purpose |
| --- | --- |
| `Test-SensitiveContent.ps1` | Scans files or staged content for tenant identifiers and credential material. |
| `Install-GitHook.ps1` | Points `core.hooksPath` at `Tools/Hooks`, enabling the pre-commit scan in this clone. |
| `Hooks/pre-commit` | Runs the scan against staged content and blocks the commit on a finding. |

## Setting up a clone

```powershell
.\Tools\Install-GitHook.ps1
```

Git does not clone hooks, so this runs once per clone. Undo it with
`-Uninstall`.

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
   add it to the CI workflow if it should apply everywhere.

`git commit --no-verify` skips the hook entirely. CI runs the same scan, so a
skipped hook surfaces on the next push rather than disappearing.

## Limits

The scanner matches shapes, not meaning. It cannot recognise a distinctive
policy name, an internal naming convention, a custom OMA-URI, or a screenshot.
Those need a human read before anything is published.
