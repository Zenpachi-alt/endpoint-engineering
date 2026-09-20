# Configuration

Admin-side tooling over the Intune configuration surface: remediations, platform
scripts, configuration profiles and compliance policies, as objects in the
tenant rather than as things running on a device.

| Script | Purpose |
| --- | --- |
| `Backup-IntuneConfiguration.ps1` | Point-in-time export of four configuration categories, with assignments, embedded scripts and an index. |

## Backup-IntuneConfiguration.ps1

Reads four categories of Intune object on Microsoft Graph and writes each one to
disk as JSON, together with its assignments and any embedded script content. It
writes nothing to the tenant — every call is an HTTP GET.

The point of it is the moment before a change: a policy edit, a bulk cleanup, a
remediation being deleted. Run it first and the previous state is on disk,
readable, with the assignment targets resolved to names rather than GUIDs.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 7.2 or later. Not 5.1: the script uses `-SkipHttpErrorCheck` and ternary syntax. |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scopes | `DeviceManagementConfiguration.Read.All` always; `DeviceManagementScripts.Read.All` for remediations, platform scripts and compliance policies; `DeviceManagementManagedDevices.Read.All` with `-IncludeDeviceRunStates`; `GroupMember.Read.All` unless `-SkipGroupNameResolution` |
| Admin consent | Required, once per tenant, for every scope above |
| Licensing | Microsoft Intune Plan 1, with an active Intune licence on the tenant |
| Role | Any Intune role with read access to these objects; read-only operator roles suffice |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Examples

```powershell
# Everything, to a timestamped folder outside the repository
.\Backup-IntuneConfiguration.ps1 -OutputPath C:\IntuneBackups -Verbose

# Only the remediations named in a change request, with their device status reports
$items = Get-Content .\cmr-items.txt
.\Backup-IntuneConfiguration.ps1 -OutputPath C:\IntuneBackups -Category Remediations `
    -Name $items -IncludeDeviceRunStates

# One profile by ID, no directory permission required
.\Backup-IntuneConfiguration.ps1 -OutputPath C:\IntuneBackups `
    -Id 00000000-0000-0000-0000-000000000000 -SkipGroupNameResolution

# Wildcards are accepted by -Name
.\Backup-IntuneConfiguration.ps1 -OutputPath C:\IntuneBackups -Name 'Pilot - *'
```

### What a backup looks like

```
IntuneBackup_20260920-141530\
    BackupIndex.csv             one row per object, with a resolved assignment summary
    BackupManifest.json         tenant, account, parameters, counts
    Backup.log                  timestamped log of the run
    Remediations\
        <Name>_<id8>\           remediation.json, assignments.json,
                                detection.ps1, remediation.ps1,
                                deviceRunStates.csv with -IncludeDeviceRunStates
    PlatformScripts\
        Windows\<Name>_<id8>\   script.json, assignments.json, the .ps1 itself
        macOS\<Name>_<id8>\     script.json, assignments.json, the .sh itself
    ConfigurationProfiles\
        SettingsCatalog\        policy.json, settings.json, assignments.json
        EndpointSecurity\       as above, one folder per template family
        SecurityBaselines\
        Templates\              profile.json, assignments.json
        AdministrativeTemplates\
                                profile.json, definitionValues.json, assignments.json
    CompliancePolicies\
        Policies\               policy.json, assignments.json
        CustomComplianceScripts\
                                script.json, discovery.ps1
```

Embedded script content is written byte-for-byte from the base64 Graph returns,
so the original encoding survives the round trip.

`BackupIndex.csv` is the file to open first. It carries the category, sub-type,
display name, ID, last modified date, assignment summary, status and notes for
every object, which makes it the fastest way to answer "what was assigned to
what" without opening a single JSON file.

### Start with the index, not the JSON

Assignments are resolved while the backup runs: group IDs become group names,
filter IDs become filter names, and remediation schedules are rendered as text.
A deleted group is recorded as `[deleted group <id>]` rather than silently
dropped. Use `-SkipGroupNameResolution` when the account cannot read the
directory; the IDs are recorded instead, and the run continues.

If the account loses group read access mid-run, the script says so once and
records IDs for the remainder rather than failing.

### The beta endpoint, deliberately

Every call goes to `/beta`. Most of these resources exist nowhere else —
`deviceHealthScripts`, `deviceManagementScripts`, `configurationPolicies`,
`groupPolicyConfigurations`, `deviceComplianceScripts`. The two that also exist
on v1.0 are read on beta as well, so that one backup is not split across two
contracts with different property sets.

This is the exception to the `Graph/` folder's v1.0-by-default rule, and the
reason is in the script's `.NOTES`. The beta contract changes without notice;
treat an unexpected property change as expected eventually.

### Scope tags cause silent gaps

Intune scope tags apply to these endpoints. An object outside the signed-in
account's scope is not returned at all, and its absence is not an error. A
backup taken by a scoped operator is a backup of what that operator can see, not
of the tenant. Take it with an account that can see everything you intend to
restore.

### Secrets

Graph does not return every secret. Some Wi-Fi and VPN keys come back empty and
must be re-entered on restore; where that is known the object's row in
`BackupIndex.csv` says so.

Encrypted OMA-URI values in custom profiles are the exception: they can be
retrieved, and `-IncludeOmaSecretValues` does retrieve them and writes them to
`omaSettings-plaintext.json` in clear text. It is off by default. Turn it on
only when you have somewhere appropriate to put the result, and treat the whole
backup folder as a secret from that point on.

### Not included

Apps, legacy endpoint security intents (`deviceManagement/intents`), and the
notification message templates that compliance actions reference. Template IDs
are recorded in the Notes column so a restore knows what it is missing.

This is an export, not a restore tool. The JSON is the record of what existed;
putting it back is a separate exercise, and one that needs a human reading the
diff first.

### Run states are deleted with the object

`-IncludeDeviceRunStates` exports the per-device status report for remediations
and platform scripts. Intune deletes that history along with the object, so this
is the switch to remember on the run immediately before a deletion. It is slow
on a large estate — one request per object, paged — which is why it is opt-in.

### Throttling and failures

Requests are retried on 429 and 5xx, honouring `Retry-After` where the service
sends it and backing off exponentially with jitter where it does not.
`-MaxRetries` caps the attempts per request.

A failure on one object is recorded in that object's index row and the run
continues; a failure listing a whole category is logged and the other categories
still run. The exit code says which happened:

| Code | Meaning |
| --- | --- |
| 0 | Every selected object was backed up. Warnings may still be listed in `BackupIndex.csv`. |
| 1 | Fatal: the output folder could not be created, or the Graph connection failed. |
| 2 | Finished, but at least one object or category listing failed. |

### The output is tenant data

Policy names, group names, the tenant ID, and with `-IncludeDeviceRunStates` the
names of real devices. Write backups outside this repository.
`Tools/Test-SensitiveContent.ps1` would stop a commit containing one, but the
better habit is not to put it in the working tree at all.

### Reference

- [Intune Graph API overview](https://learn.microsoft.com/graph/api/resources/intune-graph-overview)
- [Microsoft Graph throttling guidance](https://learn.microsoft.com/graph/throttling)
- [Role-based access control and scope tags in Intune](https://learn.microsoft.com/mem/intune/fundamentals/scope-tags)
