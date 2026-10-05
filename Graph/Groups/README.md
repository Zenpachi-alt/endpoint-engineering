# Groups

Group membership changes made from a workstation against the tenant.

| Script | Purpose |
| --- | --- |
| `Add-GroupDeviceMember.ps1` | Resolves a list of device names to Entra device object IDs, filtered by join type and recent activity, and adds them to a group or writes the portal's bulk import CSV. |

## Add-GroupDeviceMember.ps1

The usual starting point is a list of host names from a spreadsheet, a
ticket or an on-premises query. Group membership needs each device's Entra
**object ID**, and a name doesn't always identify a single device. Hybrid join,
re-imaging and personal registrations all leave several device records with
the same name. This script looks each name up, sets aside the records that
fail the filters, and reports exactly what happened to every name.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scopes | `Device.Read.All`. With `-GroupId`, also `GroupMember.ReadWrite.All`, or only `GroupMember.Read.All` with `-WhatIf`. Broader scopes that are already granted are accepted; see `.NOTES` in the script. |
| Admin consent | Required for every scope, once per tenant |
| Licensing | Microsoft Entra ID Free. No Intune licence is needed. |
| Role | Reading devices: any member user, unless default user permissions are restricted. Adding: Groups Administrator, Intune Administrator (security groups only), User Administrator, Directory Writers, or an owner of the group. A role-assignable group also needs Privileged Role Administrator. |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Examples

```powershell
# Hybrid joined devices active in the last 30 days: report and import CSV only
.\Add-GroupDeviceMember.ps1 -Path .\servers.txt -TrustType ServerAd -ActiveWithinDays 30

# The same names from a CSV column, checked against a group without changing it
.\Add-GroupDeviceMember.ps1 -Path .\devices.csv -ColumnName Hostname `
    -GroupId '<GroupId>' -TrustType ServerAd -ActiveWithinDays 30 -WhatIf

# Add them, after one confirmation, with the files written to C:\Reports
.\Add-GroupDeviceMember.ps1 -Path .\servers.txt -GroupId '<GroupId>' `
    -TrustType ServerAd -ActiveWithinDays 30 -OutputPath C:\Reports

# The names that did not resolve to exactly one device, and why
.\Add-GroupDeviceMember.ps1 -DeviceName 'PC01', 'PC02' |
    Where-Object Status -ne 'Matched' | Format-Table InputName, Status, Reason
```

For an unattended run, add `-Confirm:$false`. Without it, the script asks
once before adding the batch.

### Input

`-Path` takes a text file with one name per line, or a CSV file. A CSV is read
from `-ColumnName`, or from its only column. `-DeviceName` takes names
directly.

Names are trimmed and compared without regard to case. A fully qualified name
is looked up by its host name, so `pc01.contoso.com` finds `pc01`. A name
that contains a space is kept whole. Duplicate names are collapsed and counted
in a warning.

### Filters

| Parameter | Keeps |
| --- | --- |
| `-TrustType` | `ServerAd` (Microsoft Entra hybrid joined), `AzureAd` (Microsoft Entra joined), `Workplace` (Microsoft Entra registered). Several may be given. |
| `-ActiveWithinDays` | Devices whose activity timestamp, `approximateLastSignInDateTime`, is no older than this. A device with no timestamp is excluded. |
| `-IncludeDisabled` | Disabled devices as well. They are excluded by default because a disabled device cannot authenticate to Entra ID. |

**"Last sync" here means Entra activity**, not an Intune check-in or an
Entra Connect sync. Entra ID refreshes the timestamp only once it is 14 days
old, give or take 5, so a window shorter than 21 days excludes devices that are
in use. The script warns when you ask for one.

The filters are applied locally, after the lookup, so an excluded device can
be reported along with the reason. Only the name lookup runs on the service:
`displayName in (...)`, 15 names per request.

### Status

| Status | Meaning |
| --- | --- |
| `Matched` | Exactly one device record by that name passed the filters. `ObjectId` is the one to use. |
| `NotFound` | No device record has that name. |
| `Excluded` | Records have that name, and none passed. `Reason` gives what each one failed. |
| `Ambiguous` | More than one record passed. None is chosen: narrow the filters, or clean up the stale duplicates. `CandidateObjectIds` lists them. |

A `Matched` record whose name also belongs to records that failed the filters
says so in `Reason`. That is usually the stale half of a re-imaged or
dual-registered device.

`ObjectId` is the directory object ID that group membership uses. `DeviceId`
is the device's own registration ID. The two are easy to confuse, and only the
first works for membership.

### Adding to a group

With `-GroupId`, the group is checked before any device is looked up. The
script refuses a group whose membership cannot take devices added by hand:

- a group with dynamic membership
- a Microsoft 365 group (only security groups can hold devices)
- a distribution list or mail-enabled security group
- a group synced from on-premises Active Directory

Devices already in the group are skipped and reported as `AlreadyMember`.
The rest are added one request at a time, because a request that adds several
devices fails completely if any one of them is refused. The first HTTP 403
stops the batch: every later request would be refused for the same reason.

**Adding a device to a group can start deployments to it immediately.**
Whatever is assigned to the group, whether apps, configuration profiles,
scripts or remediations, applies to the new members at their next check-in.
Run with `-WhatIf` first.

| Membership | Meaning |
| --- | --- |
| `Added` | The device was added. |
| `AlreadyMember` | The device was already a direct member. |
| `WouldAdd` | Under `-WhatIf`, or with the confirmation declined, this device would have been added. |
| `Failed` | The request was refused; `MembershipDetail` says why. |
| `NotAttempted` | An earlier 403 stopped the batch. |

The script exits `1` when any device is `Failed` or `NotAttempted`, after
returning every record and writing the report. Names that did not resolve do
not change the exit code. They are data to act on, not a failed run. The code
is the same in a session, as `$LASTEXITCODE`, and from `pwsh -File`.

### Output files

Both files are written to `-OutputPath`, which defaults to the temp directory.

- `GroupDeviceMember-<timestamp>.csv` is every record, in input order.
- `GroupDeviceMember-<timestamp>-Import.csv` holds the `Matched` object IDs
  in the format the Microsoft Entra admin center expects under **Groups** >
  the group > **Members** > **Bulk operations** > **Import members**. It
  starts with the template's exact header and has no version row. Current
  members are left out, because the import would fail on them. The file is
  written unless the script added the devices itself. The admin center asks
  for at least two rows, and the script warns when there is only one.

Records are also returned on the pipeline, so they can be filtered and
formatted without reopening a file.

### How it is tested

`Add-GroupDeviceMember.Tests.ps1` loads the script's functions and runs the
body of its main block against a stand-in tenant held in memory. The stand-in
answers the device lookup by parsing the filter the script sends, so a filter
that asks for the wrong names fails. The tests cover:

- input cleaning and CSV columns
- batching and quote escaping in the lookup
- every status, filter, and filter combination, including the boundary day
- every group the script refuses
- the add requests, `-WhatIf`, a retried add that had already landed, and the
  403 stop
- both files and the exit path
- the script started with `-File` in a child process, for its exit code and
  its message; skipped where `Microsoft.Graph.Authentication` is not installed

The tests run under Windows PowerShell 5.1 and PowerShell 7. What they cannot
show is a real tenant's answers.

### Reference

- [Add members to a group](https://learn.microsoft.com/graph/api/group-post-members)
- [device resource type](https://learn.microsoft.com/graph/api/resources/device)
- [Bulk add group members](https://learn.microsoft.com/entra/identity/users/groups-bulk-import-members)
- [Manage stale devices: the activity timestamp](https://learn.microsoft.com/entra/identity/devices/manage-stale-devices)
