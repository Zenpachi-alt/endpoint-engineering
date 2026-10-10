# Devices

Reporting over Intune managed devices, and cleanup of stale Microsoft Entra
device objects.

| Script | Purpose |
| --- | --- |
| `Get-BitLockerKeyEscrowReport.ps1` | For every Windows device, whether Entra ID holds its BitLocker recovery key. Never reads a key. |
| `Get-ManagedDeviceInventory.ps1` | Every managed device in the tenant, with optional filtering and CSV export. |
| `Remove-StaleEntraDevice.ps1` | Finds stale Entra device objects, disables them, and deletes them after a grace period: one explicit stage per run, report by default. **Deletion cannot be undone.** |

## Get-ManagedDeviceInventory.ps1

Reads `/deviceManagement/managedDevices` on Graph v1.0, follows every page, and
returns one flat object per device. It writes nothing to the tenant.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scope | `DeviceManagementManagedDevices.Read.All` (`ReadWrite.All` is accepted) |
| Admin consent | Required, once per tenant, for the application you sign in with |
| Licensing | Microsoft Intune Plan 1, with an active Intune licence on the tenant |
| Role | Any Intune role with device read access; read-only operator roles suffice |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Examples

```powershell
# Device code sign-in, useful where a browser prompt is blocked or unavailable
.\Get-ManagedDeviceInventory.ps1 -UseDeviceCode -Verbose

# Windows devices that have not checked in for a month, stalest first
.\Get-ManagedDeviceInventory.ps1 -OperatingSystem Windows -StaleAfterDays 30 |
    Sort-Object DaysSinceLastSync -Descending | Format-Table

# Non-compliant devices, written to a timestamped CSV outside the repository
.\Get-ManagedDeviceInventory.ps1 -ComplianceState noncompliant -CsvPath C:\Reports

# Count devices by operating system
.\Get-ManagedDeviceInventory.ps1 | Group-Object OperatingSystem -NoElement
```

Objects are returned whether or not `-CsvPath` is supplied, so the result can be
sorted, grouped and piped rather than reopened from a file.

### Output

`DeviceName`, `UserPrincipalName`, `UserDisplayName`, `OperatingSystem`,
`OsVersion`, `ComplianceState`, `Ownership`, `ManagementAgent`,
`EnrollmentType`, `RegistrationState`, `EnrolledDateTime`, `LastSyncDateTime`,
`DaysSinceLastSync`, `Manufacturer`, `Model`, `SerialNumber`, `IsEncrypted`,
`IsSupervised`, `StorageTotalGB`, `StorageFreeGB`, `Category`, `EntraDeviceId`,
`IntuneDeviceId`.

`EnrolledDateTime` and `LastSyncDateTime` are UTC `DateTime` values on every
PowerShell version. `DaysSinceLastSync` is `$null` for a device that has never synced. Those devices
are always included by `-StaleAfterDays`, because never is staler than any
threshold.

### Filtering happens locally

Intune's `managedDevices` resource documents no optional OData query parameters,
and in practice `$filter` works on some properties and is rejected or ignored on
others. So `-OperatingSystem`, `-ComplianceState`, `-Ownership` and
`-StaleAfterDays` filter the results after they arrive, which always works.

`-Filter` passes a raw OData expression to the service for anyone who has
verified it against their own tenant. It is not the default for the reason
above.

### Throttling

Requests are retried on 429 and on 5xx, and when no response arrives at all. The
wait is the `Retry-After` value when the service sends one, and exponential
backoff with jitter when it does not, in line with Microsoft's guidance.
`-MaximumRetryCount` caps the attempts per request, the first included.

This is the shared Graph helpers' retry, tested against the real Graph SDK and a
local server that throttles. That test is how the SDK's own hidden retry came to
light: before version 1.1.0 the SDK absorbed every 429, gave up after four
attempts, and threw before this script's loop ever saw the status. The retry
has not yet met a real tenant's throttle.

### The output is tenant data

Every row names a real device, and most name a real person. Write reports
outside this repository. Committing one would be caught by
`Tools/Test-SensitiveContent.ps1`, but the better habit is not to put it in the
working tree at all.

### How it is tested

`Get-ManagedDeviceInventory.Tests.ps1` loads the script's functions and runs
its main block, with its own param block, against a stand-in tenant held in
memory, so no tenant or module is needed. It covers the record made of each
device, the request with and without `-Filter`, each local filter and all of
them together, the `-StaleAfterDays` boundary and never-synced devices, the
CSV, and the values the parameters refuse. The tests run under Windows
PowerShell 5.1 and PowerShell 7. The paging and retry behind the request are
the shared Graph helpers', tested by `Templates/Script-Template.Tests.ps1`.

### Reference

- [List managedDevices](https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list)
- [Microsoft Graph throttling guidance](https://learn.microsoft.com/graph/throttling)

## Get-BitLockerKeyEscrowReport.ps1

Reads every Intune managed device and every BitLocker recovery key in the
tenant, joins them on the Entra device ID, and returns one flat object per
Windows device, saying whether Entra ID holds a key for its OS volume. It writes
nothing to the tenant, and it never reads a key: it requests a scope that cannot
return one, and never asks for the `key` property, which would also write an
audit record for every key.

This is the authoritative half of the
[`BitLockerKeyEscrow`](../../Intune/Windows/Remediations/BitLockerKeyEscrow/)
remediation package. The device reports what it sent; this report says what
Entra ID holds.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scopes | `DeviceManagementManagedDevices.Read.All` (`ReadWrite.All` is accepted) and `BitlockerKey.ReadBasic.All` (`BitlockerKey.Read.All` is accepted when already granted) |
| Admin consent | Required for both, once per tenant, for the application you sign in with |
| Licensing | Microsoft Intune Plan 1 |
| Role | Read access to Intune devices, plus an Entra role that may list BitLocker keys: Global Reader, Security Reader, Security Administrator, Helpdesk Administrator, Cloud Device Administrator or Intune Administrator |

A consented scope is not enough on its own: without one of those roles, Graph
refuses to list keys with HTTP 403, and the script says which roles would do.

**Use a tenant-wide role.** A role scoped to administrative units sees only the
keys inside its scope, and every device outside it would be reported as
`MissingKey`.

### Examples

```powershell
# The encrypted devices whose key Entra ID does not hold
.\Get-BitLockerKeyEscrowReport.ps1 -Status MissingKey |
    Format-Table DeviceName, UserPrincipalName, LastSyncDateTime

# How many devices are in each status
.\Get-BitLockerKeyEscrowReport.ps1 | Group-Object Status -NoElement

# Every Windows device, written to a timestamped CSV outside the repository
.\Get-BitLockerKeyEscrowReport.ps1 -CsvPath C:\Reports -Verbose

# The devices closest to Entra ID's limit of 200 keys
.\Get-BitLockerKeyEscrowReport.ps1 | Sort-Object KeyCount -Descending |
    Select-Object -First 10 DeviceName, KeyCount
```

### Status

| Status | Meaning |
| --- | --- |
| `Escrowed` | Entra ID holds a key for the device's OS volume. |
| `MissingKey` | Intune reports the device encrypted, and Entra ID holds no OS volume key for it. The helpdesk cannot recover these devices. |
| `NotEncrypted` | Intune reports the device not encrypted, and Entra ID holds no OS volume key for it. |
| `NoEntraDevice` | The device has no Entra device ID, so its keys cannot be looked up. |

A key held for the OS volume counts whatever Intune reports about encryption,
which can lag behind the device.

Keys for fixed data volumes are counted in `FixedDataKeyCount` but do not change
the status: Graph does not say which devices have fixed data volumes. The
remediation package checks those on the device, and its output line names every
protector it finds.

### Output

`DeviceName`, `UserPrincipalName`, `Status`, `IsEncrypted`, `OsVolumeKeyCount`,
`FixedDataKeyCount`, `KeyCount`, `LatestKeyDateTime`, `KeyIds`,
`LastSyncDateTime`, `DaysSinceLastSync`, `EntraDeviceId`, `IntuneDeviceId`.

`KeyIds` lists the key IDs in lower case, separated by `; `. Each is the ID of a
protector on the device: the same GUID the remediation package's output shows in
upper case and braces, so the two can be compared directly.

Devices with 150 or more keys are named in a warning. Entra ID keeps at most 200
recovery keys per device, and silent encryption fails past that. Keys that
belong to no Windows device Intune manages are counted in the verbose stream and
not reported.

### How it is tested

`Get-BitLockerKeyEscrowReport.Tests.ps1` loads the script's functions and runs
the body of its main block against a stand-in tenant held in memory, so no
tenant or module is needed. It covers every status, the join, the filter, the
CSV and the key-count warning, and it fails if the script asks Graph for
anything but the two lists, including the `key` property. What it cannot show
is a real tenant's answers.

### Reference

- [List recoveryKeys](https://learn.microsoft.com/graph/api/bitlocker-list-recoverykeys)
- [bitlockerRecoveryKey resource type](https://learn.microsoft.com/graph/api/resources/bitlockerrecoverykey)
- [List managedDevices](https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list)

## Remove-StaleEntraDevice.ps1

Microsoft Entra ID never removes a device object by itself, so the records of
re-imaged, replaced and forgotten devices pile up. This script removes them in
three stages, and a run does only the stage it is asked for.

| Stage | What it does | How to undo it |
| --- | --- | --- |
| `Report` (default) | Lists every stale device and what would happen to it. Writes nothing to the tenant. | Nothing to undo |
| `Disable` | Disables the candidates, and writes a disabled-device file that lists them with the time. | Enable the device again in the admin center |
| `Delete` | Deletes devices from that file, and only from that file, once they have been disabled for the grace period. | **It cannot be undone** |

**Deleting a device is permanent.** Entra ID has no recycle bin for devices,
and the BitLocker recovery keys stored on a device object are deleted with it.
A device deleted by mistake has to be registered or joined again, and an
encrypted disk whose only key went with it is lost.

Intune is deliberately out of scope. Intune's own
[device cleanup rules](https://learn.microsoft.com/intune/governance/configure-cleanup-rules)
remove stale Intune records, and leave the Entra object behind. This script is
the other half.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scopes | `Device.Read.All`, `DeviceManagementManagedDevices.Read.All` and `BitlockerKey.ReadBasic.All` at every stage. With `-ExcludeGroupId`, also `GroupMember.Read.All`. With `-Stage Disable` or `Delete`, unless `-WhatIf`, also `Directory.AccessAsUser.All`. Broader scopes that are already granted are accepted; see `.NOTES` in the script. |
| Admin consent | Required for every scope, once per tenant |
| Licensing | Microsoft Intune Plan 1, for the list of managed devices. Microsoft Entra ID Free covers the rest. |
| Role | Intune Administrator covers every stage. So does Cloud Device Administrator, which may disable and delete devices and list BitLocker keys, together with an Intune role that can read managed devices. The Report stage needs only the reading half. |

`Directory.AccessAsUser.All` is the only delegated scope Graph accepts for
changing or deleting a device, and it is broad: the session can do in the
directory whatever the signed-in account can. The script asks for it only in a
run that changes something, so a report and a `-WhatIf` never hold it. What
limits the run is the role of the account, so use one that holds a device role
and nothing more. Disable and Delete need a signed-in user; an app-only session
cannot hold the scope and is refused.

### Examples

```powershell
# 1. Report. On a tenant that was never cleaned, start with the oldest slice.
.\Remove-StaleEntraDevice.ps1 -StaleAfterDays 730 -ExcludeGroupId '<GroupId>' -OutputPath C:\Reports |
    Group-Object Status -NoElement

# The candidates, stalest first
.\Remove-StaleEntraDevice.ps1 -StaleAfterDays 730 -ExcludeGroupId '<GroupId>' |
    Where-Object Status -eq 'Candidate' | Sort-Object DaysSinceActivity -Descending |
    Format-Table DisplayName, DaysSinceActivity, JoinType, RecoveryKeyCount

# 2. Preview the Disable stage, then run it. It asks once before the batch.
.\Remove-StaleEntraDevice.ps1 -Stage Disable -StaleAfterDays 730 -ExcludeGroupId '<GroupId>' `
    -OutputPath C:\Reports -WhatIf
.\Remove-StaleEntraDevice.ps1 -Stage Disable -StaleAfterDays 730 -ExcludeGroupId '<GroupId>' `
    -OutputPath C:\Reports

# 3. After the grace period, delete what is in the file and still qualifies.
.\Remove-StaleEntraDevice.ps1 -Stage Delete -ExcludeGroupId '<GroupId>' -OutputPath C:\Reports `
    -DisabledDevicePath C:\Reports\StaleEntraDevice-Disabled-20260930-101500.csv
```

Once the backlog is gone, the defaults do the routine work: stale after 120
days, deleted after 60 more.

### What counts as stale

A device is stale when its activity timestamp,
`approximateLastSignInDateTime`, is more than `-StaleAfterDays` old. Entra ID
refreshes that timestamp only once it is 14 days old, give or take 5, so the
script does not accept a value below 30.

Every device is read and the stale ones are picked out locally, so that a
device the script leaves alone can be reported together with the reason.

### Devices that are left alone

A stale device with any of these is reported as `Skipped`, with every reason
that applies. None of them can be switched off.

| Left alone when the device is | Because |
| --- | --- |
| in the group named by `-ExcludeGroupId` | You said so. Nested groups count. |
| registered with Windows Autopilot | Deleting the object breaks the next self-deploying or pre-provisioned deployment of the device. |
| Microsoft Entra hybrid joined | It is removed in on-premises Active Directory. Deleted here, Microsoft Entra Connect brings it back as a pending object. |
| of a profile type other than `RegisteredDevice` | Universal Print printers and the like are cleaned up in their own portals. |
| in a restricted management administrative unit | Only an administrator scoped to that unit may change it. |
| still in Intune | Retire or delete it in Intune first. With no Intune cleanup rule in place, this is what protects the laptop of someone on long leave. |
| without an activity timestamp | Entra ID leaves it blank on some devices that are in use, so never is not taken for stale. |

The Delete stage applies all of these again to every device in the file, and
also leaves alone a device that:

- was enabled again, which is how the helpdesk says it is wanted
- has been active since it was disabled, or is no longer stale by
  `-StaleAfterDays`
- holds BitLocker recovery keys in Entra ID

Only the last can be overridden, with `-IncludeDevicesWithRecoveryKey`. The
keys are counted from a list that cannot contain them; the script never reads
a key.

The Intune check reads Intune's device list, so the script needs an Intune
licence and stops if the list cannot be read. `IsManaged` is reported for every
device but is not a guard, because it does not say which MDM holds the device.
In a tenant with an MDM other than Intune, read that column before disabling
anything: the script does not know about devices only that MDM manages.

### The exclusion group

`-ExcludeGroupId` names a security group whose device members are never
disabled or deleted. It is for what the other checks cannot see: shared and lab
devices that are rarely used, spare stock, the personal phone of someone on a
long absence.

- The group is read before anything else, and if it cannot be read the run
  stops. A run without its exclusions is not the run that was asked for.
- It is read again at the Delete stage. A device added to the group after it
  was disabled is not deleted, and its reason says to enable it again.
- [`Add-GroupDeviceMember.ps1`](../Groups/) fills the group from a list of
  device names.

### The disabled-device file

Entra ID does not record when a device was disabled. The Disable stage writes
that down, device by device as it goes, in
`StaleEntraDevice-Disabled-<timestamp>.csv`. The Delete stage takes one or more
of these files and deletes nothing that is not in them.

- **Keep the file, and keep it as the script wrote it.** The date is read in
  one exact form. A spreadsheet that saves the file again rewrites the dates,
  and the script then refuses the file rather than risk reading a day as a
  month and shortening a grace period.
- A device in two files counts from its later date. That is the device someone
  enabled again, which went stale and was disabled a second time.
- A device that is disabled but in no file is reported as `AlreadyDisabled` and
  is never deleted by this script. That covers devices disabled by hand, and
  devices whose file was lost.

### The limit on one run

A Disable or Delete run that would change more devices than
`-MaximumDeviceCount`, 50 by default, changes none of them and fails. The batch
is never cut down to fit, because which devices were left out would be
arbitrary. The limit is what stands between a mistyped threshold and the whole
tenant, so raise it deliberately, after reading the report, and take a backlog
in slices with a high `-StaleAfterDays` first. The Report stage warns when its
candidates are over the limit.

Each run asks for one confirmation for its batch; `-Confirm:$false` skips it.
Every device is read again immediately before it is changed, and is left alone
if it was enabled, disabled or active in the meantime.

### What the user of a device sees

| Device | At the Disable stage | At the Delete stage |
| --- | --- | --- |
| Still in Intune | Left alone | Left alone |
| In the exclusion group | Left alone | Left alone |
| Holds a BitLocker key, not in Intune | Disabled: it can no longer authenticate to Entra ID until someone enables it | Left alone, unless overridden |
| Anything else, such as a personal phone or an old duplicate | Disabled, as above | Deleted: it has to be registered or joined again |

Disabling or deleting the object does not touch the device itself. It stays
registered or joined as far as it knows, until it next tries to authenticate.

### Status

| Status | Meaning |
| --- | --- |
| `Candidate` | Report: `-Stage Disable` would disable it. |
| `AlreadyDisabled` | Stale, and disabled before this run. |
| `Skipped` | Left alone. `Reason` says why. |
| `WouldDisable`, `WouldDelete` | Under `-WhatIf`, or with the confirmation declined. |
| `Disabled` | Disabled by this run, and written to the disabled-device file. |
| `InGracePeriod` | Delete: disabled for less than `-GraceDays`. |
| `Gone` | Delete: no device has that object ID any more. |
| `Deleted` | Deleted by this run. |
| `Failed` | The change failed, or a disabled device could not be written to the file. `Reason` says which. |
| `NotAttempted` | The batch was over `-MaximumDeviceCount`, or an earlier device stopped it. The first HTTP 403 stops a batch, since every later request would be refused for the same reason. |

The script exits `1` when any device is `Failed` or `NotAttempted`, after
returning every record and writing the report. Skipped devices do not change
the exit code.

The exit code is the same however the script is started: `$LASTEXITCODE` in a
PowerShell session, or what `pwsh -File` returns to a scheduled task.

### Output

`DisplayName`, `Status`, `Reason`, `ObjectId`, `DeviceId`, `JoinType`,
`TrustType`, `AccountEnabled`, `OperatingSystem`, `OperatingSystemVersion`,
`ApproximateLastSignInDateTime`, `DaysSinceActivity`, `RegistrationDateTime`,
`IsManaged`, `HasIntuneRecord`, `IntuneLastSyncDateTime`,
`AutopilotRegistered`, `Excluded`, `RecoveryKeyCount`, `DisabledDateTime`,
`DaysDisabled`.

The Report and Disable stages return a record for every device that is stale
or has no activity timestamp; devices in use are counted, not listed. The
Delete stage returns a record for every device in the files.

Files are written to `-OutputPath`, which defaults to the temp directory:

- `StaleEntraDevice-<Stage>-<timestamp>.csv` is every record of the run.
- `StaleEntraDevice-Disabled-<timestamp>.csv` is the disabled-device file,
  written only by a Disable run that disabled something.

Both name real devices. Keep them outside this repository.

### How it is tested

`Remove-StaleEntraDevice.Tests.ps1` loads the script's functions and runs the
body of its main block against a stand-in tenant held in memory. The stand-in
applies the changes it is sent and records every request, so a change to a
device that should have been left alone fails a test. The tests cover:

- every guard, alone and combined, and the boundary day of each threshold
- every status of all three stages
- what is sent: one `PATCH` of `accountEnabled` or one `DELETE` per device,
  each after a fresh read, and nothing for any other device
- the refusals: a batch over the limit, an unreadable exclusion group, Intune
  list or key list, and a disabled-device file with a date in any other form
- the scopes each stage asks for, including none that can change a device
  under `-WhatIf` and none that can read a key
- the script started with `-File` in a child process, for its exit code and
  its message; the case that gets past the module check is skipped where
  `Microsoft.Graph.Authentication` is not installed

The tests run under Windows PowerShell 5.1 and PowerShell 7. What they cannot
show is a real tenant's answers: the script has not yet been run against one.
Start with the Report stage, and read the report before anything else.

### Reference

- [Manage stale devices in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/devices/manage-stale-devices)
- [Update device](https://learn.microsoft.com/graph/api/device-update)
- [Delete device](https://learn.microsoft.com/graph/api/device-delete)
- [device resource type](https://learn.microsoft.com/graph/api/resources/device)
- [Intune device cleanup rules](https://learn.microsoft.com/intune/governance/configure-cleanup-rules)
