# Devices

Reporting over Intune managed devices.

| Script | Purpose |
| --- | --- |
| `Get-BitLockerKeyEscrowReport.ps1` | For every Windows device, whether Entra ID holds its BitLocker recovery key. Never reads a key. |
| `Get-ManagedDeviceInventory.ps1` | Every managed device in the tenant, with optional filtering and CSV export. |

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
