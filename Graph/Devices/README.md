# Devices

Reporting over Intune managed devices.

| Script | Purpose |
| --- | --- |
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

`DaysSinceLastSync` is `$null` for a device that has never synced. Those devices
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

Requests are retried on 429 and on 5xx. The wait is the `Retry-After` value when
the service sends one, and exponential backoff with jitter when it does not, in
line with Microsoft's guidance. `-MaximumRetryCount` caps the attempts per
request.

The retry path has not been exercised against a real 429. It is written from the
documented contract, not from an observed throttle.

### The output is tenant data

Every row names a real device, and most name a real person. Write reports
outside this repository. Committing one would be caught by
`Tools/Test-SensitiveContent.ps1`, but the better habit is not to put it in the
working tree at all.

### Reference

- [List managedDevices](https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list)
- [Microsoft Graph throttling guidance](https://learn.microsoft.com/graph/throttling)
