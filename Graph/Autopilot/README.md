# Autopilot

Admin-side tooling for Windows Autopilot device identities, run from a
workstation against a tenant.

| Script | Purpose |
| --- | --- |
| `Import-AutopilotDeviceIdentity.ps1` | Registers devices with Autopilot from a hardware hash CSV. |

The CSV these consume is produced on the device by
[`Intune/Windows/Autopilot/Get-AutopilotHardwareHash.ps1`](../../Intune/Windows/Autopilot/README.md),
which explains why collection and registration are two scripts rather than one.
A CSV exported from the Intune portal works equally well.

## Import-AutopilotDeviceIdentity.ps1

Posts each device to `/deviceManagement/importedWindowsAutopilotDeviceIdentities`
on Graph v1.0, then polls until the service reports a final state for every one.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7 |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Graph scope | `DeviceManagementServiceConfig.ReadWrite.All` |
| Admin consent | Required, once per tenant, for the application you sign in with |
| Licensing | Microsoft Intune Plan 1, with an active Intune licence on the tenant |
| Role | Intune Administrator, or a custom role with the Enrollment programs "Create device" permission |

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### This one writes to the tenant

Registration is a tenant write, so the script asks for confirmation once before
submitting the batch, and `-WhatIf` reports exactly what would be sent without
contacting Graph at all — it validates the CSV, then returns one object per
device with a `notSubmitted` status. Run it that way first.

Registering a device is reversible: delete the Autopilot device identity in
Intune. Deregistration is not instantaneous, though, and a device registered to
the wrong tenant is somebody else's problem to release. Check the CSV before
confirming.

### Examples

```powershell
# Validate the CSV and report what would be sent. Nothing reaches the tenant.
.\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' -WhatIf

# Register everything in the CSV and wait for the outcome
.\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' -Verbose

# Apply one group tag to the whole batch, overriding whatever the CSV carries
.\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' -GroupTag 'Kiosk' -ReportPath 'C:\Reports'

# Register, then look only at what did not succeed
.\Import-AutopilotDeviceIdentity.ps1 -CsvPath 'D:\AutopilotHWID.csv' |
    Where-Object { $_.Status -ne 'complete' }
```

Objects are returned whether or not `-ReportPath` is supplied, so the result can
be sorted, grouped and piped rather than reopened from a file.

### Output

One object per device: `SerialNumber`, `GroupTag`, `AssignedUser`, `Status`,
`ErrorCode`, `ErrorName`, `Advice`, `RegistrationId`.

`Status` is the service's own `deviceImportStatus` — `complete`, `error`,
`partial` — plus three the script adds: `submitFailed` when the request never
reached the service, `timedOut` when the wait expired before a final state
arrived, and `notSubmitted` under `-WhatIf`.

`Advice` turns the service's error name into something worth acting on. The
common one is `ZtdDeviceAlreadyAssigned`: the device is already registered,
here or in another tenant.

### Failure does not stop the batch

A device that fails to submit or import is recorded and the run continues. The
script exits `1` if any device genuinely failed, and `0` when everything
completed or there was nothing to do. Devices still pending at the timeout are
**not** counted as failures — the service usually finishes regardless, and the
Autopilot devices list in Intune is the place to confirm.

### The CSV is validated before anything is sent

Rows with no serial number, no hardware hash, or a hash that is not valid
base64 are reported with their line number and skipped. Duplicate serial
numbers are collapsed, keeping the last occurrence, matching how the collector
appends. If nothing importable survives, the script fails rather than
cheerfully submitting an empty batch.

### Why one request per device

There is a bulk `import` action on the same resource. This script uses the
per-device create instead: it is the path Microsoft's own tooling has always
taken, its per-device outcome is unambiguous, and one failure cannot take the
batch with it.

### Retries never register a device twice

A registration is resent only after 429 or 503, the answers that mean the
service did not act on it. After any other failure the device is reported as
`submitFailed` rather than resent: a second submission of a request that did
land would be tracked in place of the first and come back as a duplicate.
Status checks are reads, and are retried on 429, 5xx and a lost connection.
Every wait is the `Retry-After` value when the service sends one, and
exponential backoff with jitter when it does not.

This is the shared Graph helpers' retry, tested against the real Graph SDK and a
local server that throttles. It has not yet met a real tenant's throttle.

### Verification status

CSV parsing, validation, deduplication, group tag override, request body
construction and error advice are covered by tests run against Windows
PowerShell 5.1, including a round trip from a CSV written by the collector.

Version 1.1.0 was also run end to end, under Windows PowerShell 5.1 and
PowerShell 7, against stand-ins for the Graph cmdlets: a 503 on submission,
resent once; polling to a final state; and an already-registered device
reported as a skip with exit code 0.

The Graph calls themselves have not been run against a tenant from this
repository. The endpoint, scope and request shape come from the current v1.0
documentation linked below.

### Output is tenant data

Every row names a real device. Write reports outside this repository;
`Tools/Test-SensitiveContent.ps1` will stop a commit containing one, but the
better habit is not to put it in the working tree at all.

### Reference

- [Create importedWindowsAutopilotDeviceIdentity](https://learn.microsoft.com/graph/api/intune-enrollment-importedwindowsautopilotdeviceidentity-create)
- [Get importedWindowsAutopilotDeviceIdentity](https://learn.microsoft.com/graph/api/intune-enrollment-importedwindowsautopilotdeviceidentity-get)
- [Microsoft Graph throttling guidance](https://learn.microsoft.com/graph/throttling)
