# Autopilot

Hardware hash collection for Windows Autopilot registration. This is the
endpoint-side half of the workflow: it runs on the device being registered,
usually during OOBE, and produces a CSV. Registering that CSV against a tenant
is [`Graph/Autopilot/Import-AutopilotDeviceIdentity.ps1`](../../../Graph/Autopilot/README.md).

| File | Role |
| --- | --- |
| `Get-AutopilotHardwareHash.ps1` | Reads the hardware hash and serial number, writes an import-ready CSV. |
| `Get-AutopilotHardwareHash.cmd` | Double-click launcher for OOBE. Prompts for a group tag, collects into a shared CSV. |
| `Get-AutopilotHardwareHash.Tests.ps1` | Pester tests: the CSV and its columns, `-Append` merging, what the script refuses, file names, and the script run as a file. |

## Why collection and registration are separate

The obvious design is one script that collects the hash and uploads it there and
then. It is the wrong one:

- **It needs tenant credentials on the shop floor.** Registering from the device
  means a technician signs in as someone who can write Autopilot device
  identities, on an unmanaged machine at OOBE, once per device.
- **It needs the Graph modules on the USB key.** Around 135 MB of them, and the
  `WindowsAutopilotIntune` module still pulls in `Microsoft.Graph.Intune`, whose
  current release ships the retired ADAL authentication library.
- **It is slower where slowness costs most.** Registration is asynchronous, so
  uploading per device means waiting at the device for a service round trip that
  tells you nothing you could not learn later in bulk.

Collecting offline needs none of that. The script below depends on nothing
beyond Windows itself, never touches the network, and finishes in seconds.

## Get-AutopilotHardwareHash.ps1

Reads `DeviceHardwareData` from the `MDM_DevDetail_Ext01` WMI class and the
serial number from `Win32_BIOS`, then writes them in the column layout Intune's
import expects.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | Windows PowerShell 5.1. PowerShell 7 is not present during OOBE. |
| Modules | None |
| Context | Administrator or SYSTEM. The Shift+F10 prompt during OOBE is already SYSTEM. |
| Network | Not required |
| Graph scopes | None |
| Licensing | None to collect. Registering the result needs Microsoft Intune Plan 1. |
| Role | Local administrator on the device being collected |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The hash was collected, written, and verified by reading the file back. |
| `1` | Collection or writing failed. The reason is on stderr and in the log. |

This is a technician tool, not a remediation, so the `0`/`1`/`2` detection
contract in [`Templates/Remediation/README.md`](../../../Templates/Remediation/README.md)
does not apply.

### Examples

```powershell
# One file per device, next to the script
.\Get-AutopilotHardwareHash.ps1

# One shared file for a whole cart, with a group tag
.\Get-AutopilotHardwareHash.ps1 -Append -GroupTag 'Kiosk'

# User-driven deployment, with the target user stamped on the record
.\Get-AutopilotHardwareHash.ps1 -AssignedUser 'user@contoso.com' -Verbose

# Report the file that would be written, without touching the disk
.\Get-AutopilotHardwareHash.ps1 -OutputPath 'D:\' -WhatIf
```

### Output

A CSV with Intune's own column names: `Device Serial Number`,
`Windows Product ID`, `Hardware Hash`, then `Group Tag` and `Assigned User`,
each only when at least one device in the file has a value for it. A file with
a user and no group tag therefore has `Assigned User` straight after
`Hardware Hash`, which is where Microsoft's user-assignment guidance puts it.
`Windows Product ID` is deliberately blank — the PKID is available to OEMs only
and is not required to register a device.

With `-Append`, everything lands in one `AutopilotHWID.csv`. Records are keyed
on serial number, and collecting a device again **replaces** its earlier record
rather than duplicating it: a hardware hash changes when the motherboard does,
and the newer reading is the correct one. Rows already in the file that have no
serial number or no hash are dropped and counted, because one unusable row
fails the import for the whole file.

### The CSV is written unquoted

That matches the format Microsoft's own collector produces and the portal
accepts. Unquoted fields cannot carry a delimiter, so the script refuses to
write a serial number, group tag or assigned user containing a comma, a double
quote or a line break. Failing loudly is better than producing a file that
imports as the wrong device.

### Serial numbers are not safe file names

They are OEM-supplied and routinely contain spaces and slashes, and on white-box
hardware and virtual machines they are often placeholders like
`To be filled by O.E.M.`. The script sanitises the serial before it reaches a
file name, and warns when the value looks like an unset placeholder — Autopilot
will happily register the device under it, and you will not enjoy finding it
again later.

### Output is device data

Every row identifies a real machine. The file name always begins with
`AutopilotHWID`, which `.gitignore` excludes, so a stray run inside a clone
cannot commit device identifiers. That is a backstop, not a plan: write the CSV
to the USB key or somewhere outside the working tree.

## Get-AutopilotHardwareHash.cmd

The OOBE launcher. Put both files in the root of a USB key, boot the device,
press **Shift+F10** at the first OOBE screen, and run the `.cmd` from the key.
It prompts for a group tag, runs the collector with `-Append` so one file covers
the whole batch, and reports the exit code.

If the USB key has no drive letter you cannot launch anything from it. Run
`diskpart`, then `rescan`, then `list volume`, then `exit`, and try again — the
launcher repeats the rescan itself for a key inserted after the prompt opened,
but it cannot help with the key it lives on.

## Verification status

The hardware hash read has been run elevated on physical hardware under both
Windows PowerShell 5.1 and PowerShell 7.6, in per-device and `-Append` modes.
Run unelevated, the script stops at the elevation guard, says it must run
elevated, and exits `1`.

`Get-AutopilotHardwareHash.Tests.ps1` covers the CSV format, the merge and
replace behaviour, the file name sanitising and the unquoted-write rules. It
tests the script's functions with `Get-CimInstance` mocked, checks what the
parameters refuse against the script's own param block, and starts the whole
script with `powershell.exe -File`, as a technician does, with stand-ins for
the elevation check and the two WMI reads: one file per device, repeated
`-Append` runs against one file, the placeholder warning, `-WhatIf`, and exit
codes `0` and `1`. The tests run under Windows PowerShell 5.1 and
PowerShell 7, on Windows only, like the script.
[`Import-AutopilotDeviceIdentity.Tests.ps1`](../../../Graph/Autopilot/Import-AutopilotDeviceIdentity.Tests.ps1)
writes CSVs with this script's own functions and reads them back through the
importer's parser.

Not yet exercised: collection from the Shift+F10 prompt during a real OOBE, and
the `.cmd` launcher on a USB key.

## Reference

- [Add devices to Windows Autopilot](https://learn.microsoft.com/autopilot/add-devices)
- [Windows Autopilot registration overview](https://learn.microsoft.com/autopilot/registration-overview)
