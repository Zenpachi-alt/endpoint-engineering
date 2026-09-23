# ComponentRepairSource

Detection-only script package that reports where DISM would get repair files on
each device, and lists the devices where DISM `RestoreHealth` is likely to fail.
It is the first step of rolling out
[`SystemFileHealth`](../SystemFileHealth/): its DISM branch runs on few
devices, so learning which of them have no repair source is cheaper before the
branch runs than after.

| File | Role |
| --- | --- |
| `Test-ComponentRepairSource.ps1` | Detection only. Reads the repair-source policy, asks the Windows Update Agent whether the device uses WSUS, and reports one line. Changes nothing. |

## How it decides

DISM tries the policy's alternate source path first, then Windows Update where
that is allowed. The script follows the same order, and its output line starts
with one of four tokens:

| Token | Exit | Meaning |
| --- | --- | --- |
| `LocalSource` | `0` | An alternate source path (`LocalSourcePath`) is set, and DISM tries it first. |
| `WindowsUpdate` | `0` | Updates do not come from WSUS, so DISM downloads from Windows Update. |
| `WsusRepairFromWindowsUpdate` | `0` | Updates come from WSUS, and the pre-24H2 policy option sends repair downloads to Windows Update. |
| `WsusOnly` | `1` | Updates come from WSUS and no repair source counts. DISM `RestoreHealth` is likely to fail with `0x800F081F`. |

The line ends with the update service's name and the Windows build, for
example:

```text
WindowsUpdate: updates do not come from WSUS, so DISM downloads repair files from Windows Update. Update service: Microsoft Update. Build 26200.
```

Three choices behind that:

- **WSUS is read from the Windows Update Agent**, which reports the service the
  device actually uses, whether Group Policy, Configuration Manager or an Intune
  policy set it. The Group Policy registry values are logged as a cross-check
  and decide only if the agent cannot be queried.
- **The build decides whether `RepairContentServerSource` counts.** Before
  build 26100 (Windows 11 24H2) the policy offered "download repair content
  directly from Windows Update instead of WSUS", stored as `2`. From 24H2 the
  policy has only the source path, so a leftover value is reported and not
  counted.
- **When unsure, the verdict is `WsusOnly`.** The package exists to find the
  devices a pilot must look at, and a false "fine" would hide exactly those.

The build is read from `CurrentBuild`, never from the product name: Windows 11
still reports "Windows 10" in `ProductName`.

## Intune settings

| Setting | Value |
| --- | --- |
| Detection script file | `Test-ComponentRepairSource.ps1` |
| Remediation script file | None |
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No, unless the script is signed |
| Run script in 64-bit PowerShell | Either. Registry values are read from the 64-bit view explicitly. |
| Schedule | Once, or daily while a pilot is being planned. The check takes under a second. |

## Reading the results

With no remediation script, exit `1` starts nothing: it only puts `WsusOnly`
devices under *With issues* in the device status report, which lists the
devices at risk without reading every line. For the full picture, export the
report to CSV and group by the token at the start of the output.

Each run also logs its facts - build, both policy values, the Group Policy WSUS
values and the Windows Update Agent's answer - to
`%ProgramData%\EndpointEngineering\Logs\Test-ComponentRepairSource.log`.

## Limitations

- **Reachability is not tested.** `WindowsUpdate` means the device would ask
  Windows Update, not that a proxy or firewall lets it through; `LocalSource`
  means a path is set, not that the share is reachable or patched to the same
  level as the device.
- **Windows 11 24H2 and later with WSUS** are reported as `WsusOnly`. From 22H2,
  WSUS delivers Features on Demand and language packs through on-premises UUP,
  but whether it delivers corruption repair content is not documented. Include
  some of these devices in the pilot; the SystemFileHealth report settles it.
- **Mixed sources.** Where Windows Update for Business policies send some
  classes of update to Windows Update and others to WSUS, the verdict follows
  the agent's default service.

## Licensing and permissions

Remediations require Intune plus Windows Enterprise E3/E5, Windows Education
A3/A5, or Windows VDA per user. Creating and assigning the package needs the
Intune *Device configurations* permissions. On the device, the script only
reads, so SYSTEM or any user can run it.

## Reference

- [Policy CSP - ADMX_Servicing](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-servicing)
- [Features on Demand and language packs with WSUS or Configuration Manager](https://learn.microsoft.com/windows/deployment/update/fod-and-lang-packs)
- [Configure a Windows repair source](https://learn.microsoft.com/windows-hardware/manufacture/desktop/configure-a-windows-repair-source)
- [IUpdateService (Windows Update Agent API)](https://learn.microsoft.com/windows/win32/api/wuapi/nn-wuapi-iupdateservice)
