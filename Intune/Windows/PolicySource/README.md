# PolicySource

Where does this policy setting come from? On a device managed by both Group
Policy and Intune, often by two different teams, nothing on the device answers
that directly. `Get-PolicySource.ps1` does: for every policy setting, which GPO
or MDM setting sets it, what value each one wants, and which value Windows is
actually using.

| File | Role |
| --- | --- |
| `Get-PolicySource.ps1` | Reads every local source of policy and returns one row per setting, with a verdict. |
| `Get-PolicySource.Tests.ps1` | Pester tests: each reader against a registry tree built under `HKEY_CURRENT_USER`, each verdict, and the script run as a file. |

## Why it is needed

Intune writes many settings to the same `HKLM\SOFTWARE\Policies` keys Group
Policy writes. A message such as "a Group Policy setting prevents this" names
the mechanism, not the team: the value may well have come from Intune. A
BitLocker prompt about removable drives is a common example. The Intune setting
`BitLocker/RemovableDrivesRequireEncryption` and the GPO setting *Deny write
access to removable drives not protected by BitLocker* write the same registry
value.

When both sides set the same thing, one of three things happens:

- **Without `MDMWinsOverGP`**, both apply. Which value Windows uses depends on
  which wrote last, and Microsoft gives no guarantee which that is.
- **With `ControlPolicyConflict/MDMWinsOverGP` on**, Windows stops applying the
  GPO setting. The GPO still holds it, but the RSoP data, `rsop.msc` and
  `gpresult`'s main list no longer show it. Only `gpresult`'s
  *Setting controlled by a different authority* section does, and that needs a
  domain controller. The GP team sees nothing wrong, and the setting comes back
  as soon as the Intune policy is removed.
- **Neither side knows about the other.** Intune's reports compare Intune
  policies with each other, and Group Policy analytics reads GPO backups, not
  what a device received.

The device is the only place both sides meet, so the script runs there.

## Get-PolicySource.ps1

Run it in an elevated Windows PowerShell on the device:

```powershell
# Everything, the settings that need a decision first
.\Get-PolicySource.ps1

# BitLocker, wherever it comes from (FVE is BitLocker's policy key)
.\Get-PolicySource.ps1 -Filter '*FVE*', '*BitLocker*'

# Only what both sides claim, where one of them loses
.\Get-PolicySource.ps1 -Verdict Conflict, OverriddenByMdm, NotApplied

# Every column, with the note that explains each verdict
.\Get-PolicySource.ps1 -Filter '*WindowsUpdate*' | Format-List

# A file for the other team
.\Get-PolicySource.ps1 | Export-Csv -Path .\PolicySource.csv -NoTypeInformation
```

`-Filter` takes wildcards and tries each one against the setting, the registry
path, the MDM setting and the GPO name. `-IncludeWindowsInternal` adds what
Windows provisions for itself (see below).

### Verdicts

Rows come back in this order:

| Verdict | Meaning |
| --- | --- |
| `Conflict` | Group Policy and an MDM both apply it, with different values. The note says whose value the registry holds. |
| `OverriddenByMdm` | A GPO sets it, but Group Policy did not apply it because an MDM sets it too. The note says whether the two values differ. |
| `NotApplied` | A GPO sets it, Group Policy did not apply it, and no MDM setting explains why. Check the Group Policy operational log. |
| `Both` | Both set it. Intune sends ADMX-backed settings as a state (`Enabled`, `Disabled`, with any data), not as the registry value, so the two are not compared. |
| `Agree` | Both set it, to the same value. |
| `GpOnly` | Group Policy only: a registry policy setting, a Preferences item, or a wireless profile. |
| `MdmOnly` | Intune or another MDM only. |
| `Unclaimed` | A value under `HKLM\SOFTWARE\Policies` that no source claims: a script, an app, another management tool, or a Windows default. |

### Columns

| Column | Holds |
| --- | --- |
| `Verdict` | One of the verdicts above. |
| `Setting` | The MDM setting name where there is one (`Area/Policy`), otherwise the registry key and value. |
| `LiveValue` | The value in the registry now. |
| `GpValue`, `Gpo` | The value Group Policy sets and the winning GPO. For `OverriddenByMdm` and `NotApplied`, the GPO that holds the setting. |
| `OverriddenGpo` | GPOs that set the same value but lost on precedence. |
| `GpSource` | `Registry policy`, `Preferences`, `Wireless profile`, or `GPO, not applied`. |
| `MdmSetting`, `MdmValue` | The MDM setting and its value. An ADMX state is shown as `Enabled: id=value; ...`. |
| `MdmSource`, `MdmSourceKind` | Who set it: `Intune`, another MDM's provider name, or `Windows`. |
| `RegistryPath` | The registry value, from `HKLM`. |
| `Note` | Why the verdict is what it is, and anything that does not add up. A value written after Group Policy or the MDM is one example. |

Only the first seven columns show by default; `Format-List` or `Select-Object *`
shows the rest.

### How it decides

Everything is read locally. Nothing contacts a domain controller or the
internet, so it works off the corporate network.

| Source | Where | Gives |
| --- | --- | --- |
| MDM | `HKLM\SOFTWARE\Microsoft\PolicyManager` | Each setting's value, the winning enrollment, and its registry mapping |
| Group Policy | RSoP, `root\rsop\computer` | The applied registry settings, the winning GPO, the GPOs that lost |
| GPO cache | `%windir%\System32\GroupPolicy\DataStore` | Each applied GPO's own `Registry.pol`, including settings that were not applied |
| Preferences | `%ProgramData%\Microsoft\Group Policy\History` | Group Policy Preferences registry items |
| Registry | The value itself | What Windows reads now |

PolicyManager records, for each setting, the registry value it writes
(`RegKeyPathRedirect`, `RegValueNameRedirect`) and the Group Policy value
`MDMWinsOverGP` blocks (`GPBlockingRegKeyPath`, `GPBlockingRegValueName`), in
`default\<Area>\<Policy>` for settings built into Windows and in `AdmxDefault`
for ingested ADMX. That mapping is what puts an MDM setting and a GPO setting
on the same row. The setting's value is in `current\device\<Area>`, or, for one
stored at its registry location, in the winning enrollment's own store under
`providers`.

A GPO setting in the cache that RSoP does not show was not applied. When an MDM
setting writes the same value, or writes under the same key as an ADMX-backed
setting, that is `OverriddenByMdm`.

`gpresult` is not used. It needs a domain controller and stalls for minutes
without one, and the RSoP data and the cache together hold what it would add.

### What it leaves out

- **Windows' own provisioning.** PolicyManager holds hundreds of settings that
  Windows sets for itself through enrollments of type 1, mostly power and
  processor tuning. They are not anyone's policy, so they are left out unless
  `-IncludeWindowsInternal` is given.
- **RSoP entries that are not settings**: entries without a value name, which
  create keys, and `**` entries, which delete values or keys.
- **User settings.** Only computer settings are read.
- **Security settings**: password and lockout policy, user rights, audit. They
  are applied by a separate engine, not through the registry.
- **Value comparison for ADMX-backed MDM settings.** `Both` says they overlap,
  but the state is not translated into the registry value it implies.

`Unclaimed` is only looked for under `HKLM\SOFTWARE\Policies`. A value a script
writes anywhere else is not reported.

### Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | Windows PowerShell 5.1. It runs on the device, where PowerShell 7 cannot be assumed. |
| Modules | None |
| Context | Elevated. The RSoP data and the GPO cache are readable by administrators only. |
| Network | Not required |
| Graph scopes | None. Nothing leaves the device. |
| Licensing | None to run. It reads what Group Policy and an MDM have applied. |
| Role | Local administrator on the device |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The sources were read. Includes a run where no setting matches the filter. |
| `1` | Not elevated, or the MDM or Group Policy data could not be read. The reason is on stderr and in the log. |

This is a technician tool, not a remediation, so the `0`/`1`/`2` detection
contract in [`Templates/Remediation/README.md`](../../../Templates/Remediation/README.md)
does not apply.

If RSoP logging is turned off (policy *Turn off Resultant Set of Policy
logging*), the script stops with `1` rather than report every Group Policy
setting as missing. If the GPO cache or the Preferences history cannot be read,
it warns and carries on without `OverriddenByMdm`, `NotApplied` or Preferences.

The log, `%ProgramData%\EndpointEngineering\Logs\Get-PolicySource.log`, holds
counts and timings, not values.

### The output is organisation data

Rows hold GPO names, policy values, and sometimes identifiers set as policy
values. OneDrive's tenant allow list, for example, is a list of tenant IDs.
Before the output leaves the organisation, in a ticket, a vendor case or a chat,
run it through [`Invoke-TextScrub.ps1`](../../../Standalone/Invoke-TextScrub.ps1)
and read it.

## Verification status

The tests cover each source reader, the `Registry.pol` parser, every verdict,
and the filters. They run under Windows PowerShell 5.1 and PowerShell 7. The
script itself is run as a file: unelevated it stops at the elevation check with
`1`, and elevated, as in CI, it must finish with `0`.

Not yet exercised: this script on a managed device, the verdicts against a
deliberately conflicting GPO and Intune policy, and a device with `MDMWinsOverGP`
off.

## Reference

- [Policy CSP - ControlPolicyConflict](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-controlpolicyconflict)
- [Policies in Policy CSP supported by Group Policy](https://learn.microsoft.com/windows/client-management/mdm/policies-in-policy-csp-supported-by-group-policy)
- [Understanding ADMX-backed policies](https://learn.microsoft.com/windows/client-management/understanding-admx-backed-policies)
- [Registry policy file format](https://learn.microsoft.com/previous-versions/windows/desktop/policy/registry-policy-file-format)
