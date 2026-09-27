# BitLockerKeyEscrow

Remediation package that finds BitLocker recovery passwords with no evidence of
having been backed up to Microsoft Entra ID, and backs them up. A device whose
key never reached Entra ID looks fine until the day it asks for the key, and
then the data on it is lost.

| File | Role |
| --- | --- |
| `Test-BitLockerKeyEscrow.ps1` | Detection: lists the recovery password protectors of every OS and fixed data volume BitLocker has encrypted, and looks for evidence that each one reached Entra ID. |
| `Repair-BitLockerKeyEscrow.ps1` | Remediation: backs up each protector without evidence, and counts a backup only once Windows confirms it. |
| `BitLockerKeyEscrow.Tests.ps1` | Pester tests: every token and exit code below, and how evidence is read. Not deployed. |

## How it works

**Detection** asks Windows which recovery password protectors each OS and fixed
data volume has, by ID. It never reads a recovery password:
`Win32_EncryptableVolume.GetKeyProtectors` returns IDs only, where
`Get-BitLockerVolume` would return the passwords themselves.

A protector counts as escrowed when there is evidence of it:

- **Event 845** in the BitLocker Management log, which Windows writes after a
  successful backup to Entra ID and which names the protector; or
- **a record** under `HKLM\SOFTWARE\EndpointEngineering\BitLockerKeyEscrow`.
  The log is small and overwrites its oldest events, so detection records every
  protector it has seen escrowed, and the evidence outlives the event. Records
  of protectors the device no longer has, after a key rotation for example, are
  removed.

**Remediation** backs up each protector without evidence - no other - with
`BackupToAAD-BitLockerKeyProtector`. That cmdlet skips a volume it cannot
resolve without reporting an error, so the script does not trust the call
returning: a backup counts only when event 845 naming the protector appears
after the attempt started. Event 846 for the volume, or no event within 60
seconds, fails it, and Intune retries on its schedule.

The package never adds, removes or rotates a protector, and never restarts the
device.

## Evidence is not proof

Microsoft's BitLocker FAQ is explicit: a successful backup event does not prove
that the key is still in the directory. It can be deleted afterwards, and an
event can be spoofed. Only Entra ID can say what it holds.

What this package reliably finds is the opposite case - the devices that never
sent a key - and it gives each one a way to send it. Each output line names the
protectors by ID. Entra ID shows the same GUID, in lower case, as the key ID, so
any line can be checked against the device's **Recovery keys** in the Intune
admin center, or against `GET /informationProtection/bitlocker/recoveryKeys`
in Microsoft Graph. A Graph report that makes that check for every device is
planned as the next script under `Graph/`.

## Intune settings

| Setting | Value |
| --- | --- |
| Detection script file | `Test-BitLockerKeyEscrow.ps1` |
| Remediation script file | `Repair-BitLockerKeyEscrow.ps1` |
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No, unless the scripts are signed |
| Run script in 64-bit PowerShell | Yes |
| Assignment | Windows devices that are Microsoft Entra joined or hybrid joined. Others report `NotApplicable`. |
| Schedule | Daily. Detection takes a few seconds. |

## What the report shows

Every output line starts with a token. When one device has volumes in different
states, the token is the most urgent of them, and the line lists each volume.

| Script | Exit | Line starts with | Meaning |
| --- | --- | --- | --- |
| Detection | `0` | `Escrowed:` | Every recovery password has evidence of escrow. |
| Detection | `0` | `NoRecoveryPassword:` | A volume has no recovery password, so there is nothing to back up. Adding one changes how the device is recovered, so it is left to an administrator. |
| Detection | `0` | `NotEncrypted:` | No OS or fixed data volume is encrypted. Enforcing encryption is another policy's job. |
| Detection | `0` | `NotApplicable:` | The device is not joined to Entra ID, so there is nowhere to back a key up to. |
| Detection | `1` | `NoEscrowEvidence:` | A recovery password has no evidence of escrow. The remediation runs. |
| Detection | `2` | `Detection failed:` | No administrator rights, or the check itself failed. The remediation does not run. |
| Remediation | `0` | `Escrowed:` | Every backup was confirmed by event 845. |
| Remediation | `0` | `Nothing to escrow:` | Evidence appeared between detection and remediation. |
| Remediation | `1` | `Remediation failed:` | Names each protector whose backup failed or was not confirmed, and why: event 846 and its error code, or no confirmation. |
| Remediation | `1` | `Not repaired:` | The device is not joined to Entra ID. |

A typical 846 error is `0x80072EE7` or another network error: the device could
not reach Entra ID. Intune retries on the next run.

## Rolling it out

Some behaviour cannot be settled without real devices, so the package goes to a
pilot ring first, with these questions to answer from its report and logs:

1. **Does event 845 appear before the cmdlet returns, or shortly after?** The
   remediation waits up to 60 seconds for it. A backup that is confirmed later
   than that is reported as failed and sent again on the next run.
2. **Does backing up a protector that Entra ID already holds create a second
   entry?** The key ID in Entra ID is the protector ID, which suggests it
   updates the same one, but Microsoft does not document it. Entra ID keeps at
   most 200 recovery keys per device, and past that limit silent encryption
   fails. The remediation only sends protectors without evidence, and the record
   stops them being sent twice, so each protector is normally sent once. Compare
   the pilot devices' key count in Entra ID before and after.
3. **Do hybrid joined devices behave like Entra joined ones?** Both are in
   scope. If the organisation also requires backup to Active Directory, that is
   untouched.

## Logs and state

| Location | Holds |
| --- | --- |
| `%ProgramData%\EndpointEngineering\Logs\Test-BitLockerKeyEscrow.log` | Every detection: join state, each volume's protector IDs, what was recorded or forgotten. |
| `%ProgramData%\EndpointEngineering\Logs\Repair-BitLockerKeyEscrow.log` | Every backup attempt and how it was settled. |
| `HKLM\SOFTWARE\EndpointEngineering\BitLockerKeyEscrow` | One value per protector seen escrowed: the time of the event that showed it. Always the 64-bit view. Delete the key to make the next detection rely on the log alone. |
| BitLocker Management log (`Microsoft-Windows-BitLocker/BitLocker Management`) | Events 845 and 846, Windows' own record of each backup. |

Neither log ever holds a recovery password: the scripts never read one.

## Tests

`BitLockerKeyEscrow.Tests.ps1` runs both scripts as the Intune management
extension does, in Windows PowerShell 5.1 with `-File`, with the parts that
touch the device replaced by stand-ins: the elevation check, the join state,
the volumes and their protector IDs, the event log, the record, and the backup
itself. The backup stand-in writes the event 845 or 846 a device would, so the
remediation's confirmation logic runs as written. Nothing reaches Entra ID and
nothing on the device changes:

```powershell
Invoke-Pester -Path .\Intune\Windows\Remediations\BitLockerKeyEscrow -Output Detailed
```

The tests also read events built to the event definition in the BitLocker
provider's manifest, and check that the `BitLockerKeyEscrow` region is identical
in both scripts. What they cannot show is how Windows and Entra ID behave;
that is what the pilot is for.

## Limitations

- **Evidence, not proof**, as above. A key deleted from Entra ID after a
  successful backup still counts as escrowed here.
- **Join state is read from `dsregcmd /status`.** Its field names are not
  translated as far as is known; if a build ever printed them differently, the
  detection would exit `2` rather than guess.
- **Removable drives are out of scope.** Their keys belong with whoever holds
  the drive.
- **Volumes without a recovery password are reported, not fixed.** See
  `NoRecoveryPassword` above.
- **Detection writes one thing:** its record of backups it has seen.

## Licensing and permissions

Remediations require Intune plus Windows Enterprise E3/E5, Windows Education
A3/A5, or Windows VDA per user. Creating and assigning the package needs the
Intune *Device configurations* permissions. On the device, both scripts run as
SYSTEM, which has the administrator rights `Win32_EncryptableVolume` requires.
Reading the escrowed keys in Entra ID afterwards needs a role with
`microsoft.directory/bitlockerKeys/key/read`, such as Cloud Device
Administrator or Helpdesk Administrator.

## Reference

- [BitLocker recovery overview](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview)
- [BitLocker FAQ: event log entries for backups](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/faq#is-there-an-event-log-entry-recorded-on-the-client-computer-to-indicate-the-success-or-failure-of-the-microsoft-entra-id-or-active-directory-backup)
- [BackupToAAD-BitLockerKeyProtector](https://learn.microsoft.com/powershell/module/bitlocker/backuptoaad-bitlockerkeyprotector)
- [GetKeyProtectors method of Win32_EncryptableVolume](https://learn.microsoft.com/windows/win32/secprov/getkeyprotectors-win32-encryptablevolume)
- [Encrypt Windows devices with BitLocker using Intune: recovery keys](https://learn.microsoft.com/intune/device-configuration/endpoint-security/encrypt-bitlocker-windows#monitor-and-manage-bitlocker)
- [List recoveryKeys (Microsoft Graph)](https://learn.microsoft.com/graph/api/bitlocker-list-recoverykeys)
- [Troubleshoot devices by using the dsregcmd command](https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd)
