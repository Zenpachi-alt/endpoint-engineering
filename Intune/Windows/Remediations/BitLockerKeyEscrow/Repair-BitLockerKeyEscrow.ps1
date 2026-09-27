# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Backs up BitLocker recovery passwords to Microsoft Entra ID, and reports
    success only once Windows confirms each backup.

.DESCRIPTION
    Remediation script of the BitLockerKeyEscrow package. It runs only when
    Test-BitLockerKeyEscrow.ps1 exits 1, and backs up each recovery password
    protector that has no evidence of escrow - no other - with
    BackupToAAD-BitLockerKeyProtector.

    That cmdlet skips a mount point it cannot resolve without reporting an
    error, and a backup can fail after the call returns. So a backup counts
    only when event 845, which names the protector, appears in the BitLocker
    Management log after the attempt started. Event 846 for the volume, or no
    event within ConfirmationTimeoutSeconds, fails it. A confirmed backup is
    recorded under HKLM\SOFTWARE\EndpointEngineering\BitLockerKeyEscrow, as
    the detection script records the backups it finds.

    The script never reads a recovery password and never adds, removes or
    rotates a protector: it sends the ones the device already has. It never
    restarts the device.

    Contract enforced by the Intune management extension:
      exit 0  Every protector that lacked evidence is now confirmed escrowed,
              or none lacked it.
      exit 1  A backup failed or was not confirmed, the device is not joined
              to Entra ID, or the script failed. Intune retries on the
              configured schedule.

.PARAMETER ConfirmationTimeoutSeconds
    How long to wait, per protector, for the event that confirms or refuses
    the backup. 0 checks once, straight after the call.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Repair-BitLockerKeyEscrow.ps1 -WhatIf -Verbose

    Lists the protectors it would back up, without sending anything or
    writing a record. Intune never passes -WhatIf, so this is for local
    testing only.

.EXAMPLE
    .\Repair-BitLockerKeyEscrow.ps1 -Verbose

    Backs up every protector without evidence, from an elevated Windows
    PowerShell, and echoes every log line to the console.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-27

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM (Run this script using the logged-on credentials:
                    No). Win32_EncryptableVolume and the backup require
                    administrator rights; without them the script exits 1.
    Host          : 64-bit recommended (Run script in 64-bit PowerShell: Yes).
                    Must match the detection script.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. The file is ASCII-only.
    Modules       : BitLocker, which ships with Windows. Nothing to install.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None.
    Admin consent : Not applicable.

    Network       : The backup is sent to Entra ID by the device. Without a
                    connection it fails with event 846, and Intune retries.
    Reversibility : A backup adds the key to the device's object in Entra ID,
                    where administrators with BitLocker key permissions can read
                    it. Nothing on the device changes apart from the record of
                    the backup. Removing a key from Entra ID is done there.

.LINK
    https://learn.microsoft.com/powershell/module/bitlocker/backuptoaad-bitlockerkeyprotector

.LINK
    https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/operations-guide#reset-and-backup-a-recovery-password
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter()]
    [ValidateRange(0, 600)]
    [int]$ConfirmationTimeoutSeconds = 60,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path -Path $env:ProgramData -ChildPath 'EndpointEngineering\Logs'),

    [Parameter()]
    [ValidateRange(65536, 104857600)]
    [int]$MaxLogSizeBytes = 1048576
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitFailure = 1

$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path, or $null if logging is not possible.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Directory,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$MaxSizeBytes
    )

    try {
        if (-not (Test-Path -LiteralPath $Directory)) {
            $null = New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop
        }

        $path = Join-Path -Path $Directory -ChildPath "$Name.log"

        if (Test-Path -LiteralPath $path) {
            $existing = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($existing.Length -gt $MaxSizeBytes) {
                Move-Item -LiteralPath $path -Destination "$path.old" -Force -ErrorAction Stop
            }
        }

        return $path
    }
    catch {
        Write-Warning "Could not initialise log file in '$Directory': $($_.Exception.Message). Continuing without a log file."
        return $null
    }
}

# Named Write-LogEntry rather than Write-Log: PSScriptAnalyzer reports the
# latter as shadowing a command that exists in some PowerShell profiles.
function Write-LogEntry {
    <#
        .SYNOPSIS
            Appends a timestamped line to the log file and the verbose stream.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] [PID {2}] {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff zzz', [cultureinfo]::InvariantCulture), $Level, $PID, $Message

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            $script:LogFile = $null
            Write-Warning "Logging stopped: $($_.Exception.Message)"
        }
    }

    Write-Verbose $line
}

function Write-ResultLine {
    <#
        .SYNOPSIS
            Writes the single STDOUT line Intune surfaces, truncated to the
            2048-character output limit.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    if ($Message.Length -gt 2048) {
        $Message = $Message.Substring(0, 2045) + '...'
    }

    Write-Output $Message
}

#region BitLockerKeyEscrow 1.0.0 - keep identical in Test- and Repair-BitLockerKeyEscrow.ps1
function Test-IsElevated {
    <#
        .SYNOPSIS
            True when the process has administrator rights, as SYSTEM does
            under Intune. Win32_EncryptableVolume refuses to answer without
            them.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertFrom-DsregcmdStatus {
    <#
        .SYNOPSIS
            Reads the join state from the Device State section of the output
            of 'dsregcmd /status'. Throws when a field is missing, so output
            the script cannot read is a failure and never "not joined".
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    $state = @{}
    foreach ($name in @('AzureAdJoined', 'DomainJoined')) {
        $match = [regex]::Match($Text, "(?m)^\s*$name\s*:\s*(YES|NO)\s*$")
        if (-not $match.Success) {
            throw "dsregcmd /status printed no '$name : YES' or '$name : NO' line."
        }
        $state[$name] = $match.Groups[1].Value -eq 'YES'
    }

    return [pscustomobject]@{
        AzureAdJoined = $state['AzureAdJoined']
        DomainJoined  = $state['DomainJoined']
    }
}

function Get-EntraJoinState {
    <#
        .SYNOPSIS
            Returns whether the device is joined to Microsoft Entra ID
            (AzureAdJoined) and to a domain (DomainJoined). Both are true on a
            hybrid joined device. Only a joined device can back up a key.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    # A 32-bit host on 64-bit Windows reaches the real System32 through
    # Sysnative.
    $folder = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' } else { 'System32' }
    $dsregcmd = Join-Path -Path $env:SystemRoot -ChildPath "$folder\dsregcmd.exe"
    if (-not (Test-Path -LiteralPath $dsregcmd)) {
        throw "dsregcmd.exe was not found at '$dsregcmd'."
    }

    # Windows PowerShell 5.1 turns a native command's stderr output into a
    # terminating error under 'Stop'; the exit code is judged instead.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = & $dsregcmd /status 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }

    if ($exitCode -ne 0) {
        throw "dsregcmd /status exited with code $exitCode."
    }

    return ConvertFrom-DsregcmdStatus -Text $text
}

function ConvertTo-ProtectorKey {
    <#
        .SYNOPSIS
            Returns a key protector ID in the form this package compares and
            stores: the GUID in upper case, without braces. Entra ID shows the
            same GUID in lower case as the key ID.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )

    $guid = [guid]::Empty
    if (-not [guid]::TryParse($Id.Trim(), [ref]$guid)) {
        throw "'$Id' is not a key protector ID."
    }

    return $guid.ToString('D').ToUpperInvariant()
}

function Get-EscrowVolume {
    <#
        .SYNOPSIS
            Returns every OS and fixed data volume that BitLocker has
            encrypted or is encrypting, with the IDs of its recovery password
            protectors. Never reads a recovery password: GetKeyProtectors
            returns IDs only.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    $volumes = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop)

    foreach ($volume in $volumes) {
        # VolumeType 0 is the OS volume, 1 a fixed data volume, 2 removable.
        # ConversionStatus 0 is fully decrypted: nothing to recover.
        if (@(0, 1) -notcontains [int]$volume.VolumeType -or [int]$volume.ConversionStatus -eq 0) {
            continue
        }

        # The BitLocker cmdlets accept the drive letter or, for a volume
        # without one, the device ID.
        $mountPoint = if ($volume.DriveLetter) { [string]$volume.DriveLetter } else { [string]$volume.DeviceID }

        # KeyProtectorType 3 is the numerical (recovery) password.
        $result = Invoke-CimMethod -InputObject $volume -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]3 } -ErrorAction Stop
        if ($result.ReturnValue -ne 0) {
            throw ('GetKeyProtectors failed on {0} with 0x{1:X8}.' -f $mountPoint, [uint32]$result.ReturnValue)
        }

        [pscustomobject]@{
            MountPoint   = $mountPoint
            VolumeType   = if ([int]$volume.VolumeType -eq 0) { 'OperatingSystem' } else { 'FixedData' }
            ProtectorIds = @(@($result.VolumeKeyProtectorID) | Where-Object { $_ } | ForEach-Object { ConvertTo-ProtectorKey -Id $_ })
        }
    }
}

function Get-EscrowEvent {
    <#
        .SYNOPSIS
            Returns the backups to Entra ID recorded in the BitLocker
            Management log, oldest first: event 845 for a success, naming the
            protector, and 846 for a failure, naming the volume and the error.

        .PARAMETER Since
            Only events written at or after this time.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter()]
        [datetime]$Since = [datetime]::MinValue
    )

    $filter = @{
        LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
        Id      = @(845, 846)
    }
    if ($Since -gt [datetime]::MinValue) {
        $filter['StartTime'] = $Since.ToLocalTime()
    }

    try {
        $records = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
    }
    catch {
        # Get-WinEvent reports an empty result as an error.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return
        }
        throw
    }

    foreach ($record in @($records | Sort-Object -Property TimeCreated)) {
        $data = ConvertFrom-EscrowEventXml -Xml $record.ToXml()

        [pscustomobject]@{
            Id             = [int]$record.Id
            TimeCreatedUtc = $record.TimeCreated.ToUniversalTime()
            MountPoint     = $data.MountPoint
            ProtectorId    = $data.ProtectorId
            ErrorCode      = $data.ErrorCode
        }
    }
}

function ConvertFrom-EscrowEventXml {
    <#
        .SYNOPSIS
            Reads the data of an event 845 or 846 from its XML, by the names
            the event definition gives its fields, which do not depend on the
            display language. Returns MountPoint, ProtectorId (845 only, in
            the form ConvertTo-ProtectorKey returns) and ErrorCode (846 only,
            as 0x followed by eight hex digits).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Xml
    )

    $data = @{}
    foreach ($node in @(([xml]$Xml).Event.EventData.Data)) {
        $data[$node.GetAttribute('Name')] = [string]$node.InnerText
    }

    $protectorId = $null
    if ($data.ContainsKey('ProtectorGUID') -and $data['ProtectorGUID']) {
        $protectorId = ConvertTo-ProtectorKey -Id $data['ProtectorGUID']
    }

    # An HRESULT, written as hex or as a signed decimal.
    $errorCode = $null
    if ($data.ContainsKey('ErrorCode') -and $data['ErrorCode']) {
        $raw = $data['ErrorCode'].Trim()
        $number = 0L
        $errorCode = if ($raw -match '^0x[0-9A-Fa-f]{1,8}$') {
            '0x' + $raw.Substring(2).ToUpperInvariant().PadLeft(8, '0')
        }
        elseif ([long]::TryParse($raw, [ref]$number)) {
            '0x{0:X8}' -f ($number -band 0xFFFFFFFFL)
        }
        else {
            $raw
        }
    }

    return [pscustomobject]@{
        MountPoint  = if ($data.ContainsKey('VolumeMountPoint')) { $data['VolumeMountPoint'] } else { '' }
        ProtectorId = $protectorId
        ErrorCode   = $errorCode
    }
}

function Get-RecordedEvidence {
    <#
        .SYNOPSIS
            Returns the protectors recorded as escrowed, by ID, with the time
            of the event that showed it. Empty when nothing is recorded.
            Always the 64-bit registry view, whatever the host.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SubKey = 'SOFTWARE\EndpointEngineering\BitLockerKeyEscrow'
    )

    $recorded = @{}
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        $key = $baseKey.OpenSubKey($SubKey)
        if ($null -ne $key) {
            try {
                foreach ($name in $key.GetValueNames()) {
                    $recorded[$name] = [string]$key.GetValue($name)
                }
            }
            finally {
                $key.Dispose()
            }
        }
    }
    finally {
        $baseKey.Dispose()
    }

    return $recorded
}

function Set-RecordedEvidence {
    <#
        .SYNOPSIS
            Records that a protector was seen escrowed, or forgets it when
            Value is empty.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$')]
        [string]$ProtectorId,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SubKey = 'SOFTWARE\EndpointEngineering\BitLockerKeyEscrow'
    )

    $action = if ($Value) { "Record escrow evidence '$Value'" } else { 'Forget escrow evidence' }
    if (-not $PSCmdlet.ShouldProcess("HKLM\$SubKey\$ProtectorId", $action)) {
        return
    }

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        # CreateSubKey opens the key for writing, creating it if necessary.
        $key = $baseKey.CreateSubKey($SubKey)
        if ($null -eq $key) {
            throw "Could not open or create 'HKLM\$SubKey'."
        }

        try {
            if ($Value) {
                $key.SetValue($ProtectorId, $Value, [Microsoft.Win32.RegistryValueKind]::String)
            }
            else {
                $key.DeleteValue($ProtectorId, $false)
            }
        }
        finally {
            $key.Dispose()
        }
    }
    finally {
        $baseKey.Dispose()
    }
}

function Get-EscrowFinding {
    <#
        .SYNOPSIS
            Decides which recovery passwords have no evidence of escrow. Reads
            no state, so every combination can be tested without a device.

        .DESCRIPTION
            Returns Token, ExitCode, Line (the result line) and Missing, the
            volumes and protector IDs with no evidence. The token is the most
            urgent state of any volume:
              NoEscrowEvidence    A recovery password has no evidence. Exit 1.
              NoRecoveryPassword  A volume has no recovery password, so there
                                  is nothing to escrow. Exit 0.
              Escrowed            Every recovery password has evidence. Exit 0.
              NotEncrypted        No OS or fixed data volume is encrypted.
                                  Exit 0.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Volume,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$EscrowedId
    )

    $missing = New-Object -TypeName System.Collections.Generic.List[object]
    $parts = New-Object -TypeName System.Collections.Generic.List[string]
    $withoutPassword = 0

    foreach ($item in $Volume) {
        $ids = @($item.ProtectorIds)
        if ($ids.Count -eq 0) {
            $withoutPassword++
            $parts.Add("$($item.MountPoint) no recovery password")
            continue
        }

        $states = foreach ($id in $ids) {
            if ($EscrowedId -contains $id) {
                "escrowed {$id}"
            }
            else {
                $missing.Add([pscustomobject]@{ MountPoint = $item.MountPoint; ProtectorId = $id })
                "no escrow evidence for {$id}"
            }
        }
        $parts.Add("$($item.MountPoint) " + (@($states) -join ', '))
    }

    if ($Volume.Count -eq 0) {
        $token = 'NotEncrypted'
        $exitCode = 0
        $line = 'NotEncrypted: no OS or fixed data volume is encrypted with BitLocker.'
    }
    else {
        if ($missing.Count -gt 0) {
            $token = 'NoEscrowEvidence'
            $exitCode = 1
        }
        elseif ($withoutPassword -gt 0) {
            $token = 'NoRecoveryPassword'
            $exitCode = 0
        }
        else {
            $token = 'Escrowed'
            $exitCode = 0
        }
        $line = "${token}: " + ($parts -join '; ') + '.'
    }

    return [pscustomobject]@{
        Token    = $token
        ExitCode = $exitCode
        Line     = $line
        Missing  = $missing.ToArray()
    }
}
#endregion BitLockerKeyEscrow

function Invoke-KeyEscrow {
    <#
        .SYNOPSIS
            Asks Windows to back up one recovery password protector to Entra
            ID. Throws when the call fails or does not attempt the backup.

        .DESCRIPTION
            BackupToAAD-BitLockerKeyProtector skips a mount point it cannot
            resolve with no error, returning nothing, so a call that returns
            no volume is a failure. The volume objects it returns carry the
            recovery passwords; they are counted and dropped, never kept or
            logged.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MountPoint,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProtectorId
    )

    Import-Module -Name BitLocker -ErrorAction Stop
    $returned = @(BackupToAAD-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId "{$ProtectorId}" -Confirm:$false -ErrorAction Stop).Count

    if ($returned -eq 0) {
        throw "BackupToAAD-BitLockerKeyProtector returned no volume for '$MountPoint', so it did not attempt the backup."
    }
}

function Wait-EscrowConfirmation {
    <#
        .SYNOPSIS
            Waits for the event that settles a backup started at Since: 845
            naming the protector confirms it, 846 for the volume refuses it.
            Returns Confirmed, EventTimeUtc and Reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [string]$ProtectorId,

        [Parameter(Mandatory)]
        [string]$MountPoint,

        [Parameter(Mandatory)]
        [datetime]$Since,

        [Parameter(Mandatory)]
        [ValidateRange(0, 600)]
        [int]$TimeoutSeconds
    )

    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)

    while ($true) {
        foreach ($record in @(Get-EscrowEvent -Since $Since)) {
            if ($record.Id -eq 845 -and $record.ProtectorId -eq $ProtectorId) {
                return [pscustomobject]@{
                    Confirmed    = $true
                    EventTimeUtc = $record.TimeCreatedUtc
                    Reason       = "event 845 at $($record.TimeCreatedUtc.ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture)) UTC"
                }
            }

            if ($record.Id -eq 846 -and $record.MountPoint -eq $MountPoint) {
                return [pscustomobject]@{
                    Confirmed    = $false
                    EventTimeUtc = $record.TimeCreatedUtc
                    Reason       = "event 846 reports error $($record.ErrorCode)"
                }
            }
        }

        if ([datetime]::UtcNow -ge $deadline) {
            return [pscustomobject]@{
                Confirmed    = $false
                EventTimeUtc = $null
                Reason       = "no event 845 confirmed the backup within $TimeoutSeconds seconds"
            }
        }

        Start-Sleep -Seconds 2
    }
}

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Remediation started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if (-not (Test-IsElevated)) {
        Write-LogEntry -Message 'Not running with administrator rights, which Win32_EncryptableVolume and the backup require. Under Intune the script runs as SYSTEM and has them.' -Level ERROR
        Write-ResultLine -Message 'Remediation failed: administrator rights are required.'
        exit $ExitFailure
    }

    $join = Get-EntraJoinState
    Write-LogEntry -Message "Join state: AzureAdJoined $($join.AzureAdJoined), DomainJoined $($join.DomainJoined)."

    if (-not $join.AzureAdJoined) {
        Write-ResultLine -Message 'Not repaired: the device is not joined to Microsoft Entra ID, so no key can be backed up there.'
        exit $ExitFailure
    }

    #region Find
    # The same evidence the detection script uses: the log, and the record of
    # backups the log no longer holds.
    $volumes = @(Get-EscrowVolume)
    $seen = @(Get-EscrowEvent | Where-Object { $_.Id -eq 845 -and $_.ProtectorId } | ForEach-Object { $_.ProtectorId })
    $recorded = Get-RecordedEvidence
    $escrowed = @(@($seen) + @($recorded.Keys) | Select-Object -Unique)
    $finding = Get-EscrowFinding -Volume $volumes -EscrowedId $escrowed
    Write-LogEntry -Message "Before: $($finding.Line)"

    $targets = @($finding.Missing)
    if ($targets.Count -eq 0) {
        Write-ResultLine -Message 'Nothing to escrow: every recovery password already has evidence of escrow.'
        exit $ExitSuccess
    }
    #endregion

    #region Escrow
    $escrowedNow = New-Object -TypeName System.Collections.Generic.List[string]
    $failures = New-Object -TypeName System.Collections.Generic.List[string]
    $declined = 0

    foreach ($target in $targets) {
        $label = "$($target.MountPoint) {$($target.ProtectorId)}"

        if (-not $PSCmdlet.ShouldProcess($label, 'Back up the recovery password to Microsoft Entra ID')) {
            $declined++
            continue
        }

        # One second earlier than now, so an event stamped within the same
        # second as the call is not missed.
        $started = [datetime]::UtcNow.AddSeconds(-1)
        Write-LogEntry -Message "Backing up $label."

        try {
            Invoke-KeyEscrow -MountPoint $target.MountPoint -ProtectorId $target.ProtectorId
        }
        catch {
            Write-LogEntry -Message "Backup of $label failed: $($_.Exception.Message)" -Level ERROR
            # Without its full stop: the result line adds its own.
            $failures.Add("${label}: $($_.Exception.Message.TrimEnd('.'))")
            continue
        }

        $confirmation = Wait-EscrowConfirmation -ProtectorId $target.ProtectorId -MountPoint $target.MountPoint -Since $started -TimeoutSeconds $ConfirmationTimeoutSeconds
        if (-not $confirmation.Confirmed) {
            Write-LogEntry -Message "Backup of $label not confirmed: $($confirmation.Reason)." -Level ERROR
            $failures.Add("${label}: $($confirmation.Reason)")
            continue
        }

        Write-LogEntry -Message "Backup of $label confirmed by $($confirmation.Reason)."
        $escrowedNow.Add($label)

        try {
            Set-RecordedEvidence -ProtectorId $target.ProtectorId -Value $confirmation.EventTimeUtc.ToString('o', [cultureinfo]::InvariantCulture)
        }
        catch {
            # The backup itself succeeded; the event stays in the log for the
            # next detection to find.
            Write-LogEntry -Message "Could not record the backup of ${label}: $($_.Exception.Message)" -Level WARN
        }
    }
    #endregion

    if ($declined -eq $targets.Count) {
        Write-LogEntry -Message 'ShouldProcess declined every backup. Nothing was sent or recorded.'
        Write-ResultLine -Message 'No change made (WhatIf or declined confirmation).'
        exit $ExitSuccess
    }

    if ($failures.Count -gt 0) {
        $done = if ($escrowedNow.Count -gt 0) { " Escrowed: $($escrowedNow -join ', ')." } else { '' }
        Write-ResultLine -Message "Remediation failed: $($failures -join '; ').$done"
        exit $ExitFailure
    }

    Write-LogEntry -Message "Remediation succeeded: $($escrowedNow -join ', ')."
    Write-ResultLine -Message "Escrowed: $($escrowedNow -join ', ')."
    exit $ExitSuccess
}
catch {
    $message = "Remediation failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitFailure
}
