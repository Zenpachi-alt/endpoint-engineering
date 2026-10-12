# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Detects BitLocker recovery passwords that show no evidence of having been
    backed up to Microsoft Entra ID.

.DESCRIPTION
    Detection script of the BitLockerKeyEscrow remediation package. For every
    OS and fixed data volume that BitLocker has encrypted, or is encrypting,
    it lists the recovery password protectors and looks for evidence that each
    one reached Entra ID. When one has none, it exits 1 and Intune runs
    Repair-BitLockerKeyEscrow.ps1.

    The evidence is event 845 in the BitLocker Management log, which Windows
    writes after a successful backup and which names the protector. The log
    is small and overwrites its oldest events, so the script records every
    protector it has seen escrowed under
    HKLM\SOFTWARE\EndpointEngineering\BitLockerKeyEscrow, and a protector
    stays escrowed after its event has rolled off. Records of protectors the
    device no longer has are removed.

    Evidence is not proof. Microsoft's BitLocker FAQ notes that a key can be
    deleted from the directory after a successful backup, and that the event
    can be spoofed. Only Entra ID can say what it holds; this script finds the
    devices that never sent a key, and the output line names each protector
    so it can be checked against Entra ID, where the key ID is the same GUID.

    Recovery passwords are never read. Protectors are listed with the
    GetKeyProtectors method of Win32_EncryptableVolume, which returns their
    IDs only; Get-BitLockerVolume would return the passwords themselves.

    A volume with no recovery password at all has nothing to escrow. It is
    reported, and does not start the remediation: adding a protector changes
    how the device is recovered, which is for an administrator to decide.

    Contract enforced by the Intune management extension:
      exit 0  Every recovery password has evidence of escrow, or there is
              nothing this package can escrow: the device is not joined to
              Entra ID, no volume is encrypted, or a volume has no recovery
              password. The output line starts with a token saying which.
      exit 1  A recovery password has no evidence of escrow. The remediation
              script runs.
      exit 2  The check could not be completed. The remediation does not run.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs, which is writable by SYSTEM and
    readable by support staff.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Test-BitLockerKeyEscrow.ps1 -Verbose

    Runs the detection from an elevated Windows PowerShell and echoes every
    log line to the console.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-27

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM (Run this script using the logged-on credentials:
                    No). Win32_EncryptableVolume requires administrator rights;
                    without them the script exits 2.
    Host          : 64-bit recommended (Run script in 64-bit PowerShell: Yes).
                    The registry is read in its 64-bit view and dsregcmd.exe is
                    started from the native System32 in either host.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. The file is ASCII-only.
    Modules       : None. Win32_EncryptableVolume, the event log and
                    dsregcmd.exe ship with Windows.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None (runs on the device, not against Graph).
    Admin consent : Not applicable.

.LINK
    https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview

.LINK
    https://learn.microsoft.com/windows/win32/secprov/getkeyprotectors-win32-encryptablevolume
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path -Path $env:ProgramData -ChildPath 'EndpointEngineering\Logs'),

    [Parameter()]
    [ValidateRange(65536, 104857600)]
    [int]$MaxLogSizeBytes = 1048576
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Exit codes are part of the Intune contract - do not repurpose them.
$ExitIssueNotFound = 0
$ExitIssueFound = 1
$ExitError = 2

# Set by Initialize-LogFile. $null means "log to the verbose stream only".
$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path. Returns $null if logging is not possible, so that a
            logging problem never fails the detection.
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
            Never writes to STDOUT: that stream carries the detection result.
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
            # Disable logging rather than fail the run, and say so once.
            $script:LogFile = $null
            Write-Warning "Logging stopped: $($_.Exception.Message)"
        }
    }

    Write-Verbose $line
}

function Write-ResultLine {
    <#
        .SYNOPSIS
            Writes the single STDOUT line Intune surfaces in the console,
            truncated to the 2048-character output limit.
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

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Detection started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if (-not (Test-IsElevated)) {
        Write-LogEntry -Message 'Not running with administrator rights, which Win32_EncryptableVolume requires. Under Intune the script runs as SYSTEM and has them.' -Level ERROR
        Write-ResultLine -Message 'Detection failed: administrator rights are required.'
        exit $ExitError
    }

    #region Detect
    $join = Get-EntraJoinState
    Write-LogEntry -Message "Join state: AzureAdJoined $($join.AzureAdJoined), DomainJoined $($join.DomainJoined)."

    if (-not $join.AzureAdJoined) {
        # Nothing this package can fix: a device that is not joined has no
        # directory object in Entra ID to back a key up to.
        Write-ResultLine -Message 'NotApplicable: the device is not joined to Microsoft Entra ID, so no key can be backed up there.'
        exit $ExitIssueNotFound
    }

    $volumes = @(Get-EscrowVolume)
    foreach ($volume in $volumes) {
        Write-LogEntry -Message "$($volume.MountPoint) ($($volume.VolumeType)): $(@($volume.ProtectorIds).Count) recovery password(s) $(@($volume.ProtectorIds | ForEach-Object { "{$_}" }) -join ', ')."
    }

    # The latest successful backup of each protector the log still holds.
    $seen = @{}
    foreach ($record in @(Get-EscrowEvent)) {
        if ($record.Id -eq 845 -and $record.ProtectorId) {
            $seen[$record.ProtectorId] = $record.TimeCreatedUtc.ToString('o', [cultureinfo]::InvariantCulture)
        }
    }

    $recorded = Get-RecordedEvidence
    $current = @($volumes | ForEach-Object { @($_.ProtectorIds) })

    # Recording what the log shows keeps a protector escrowed once its event
    # has rolled off; forgetting protectors the device no longer has keeps the
    # record to the keys that exist. A failed write costs at most a repeated
    # backup, so it is logged and the check goes on.
    foreach ($id in $current) {
        if ($seen.ContainsKey($id) -and -not $recorded.ContainsKey($id)) {
            try {
                Set-RecordedEvidence -ProtectorId $id -Value $seen[$id]
                Write-LogEntry -Message "Recorded the backup of {$id} seen at $($seen[$id])."
            }
            catch {
                Write-LogEntry -Message "Could not record the backup of {$id}: $($_.Exception.Message)" -Level WARN
            }
        }
    }
    foreach ($id in @($recorded.Keys)) {
        if ($current -notcontains $id) {
            try {
                Set-RecordedEvidence -ProtectorId $id -Value ''
                Write-LogEntry -Message "Forgot {$id}, which the device no longer has."
            }
            catch {
                Write-LogEntry -Message "Could not forget {$id}: $($_.Exception.Message)" -Level WARN
            }
        }
    }

    $escrowed = @(@($seen.Keys) + @($recorded.Keys) | Select-Object -Unique)
    $finding = Get-EscrowFinding -Volume $volumes -EscrowedId $escrowed
    #endregion

    Write-LogEntry -Message $finding.Line -Level $(if ($finding.ExitCode -eq 0) { 'INFO' } else { 'WARN' })
    Write-ResultLine -Message $finding.Line
    exit $(if ($finding.ExitCode -eq 0) { $ExitIssueNotFound } else { $ExitIssueFound })
}
catch {
    $message = "Detection failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR

    # Continue, not Stop: this error must not escape and turn into exit code 1,
    # which would tell Intune the issue was found and run the remediation.
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitError
}
