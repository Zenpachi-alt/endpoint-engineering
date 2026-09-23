# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Collects the Windows Autopilot hardware hash from the local device and
    writes a CSV ready for import into Intune.

.DESCRIPTION
    Reads the device hardware hash from the MDM_DevDetail_Ext01 WMI class and
    the serial number from Win32_BIOS, then writes them in the column layout
    Intune's Autopilot device import expects.

    The script is built for a technician running it from removable media during
    OOBE (Shift+F10), which is why it depends on nothing beyond Windows itself:
    no modules, no network, no tenant credentials. Registering the collected
    devices is a separate, admin-side step - see
    Graph/Autopilot/Import-AutopilotDeviceIdentity.ps1.

    Collecting offline and importing later is a deliberate split. It keeps
    tenant credentials off the shop floor, removes the Graph modules from the
    USB key entirely, and means a technician imaging a cart of devices never
    waits on an Autopilot service round trip.

    The CSV is written unquoted, matching the format Microsoft's own collector
    produces and the Intune portal accepts. Because unquoted fields cannot
    carry a delimiter, the script rejects a serial number, group tag or
    assigned user containing a comma, a double quote or a line break rather
    than writing a file that would import incorrectly.

    Exit codes:
      0  The hash was collected and written, and the written file was verified.
      1  Collection or writing failed. The reason is on stderr and in the log.

    This is a technician tool, not an Intune remediation, so the 0/1/2
    detection contract described in Templates/Remediation/README.md does not
    apply here.

.PARAMETER OutputPath
    Directory to write the CSV to. Defaults to the directory the script is run
    from, which on a USB key is the key itself. The file name always begins
    with "AutopilotHWID", which .gitignore in this repository excludes, so a
    stray run inside a clone cannot commit device identifiers.

.PARAMETER GroupTag
    Optional Autopilot group tag to stamp on the collected device. Commas,
    double quotes and line breaks are rejected; see the description.

.PARAMETER AssignedUser
    Optional user principal name to assign to the device on import. Only
    meaningful for user-driven Entra ID join deployments.

.PARAMETER Append
    Merge into a single shared AutopilotHWID.csv in OutputPath instead of
    writing one file per device. Records are keyed on serial number, and a
    device collected again replaces its earlier record - a hash changes when
    the motherboard does, and the newer reading is the correct one.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs, which SYSTEM can write and support
    staff can read.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.PARAMETER NoBeep
    Suppress the success and failure tones. The tones exist because a
    technician working through a cart of devices is rarely watching the screen.

.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1

    Writes AutopilotHWID-<serial>-<timestamp>.csv next to the script.

.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1 -Append -GroupTag 'Kiosk'

    Adds this device to a shared AutopilotHWID.csv, replacing any earlier
    record for the same serial number.

.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1 -AssignedUser 'user@contoso.com' -Verbose

    Collects for a user-driven deployment and echoes every log line.

.EXAMPLE
    .\Get-AutopilotHardwareHash.ps1 -OutputPath 'D:\' -WhatIf

    Reports the file that would be written without touching the disk.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-23

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 is not present
                    during OOBE and cannot be assumed on a stock device.
    Context       : Administrator or SYSTEM. Reading MDM_DevDetail_Ext01
                    requires elevation; the script checks and says so.
    Encoding      : UTF-8 without BOM, ASCII-only content.
    Modules       : None. Nothing beyond what ships with Windows.
    Graph scopes  : None. The script never contacts Graph.
    Admin consent : Not applicable.
    Licensing     : None to collect. Registering the result needs Microsoft
                    Intune Plan 1.
    Role required : Local administrator on the device being collected.

.LINK
    https://learn.microsoft.com/autopilot/add-devices
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }),

    [Parameter()]
    [ValidateLength(0, 255)]
    [ValidatePattern('^[^,"\r\n]*$')]
    [string]$GroupTag = '',

    [Parameter()]
    [ValidateLength(0, 255)]
    [ValidatePattern('^(|[^,"\r\n@]+@[^,"\r\n@]+\.[A-Za-z]{2,})$')]
    [string]$AssignedUser = '',

    [Parameter()]
    [switch]$Append,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path -Path $env:ProgramData -ChildPath 'EndpointEngineering\Logs'),

    [Parameter()]
    [ValidateRange(65536, 104857600)]
    [int]$MaxLogSizeBytes = 1048576,

    [Parameter()]
    [switch]$NoBeep
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExitSuccess = 0
$ExitError = 1

# Column names are Intune's, not ours. Order matters to the portal importer.
$SerialColumn = 'Device Serial Number'
$ProductIdColumn = 'Windows Product ID'
$HashColumn = 'Hardware Hash'
$GroupTagColumn = 'Group Tag'
$AssignedUserColumn = 'Assigned User'

# Set by Initialize-LogFile. $null means "log to the verbose stream only".
$script:LogFile = $null

function Initialize-LogFile {
    <#
        .SYNOPSIS
            Creates the log directory, rotates an oversized log, and returns the
            log file path. Returns $null when logging is not possible, so that a
            logging problem never fails a collection.
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

function Write-LogEntry {
    <#
        .SYNOPSIS
            Appends a timestamped line to the log file and the verbose stream.
            Never writes to STDOUT: that stream carries the result line.
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

function Get-PropertyValue {
    <#
        .SYNOPSIS
            Reads a property that may not exist on an object without tripping
            Set-StrictMode. Import-Csv returns rows whose columns vary between
            files written by different versions of a collector.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }

    return $property.Value
}

function Invoke-Tone {
    <#
        .SYNOPSIS
            Plays a success or failure tone. A host without a console speaker
            throws; that is logged, never silently swallowed, and never fails
            the collection.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Success', 'Failure')]
        [string]$Kind
    )

    try {
        if ($Kind -eq 'Success') {
            [console]::Beep(1200, 200)
            [console]::Beep(1600, 250)
        }
        else {
            [console]::Beep(500, 350)
        }
    }
    catch {
        Write-LogEntry -Message "Could not play the $Kind tone: $($_.Exception.Message)" -Level WARN
    }
}

function Test-Elevated {
    <#
        .SYNOPSIS
            True when the current process can read the MDM dmmap namespace.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DeviceSerialNumber {
    <#
        .SYNOPSIS
            Returns the BIOS serial number, trimmed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    $bios = Get-CimInstance -ClassName 'Win32_BIOS' -ErrorAction Stop

    if ($null -eq $bios) {
        throw 'Win32_BIOS returned nothing. WMI may be corrupt on this device.'
    }

    $serial = [string](Get-PropertyValue -InputObject $bios -Name 'SerialNumber')

    if ([string]::IsNullOrWhiteSpace($serial)) {
        throw 'This device reports no BIOS serial number. Autopilot requires one; the OEM or firmware needs to set it.'
    }

    return $serial.Trim()
}

function Get-DeviceHardwareHash {
    <#
        .SYNOPSIS
            Returns the Autopilot hardware hash (DeviceHardwareData) as the
            base64 string Intune expects.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    try {
        $devDetail = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
            -ClassName 'MDM_DevDetail_Ext01' `
            -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
            -ErrorAction Stop
    }
    catch {
        throw "Could not query MDM_DevDetail_Ext01: $($_.Exception.Message). This class exists on Windows 10 and later; confirm the device runs a supported build and that the script is elevated."
    }

    if ($null -eq $devDetail) {
        throw 'MDM_DevDetail_Ext01 returned no instance, so the device exposes no Autopilot hardware hash. This is expected on a virtual machine without a virtual TPM and on unsupported Windows editions.'
    }

    $hash = [string](Get-PropertyValue -InputObject $devDetail -Name 'DeviceHardwareData')

    if ([string]::IsNullOrWhiteSpace($hash)) {
        throw 'DeviceHardwareData is empty. The device reported no hardware hash, so there is nothing to register.'
    }

    return $hash.Trim()
}

function ConvertTo-SafeFileName {
    <#
        .SYNOPSIS
            Makes a string usable as part of a file name. Serial numbers are
            OEM-supplied and routinely contain spaces and slashes, which would
            otherwise throw when the output path is built.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Fallback = 'UNKNOWN'
    )

    $invalid = New-Object System.Collections.Generic.List[char]
    foreach ($character in [System.IO.Path]::GetInvalidFileNameChars()) {
        $invalid.Add($character)
    }
    $invalid.Add([char]' ')

    $builder = New-Object System.Text.StringBuilder

    foreach ($character in $Name.ToCharArray()) {
        if ($invalid.Contains($character)) {
            $null = $builder.Append('-')
        }
        else {
            $null = $builder.Append($character)
        }
    }

    $safe = $builder.ToString() -replace '-{2,}', '-'
    $safe = $safe.Trim('-', '.')

    if ($safe.Length -gt 64) { $safe = $safe.Substring(0, 64).Trim('-', '.') }

    if ([string]::IsNullOrWhiteSpace($safe)) { return $Fallback }

    return $safe
}

function Assert-CsvSafe {
    <#
        .SYNOPSIS
            Throws when a value cannot survive an unquoted CSV field. Failing
            here is better than writing a file that imports as the wrong device.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Label
    )

    if ($Value -match '[,"\r\n]') {
        throw "$Label contains a comma, a double quote or a line break, which cannot be written to the unquoted CSV the Intune importer expects. Value: '$Value'."
    }
}

function ConvertTo-AutopilotRecord {
    <#
        .SYNOPSIS
            Builds one row in Intune's import layout. Windows Product ID is
            deliberately blank: the PKID is available to OEMs only and is not
            required to register a device.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SerialNumber,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$HardwareHash,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Tag = '',

        [Parameter()]
        [AllowEmptyString()]
        [string]$User = ''
    )

    return [pscustomobject][ordered]@{
        $SerialColumn       = $SerialNumber
        $ProductIdColumn    = ''
        $HashColumn         = $HardwareHash
        $GroupTagColumn     = $Tag
        $AssignedUserColumn = $User
    }
}

function Merge-AutopilotRecord {
    <#
        .SYNOPSIS
            Merges a freshly collected record into the rows already in a shared
            CSV, keyed on serial number.

        .DESCRIPTION
            A device collected again replaces its earlier record: a hardware
            hash changes when the motherboard does, and the newer reading is
            the correct one.

            Rows missing a serial number or a hardware hash are dropped rather
            than carried forward - they cannot be imported, and leaving them in
            turns one unusable row into a failed import for the whole file. The
            count comes back so the caller can report it.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]]$ExistingRow,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$NewRecord,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SerialNumber
    )

    $records = New-Object System.Collections.Generic.List[psobject]
    $replaced = $false
    $dropped = 0

    foreach ($row in $ExistingRow) {
        $existingSerial = ([string](Get-PropertyValue -InputObject $row -Name $SerialColumn)).Trim()
        $existingHash = ([string](Get-PropertyValue -InputObject $row -Name $HashColumn)).Trim()

        if ($existingSerial.ToUpperInvariant() -eq $SerialNumber.ToUpperInvariant()) {
            $replaced = $true
            continue
        }

        if ([string]::IsNullOrWhiteSpace($existingSerial) -or [string]::IsNullOrWhiteSpace($existingHash)) {
            $dropped++
            continue
        }

        $records.Add((ConvertTo-AutopilotRecord -SerialNumber $existingSerial -HardwareHash $existingHash `
                    -Tag ([string](Get-PropertyValue -InputObject $row -Name $GroupTagColumn)) `
                    -User ([string](Get-PropertyValue -InputObject $row -Name $AssignedUserColumn))))
    }

    $records.Add($NewRecord)

    return [pscustomobject]@{
        Record   = $records.ToArray()
        Replaced = $replaced
        Dropped  = $dropped
    }
}

function Export-AutopilotCsv {
    <#
        .SYNOPSIS
            Writes records as an unquoted, UTF-8 (no BOM) CSV.

        .DESCRIPTION
            The optional Group Tag and Assigned User columns are emitted only
            when at least one record carries a value, matching what the portal
            importer expects. WriteAllLines is given a fully resolved path
            because .NET resolves a relative path against the process working
            directory rather than the PowerShell location.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [psobject[]]$Record,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $columns = New-Object System.Collections.Generic.List[string]
    $columns.Add($SerialColumn)
    $columns.Add($ProductIdColumn)
    $columns.Add($HashColumn)

    foreach ($optional in @($GroupTagColumn, $AssignedUserColumn)) {
        $hasValue = $false

        foreach ($row in $Record) {
            $value = [string](Get-PropertyValue -InputObject $row -Name $optional)
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $hasValue = $true
                break
            }
        }

        if ($hasValue) { $columns.Add($optional) }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(($columns -join ','))

    foreach ($row in $Record) {
        $values = foreach ($column in $columns) {
            $value = [string](Get-PropertyValue -InputObject $row -Name $column)
            Assert-CsvSafe -Value $value -Label "Column '$column'"
            $value
        }

        $lines.Add((@($values) -join ','))
    }

    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllLines($Path, $lines, $encoding)
}

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Collection started. PowerShell $($PSVersionTable.PSVersion); host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if (-not (Test-Elevated)) {
        throw 'This script must run elevated. The Autopilot hardware hash lives in the MDM dmmap WMI namespace, which only an administrator or SYSTEM can read. During OOBE the Shift+F10 command prompt is already SYSTEM.'
    }

    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        throw "OutputPath '$OutputPath' does not exist or is not a directory."
    }

    $resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop).Path

    #region Collect
    $serialNumber = Get-DeviceSerialNumber
    Write-LogEntry -Message "Serial number: $serialNumber"

    if ($serialNumber -match '^(To be filled by O\.E\.M\.|System Serial Number|Default string|None|0+)$') {
        Write-LogEntry -Message 'The BIOS serial number looks like an unset OEM placeholder. Autopilot will register the device under this value, which makes it hard to identify later.' -Level WARN
        Write-Warning "Serial number '$serialNumber' looks like an unset OEM placeholder rather than a real serial."
    }

    $hardwareHash = Get-DeviceHardwareHash
    Write-LogEntry -Message "Hardware hash collected: $($hardwareHash.Length) characters."

    Assert-CsvSafe -Value $serialNumber -Label 'Serial number'

    $record = ConvertTo-AutopilotRecord -SerialNumber $serialNumber -HardwareHash $hardwareHash `
        -Tag $GroupTag -User $AssignedUser
    #endregion

    #region Resolve the target file
    if ($Append) {
        $targetFile = Join-Path -Path $resolvedOutputPath -ChildPath 'AutopilotHWID.csv'
    }
    else {
        $safeSerial = ConvertTo-SafeFileName -Name $serialNumber
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $targetFile = Join-Path -Path $resolvedOutputPath -ChildPath "AutopilotHWID-$safeSerial-$stamp.csv"
    }

    Write-LogEntry -Message "Target file: $targetFile"
    #endregion

    if (-not $PSCmdlet.ShouldProcess($targetFile, 'Write Autopilot hardware hash')) {
        Write-LogEntry -Message 'Running with -WhatIf. Nothing was written.'
        exit $ExitSuccess
    }

    #region Merge and write
    $existing = @()

    if ($Append -and (Test-Path -LiteralPath $targetFile -PathType Leaf)) {
        $existing = @(Import-Csv -LiteralPath $targetFile -ErrorAction Stop)
        Write-LogEntry -Message "Existing file holds $($existing.Count) record(s)."
    }

    $merge = Merge-AutopilotRecord -ExistingRow $existing -NewRecord $record -SerialNumber $serialNumber

    if ($merge.Dropped -gt 0) {
        Write-LogEntry -Message "Dropped $($merge.Dropped) row(s) in '$targetFile' with no serial number or no hardware hash." -Level WARN
        Write-Warning "Dropped $($merge.Dropped) unusable row(s) already present in '$targetFile'."
    }

    Export-AutopilotCsv -Record $merge.Record -Path $targetFile
    #endregion

    #region Verify
    # Read the file back rather than trusting the write. A CSV that looks
    # written but parses to nothing is the failure that costs a re-image.
    $written = @(Import-Csv -LiteralPath $targetFile -ErrorAction Stop)

    $match = @($written | Where-Object {
            ([string](Get-PropertyValue -InputObject $_ -Name $SerialColumn)).Trim().ToUpperInvariant() -eq $serialNumber.ToUpperInvariant()
        })

    if ($match.Count -eq 0) {
        throw "Wrote '$targetFile' but reading it back found no record for serial '$serialNumber'."
    }

    $writtenHash = ([string](Get-PropertyValue -InputObject $match[0] -Name $HashColumn)).Trim()
    if ($writtenHash -ne $hardwareHash) {
        throw "Wrote '$targetFile' but the hardware hash read back does not match the one collected."
    }
    #endregion

    if ($Append) {
        $verb = if ($merge.Replaced) { 'Replaced' } else { 'Added' }
        $summary = "$verb $serialNumber in $targetFile ($($written.Count) device(s) total)."
    }
    else {
        $summary = "Collected $serialNumber to $targetFile."
    }

    Write-LogEntry -Message $summary
    if (-not $NoBeep) { Invoke-Tone -Kind Success }
    Write-Output $summary

    exit $ExitSuccess
}
catch {
    $message = "Autopilot hash collection failed: $($_.Exception.Message)"

    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR
    if (-not $NoBeep) { Invoke-Tone -Kind Failure }

    Write-Error -Message $message -ErrorAction Continue
    exit $ExitError
}
