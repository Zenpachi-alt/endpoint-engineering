# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Reports where DISM would get repair files on this device, and flags the
    devices where DISM RestoreHealth is likely to fail.

.DESCRIPTION
    Detection-only script package: there is no remediation script. It answers
    one question before SystemFileHealth is rolled out - if DISM RestoreHealth
    ran here, where would it get replacement files? - and reports the answer
    as one line, which Intune keeps for every device and exports to CSV.

    DISM looks first at the alternate source path set by the policy "Specify
    settings for optional component installation and component repair"
    (LocalSourcePath), then at Windows Update where that is allowed. A device
    that takes its updates from WSUS and has no alternate source is the one
    that fails with 0x800F081F.

    Whether the device uses WSUS is read from the Windows Update Agent, which
    reports the service the device actually uses however it was configured -
    Group Policy, Configuration Manager or an Intune policy. The Group Policy
    registry values are logged as a cross-check and used as a fallback if the
    agent cannot be queried.

    Before Windows 11 24H2 (build 26100), the policy also offered "download
    repair content directly from Windows Update instead of WSUS", stored as
    RepairContentServerSource = 2. From build 26100 the policy no longer has
    that option, so a leftover value is reported but not counted.

    The output line starts with a token, for filtering an export:
      LocalSource                  An alternate source path is set, and DISM
                                   tries it first.
      WindowsUpdate                Updates do not come from WSUS; DISM
                                   downloads from Windows Update.
      WsusRepairFromWindowsUpdate  Updates come from WSUS, and the pre-24H2
                                   policy option sends repair downloads to
                                   Windows Update.
      WsusOnly                     Updates come from WSUS and no repair source
                                   counts: DISM RestoreHealth is likely to fail.

    The package has no remediation, so exit 1 starts nothing. It puts the
    device under "With issues" in the report, which lists the devices at risk
    without reading every line:
      exit 0  A repair source exists.
      exit 1  WsusOnly.
      exit 2  The check could not be completed.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs, which is writable by SYSTEM and
    readable by support staff.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Test-ComponentRepairSource.ps1 -Verbose

    Reports this device's repair source and echoes every log line to the
    console. It only reads, so it needs no administrator rights.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-23

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM under Intune (Run this script using the logged-on
                    credentials: No). Any user when run by hand: it only reads.
    Host          : 32-bit or 64-bit. Registry values are read from the 64-bit
                    view explicitly, so the host setting does not change the
                    result.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. The file is ASCII-only.
    Modules       : None. The Windows Update Agent is queried through its COM
                    interface, which ships with Windows.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None (runs on the device, not against Graph).
    Admin consent : Not applicable.

.LINK
    https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-servicing

.LINK
    https://learn.microsoft.com/windows/deployment/update/fod-and-lang-packs
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

function Get-MachineRegistryValue {
    <#
        .SYNOPSIS
            Reads one value under HKLM from the 64-bit registry view, whatever
            the host. Returns $null when the key or the value does not exist.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SubKey,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ValueName
    )

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        $key = $baseKey.OpenSubKey($SubKey)
        if ($null -eq $key) {
            return $null
        }

        try {
            # DoNotExpandEnvironmentNames keeps a REG_EXPAND_SZ path as written.
            return $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        finally {
            $key.Dispose()
        }
    }
    finally {
        $baseKey.Dispose()
    }
}

function Get-DefaultUpdateService {
    <#
        .SYNOPSIS
            Returns the Windows Update Agent's default automatic-update service:
            its name and whether it is a managed (WSUS) service. Throws if the
            agent cannot be queried or reports no default service.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    $default = @($serviceManager.Services | Where-Object { $_.IsDefaultAUService }) | Select-Object -First 1

    if ($null -eq $default) {
        throw 'The Windows Update Agent reports no default automatic-update service.'
    }

    return [pscustomobject]@{
        Name      = [string]$default.Name
        IsManaged = [bool]$default.IsManaged
    }
}

function Get-RepairSourceVerdict {
    <#
        .SYNOPSIS
            Decides where DISM would get repair files. Reads no state, so every
            combination can be tested without a device.

        .DESCRIPTION
            Returns an object with Token, ExitCode and Detail. The order follows
            DISM's: an alternate source path is tried first, then Windows
            Update where allowed. When unsure, the verdict is WsusOnly: the
            purpose is to find the devices a pilot must look at, and a false
            "fine" hides exactly those.

        .PARAMETER Build
            The Windows build number (CurrentBuild), never the product name:
            Windows 11 still reports 'Windows 10' in ProductName.

        .PARAMETER UsesWsus
            Whether the device takes its updates from WSUS.

        .PARAMETER LocalSourcePath
            The policy's alternate source path, or $null when not set.

        .PARAMETER RepairContentServerSource
            The pre-24H2 policy value; 2 means repair from Windows Update
            directly. $null when not set.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateRange(1, 999999)]
        [int]$Build,

        [Parameter(Mandatory)]
        [bool]$UsesWsus,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LocalSourcePath,

        [Parameter()]
        [AllowNull()]
        [Nullable[int]]$RepairContentServerSource
    )

    # Windows 11 24H2. From this build the policy offers only the source path.
    $firstBuildWithoutRepairOption = 26100
    $repairFromWindowsUpdateSet = $RepairContentServerSource -eq 2

    if (-not [string]::IsNullOrWhiteSpace($LocalSourcePath)) {
        return [pscustomobject]@{
            Token    = 'LocalSource'
            ExitCode = 0
            Detail   = 'an alternate repair source path is set by policy, and DISM tries it first'
        }
    }

    if (-not $UsesWsus) {
        return [pscustomobject]@{
            Token    = 'WindowsUpdate'
            ExitCode = 0
            Detail   = 'updates do not come from WSUS, so DISM downloads repair files from Windows Update'
        }
    }

    if ($repairFromWindowsUpdateSet -and $Build -lt $firstBuildWithoutRepairOption) {
        return [pscustomobject]@{
            Token    = 'WsusRepairFromWindowsUpdate'
            ExitCode = 0
            Detail   = 'updates come from WSUS, and policy sends repair downloads to Windows Update'
        }
    }

    $detail = if ($repairFromWindowsUpdateSet) {
        "updates come from WSUS; RepairContentServerSource is set, but the policy has no such option from build $firstBuildWithoutRepairOption, so it is not counted"
    }
    else {
        'updates come from WSUS and no repair source is set; DISM RestoreHealth is likely to fail with 0x800F081F'
    }

    return [pscustomobject]@{
        Token    = 'WsusOnly'
        ExitCode = 1
        Detail   = $detail
    }
}

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Detection started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    #region Detect
    $buildText = Get-MachineRegistryValue -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ValueName 'CurrentBuild'
    $build = 0
    if (-not [int]::TryParse([string]$buildText, [ref]$build) -or $build -lt 1) {
        throw "Could not read the Windows build number (CurrentBuild = '$buildText')."
    }

    $servicingKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing'
    $localSourcePath = Get-MachineRegistryValue -SubKey $servicingKey -ValueName 'LocalSourcePath'
    $repairContentServerSource = Get-MachineRegistryValue -SubKey $servicingKey -ValueName 'RepairContentServerSource'

    $wuServer = Get-MachineRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'WUServer'
    $useWuServer = Get-MachineRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'UseWUServer'
    $wsusByPolicy = ($useWuServer -eq 1) -and -not [string]::IsNullOrWhiteSpace([string]$wuServer)

    Write-LogEntry -Message "Build $build. LocalSourcePath: $(if ($localSourcePath) { "'$localSourcePath'" } else { 'not set' }). RepairContentServerSource: $(if ($null -ne $repairContentServerSource) { $repairContentServerSource } else { 'not set' })."
    Write-LogEntry -Message "Group Policy WSUS values: WUServer $(if ($wuServer) { "'$wuServer'" } else { 'not set' }); UseWUServer $(if ($null -ne $useWuServer) { $useWuServer } else { 'not set' })."

    try {
        $service = Get-DefaultUpdateService
        $usesWsus = $service.IsManaged
        $serviceName = $service.Name
        Write-LogEntry -Message "Windows Update Agent default service: '$serviceName' (managed: $($service.IsManaged))."

        if ($usesWsus -ne $wsusByPolicy) {
            Write-LogEntry -Message 'The Windows Update Agent and the Group Policy values disagree about WSUS. The agent is used: it also sees WSUS configured by Configuration Manager or an Intune policy.' -Level WARN
        }
    }
    catch {
        $usesWsus = $wsusByPolicy
        $serviceName = 'not queried'
        Write-LogEntry -Message "Could not query the Windows Update Agent, so the Group Policy values decide: $($_.Exception.Message)" -Level WARN
    }

    $repairValue = $null
    if ($null -ne $repairContentServerSource) {
        $parsed = 0
        if ([int]::TryParse([string]$repairContentServerSource, [ref]$parsed)) {
            $repairValue = $parsed
        }
    }

    $verdict = Get-RepairSourceVerdict -Build $build -UsesWsus $usesWsus -LocalSourcePath ([string]$localSourcePath) -RepairContentServerSource $repairValue
    #endregion

    $line = "$($verdict.Token): $($verdict.Detail). Update service: $serviceName. Build $build."
    Write-LogEntry -Message $line -Level $(if ($verdict.ExitCode -eq 0) { 'INFO' } else { 'WARN' })
    Write-ResultLine -Message $line
    exit $(if ($verdict.ExitCode -eq 0) { $ExitIssueNotFound } else { $ExitIssueFound })
}
catch {
    $message = "Detection failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR

    # Continue, not Stop: this error must not escape and turn into exit code 1,
    # which would list the device as at risk when the check simply failed.
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitError
}
