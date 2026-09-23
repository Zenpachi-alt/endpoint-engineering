# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Detection template for an Intune remediation script package.

.DESCRIPTION
    Copy this file, rename it after the setting it checks (Test-<Noun>.ps1), and
    replace the detection logic in the "Detect" region. The template checks that
    a registry value matches an expected value; the surrounding structure
    (logging, exit codes, error handling) is the part meant to be reused.

    The script reads only. It never changes device state - that belongs in the
    paired Repair-<Noun>.ps1 script.

    Contract enforced by the Intune management extension:
      exit 0  Issue not found. The remediation script does not run.
      exit 1  Issue found. The remediation script runs.
      exit 2  The detection itself failed. Treated as "issue not found", so the
              remediation script does not run and the failure surfaces in the
              script output rather than silently triggering a repair.

    Only the last 2048 characters of STDOUT are kept by Intune, so the script
    writes exactly one short result line to STDOUT. Everything else goes to the
    log file and the verbose stream.

.PARAMETER RegistryPath
    Registry key holding the value to check. Replace with the real key.

.PARAMETER ValueName
    Name of the registry value to check.

.PARAMETER ExpectedValue
    Value the device is expected to have.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs, which is writable by SYSTEM and
    readable by support staff.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Test-ExampleSetting.ps1 -Verbose

    Runs the detection locally and echoes every log line to the console.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-23

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM (Run this script using the logged-on credentials: No)
    Host          : 32-bit unless "Run script in 64-bit PowerShell" is set to
                    Yes. On a 64-bit device a 32-bit host is redirected to
                    HKLM\SOFTWARE\WOW6432Node and %SystemRoot%\SysWOW64; the
                    script logs which host it is running in.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. Keep the file ASCII-only so Windows
                    PowerShell 5.1 reads it correctly either way.
    Modules       : None. Endpoint-side scripts must not depend on anything that
                    is not already on a stock Windows device.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None (runs on the device, not against Graph).
    Admin consent : Not applicable.

.LINK
    https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RegistryPath = 'HKLM:\SOFTWARE\EndpointEngineering\Example',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ValueName = 'ExampleSetting',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [int]$ExpectedValue = 1,

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
# latter as shadowing a command that exists in some PowerShell profiles, and
# a template should not teach people to override one.
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

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Detection started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-LogEntry -Message 'Running in a 32-bit host on a 64-bit OS. Registry and file system calls are redirected (WOW6432Node, SysWOW64). Enable "Run script in 64-bit PowerShell" if the target is a 64-bit location.' -Level WARN
    }

    #region Detect
    # Replace everything in this region with the real check. Read only.
    $isCompliant = $false
    $detail = ''

    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        $detail = "Key '$RegistryPath' does not exist."
    }
    else {
        $key = Get-Item -LiteralPath $RegistryPath -ErrorAction Stop

        if ($ValueName -notin $key.GetValueNames()) {
            $detail = "Value '$ValueName' is not set under '$RegistryPath'."
        }
        else {
            $actualValue = $key.GetValue($ValueName)

            if ($actualValue -eq $ExpectedValue) {
                $isCompliant = $true
                $detail = "'$ValueName' is $actualValue as expected."
            }
            else {
                $detail = "'$ValueName' is '$actualValue'; expected '$ExpectedValue'."
            }
        }
    }
    #endregion

    if ($isCompliant) {
        Write-LogEntry -Message "Compliant. $detail"
        Write-ResultLine -Message "Compliant: $detail"
        exit $ExitIssueNotFound
    }

    Write-LogEntry -Message "Issue found. $detail" -Level WARN
    Write-ResultLine -Message "Issue found: $detail"
    exit $ExitIssueFound
}
catch {
    $message = "Detection failed: $($_.Exception.Message)"
    Write-LogEntry -Message "$message Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level ERROR

    # Continue, not Stop: this error must not escape and turn into exit code 1,
    # which would tell Intune the issue was found and run the remediation.
    Write-Error -Message $message -ErrorAction Continue
    exit $ExitError
}
