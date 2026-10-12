# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Detects corrupt Windows system files and a flagged component store, at most
    once per TimeGuard interval.

.DESCRIPTION
    Detection script of the SystemFileHealth remediation package. It runs
    'sfc /verifyonly', which checks every protected system file without
    repairing anything, and 'Repair-WindowsImage -Online -CheckHealth', which
    reads in seconds whether Windows has already flagged the component store as
    corrupt. Either finding is an issue, and Intune then runs
    Repair-SystemFileHealth.ps1.

    The SFC scan is heavy, and Intune starts detection more often than the
    assignment schedule suggests: missed runs catch up as soon as the device is
    online, and policy is read again after every restart and sign-in.
    TimeGuard skips the check while the last full check is younger than
    TimeGuardIntervalDays - unless a remediation has started since. That is the
    check Intune makes straight after a remediation, and it must run for real,
    or a device the remediation did not fix would be reported as fixed.

    SFC's result is read from its closing message, after the output is reduced
    to lowercase letters and digits so that line wrapping and SFC's UTF-16
    output cannot break a match. The messages are English. On a device
    installed in another language nothing matches, and the script reports that
    it could not tell rather than guessing.

    Apart from its TimeGuard timestamp under
    HKLM\SOFTWARE\EndpointEngineering\TimeGuard\<TimeGuardName>, the script
    changes nothing on the device.

    Contract enforced by the Intune management extension:
      exit 0  No issue found, or the check was skipped by TimeGuard. The output
              line says which.
      exit 1  Corrupt system files, or a flagged component store. The
              remediation script runs.
      exit 2  The check could not be completed: wrong host, no administrator
              rights, a repair waiting for a restart, or an SFC result the
              script does not recognise. The remediation does not run.

.PARAMETER TimeGuardName
    Name of the TimeGuard key shared with Repair-SystemFileHealth.ps1. Both
    scripts must use the same name.

.PARAMETER TimeGuardIntervalDays
    Minimum number of days between full checks. 0 turns TimeGuard off; the
    timestamp is still recorded.

.PARAMETER LogDirectory
    Directory for the script log. Defaults to
    %ProgramData%\EndpointEngineering\Logs, which is writable by SYSTEM and
    readable by support staff.

.PARAMETER MaxLogSizeBytes
    Size at which the log is rotated to a single .old copy.

.EXAMPLE
    .\Test-SystemFileHealth.ps1 -Verbose

    Runs the detection from an elevated 64-bit Windows PowerShell and echoes
    every log line to the console. TimeGuard applies as it does under Intune.

.EXAMPLE
    .\Test-SystemFileHealth.ps1 -TimeGuardIntervalDays 0 -Verbose

    Runs the full check regardless of when it last ran.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.1.0
    Last updated  : 2026-09-23

    PowerShell    : Windows PowerShell 5.1 only. PowerShell 7 has to be
                    deployed separately and cannot be assumed on a device.
    Context       : SYSTEM (Run this script using the logged-on credentials:
                    No). SFC and DISM need administrator rights; without them
                    the script exits 2.
    Host          : 64-bit (Run script in 64-bit PowerShell: Yes). DISM cannot
                    service a running 64-bit Windows from a 32-bit host, so the
                    script exits 2 in one instead of reporting a false result.
    Encoding      : UTF-8. Use UTF-8 without BOM if "Enforce script signature
                    check" is enabled. The file is ASCII-only.
    Modules       : Dism, which ships with Windows. Nothing to install.
    Licensing     : Remediations require Windows Enterprise E3/E5, Windows
                    Education A3/A5, or Windows VDA per user, plus Intune.
    Graph scopes  : None (runs on the device, not against Graph).
    Admin consent : Not applicable.

    Run time      : A full check takes several minutes. A TimeGuard skip takes
                    under a second.

.LINK
    https://learn.microsoft.com/intune/device-management/tools/deploy-remediations

.LINK
    https://learn.microsoft.com/windows-server/administration/windows-commands/sfc
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$TimeGuardName = 'SystemFileHealth',

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$TimeGuardIntervalDays = 30,

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

#region TimeGuard 1.0.0 - canonical copy in Templates/Remediation/TimeGuard.ps1
# Paste this region unchanged into both scripts of a package. The rules it
# implements are described in Templates/Remediation/README.md.

function Get-TimeGuardValue {
    <#
        .SYNOPSIS
            Reads one TimeGuard timestamp. Returns $null when the key or the
            value does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('LastDetection', 'LastRemediation')]
        [string]$ValueName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Root = 'SOFTWARE\EndpointEngineering\TimeGuard'
    )

    # The 64-bit view is opened explicitly so that a 32-bit and a 64-bit host
    # read the same key, rather than one of them landing in WOW6432Node.
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        $key = $baseKey.OpenSubKey("$Root\$Name")
        if ($null -eq $key) {
            return $null
        }

        try {
            $value = $key.GetValue($ValueName)
            if ($null -eq $value) {
                return $null
            }

            return [string]$value
        }
        finally {
            $key.Dispose()
        }
    }
    finally {
        $baseKey.Dispose()
    }
}

function Set-TimeGuardValue {
    <#
        .SYNOPSIS
            Writes one TimeGuard timestamp, or removes it when Value is empty.
            Restoring a previous value is how a run that did no heavy work is
            taken back.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('LastDetection', 'LastRemediation')]
        [string]$ValueName,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Root = 'SOFTWARE\EndpointEngineering\TimeGuard'
    )

    $target = "HKLM\$Root\$Name\$ValueName"
    $action = if ($Value) { "Set to '$Value'" } else { 'Remove' }

    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
        return
    }

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)

    try {
        # CreateSubKey opens the key for writing, creating it if necessary.
        $key = $baseKey.CreateSubKey("$Root\$Name")
        if ($null -eq $key) {
            throw "Could not open or create 'HKLM\$Root\$Name'."
        }

        try {
            if ($Value) {
                $key.SetValue($ValueName, $Value, [Microsoft.Win32.RegistryValueKind]::String)
            }
            else {
                $key.DeleteValue($ValueName, $false)
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

function ConvertFrom-TimeGuardValue {
    <#
        .SYNOPSIS
            Parses a stored round-trip ('o') timestamp into UTC. Returns $null
            for anything else, including an empty value.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    $parsed = [datetime]::MinValue
    $isValid = [datetime]::TryParseExact(
        $Value,
        'o',
        [cultureinfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed)

    if (-not $isValid) {
        return $null
    }

    return $parsed.ToUniversalTime()
}

function Get-TimeGuardDecision {
    <#
        .SYNOPSIS
            Decides whether the heavy work runs now, and says why.

        .DESCRIPTION
            Reads no state, so every rule can be tested with any combination
            of times. Returns an object with Run (bool), Reason (string) and
            LastRunUtc (the parsed LastRun, or $null).

            The work runs when the guard is off, when no usable timestamp
            exists, when the stored time is in the future, when a remediation
            started after the last run, or when the interval has elapsed. It
            is skipped only when the last run is recent and nothing has
            happened since. A guard that cannot decide lets the work run: it
            limits how often the work happens and must never stop it.

        .PARAMETER Now
            The current time, normally [datetime]::UtcNow.

        .PARAMETER LastRun
            This script's stored timestamp, as read from the registry.

        .PARAMETER LastRemediation
            The remediation's stored timestamp. Detection passes it so that
            the check Intune makes straight after a remediation always runs;
            the remediation leaves it out.

        .PARAMETER IntervalDays
            Minimum number of days between runs. 0 turns the guard off.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [datetime]$Now,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LastRun,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LastRemediation,

        [Parameter(Mandatory)]
        [ValidateRange(0, 3650)]
        [int]$IntervalDays
    )

    $format = 'yyyy-MM-dd HH:mm'
    $culture = [cultureinfo]::InvariantCulture
    $nowUtc = $Now.ToUniversalTime()
    $lastRunUtc = ConvertFrom-TimeGuardValue -Value $LastRun

    $decision = [pscustomobject]@{
        Run        = $true
        Reason     = ''
        LastRunUtc = $lastRunUtc
    }

    if ($IntervalDays -eq 0) {
        $decision.Reason = 'TimeGuard is off (interval 0 days).'
    }
    elseif ([string]::IsNullOrWhiteSpace($LastRun)) {
        $decision.Reason = 'No previous run is recorded.'
    }
    elseif ($null -eq $lastRunUtc) {
        $decision.Reason = "The recorded time '$LastRun' is not a valid timestamp."
    }
    elseif ($lastRunUtc -gt $nowUtc.AddMinutes(5)) {
        # Five minutes of tolerance absorbs a small clock correction without
        # treating it as a broken timestamp.
        $decision.Reason = "The recorded time $($lastRunUtc.ToString($format, $culture)) UTC is in the future; the clock was probably wrong when it was written."
    }
    else {
        $lastRemediationUtc = ConvertFrom-TimeGuardValue -Value $LastRemediation
        $dueUtc = $lastRunUtc.AddDays($IntervalDays)

        if ($null -ne $lastRemediationUtc -and $lastRemediationUtc -gt $lastRunUtc) {
            $decision.Reason = "A remediation started at $($lastRemediationUtc.ToString($format, $culture)) UTC, after the last run at $($lastRunUtc.ToString($format, $culture)) UTC. Running to verify it."
        }
        elseif ($nowUtc -lt $dueUtc) {
            $decision.Run = $false
            $decision.Reason = "Last run at $($lastRunUtc.ToString($format, $culture)) UTC. Next run due after $($dueUtc.ToString($format, $culture)) UTC."
        }
        else {
            $decision.Reason = "$IntervalDays days or more have passed since the last run at $($lastRunUtc.ToString($format, $culture)) UTC."
        }
    }

    return $decision
}

#endregion TimeGuard

#region SystemFileHealth 1.1.0 - keep identical in Test- and Repair-SystemFileHealth.ps1
function Test-IsElevated {
    <#
        .SYNOPSIS
            True when the process has administrator rights, as SYSTEM does
            under Intune. SFC and DISM refuse to run without them.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SfcResult {
    <#
        .SYNOPSIS
            Names the result that SFC's closing message reports. Returns
            'Unknown' when no known message is present, which callers treat as
            a failure and never as healthy.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Output
    )

    # Reduced to lowercase letters and digits, so line wrapping, punctuation
    # and the NUL padding of SFC's UTF-16 output cannot break a match.
    $normalized = ($Output -replace "`0", '').ToLowerInvariant() -replace '[^\p{L}\p{Nd}]', ''

    # No pattern is contained in another, so the order does not decide the
    # result; [ordered] keeps it predictable should SFC ever print two.
    $patterns = [ordered]@{
        Healthy             = 'windowsresourceprotectiondidnotfindanyintegrityviolations'
        Repaired            = 'windowsresourceprotectionfoundcorruptfilesandsuccessfullyrepairedthem'
        Unrepaired          = 'windowsresourceprotectionfoundcorruptfilesbutwasunabletofixsomeofthem'
        Corrupt             = 'windowsresourceprotectionfoundintegrityviolations'
        PendingRepairReboot = 'thereisasystemrepairpendingwhichrequiresreboottocompleterestart|systemrepairpending.*requiresreboot.*restart'
        Failed              = 'windowsresourceprotectioncouldnotperformtherequestedoperation'
    }

    foreach ($result in $patterns.Keys) {
        if ($normalized -match $patterns[$result]) {
            return $result
        }
    }

    return 'Unknown'
}

function Invoke-SystemFileChecker {
    <#
        .SYNOPSIS
            Runs sfc.exe and returns its exit code, the result its closing
            message reports, and the last lines of its output for the log.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('VerifyOnly', 'ScanNow')]
        [string]$Mode
    )

    $sfcPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\sfc.exe'
    if (-not (Test-Path -LiteralPath $sfcPath)) {
        throw "sfc.exe was not found at '$sfcPath'."
    }

    $argument = '/' + $Mode.ToLowerInvariant()
    Write-LogEntry -Message "Running '$sfcPath $argument'. This takes several minutes."

    # Windows PowerShell 5.1 turns a native command's stderr output into a
    # terminating error under 'Stop'. The call runs under 'Continue' and its
    # exit code and output are judged afterwards instead.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $sfcPath $argument 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }

    # sfc.exe writes UTF-16, which arrives with a NUL after every character.
    $lines = @(($raw -replace "`0", '') -split '[\r\n]+' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ })

    $result = Get-SfcResult -Output ($lines -join ' ')

    # Progress lines ('Verification 97% complete.') would fill the summary and
    # push out the messages that matter. A number followed by a percent sign
    # identifies them in any language.
    $messages = @($lines | Where-Object { $_ -notmatch '\d+\s*%' })

    return [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Summary  = ($messages | Select-Object -Last 6) -join ' | '
    }
}

function Get-ComponentStoreHealth {
    <#
        .SYNOPSIS
            Returns whether Windows has flagged the component store as corrupt
            (DISM CheckHealth): Healthy, Repairable or NonRepairable. Takes
            seconds, because it reads a flag rather than scanning.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Import-Module -Name Dism -ErrorAction Stop
    $image = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop
    return [string]$image.ImageHealthState
}
#endregion SystemFileHealth

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $script:LogFile = Initialize-LogFile -Directory $LogDirectory -Name $scriptName -MaxSizeBytes $MaxLogSizeBytes

    Write-LogEntry -Message "Detection started. Host: $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }); OS: $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }); user: $([Environment]::UserName)."

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-LogEntry -Message 'Running in 32-bit PowerShell on 64-bit Windows, where DISM cannot service the running system. Set "Run script in 64-bit PowerShell" to Yes.' -Level ERROR
        Write-ResultLine -Message 'Detection failed: running in 32-bit PowerShell. Set "Run script in 64-bit PowerShell" to Yes.'
        exit $ExitError
    }

    if (-not (Test-IsElevated)) {
        Write-LogEntry -Message 'Not running with administrator rights, which SFC and DISM require. Under Intune the script runs as SYSTEM and has them.' -Level ERROR
        Write-ResultLine -Message 'Detection failed: administrator rights are required.'
        exit $ExitError
    }

    #region Guard
    # If TimeGuard's state cannot be read, the check runs: the guard limits
    # how often a device is checked and must never be why it goes unchecked.
    $nowUtc = [datetime]::UtcNow
    $previousCheck = $null
    $guardUsable = $true

    try {
        $previousCheck = Get-TimeGuardValue -Name $TimeGuardName -ValueName 'LastDetection'
        $lastRemediation = Get-TimeGuardValue -Name $TimeGuardName -ValueName 'LastRemediation'
        $guard = Get-TimeGuardDecision -Now $nowUtc -LastRun $previousCheck -LastRemediation $lastRemediation -IntervalDays $TimeGuardIntervalDays
        Write-LogEntry -Message "TimeGuard: $($guard.Reason)"
    }
    catch {
        $guardUsable = $false
        $guard = [pscustomobject]@{ Run = $true; Reason = ''; LastRunUtc = $null }
        Write-LogEntry -Message "TimeGuard state could not be read, so the check runs: $($_.Exception.Message)" -Level WARN
    }

    if (-not $guard.Run) {
        # One stable line: Intune reports a device again whenever its output
        # changes, so a skip names the date of the last check and nothing that
        # changes between runs.
        Write-ResultLine -Message "Skipped by TimeGuard: last full check $($guard.LastRunUtc.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)) UTC."
        exit $ExitIssueNotFound
    }
    #endregion

    #region Detect
    $storeHealth = Get-ComponentStoreHealth
    Write-LogEntry -Message "Component store (DISM CheckHealth): $storeHealth."

    # The check counts from the moment the heavy work starts, so a scan that
    # is stopped part-way through is not started again on every trigger.
    if ($guardUsable) {
        try {
            Set-TimeGuardValue -Name $TimeGuardName -ValueName 'LastDetection' -Value $nowUtc.ToString('o', [cultureinfo]::InvariantCulture)
        }
        catch {
            Write-LogEntry -Message "Could not record the TimeGuard timestamp: $($_.Exception.Message)" -Level WARN
        }
    }

    $sfc = Invoke-SystemFileChecker -Mode VerifyOnly
    Write-LogEntry -Message "SFC exit code $($sfc.ExitCode), result '$($sfc.Result)'. Output: $($sfc.Summary)"

    # SFC refused to start - a repair is waiting for a restart, or it could
    # not begin - so no heavy work ran. Restoring the previous timestamp keeps
    # this run from counting, and the first check after the restart is real.
    if ($guardUsable -and ($sfc.Result -in @('PendingRepairReboot', 'Failed'))) {
        try {
            Set-TimeGuardValue -Name $TimeGuardName -ValueName 'LastDetection' -Value $previousCheck
            Write-LogEntry -Message 'SFC did not scan, so the TimeGuard timestamp was restored.'
        }
        catch {
            Write-LogEntry -Message "Could not restore the TimeGuard timestamp: $($_.Exception.Message)" -Level WARN
        }
    }
    #endregion

    if ($sfc.Result -eq 'PendingRepairReboot') {
        Write-LogEntry -Message 'A system file repair is waiting for a restart. SFC cannot check the device until it restarts.' -Level WARN
        Write-ResultLine -Message 'Not checked: a system file repair is waiting for a restart.'
        exit $ExitError
    }

    if ($sfc.Result -eq 'Failed') {
        Write-LogEntry -Message 'SFC could not perform the requested operation. See %windir%\Logs\CBS\CBS.log.' -Level ERROR
        Write-ResultLine -Message 'Detection failed: SFC could not perform the requested operation.'
        exit $ExitError
    }

    if ($sfc.Result -notin @('Healthy', 'Corrupt')) {
        # 'Unknown', or a repair message that /verifyonly never prints.
        Write-LogEntry -Message "SFC's output did not match a result this script expects ('$($sfc.Result)'). On a device installed in a language other than English, SFC's messages are translated and cannot be matched." -Level ERROR
        Write-ResultLine -Message 'Detection failed: SFC result not recognised; see the log.'
        exit $ExitError
    }

    $findings = New-Object -TypeName System.Collections.Generic.List[string]
    if ($sfc.Result -eq 'Corrupt') {
        $findings.Add('SFC found integrity violations')
    }
    if ($storeHealth -ne 'Healthy') {
        $findings.Add("the component store is flagged $storeHealth")
    }

    if ($findings.Count -eq 0) {
        Write-LogEntry -Message 'Healthy. SFC found no integrity violations and the component store is not flagged.'
        Write-ResultLine -Message 'Healthy: SFC found no integrity violations; component store Healthy.'
        exit $ExitIssueNotFound
    }

    $detail = $findings -join '; '
    Write-LogEntry -Message "Issue found: $detail." -Level WARN
    Write-ResultLine -Message "Issue found: $detail."
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
