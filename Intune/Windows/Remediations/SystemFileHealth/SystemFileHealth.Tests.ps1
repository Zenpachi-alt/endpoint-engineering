# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for the SystemFileHealth package: how SFC's messages are read,
    and the exit code and output line of both scripts in every situation they
    handle.

.DESCRIPTION
    Shared region: the SystemFileHealth region must be identical in both
    scripts. TimeGuard's copies are checked by
    Templates/Remediation/TimeGuard.Tests.ps1.

    Get-SfcResult: SFC's closing messages, including UTF-16 padding and line
    wrapping, and messages it must not recognise. Runs anywhere.

    Detection and remediation: each script runs as the Intune management
    extension runs it, in Windows PowerShell 5.1 with -File, with the functions
    that touch the device replaced by stand-ins - SFC, DISM, the elevation
    check and TimeGuard's registry state. Everything the scripts decide runs
    as written. No scan runs and nothing on the device changes. Windows only.

.EXAMPLE
    Invoke-Pester -Path .\Intune\Windows\Remediations\SystemFileHealth -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. The scripts under test always run in Windows
                    PowerShell 5.1, whichever host runs Pester.
    Context       : Any user. Nothing needs administrator rights: the
                    elevation check is one of the stand-ins.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    $script:OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $script:Has32BitHost = $script:OnWindows -and [Environment]::Is64BitOperatingSystem -and
        (Test-Path -LiteralPath (Join-Path -Path $env:SystemRoot -ChildPath 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'))
}

BeforeAll {
    $script:DetectionPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-SystemFileHealth.ps1'
    $script:RemediationPath = Join-Path -Path $PSScriptRoot -ChildPath 'Repair-SystemFileHealth.ps1'

    function Get-SharedRegion {
        # The lines from '#region <Name>' to '#endregion <Name>', or $null
        # unless the file holds exactly one such block.
        param ([string]$Path, [string]$Name)

        $lines = @((Get-Content -LiteralPath $Path -Raw) -split '\r?\n')
        $escaped = [regex]::Escape($Name)
        $starts = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -cmatch "^\s*#region $escaped\b") { $i } })
        $ends = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -cmatch "^\s*#endregion $escaped\s*$") { $i } })

        if ($starts.Count -ne 1 -or $ends.Count -ne 1 -or $ends[0] -le $starts[0]) { return $null }

        , $lines[$starts[0]..$ends[0]]
    }

    #region Remediation test harness 1.0.0 - canonical copy in Templates/Remediation/ExampleSetting.Tests.ps1
    # Paste this region unchanged into the BeforeAll block of a remediation
    # package's tests. Templates/Remediation/README.md describes how to use it.

    function ConvertTo-StubbedScript {
        <#
            Writes a copy of a script in which the named functions are replaced
            by stand-ins, and returns the copy's path. The parameters, the main
            block and every other function run as written.

            A stand-in keeps the original's attributes and parameters, records
            each call in $Fake.Calls, and then runs its body from -Stub. A body
            of $null returns the next result queued for the function in
            $Fake.Results. $Fake is the device the test passed to
            Invoke-RemediationScript, and changes a stand-in makes to it are
            returned to the test.
        #>
        param (
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [System.Collections.IDictionary]$Stub,

            [Parameter(Mandatory)]
            [string]$Destination
        )

        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "$Path does not parse: $($parseErrors[0].Message)" }
        if ($null -eq $syntaxTree.ParamBlock) { throw "$Path has no param block for the stand-ins to follow." }

        $text = $syntaxTree.Extent.Text
        if ($text -match '\$Fake\b') { throw "$Path already uses `$Fake, which the stand-ins need." }

        $functions = @($syntaxTree.FindAll({ param ($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false))
        $edits = New-Object -TypeName System.Collections.Generic.List[object]

        foreach ($name in $Stub.Keys) {
            $matching = @($functions | Where-Object { $_.Name -eq $name })
            if ($matching.Count -ne 1) {
                throw "$Path defines $($matching.Count) functions named '$name'; a stand-in needs exactly one."
            }

            $original = $matching[0]
            $paramBlock = $original.Body.ParamBlock
            $signature = if ($null -eq $paramBlock) {
                "[CmdletBinding()]`nparam ()"
            }
            else {
                (@($paramBlock.Attributes | ForEach-Object { $_.Extent.Text }) + $paramBlock.Extent.Text) -join "`n"
            }

            $body = if ($null -eq $Stub[$name]) { "Get-FakeResult -Name '$name'" } else { $Stub[$name].ToString() }

            $edits.Add([pscustomobject]@{
                    Start = $original.Extent.StartOffset
                    End   = $original.Extent.EndOffset
                    Text  = "function $name {`n$signature`nAdd-FakeCall -Name '$name' -Parameter `$PSBoundParameters`ntry {`n$body`n}`nfinally {`nSave-Fake`n}`n}"
                })
        }

        # The device the test describes, and the functions the stand-ins use,
        # placed straight after the param block so the stand-ins can use them.
        $prelude = @'


# ---- Inserted by ConvertTo-StubbedScript: this copy is for tests only. ----
$Fake = Import-Clixml -LiteralPath $env:REMEDIATION_TEST_FAKE

function Save-Fake {
    $Fake | Export-Clixml -LiteralPath $env:REMEDIATION_TEST_FAKE -Depth 5
}

function Add-FakeCall {
    param ([string]$Name, [System.Collections.IDictionary]$Parameter)

    $arguments = @{}
    foreach ($key in $Parameter.Keys) { $arguments[$key] = [string]$Parameter[$key] }
    $Fake.Calls = @($Fake.Calls) + @{ Name = $Name; Parameters = $arguments }
    Save-Fake
}

function Get-FakeResult {
    param ([string]$Name)

    if (-not $Fake.Results.ContainsKey($Name)) { throw "The test queued no result for $Name." }
    $queue = @($Fake.Results[$Name])
    $made = @($Fake.Calls | Where-Object { $_.Name -eq $Name }).Count
    $next = $queue[[Math]::Min($made, $queue.Count) - 1]
    if ($next -is [System.Collections.IDictionary] -and $next.Contains('Throw')) { throw [string]$next['Throw'] }
    return $next
}
# ---- End of inserted code. ----
'@
        $edits.Add([pscustomobject]@{
                Start = $syntaxTree.ParamBlock.Extent.EndOffset
                End   = $syntaxTree.ParamBlock.Extent.EndOffset
                Text  = $prelude
            })

        # From the end backwards, so every offset still points where it did.
        foreach ($edit in @($edits | Sort-Object -Property Start -Descending)) {
            $text = $text.Substring(0, $edit.Start) + $edit.Text + $text.Substring($edit.End)
        }

        # Written without a BOM, ASCII-only, like the script it came from.
        [System.IO.File]::WriteAllText($Destination, $text, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
        return $Destination
    }

    function Invoke-RemediationScript {
        <#
            Runs a script as the Intune management extension does and returns
            ExitCode, Output (the non-empty STDOUT lines), Error (STDERR, with
            the console's line wrapping undone), and
            Fake: the device after the run, with every stand-in call in Calls
            as Name and Parameters. -Fake is needed for a stubbed script, where
            Results holds what each stand-in returns by function name: one
            value, or a list used in turn whose last item repeats. A value of
            @{ Throw = '<message>' } makes the stand-in throw instead.
        #>
        param (
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter()]
            [string[]]$ArgumentList = @(),

            [Parameter()]
            [hashtable]$Fake,

            [Parameter()]
            [switch]$Use32BitHost,

            [Parameter()]
            [int]$TimeoutSeconds = 120
        )

        # A 32-bit process sees SysWOW64 as System32; Sysnative reaches the
        # real one.
        $folder = if ($Use32BitHost) { 'SysWOW64' }
        elseif ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' }
        else { 'System32' }
        $executable = Join-Path -Path $env:SystemRoot -ChildPath "$folder\WindowsPowerShell\v1.0\powershell.exe"

        $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Path) + $ArgumentList
        $quoted = foreach ($argument in $arguments) {
            if ($argument -notmatch '[\s"]') { $argument; continue }
            # A backslash before the closing quote would escape it.
            '"' + (($argument -replace '"', '\"') -replace '(\\+)$', '$1$1') + '"'
        }

        $info = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $info.FileName = $executable
        $info.Arguments = $quoted -join ' '
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true

        $fakePath = $null
        if ($Fake) {
            $state = @{ Calls = @(); Results = @{} }
            foreach ($key in $Fake.Keys) { $state[$key] = $Fake[$key] }
            $fakePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('RemediationFake-' + [guid]::NewGuid().ToString('n') + '.xml')
            $state | Export-Clixml -LiteralPath $fakePath -Depth 5
            $info.EnvironmentVariables['REMEDIATION_TEST_FAKE'] = $fakePath
        }

        try {
            $process = [System.Diagnostics.Process]::Start($info)
            $outputTask = $process.StandardOutput.ReadToEndAsync()
            $errorTask = $process.StandardError.ReadToEndAsync()

            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                $process.Kill()
                throw "$Path did not finish within $TimeoutSeconds seconds."
            }
            $process.WaitForExit()

            [pscustomobject]@{
                ExitCode = $process.ExitCode
                Output   = @($outputTask.Result -split '\r?\n' | Where-Object { $_ -ne '' })
                Error    = ($errorTask.Result -replace '\s+', ' ').Trim()
                Fake     =if ($fakePath) { Import-Clixml -LiteralPath $fakePath } else { $null }
            }
        }
        finally {
            if ($fakePath -and (Test-Path -LiteralPath $fakePath)) { Remove-Item -LiteralPath $fakePath -Force }
        }
    }

    function Get-FakeCall {
        # The stand-in calls a run made, in order, optionally of one function.
        # PowerShell unrolls a single call into the hashtable itself, so index
        # the result as @(Get-FakeCall ...)[0].
        param ([Parameter(Mandatory)][object]$Run, [string]$Name)

        @($Run.Fake.Calls | Where-Object { -not $Name -or $_.Name -eq $Name })
    }
    #endregion Remediation test harness

    # The stand-ins. TimeGuard's state lives in $Fake.Registry instead of HKLM.
    $script:Stubs = [ordered]@{
        'Test-IsElevated'          = $null
        'Get-ComponentStoreHealth' = $null
        'Invoke-SystemFileChecker' = $null
        'Get-TimeGuardValue'       = {
            if ($Fake.RegistryUnreadable) { throw 'Requested registry access is not allowed.' }
            $Fake.Registry[$ValueName]
        }
        'Set-TimeGuardValue'       = {
            if ($Value) { $Fake.Registry[$ValueName] = $Value } else { $Fake.Registry.Remove($ValueName) }
        }
    }

    $script:StubbedDetection = ConvertTo-StubbedScript -Path $script:DetectionPath -Stub $script:Stubs `
        -Destination (Join-Path -Path $TestDrive -ChildPath 'Test-SystemFileHealth.ps1')

    $remediationStubs = [ordered]@{ 'Repair-ComponentStore' = $null }
    foreach ($key in $script:Stubs.Keys) { $remediationStubs[$key] = $script:Stubs[$key] }
    $script:StubbedRemediation = ConvertTo-StubbedScript -Path $script:RemediationPath -Stub $remediationStubs `
        -Destination (Join-Path -Path $TestDrive -ChildPath 'Repair-SystemFileHealth.ps1')

    $script:LogArguments = @('-LogDirectory', (Join-Path -Path $TestDrive -ChildPath 'Logs'))

    function Get-SfcRun {
        # What Invoke-SystemFileChecker returns for one SFC run.
        param ([Parameter(Mandatory)][string]$Result)

        [pscustomobject]@{ ExitCode = 0; Result = $Result; Summary = "Stand-in for sfc.exe: $Result" }
    }

    function Get-FakeDevice {
        # A healthy, elevated device with no TimeGuard state, changed by the
        # arguments. -Result values replace the queued results by function name.
        param (
            [hashtable]$Result = @{},
            [hashtable]$Registry = @{},
            [switch]$RegistryUnreadable
        )

        $results = @{
            'Test-IsElevated'          = $true
            'Get-ComponentStoreHealth' = 'Healthy'
            'Invoke-SystemFileChecker' = Get-SfcRun -Result 'Healthy'
            'Repair-ComponentStore'    = 'Healthy'
        }
        foreach ($key in $Result.Keys) { $results[$key] = $Result[$key] }

        @{
            Results            = $results
            Registry           = $Registry
            RegistryUnreadable = $RegistryUnreadable.IsPresent
        }
    }

    function Get-Stamp {
        # A round-trip UTC timestamp some days before now, as TimeGuard stores it.
        param ([double]$DaysAgo)

        [datetime]::UtcNow.AddDays(-$DaysAgo).ToString('o', [cultureinfo]::InvariantCulture)
    }

    function Assert-RecentStamp {
        # The value is a round-trip timestamp from the last few minutes.
        param ([string]$Value)

        $Value | Should -Not -BeNullOrEmpty
        $parsed = [datetime]::Parse($Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        ([datetime]::UtcNow - $parsed.ToUniversalTime()).TotalMinutes | Should -BeLessThan 5
    }
}

Describe 'The SystemFileHealth region' {

    It 'is identical in the detection and the remediation script' {
        $detection = Get-SharedRegion -Path $script:DetectionPath -Name 'SystemFileHealth'
        $remediation = Get-SharedRegion -Path $script:RemediationPath -Name 'SystemFileHealth'

        $detection | Should -Not -BeNullOrEmpty
        $remediation | Should -Not -BeNullOrEmpty

        $length = [Math]::Max($detection.Count, $remediation.Count)
        for ($i = 0; $i -lt $length; $i++) {
            $expected = if ($i -lt $detection.Count) { $detection[$i] } else { '<end of region>' }
            $actual = if ($i -lt $remediation.Count) { $remediation[$i] } else { '<end of region>' }

            if ($actual -cne $expected) {
                throw ("Repair-SystemFileHealth.ps1 differs from Test-SystemFileHealth.ps1 at line {0} of the SystemFileHealth region.`n" +
                    "  Test-:   {1}`n  Repair-: {2}`nChange the region in both scripts, and raise its version.") -f ($i + 1), $expected, $actual
            }
        }
    }
}

Describe 'Get-SfcResult' {

    BeforeAll {
        . ([scriptblock]::Create(((Get-SharedRegion -Path $script:DetectionPath -Name 'SystemFileHealth') -join [Environment]::NewLine)))
    }

    It 'reads <Expected> from its closing message' -ForEach @(
        @{ Expected = 'Healthy'; Message = 'Windows Resource Protection did not find any integrity violations.' }
        @{ Expected = 'Repaired'; Message = 'Windows Resource Protection found corrupt files and successfully repaired them. For online repairs, details are included in the CBS log file.' }
        @{ Expected = 'Unrepaired'; Message = 'Windows Resource Protection found corrupt files but was unable to fix some of them. For online repairs, details are included in the CBS log file.' }
        @{ Expected = 'Corrupt'; Message = 'Windows Resource Protection found integrity violations. For online repairs, details are included in the CBS log file.' }
        @{ Expected = 'PendingRepairReboot'; Message = 'There is a system repair pending which requires reboot to complete.  Restart Windows and run sfc again.' }
        @{ Expected = 'Failed'; Message = 'Windows Resource Protection could not perform the requested operation.' }
    ) {
        $output = "Beginning system scan.  This process will take some time.`r`n`r`nVerification 100% complete.`r`n`r`n$Message"

        Get-SfcResult -Output $output | Should -Be $Expected
    }

    It 'reads the message through the NUL padding of UTF-16 output' {
        $padded = ('Windows Resource Protection did not find any integrity violations.'.ToCharArray() | ForEach-Object { "$_`0" }) -join ''

        Get-SfcResult -Output $padded | Should -Be 'Healthy'
    }

    It 'reads a message that is wrapped across lines' {
        Get-SfcResult -Output "Windows Resource Protection found corrupt files but was unable to fix`r`nsome of them." | Should -Be 'Unrepaired'
    }

    It 'returns Unknown, never Healthy, for <Case>' -ForEach @(
        @{ Case = 'no output'; Output = '' }
        @{ Case = 'only progress'; Output = 'Verification 42% complete.' }
        @{ Case = 'a message in another language'; Output = 'Der Windows-Ressourcenschutz hat keine Integritaetsverletzungen gefunden.' }
        @{ Case = 'usage text after a bad argument'; Output = 'Microsoft (R) Windows Resource Checker Version 6.0 Scans the integrity of all protected system files.' }
    ) {
        Get-SfcResult -Output $Output | Should -Be 'Unknown'
    }
}

Describe 'Test-SystemFileHealth.ps1' -Skip:(-not $script:OnWindows) {

    Context 'exit code' {

        It 'exits 0 with one line when SFC and the component store are healthy, and records the check' {
            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake (Get-FakeDevice)

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @('Healthy: SFC found no integrity violations; component store Healthy.')
            Assert-RecentStamp -Value $run.Fake.Registry['LastDetection']
            @(Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker')[0].Parameters.Mode | Should -Be 'VerifyOnly'
        }

        It 'exits 1 when SFC finds integrity violations' {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result 'Corrupt' }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Issue found: SFC found integrity violations.')
        }

        It 'exits 1 when the component store is flagged, even though SFC is satisfied' {
            $device = Get-FakeDevice -Result @{ 'Get-ComponentStoreHealth' = 'Repairable' }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Issue found: the component store is flagged Repairable.')
        }

        It 'exits 2 when SFC reports <Result>, which /verifyonly should not' -ForEach @(
            @{ Result = 'Unknown' }
            @{ Result = 'Repaired' }
            @{ Result = 'Unrepaired' }
        ) {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result $Result }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2 -Because $run.Error
            $run.Output | Should -Be @('Detection failed: SFC result not recognised; see the log.')
        }

        It 'exits 2 and takes the check back when SFC <Result>' -ForEach @(
            @{ Result = 'PendingRepairReboot'; Line = 'Not checked: a system file repair is waiting for a restart.' }
            @{ Result = 'Failed'; Line = 'Detection failed: SFC could not perform the requested operation.' }
        ) {
            $previous = Get-Stamp -DaysAgo 40
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result $Result } -Registry @{ LastDetection = $previous }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2 -Because $run.Error
            $run.Output | Should -Be @($Line)
            $run.Fake.Registry['LastDetection'] | Should -Be $previous
        }

        It 'removes the timestamp when a check that never ran was the first' {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result 'PendingRepairReboot' }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2 -Because $run.Error
            $run.Fake.Registry.ContainsKey('LastDetection') | Should -BeFalse
        }

        It 'exits 2, never 1, when <Function> throws' -ForEach @(
            @{ Function = 'Get-ComponentStoreHealth' }
            @{ Function = 'Invoke-SystemFileChecker' }
        ) {
            $device = Get-FakeDevice -Result @{ $Function = @{ Throw = 'The stand-in failed.' } }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2
            $run.Output | Should -BeNullOrEmpty
            $run.Error | Should -Match 'Detection failed: The stand-in failed\.'
        }

        It 'exits 2 without scanning when it has no administrator rights' {
            $device = Get-FakeDevice -Result @{ 'Test-IsElevated' = $false }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 2 -Because $run.Error
            $run.Output | Should -Be @('Detection failed: administrator rights are required.')
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -BeNullOrEmpty
        }

        It 'exits 2 without scanning in 32-bit PowerShell' -Skip:(-not $script:Has32BitHost) {
            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake (Get-FakeDevice) -Use32BitHost

            $run.ExitCode | Should -Be 2 -Because $run.Error
            $run.Output | Should -Be @('Detection failed: running in 32-bit PowerShell. Set "Run script in 64-bit PowerShell" to Yes.')
            Get-FakeCall -Run $run | Should -BeNullOrEmpty
        }
    }

    Context 'TimeGuard' {

        It 'skips a recent check with exit 0 and one stable line, without scanning or writing' {
            $lastCheck = Get-Stamp -DaysAgo 1
            $device = Get-FakeDevice -Registry @{ LastDetection = $lastCheck }
            $date = [datetime]::Parse($lastCheck, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)

            $first = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device
            $second = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $first.ExitCode | Should -Be 0 -Because $first.Error
            $first.Output | Should -Be @("Skipped by TimeGuard: last full check $date UTC.")
            $second.Output | Should -Be $first.Output
            Get-FakeCall -Run $first -Name 'Invoke-SystemFileChecker' | Should -BeNullOrEmpty
            Get-FakeCall -Run $first -Name 'Get-ComponentStoreHealth' | Should -BeNullOrEmpty
            Get-FakeCall -Run $first -Name 'Set-TimeGuardValue' | Should -BeNullOrEmpty
        }

        It 'checks for real after a remediation, however recent the last check' {
            $device = Get-FakeDevice -Registry @{ LastDetection = (Get-Stamp -DaysAgo 1); LastRemediation = (Get-Stamp -DaysAgo 0.01) }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output[0] | Should -BeLike 'Healthy:*'
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -HaveCount 1
        }

        It 'checks once the interval has passed' {
            $device = Get-FakeDevice -Registry @{ LastDetection = (Get-Stamp -DaysAgo 31) }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -HaveCount 1
            Assert-RecentStamp -Value $run.Fake.Registry['LastDetection']
        }

        It 'checks every time with -TimeGuardIntervalDays 0' {
            $device = Get-FakeDevice -Registry @{ LastDetection = (Get-Stamp -DaysAgo 0.01) }

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList ($script:LogArguments + @('-TimeGuardIntervalDays', '0')) -Fake $device

            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -HaveCount 1
        }

        It 'checks, and writes nothing, when its state cannot be read' {
            $device = Get-FakeDevice -Registry @{ LastDetection = (Get-Stamp -DaysAgo 1) } -RegistryUnreadable

            $run = Invoke-RemediationScript -Path $script:StubbedDetection -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -HaveCount 1
            Get-FakeCall -Run $run -Name 'Set-TimeGuardValue' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Repair-SystemFileHealth.ps1' -Skip:(-not $script:OnWindows) {

    Context 'exit code' {

        It 'exits 0 without DISM when <Case>' -ForEach @(
            @{ Case = 'SFC finds nothing to repair'; Result = 'Healthy'; Line = 'Remediated: SFC found nothing to repair; DISM not needed.' }
            @{ Case = 'SFC repairs everything'; Result = 'Repaired'; Line = 'Remediated: SFC repaired the corrupt files; DISM not needed.' }
        ) {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result $Result }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @($Line)
            Get-FakeCall -Run $run -Name 'Repair-ComponentStore' | Should -BeNullOrEmpty
            @(Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker')[0].Parameters.Mode | Should -Be 'ScanNow'
            Assert-RecentStamp -Value $run.Fake.Registry['LastRemediation']
        }

        It 'runs SFC, DISM, then SFC again when SFC cannot repair everything, and exits 0 once it has' {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = @((Get-SfcRun -Result 'Unrepaired'), (Get-SfcRun -Result 'Repaired')) }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @('Remediated: DISM repaired the component store, then SFC repaired the remaining files.')
            $sequence = @(Get-FakeCall -Run $run | Where-Object { $_.Name -in @('Invoke-SystemFileChecker', 'Repair-ComponentStore') } | ForEach-Object { $_.Name })
            $sequence | Should -Be @('Invoke-SystemFileChecker', 'Repair-ComponentStore', 'Invoke-SystemFileChecker')
        }

        It 'exits 1 when SFC still cannot repair everything after DISM' {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = @((Get-SfcRun -Result 'Unrepaired'), (Get-SfcRun -Result 'Unrepaired')) }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Remediation failed: SFC reports 'Unrepaired' after DISM; see CBS.log.")
        }

        It 'repairs a flagged component store with DISM and exits 0 without a second SFC pass' {
            $device = Get-FakeDevice -Result @{ 'Get-ComponentStoreHealth' = 'Repairable' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @('Remediated: SFC found nothing to repair; DISM repaired the component store.')
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -HaveCount 1
        }

        It 'exits 1 when DISM fails' {
            $device = Get-FakeDevice -Result @{
                'Get-ComponentStoreHealth' = 'Repairable'
                'Repair-ComponentStore'    = @{ Throw = 'The source files could not be found. 0x800F081F' }
            }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Remediation failed: DISM could not repair the component store; see dism.log.')
        }

        It 'exits 1 when DISM leaves the component store unhealthy' {
            $device = Get-FakeDevice -Result @{ 'Get-ComponentStoreHealth' = 'Repairable'; 'Repair-ComponentStore' = 'NonRepairable' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Remediation failed: DISM left the component store NonRepairable; see dism.log.')
        }

        It 'exits 1 when SFC reports <Result>' -ForEach @(
            @{ Result = 'PendingRepairReboot'; Line = 'Not repaired: a system file repair is waiting for a restart.' }
            @{ Result = 'Failed'; Line = 'Remediation failed: SFC could not perform the requested operation.' }
            @{ Result = 'Unknown'; Line = 'Remediation failed: SFC result not recognised; see the log.' }
            @{ Result = 'Corrupt'; Line = 'Remediation failed: SFC result not recognised; see the log.' }
        ) {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result $Result }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @($Line)
        }

        It 'keeps its timestamp when SFC could not start, so the next detection is a real check' {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = Get-SfcRun -Result 'PendingRepairReboot' }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            Assert-RecentStamp -Value $run.Fake.Registry['LastRemediation']
        }

        It 'exits 1 when SFC throws' {
            $device = Get-FakeDevice -Result @{ 'Invoke-SystemFileChecker' = @{ Throw = 'The stand-in failed.' } }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1
            $run.Error | Should -Match 'Remediation failed: The stand-in failed\.'
        }

        It 'exits 1 without repairing when it has no administrator rights' {
            $device = Get-FakeDevice -Result @{ 'Test-IsElevated' = $false }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @('Remediation failed: administrator rights are required.')
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -BeNullOrEmpty
        }

        It 'exits 1 without repairing in 32-bit PowerShell' -Skip:(-not $script:Has32BitHost) {
            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake (Get-FakeDevice) -Use32BitHost

            $run.ExitCode | Should -Be 1 -Because $run.Error
            Get-FakeCall -Run $run | Should -BeNullOrEmpty
        }
    }

    Context 'TimeGuard and -WhatIf' {

        It 'repairs whenever detection asks, by default' {
            $device = Get-FakeDevice -Registry @{ LastRemediation = (Get-Stamp -DaysAgo 0.01) }

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList $script:LogArguments -Fake $device

            $run.ExitCode | Should -Be 0 -Because $run.Error
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -HaveCount 1
        }

        It 'exits 1, not 0, when an interval is set and the last repair is recent' {
            $lastRepair = Get-Stamp -DaysAgo 1
            $device = Get-FakeDevice -Registry @{ LastRemediation = $lastRepair }
            $date = [datetime]::Parse($lastRepair, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)

            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList ($script:LogArguments + @('-TimeGuardIntervalDays', '7')) -Fake $device

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Skipped by TimeGuard: last repair $date UTC.")
            Get-FakeCall -Run $run -Name 'Invoke-SystemFileChecker' | Should -BeNullOrEmpty
            $run.Fake.Registry['LastRemediation'] | Should -Be $lastRepair
        }

        It 'scans, repairs and records nothing under -WhatIf' {
            $run = Invoke-RemediationScript -Path $script:StubbedRemediation -ArgumentList ($script:LogArguments + @('-WhatIf')) -Fake (Get-FakeDevice)

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Contain 'No change made (WhatIf or declined confirmation).'
            Get-FakeCall -Run $run | Where-Object { $_.Name -notin @('Test-IsElevated', 'Get-TimeGuardValue') } | Should -BeNullOrEmpty
        }
    }
}
