# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for the remediation template pair, the exit-code contract of
    every detection script in the repository, and the canonical copy of the
    remediation test harness.

.DESCRIPTION
    Four parts.

    Detection contract: every detection script under a Remediations folder,
    and the template's, keeps all of its work inside one try whose catch-all
    exits with $ExitError, which is 2. An error that escaped would end the
    script with exit code 1, and Intune would run the remediation on every
    device the package is assigned to. This part only reads the scripts, so
    it runs anywhere.

    Template pair: Test-ExampleSetting.ps1 and Repair-ExampleSetting.ps1 run
    for real, in a process of their own, against a registry key under HKCU
    that the tests create and remove. Windows only.

    Harness copies: the tests of every remediation package carry the region
    below unchanged. A failure names the file and the first line that differs.

    The harness: runs a script the way the Intune management extension does -
    powershell.exe -File, in a process of its own - so a test sees the exit
    code and the STDOUT that Intune would see. ConvertTo-StubbedScript swaps
    the functions that touch the device (SFC, DISM, elevation, HKLM) for
    stand-ins that answer as the test describes, and leaves everything else,
    the main block included, as written.

.EXAMPLE
    Invoke-Pester -Path .\Templates\Remediation -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. The scripts under test always run in Windows
                    PowerShell 5.1, as they do on a device, whichever host runs
                    Pester. Tests that run them are skipped outside Windows.
    Context       : Any user. Nothing needs administrator rights; the template
                    pair is pointed at HKCU instead of HKLM.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $separator = [System.IO.Path]::DirectorySeparatorChar

    # Detection scripts: Test-*.ps1 in a Remediations folder, and the template.
    $script:DetectionScripts = @(
        Get-ChildItem -Path $repositoryRoot -Filter 'Test-*.ps1' -Recurse -File |
            Where-Object {
                $_.Name -notlike '*.Tests.ps1' -and (
                    $_.FullName -like "*${separator}Remediations${separator}*" -or
                    $_.FullName -eq (Join-Path -Path $PSScriptRoot -ChildPath 'Test-ExampleSetting.ps1'))
            } |
            ForEach-Object {
                @{
                    Path = $_.FullName
                    Name = $_.FullName.Substring($repositoryRoot.Length + 1) -replace '\\', '/'
                }
            }
    )

    # Test files that carry the harness, other than this one.
    $script:HarnessCopies = @(
        Get-ChildItem -Path $repositoryRoot -Filter '*.Tests.ps1' -Recurse -File |
            Where-Object { $_.FullName -ne $PSCommandPath } |
            Where-Object { @(Get-Content -LiteralPath $_.FullName) -match '^\s*#region Remediation test harness\b' } |
            ForEach-Object {
                @{
                    Path = $_.FullName
                    Name = $_.FullName.Substring($repositoryRoot.Length + 1) -replace '\\', '/'
                }
            }
    )

    $script:OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

BeforeAll {
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
}

Describe 'Detection scripts keep the exit-code contract' {

    It '<Name> keeps all of its work inside one try whose catch-all exits 2' -ForEach $script:DetectionScripts {
        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty

        $exitCodes = @{}
        $tries = New-Object -TypeName System.Collections.Generic.List[object]

        foreach ($statement in $syntaxTree.EndBlock.Statements) {
            if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }

            if ($statement -is [System.Management.Automation.Language.TryStatementAst]) {
                $tries.Add($statement)
                continue
            }

            # Outside the try, only settings and constants: nothing that can fail.
            if ($statement -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                $value = $statement.Right.Extent.Text
                $value | Should -Match '^(\$null|\$true|\$false|''[^'']*''|-?\d+)$' -Because "only constants may be assigned outside the try in $Name (line $($statement.Extent.StartLineNumber))"
                $exitCodes[$statement.Left.Extent.Text] = $value
                continue
            }

            $statement.Extent.Text | Should -Match '^Set-StrictMode\b' -Because "only Set-StrictMode may run outside the try in $Name (line $($statement.Extent.StartLineNumber))"
        }

        $exitCodes['$ExitIssueFound'] | Should -Be '1'
        $exitCodes['$ExitError'] | Should -Be '2'

        $tries.Count | Should -Be 1 -Because 'all of the work must run inside one try'
        [object]::ReferenceEquals($syntaxTree.EndBlock.Statements[-1], $tries[0]) | Should -BeTrue -Because 'nothing may run after the try'

        $catches = @($tries[0].CatchClauses)
        $catches.Count | Should -Be 1
        $catches[0].IsCatchAll | Should -BeTrue -Because 'the catch must take every error, not only some types'
        $catches[0].Body.Statements[-1].Extent.Text | Should -Be 'exit $ExitError'
    }
}

Describe 'Template pair' -Skip:(-not $script:OnWindows) {

    BeforeAll {
        $script:Detection = Join-Path -Path $PSScriptRoot -ChildPath 'Test-ExampleSetting.ps1'
        $script:Remediation = Join-Path -Path $PSScriptRoot -ChildPath 'Repair-ExampleSetting.ps1'
        $script:TestRoot = 'HKCU:\Software\EndpointEngineeringTests'
        $script:LogDirectory = Join-Path -Path $TestDrive -ChildPath 'Logs'
    }

    BeforeEach {
        $script:Key = Join-Path -Path $script:TestRoot -ChildPath ([guid]::NewGuid().ToString('n'))
        $script:Arguments = @('-RegistryPath', $script:Key, '-ValueName', 'ExampleSetting', '-LogDirectory', $script:LogDirectory)
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:TestRoot) { Remove-Item -LiteralPath $script:TestRoot -Recurse -Force }
    }

    Context 'Detection' {

        It 'exits 1 with one result line when the key does not exist' {
            $run = Invoke-RemediationScript -Path $script:Detection -ArgumentList ($script:Arguments + @('-ExpectedValue', '1'))

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -HaveCount 1
            $run.Output[0] | Should -BeLike 'Issue found: Key * does not exist.'
        }

        It 'exits 1 when the value differs from the expected one' {
            $null = New-Item -Path $script:Key -Force
            $null = New-ItemProperty -LiteralPath $script:Key -Name 'ExampleSetting' -Value 0 -PropertyType DWord

            $run = Invoke-RemediationScript -Path $script:Detection -ArgumentList ($script:Arguments + @('-ExpectedValue', '1'))

            $run.ExitCode | Should -Be 1 -Because $run.Error
            $run.Output | Should -Be @("Issue found: 'ExampleSetting' is '0'; expected '1'.")
        }

        It 'exits 0 when the value is the expected one, and logs to the log directory' {
            $null = New-Item -Path $script:Key -Force
            $null = New-ItemProperty -LiteralPath $script:Key -Name 'ExampleSetting' -Value 1 -PropertyType DWord

            $run = Invoke-RemediationScript -Path $script:Detection -ArgumentList ($script:Arguments + @('-ExpectedValue', '1'))

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Compliant: 'ExampleSetting' is 1 as expected.")
            Join-Path -Path $script:LogDirectory -ChildPath 'Test-ExampleSetting.log' | Should -FileContentMatch '\[INFO\] \[PID \d+\] Compliant\.'
        }

        It 'exits 2, never 1, when the check itself fails' {
            # A folder passes Test-Path but is not a registry key, so reading
            # its values throws inside the check.
            $folder = Join-Path -Path $TestDrive -ChildPath 'NotAKey'
            $null = New-Item -Path $folder -ItemType Directory -Force
            $arguments = @('-RegistryPath', $folder, '-LogDirectory', $script:LogDirectory)

            $run = Invoke-RemediationScript -Path $script:Detection -ArgumentList $arguments

            $run.ExitCode | Should -Be 2
            $run.Output | Should -BeNullOrEmpty
            $run.Error | Should -Match 'Detection failed:'
        }
    }

    Context 'Remediation' {

        It 'sets the value, verifies it and exits 0, after which detection exits 0' {
            $run = Invoke-RemediationScript -Path $script:Remediation -ArgumentList ($script:Arguments + @('-DesiredValue', '1'))

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Be @("Remediated: 'ExampleSetting' set to 1.")
            (Get-ItemProperty -LiteralPath $script:Key -Name 'ExampleSetting').ExampleSetting | Should -Be 1

            $check = Invoke-RemediationScript -Path $script:Detection -ArgumentList ($script:Arguments + @('-ExpectedValue', '1'))
            $check.ExitCode | Should -Be 0 -Because $check.Error
        }

        It 'changes nothing under -WhatIf' {
            $run = Invoke-RemediationScript -Path $script:Remediation -ArgumentList ($script:Arguments + @('-DesiredValue', '1', '-WhatIf'))

            $run.ExitCode | Should -Be 0 -Because $run.Error
            $run.Output | Should -Contain 'No change made (WhatIf or declined confirmation).'
            Test-Path -LiteralPath $script:Key | Should -BeFalse
        }

        It 'exits 1 when the change fails' {
            $folder = Join-Path -Path $TestDrive -ChildPath 'NotAKey'
            $null = New-Item -Path $folder -ItemType Directory -Force
            $arguments = @('-RegistryPath', $folder, '-LogDirectory', $script:LogDirectory)

            $run = Invoke-RemediationScript -Path $script:Remediation -ArgumentList $arguments

            $run.ExitCode | Should -Be 1
            $run.Error | Should -Match 'Remediation failed:'
        }
    }
}

Describe 'Copies of the remediation test harness' {

    BeforeAll {
        $script:MasterHarness = Get-SharedRegion -Path $PSCommandPath -Name 'Remediation test harness'
    }

    It 'this file holds exactly one harness region' {
        @($script:MasterHarness).Count | Should -BeGreaterThan 2
    }

    It '<Name> matches the canonical copy' -ForEach $script:HarnessCopies {
        $copy = Get-SharedRegion -Path $Path -Name 'Remediation test harness'

        if ($null -eq $copy) {
            throw "$Name has no single '#region Remediation test harness' ... '#endregion Remediation test harness' block. Copy the region from Templates/Remediation/ExampleSetting.Tests.ps1."
        }

        $length = [Math]::Max($copy.Count, $script:MasterHarness.Count)
        for ($i = 0; $i -lt $length; $i++) {
            $expected = if ($i -lt $script:MasterHarness.Count) { $script:MasterHarness[$i] } else { '<end of region>' }
            $actual = if ($i -lt $copy.Count) { $copy[$i] } else { '<end of region>' }

            if ($actual -cne $expected) {
                throw ("{0} differs from the canonical copy at line {1} of the region.`n  canonical: {2}`n  copy:      {3}`n" +
                    "Paste the region from Templates/Remediation/ExampleSetting.Tests.ps1 over this copy.") -f $Name, ($i + 1), $expected, $actual
            }
        }
    }
}
