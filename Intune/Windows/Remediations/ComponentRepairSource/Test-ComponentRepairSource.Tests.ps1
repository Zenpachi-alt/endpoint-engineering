# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Test-ComponentRepairSource.ps1: the verdict for every
    combination of repair source and update service, and the exit code and
    output line the script reports for each.

.DESCRIPTION
    Get-RepairSourceVerdict reads no state, so its rules are checked directly.
    Runs anywhere.

    The script itself runs as the Intune management extension runs it, in
    Windows PowerShell 5.1 with -File, with the registry reads and the Windows
    Update Agent query replaced by stand-ins that describe a device. Windows
    only.

.EXAMPLE
    Invoke-Pester -Path .\Intune\Windows\Remediations\ComponentRepairSource -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7. The script under test always runs in Windows
                    PowerShell 5.1, whichever host runs Pester.
    Context       : Any user.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    $script:OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-ComponentRepairSource.ps1'

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

    $script:LogArguments = @('-LogDirectory', (Join-Path -Path $TestDrive -ChildPath 'Logs'))

    $script:BuildValue = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild'
    $script:SourceValue = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
    $script:RepairValue = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
    $script:WuServerValue = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer'
    $script:UseWuServerValue = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer'

    function Get-FakeDevice {
        # A device on build 22631 that takes updates from Windows Update, with
        # no repair policy, changed by the arguments.
        param (
            [hashtable]$Registry = @{},
            [object]$UpdateService = [pscustomobject]@{ Name = 'Microsoft Update'; IsManaged = $false },
            [switch]$RegistryUnreadable
        )

        $values = @{ $script:BuildValue = '22631' }
        foreach ($key in $Registry.Keys) { $values[$key] = $Registry[$key] }

        @{
            Results            = @{ 'Get-DefaultUpdateService' = $UpdateService }
            Registry           = $values
            RegistryUnreadable = $RegistryUnreadable.IsPresent
        }
    }

    $script:Wsus = [pscustomobject]@{ Name = 'Windows Server Update Service'; IsManaged = $true }
}

Describe 'Get-RepairSourceVerdict' {

    BeforeAll {
        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "Test-ComponentRepairSource.ps1 does not parse: $($parseErrors[0].Message)" }
        $verdict = $syntaxTree.EndBlock.Statements |
            Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Get-RepairSourceVerdict' }
        . ([scriptblock]::Create($verdict.Extent.Text))
    }

    It '<Token> (exit <ExitCode>) for <Case>' -ForEach @(
        @{ Case = 'a source path with WSUS'; Build = 22631; UsesWsus = $true; Source = 'C:\RepairSource\Sxs'; Repair = $null; Token = 'LocalSource'; ExitCode = 0 }
        @{ Case = 'a source path on 24H2'; Build = 26100; UsesWsus = $true; Source = 'C:\RepairSource\Sxs'; Repair = $null; Token = 'LocalSource'; ExitCode = 0 }
        @{ Case = 'Windows Update'; Build = 22631; UsesWsus = $false; Source = $null; Repair = $null; Token = 'WindowsUpdate'; ExitCode = 0 }
        @{ Case = 'WSUS with the repair option before 24H2'; Build = 22631; UsesWsus = $true; Source = $null; Repair = 2; Token = 'WsusRepairFromWindowsUpdate'; ExitCode = 0 }
        @{ Case = 'WSUS with the repair option on 24H2, where it no longer exists'; Build = 26100; UsesWsus = $true; Source = $null; Repair = 2; Token = 'WsusOnly'; ExitCode = 1 }
        @{ Case = 'WSUS with another repair value'; Build = 22631; UsesWsus = $true; Source = $null; Repair = 1; Token = 'WsusOnly'; ExitCode = 1 }
        @{ Case = 'WSUS alone'; Build = 22631; UsesWsus = $true; Source = $null; Repair = $null; Token = 'WsusOnly'; ExitCode = 1 }
        @{ Case = 'WSUS with a blank source path'; Build = 22631; UsesWsus = $true; Source = '   '; Repair = $null; Token = 'WsusOnly'; ExitCode = 1 }
    ) {
        $result = Get-RepairSourceVerdict -Build $Build -UsesWsus $UsesWsus -LocalSourcePath $Source -RepairContentServerSource $Repair

        $result.Token | Should -Be $Token
        $result.ExitCode | Should -Be $ExitCode
    }

    It 'says why a leftover repair value on 24H2 is not counted' {
        $result = Get-RepairSourceVerdict -Build 26100 -UsesWsus $true -LocalSourcePath $null -RepairContentServerSource 2

        $result.Detail | Should -Match 'not counted'
    }
}

Describe 'Test-ComponentRepairSource.ps1' -Skip:(-not $script:OnWindows) {

    BeforeAll {
        $stubs = [ordered]@{
            'Get-DefaultUpdateService' = $null
            'Get-MachineRegistryValue' = {
                if ($Fake.RegistryUnreadable) { throw 'Requested registry access is not allowed.' }
                $Fake.Registry["$SubKey\$ValueName"]
            }
        }
        $script:Stubbed = ConvertTo-StubbedScript -Path $script:ScriptPath -Stub $stubs `
            -Destination (Join-Path -Path $TestDrive -ChildPath 'Test-ComponentRepairSource.ps1')
    }

    It 'exits 0 and reports WindowsUpdate for a device that does not use WSUS' {
        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake (Get-FakeDevice)

        $run.ExitCode | Should -Be 0 -Because $run.Error
        $run.Output | Should -HaveCount 1
        $run.Output[0] | Should -BeLike "WindowsUpdate: *. Update service: Microsoft Update. Build 22631."
    }

    It 'exits 0 and reports LocalSource when a source path is set, even with WSUS' {
        $device = Get-FakeDevice -Registry @{ $script:SourceValue = 'C:\RepairSource\Sxs' } -UpdateService $script:Wsus

        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

        $run.ExitCode | Should -Be 0 -Because $run.Error
        $run.Output[0] | Should -BeLike 'LocalSource: *'
    }

    It 'exits 0 and reports WsusRepairFromWindowsUpdate for the pre-24H2 repair option' {
        $device = Get-FakeDevice -Registry @{ $script:RepairValue = 2 } -UpdateService $script:Wsus

        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

        $run.ExitCode | Should -Be 0 -Because $run.Error
        $run.Output[0] | Should -BeLike 'WsusRepairFromWindowsUpdate: *'
    }

    It 'exits 1 and reports WsusOnly for a WSUS device with no repair source' {
        $device = Get-FakeDevice -UpdateService $script:Wsus

        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

        $run.ExitCode | Should -Be 1 -Because $run.Error
        $run.Output | Should -HaveCount 1
        $run.Output[0] | Should -BeLike 'WsusOnly: *. Update service: Windows Server Update Service. Build 22631.'
    }

    It 'falls back to the Group Policy values when the Windows Update Agent cannot be queried' {
        $device = Get-FakeDevice -Registry @{ $script:WuServerValue = 'wsus.contoso.com'; $script:UseWuServerValue = 1 } `
            -UpdateService @{ Throw = 'The service cannot be started.' }

        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

        $run.ExitCode | Should -Be 1 -Because $run.Error
        $run.Output[0] | Should -BeLike 'WsusOnly: *. Update service: not queried. Build 22631.'
    }

    It 'exits 2, never 1, when the build number cannot be read' {
        $device = Get-FakeDevice -Registry @{ $script:BuildValue = $null } -UpdateService $script:Wsus

        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

        $run.ExitCode | Should -Be 2
        $run.Output | Should -BeNullOrEmpty
        $run.Error | Should -Match 'Detection failed: Could not read the Windows build number'
    }

    It 'exits 2, never 1, when the registry cannot be read' {
        $device = Get-FakeDevice -UpdateService $script:Wsus -RegistryUnreadable

        $run = Invoke-RemediationScript -Path $script:Stubbed -ArgumentList $script:LogArguments -Fake $device

        $run.ExitCode | Should -Be 2
        $run.Error | Should -Match 'Detection failed: Requested registry access is not allowed\.'
    }
}
