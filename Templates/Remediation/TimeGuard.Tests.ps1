# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for TimeGuard: its rules, its registry state, and the check
    that every copy of the region still matches the canonical one.

.DESCRIPTION
    Three parts.

    Copies: every script that carries the TimeGuard region must hold a copy
    identical to the one in TimeGuard.ps1, version line included. A failure
    names the file and the first line that differs.

    Rules: Get-TimeGuardDecision and ConvertFrom-TimeGuardValue read no state,
    so every rule in Templates/Remediation/README.md is checked with fixed
    times. Runs anywhere.

    Registry: reading a key that does not exist runs on any Windows device.
    Writing needs HKLM, so those tests run only with administrator rights, as
    in CI, under a key of their own that they remove afterwards.

.EXAMPLE
    Invoke-Pester -Path .\Templates\Remediation\TimeGuard.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Context       : Any user. The registry write tests are skipped without
                    administrator rights.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $canonical = Join-Path -Path $PSScriptRoot -ChildPath 'TimeGuard.ps1'

    $script:Copies = @(
        Get-ChildItem -Path $repositoryRoot -Filter '*.ps1' -Recurse -File |
            Where-Object { $_.FullName -ne $canonical -and $_.Name -notlike '*.Tests.ps1' } |
            Where-Object { @(Get-Content -LiteralPath $_.FullName) -cmatch '^\s*#region TimeGuard\b' } |
            ForEach-Object {
                @{
                    Path = $_.FullName
                    Name = $_.FullName.Substring($repositoryRoot.Length + 1) -replace '\\', '/'
                }
            }
    )

    $script:OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $script:Elevated = $script:OnWindows -and
        (New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

BeforeAll {
    $script:TimeGuardPath = Join-Path -Path $PSScriptRoot -ChildPath 'TimeGuard.ps1'

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

    . ([scriptblock]::Create(((Get-SharedRegion -Path $script:TimeGuardPath -Name 'TimeGuard') -join [Environment]::NewLine)))

    function Get-Stamp {
        # A round-trip timestamp, as TimeGuard stores it.
        param ([datetime]$Time)

        $Time.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
    }

    $script:Now = [datetime]::new(2026, 9, 22, 12, 0, 0, [System.DateTimeKind]::Utc)
}

Describe 'Copies of the TimeGuard region' {

    BeforeAll {
        $script:MasterRegion = Get-SharedRegion -Path $script:TimeGuardPath -Name 'TimeGuard'
    }

    It 'TimeGuard.ps1 holds exactly one TimeGuard region' {
        @($script:MasterRegion).Count | Should -BeGreaterThan 2
    }

    It '<Name> matches TimeGuard.ps1' -ForEach $script:Copies {
        $copy = Get-SharedRegion -Path $Path -Name 'TimeGuard'

        if ($null -eq $copy) {
            throw "$Name has no single '#region TimeGuard' ... '#endregion TimeGuard' block. Copy the region from Templates/Remediation/TimeGuard.ps1."
        }

        $length = [Math]::Max($copy.Count, $script:MasterRegion.Count)
        for ($i = 0; $i -lt $length; $i++) {
            $expected = if ($i -lt $script:MasterRegion.Count) { $script:MasterRegion[$i] } else { '<end of region>' }
            $actual = if ($i -lt $copy.Count) { $copy[$i] } else { '<end of region>' }

            if ($actual -cne $expected) {
                throw ("{0} differs from TimeGuard.ps1 at line {1} of the region.`n  canonical: {2}`n  copy:      {3}`n" +
                    "Paste the region from Templates/Remediation/TimeGuard.ps1 over this copy.") -f $Name, ($i + 1), $expected, $actual
            }
        }
    }
}

Describe 'Get-TimeGuardDecision' {

    Context 'the work runs' {

        It 'when the guard is off, however recent the last run' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddHours(-1)) -IntervalDays 0

            $decision.Run | Should -BeTrue
            $decision.Reason | Should -Match 'off'
        }

        It 'when no run is recorded: <Case>' -ForEach @(
            @{ Case = 'null'; Value = $null }
            @{ Case = 'empty'; Value = '' }
            @{ Case = 'whitespace'; Value = '   ' }
        ) {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun $Value -IntervalDays 30

            $decision.Run | Should -BeTrue
            $decision.Reason | Should -Be 'No previous run is recorded.'
            $decision.LastRunUtc | Should -BeNullOrEmpty
        }

        It 'when the recorded time is not a round-trip timestamp: <Value>' -ForEach @(
            @{ Value = 'yesterday' }
            @{ Value = '2026-09-21 12:00' }
            @{ Value = '22/09/2026 12:00:00' }
        ) {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun $Value -IntervalDays 30

            $decision.Run | Should -BeTrue
            $decision.Reason | Should -Match 'not a valid timestamp'
        }

        It 'when the recorded time is more than five minutes in the future' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddMinutes(10)) -IntervalDays 30

            $decision.Run | Should -BeTrue
            $decision.Reason | Should -Match 'in the future'
        }

        It 'when a remediation started after the last run' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddDays(-1)) `
                -LastRemediation (Get-Stamp -Time $script:Now.AddHours(-1)) -IntervalDays 30

            $decision.Run | Should -BeTrue
            $decision.Reason | Should -Match 'Running to verify it\.$'
        }

        It 'when exactly the interval has passed' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddDays(-30)) -IntervalDays 30

            $decision.Run | Should -BeTrue
            $decision.Reason | Should -Match '^30 days or more have passed'
        }
    }

    Context 'the work is skipped' {

        It 'when the last run is younger than the interval, and says when it is due' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddDays(-1)) -IntervalDays 30

            $decision.Run | Should -BeFalse
            $decision.Reason | Should -Be 'Last run at 2026-09-21 12:00 UTC. Next run due after 2026-10-21 12:00 UTC.'
            $decision.LastRunUtc | Should -Be $script:Now.AddDays(-1)
        }

        It 'when the recorded time is less than five minutes in the future, which a clock correction explains' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddMinutes(3)) -IntervalDays 30

            $decision.Run | Should -BeFalse
        }

        It 'when the last remediation is older than the last run' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddDays(-1)) `
                -LastRemediation (Get-Stamp -Time $script:Now.AddDays(-2)) -IntervalDays 30

            $decision.Run | Should -BeFalse
        }

        It 'when the remediation timestamp cannot be parsed, which is ignored' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun (Get-Stamp -Time $script:Now.AddDays(-1)) `
                -LastRemediation 'not a time' -IntervalDays 30

            $decision.Run | Should -BeFalse
        }
    }

    Context 'times and time zones' {

        It 'decides the same whether Now is given in UTC or local time' {
            $lastRun = Get-Stamp -Time $script:Now.AddDays(-29).AddHours(-23)
            $utc = Get-TimeGuardDecision -Now $script:Now -LastRun $lastRun -IntervalDays 30
            $local = Get-TimeGuardDecision -Now $script:Now.ToLocalTime() -LastRun $lastRun -IntervalDays 30

            $local.Run | Should -Be $utc.Run
            $local.Reason | Should -Be $utc.Reason
        }

        It 'reads a timestamp written with an offset as the UTC time it stands for' {
            $decision = Get-TimeGuardDecision -Now $script:Now -LastRun '2026-09-21T14:00:00.0000000+02:00' -IntervalDays 30

            $decision.LastRunUtc | Should -Be ([datetime]::new(2026, 9, 21, 12, 0, 0, [System.DateTimeKind]::Utc))
            $decision.LastRunUtc.Kind | Should -Be 'Utc'
        }

        It 'refuses an interval over ten years' {
            { Get-TimeGuardDecision -Now $script:Now -LastRun $null -IntervalDays 3651 } | Should -Throw
        }
    }
}

Describe 'ConvertFrom-TimeGuardValue' {

    It 'returns the UTC time a round-trip timestamp stands for' {
        ConvertFrom-TimeGuardValue -Value '2026-09-22T12:00:00.0000000Z' | Should -Be $script:Now
    }

    It 'returns nothing for <Case>' -ForEach @(
        @{ Case = 'null'; Value = $null }
        @{ Case = 'an empty string'; Value = '' }
        @{ Case = 'text'; Value = 'soon' }
        @{ Case = 'a date without a time'; Value = '2026-09-22' }
    ) {
        ConvertFrom-TimeGuardValue -Value $Value | Should -BeNullOrEmpty
    }
}

Describe 'TimeGuard registry state' -Skip:(-not $script:OnWindows) {

    BeforeAll {
        # A root of the tests' own, so nothing a device relies on is touched.
        $script:TestRoot = 'SOFTWARE\EndpointEngineeringTests\TimeGuard-' + [guid]::NewGuid().ToString('n')
    }

    AfterAll {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        try {
            if ($null -ne $baseKey.OpenSubKey($script:TestRoot)) { $baseKey.DeleteSubKeyTree($script:TestRoot) }
        }
        finally {
            $baseKey.Dispose()
        }
    }

    It 'reads nothing, without an error, when the key does not exist' {
        Get-TimeGuardValue -Name 'Missing' -ValueName 'LastDetection' -Root $script:TestRoot | Should -BeNullOrEmpty
    }

    It 'writes a value that reads back unchanged' -Skip:(-not $script:Elevated) {
        $stamp = Get-Stamp -Time $script:Now

        Set-TimeGuardValue -Name 'RoundTrip' -ValueName 'LastDetection' -Value $stamp -Root $script:TestRoot

        Get-TimeGuardValue -Name 'RoundTrip' -ValueName 'LastDetection' -Root $script:TestRoot | Should -Be $stamp
    }

    It 'removes the value when given an empty one, which is how a run is taken back' -Skip:(-not $script:Elevated) {
        Set-TimeGuardValue -Name 'TakeBack' -ValueName 'LastDetection' -Value (Get-Stamp -Time $script:Now) -Root $script:TestRoot

        Set-TimeGuardValue -Name 'TakeBack' -ValueName 'LastDetection' -Value '' -Root $script:TestRoot

        Get-TimeGuardValue -Name 'TakeBack' -ValueName 'LastDetection' -Root $script:TestRoot | Should -BeNullOrEmpty
    }

    It 'writes nothing under -WhatIf' -Skip:(-not $script:Elevated) {
        Set-TimeGuardValue -Name 'WhatIf' -ValueName 'LastRemediation' -Value (Get-Stamp -Time $script:Now) -Root $script:TestRoot -WhatIf

        Get-TimeGuardValue -Name 'WhatIf' -ValueName 'LastRemediation' -Root $script:TestRoot | Should -BeNullOrEmpty
    }
}
