# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Invoke-TextScrub.ps1.

.DESCRIPTION
    Runs the script in-process against files in Pester's TestDrive, so nothing
    is written outside a temporary folder. Every identifier-shaped value is
    generated at run time - random GUIDs, a JWT assembled from parts - so this
    file passes Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Standalone -Output Detailed

.NOTES
    PowerShell    : 7.0 or later, matching the script under test.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Install-Module Pester -Scope CurrentUser -SkipPublisherCheck
#>

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-TextScrub.ps1'

    function Invoke-UnderTest {
        # Runs the script and separates what it returns from what it warns and reports.
        param ([hashtable]$Parameters, [string[]]$InputText)
        $all = if ($InputText) {
            $InputText | & $script:ScriptPath @Parameters 3>&1 2>&1
        }
        else {
            & $script:ScriptPath @Parameters 3>&1 2>&1
        }
        $exitCode = $LASTEXITCODE
        [pscustomobject]@{
            Output   = @($all | Where-Object {
                    $_ -isnot [System.Management.Automation.WarningRecord] -and
                    $_ -isnot [System.Management.Automation.ErrorRecord]
                })
            Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)
            Errors   = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
            ExitCode = $exitCode
        }
    }

    function Write-TestFile {
        param ([string]$Content)
        $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $folder
        $file = Join-Path -Path $folder -ChildPath 'input.txt'
        [IO.File]::WriteAllText($file, $Content)
        $file
    }

    function Get-DataDirectoryPath {
        Join-Path -Path $TestDrive -ChildPath ('data-' + [guid]::NewGuid().ToString('n'))
    }

    function Read-Map {
        param ([string]$DataDirectory)
        @(Get-Content -LiteralPath (Join-Path -Path $DataDirectory -ChildPath 'map.json') -Raw | ConvertFrom-Json)
    }
}

Describe 'Invoke-TextScrub' {

    Context 'Round trip' {

        It 'restores the exact original text' {
            $original = "Device $([guid]::NewGuid()) enrolled by alice@fabrikam.com`nObject $([guid]::NewGuid()) owner bob@fabrikam.com"
            $file = Write-TestFile -Content $original
            $data = Get-DataDirectoryPath

            (Invoke-UnderTest @{ Path = $file; DataDirectory = $data; SkipLocalIdentity = $true }).ExitCode | Should -Be 0
            $scrubbed = $file -replace 'input\.txt$', 'input.scrubbed.txt'
            (Invoke-UnderTest @{ Path = $scrubbed; DataDirectory = $data; Restore = $true }).ExitCode | Should -Be 0

            $restored = $scrubbed -replace 'scrubbed\.txt$', 'scrubbed.restored.txt'
            [IO.File]::ReadAllText($restored) | Should -BeExactly $original
        }

        It 'reuses placeholders on a second run without growing the map' {
            $data = Get-DataDirectoryPath
            $text = "Device $([guid]::NewGuid()) and alice@fabrikam.com"

            $first = (Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true } -InputText $text).Output
            $countAfterFirst = (Read-Map $data).Count
            $second = (Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true } -InputText $text).Output

            $second | Should -BeExactly $first
            (Read-Map $data).Count | Should -Be $countAfterFirst
        }

        It 'gives a value first seen on a later run its own placeholder' {
            # The Windows PowerShell 5.1 map-loading bug made a later run reissue 001 for a new value.
            $data = Get-DataDirectoryPath
            $first = (Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true } -InputText "id $([guid]::NewGuid())").Output
            $second = (Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true } -InputText "id $([guid]::NewGuid())").Output

            $first | Should -BeExactly 'id 00000000-0000-0000-0000-000000000001'
            $second | Should -BeExactly 'id 00000000-0000-0000-0000-000000000002'
        }

        It 'leaves already scrubbed text unchanged' {
            $data = Get-DataDirectoryPath
            $parameters = @{ DataDirectory = $data; SkipLocalIdentity = $true; Domain = 'fabrikam.com' }
            $once = (Invoke-UnderTest $parameters -InputText "srv01.corp.fabrikam.com $([guid]::NewGuid()) carol@fabrikam.com").Output
            $twice = (Invoke-UnderTest $parameters -InputText $once).Output

            $twice | Should -BeExactly $once
        }
    }

    Context 'Placeholders' {

        It 'does not let a later step rewrite an earlier placeholder' {
            $data = Get-DataDirectoryPath
            $result = Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true; LiteralTerm = 'user' } `
                -InputText 'C:\Users\jdoe\Desktop and the user'

            $result.Output | Should -BeExactly 'C:\Users\USER-001\Desktop and the TERM-001'
        }

        It 'numbers GUID placeholders in decimal, which the repository scanner accepts' {
            $text = (1..12 | ForEach-Object { [guid]::NewGuid() }) -join ' '
            $output = (Invoke-UnderTest @{ DataDirectory = (Get-DataDirectoryPath); SkipLocalIdentity = $true } -InputText $text).Output

            ($output -split ' ')[-1] | Should -BeExactly '00000000-0000-0000-0000-000000000012'
        }

        It 'keeps well-known Microsoft application IDs readable' {
            $graph = '00000003-0000-0000-c000-000000000000'
            $output = (Invoke-UnderTest @{ DataDirectory = (Get-DataDirectoryPath); SkipLocalIdentity = $true } -InputText "app $graph").Output

            $output | Should -BeExactly "app $graph"
        }
    }

    Context 'Secrets' {

        It 'redacts secrets one way and never writes them to the map' {
            $jwt = 'eyJ' + ('a' * 12) + '.' + ('b' * 12) + '.' + ('c' * 12)
            $secret = 'Hunter2' + 'Hunter2'
            $data = Get-DataDirectoryPath
            $text = "Authorization: Bearer $jwt`n" + 'pass' + "word=$secret`nowner alice@fabrikam.com"

            $output = (Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true } -InputText $text).Output -join "`n"

            $output | Should -Match '\[REDACTED-JWT\]'
            $output | Should -Match 'word=\[REDACTED\]'
            $output | Should -Not -Match ([regex]::Escape($secret))
            $mapText = Get-Content -LiteralPath (Join-Path $data 'map.json') -Raw
            $mapText | Should -Not -Match ([regex]::Escape($secret))
            $mapText | Should -Not -Match 'eyJ'
        }
    }

    Context 'Residual detection' {

        It 'exits 2 and reports the line and placeholder, never the value' {
            $result = Invoke-UnderTest @{ DataDirectory = (Get-DataDirectoryPath); SkipLocalIdentity = $true; LiteralTerm = 'Acme' } `
                -InputText "first line`nAcme and Acmecorp"

            $result.ExitCode | Should -Be 2
            $result.Warnings -join "`n" | Should -Match 'line 2: the value mapped to TERM-001'
            $result.Warnings -join "`n" | Should -Not -Match 'Acme'
        }

        It 'does not report a value that only appears inside a placeholder' {
            $result = Invoke-UnderTest @{ DataDirectory = (Get-DataDirectoryPath); SkipLocalIdentity = $true; LiteralTerm = 'user' } `
                -InputText 'the user is alice@fabrikam.com'

            $result.Output | Should -BeExactly 'the TERM-001 is user001@example.com'
            $result.ExitCode | Should -Be 0
            $result.Warnings -join "`n" | Should -Not -Match 'still in the output'
        }
    }

    Context 'Writing nothing when asked' {

        It '-ReportOnly returns report objects and creates no files' {
            $file = Write-TestFile -Content "owner alice@fabrikam.com"
            $data = Get-DataDirectoryPath
            $result = Invoke-UnderTest @{ Path = $file; DataDirectory = $data; SkipLocalIdentity = $true; ReportOnly = $true }

            $result.Output.Category | Should -Contain 'EMAIL'
            $result.Output.Placeholder | Should -Contain 'user001@example.com'
            Test-Path -LiteralPath $data | Should -BeFalse
            Test-Path -LiteralPath ($file -replace 'input\.txt$', 'input.scrubbed.txt') | Should -BeFalse
        }

        It '-WhatIf creates no files' {
            $file = Write-TestFile -Content "owner alice@fabrikam.com"
            $data = Get-DataDirectoryPath
            $null = Invoke-UnderTest @{ Path = $file; DataDirectory = $data; SkipLocalIdentity = $true; WhatIf = $true }

            Test-Path -LiteralPath $data | Should -BeFalse
            Test-Path -LiteralPath ($file -replace 'input\.txt$', 'input.scrubbed.txt') | Should -BeFalse
        }
    }

    Context 'Restore' {

        It 'warns when the text holds no known placeholder' {
            $data = Get-DataDirectoryPath
            $null = Invoke-UnderTest @{ DataDirectory = $data; SkipLocalIdentity = $true } -InputText 'owner alice@fabrikam.com'
            $result = Invoke-UnderTest @{ DataDirectory = $data; Restore = $true } -InputText 'nothing scrubbed here'

            $result.Output | Should -BeExactly 'nothing scrubbed here'
            $result.Warnings -join "`n" | Should -Match 'nothing was restored'
        }

        It 'fails with exit 1 when there is no map' {
            $result = Invoke-UnderTest @{ DataDirectory = (Get-DataDirectoryPath); Restore = $true } -InputText 'user001@example.com'

            $result.ExitCode | Should -Be 1
            $result.Errors -join "`n" | Should -Match 'nothing to restore from'
        }
    }

    Context 'Input validation' {

        It 'rejects -ReportOnly together with -Restore' {
            $result = Invoke-UnderTest @{ DataDirectory = (Get-DataDirectoryPath); Restore = $true; ReportOnly = $true } -InputText 'x'

            $result.ExitCode | Should -Be 1
            $result.Errors -join "`n" | Should -Match 'cannot be combined'
        }

        It 'rejects an invalid host name pattern before doing any work' {
            { & $script:ScriptPath -HostnamePattern '([' -InputObject 'x' } | Should -Throw '*Not a valid regular expression*'
        }
    }

    Context 'Config' {

        It 'writes a template once and refuses to overwrite it' {
            $data = Get-DataDirectoryPath

            (Invoke-UnderTest @{ DataDirectory = $data; NewConfig = $true }).ExitCode | Should -Be 0
            Test-Path -LiteralPath (Join-Path $data 'config.json') | Should -BeTrue

            $again = Invoke-UnderTest @{ DataDirectory = $data; NewConfig = $true }
            $again.ExitCode | Should -Be 1
            $again.Errors -join "`n" | Should -Match 'already exists'
        }
    }
}
