# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-UninstallEntry.ps1.

.DESCRIPTION
    The script's functions are loaded from its syntax tree and tested on their
    own: the registry reader against a test key under HKEY_CURRENT_USER\Software,
    never the real Uninstall keys, and the Intune settings, the comparison and
    the snapshot reader against entries built here. The test key is removed
    afterwards.

    The script itself is also run end to end. Those runs only read the real
    Uninstall keys, and write snapshots to TestDrive. One runs a copy of the
    script in which stand-ins point it at the test key instead, and make one
    uninstaller throw what reading an app execution alias throws.

    Product codes and other identifier-shaped values are generated at run
    time, so this file passes Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Standalone\Packaging\Get-UninstallEntry.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or later, matching the script under test.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

Describe 'Get-UninstallEntry' -Skip:([Environment]::OSVersion.Platform -ne 'Win32NT') {

    BeforeAll {
        $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-UninstallEntry.ps1'

        # Every top-level function of the script, without its main block.
        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "Get-UninstallEntry.ps1 does not parse: $($parseErrors[0].Message)" }
        foreach ($statement in $syntaxTree.EndBlock.Statements) {
            if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                . ([scriptblock]::Create($statement.Extent.Text))
            }
        }

        $script:TestParent = 'Software\EndpointEngineeringTests'
        $script:TestRoot = '{0}\{1}' -f $script:TestParent, [guid]::NewGuid().ToString('n')
        $script:MachinePath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

        function Get-TestGuid {
            [guid]::NewGuid().ToString('B').ToUpperInvariant()
        }

        function Write-TestEntry {
            # An Uninstall entry under the test key: ints become DWORDs, arrays REG_MULTI_SZ.
            param ([string]$KeyName, [hashtable]$Value = @{}, [string]$Folder = 'Uninstall')
            $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(('{0}\{1}\{2}' -f $script:TestRoot, $Folder, $KeyName))
            try {
                foreach ($valueName in $Value.Keys) {
                    $data = $Value[$valueName]
                    if ($data -is [int]) { $key.SetValue($valueName, $data, [Microsoft.Win32.RegistryValueKind]::DWord) }
                    elseif ($data -is [array]) { $key.SetValue($valueName, [string[]]$data, [Microsoft.Win32.RegistryValueKind]::MultiString) }
                    else { $key.SetValue($valueName, [string]$data, [Microsoft.Win32.RegistryValueKind]::String) }
                }
            }
            finally {
                $key.Dispose()
            }
        }

        function Read-TestKey {
            param ([string]$RegistryView = '64-bit', [string]$Scope = 'Machine')
            Read-UninstallKey -Hive CurrentUser -View Default -SubKey ('{0}\Uninstall' -f $script:TestRoot) -Scope $Scope `
                -RegistryView $RegistryView -RegistryPath $script:MachinePath
        }

        function Get-TestEntry {
            # An entry as Read-UninstallKey returns it, with any value replaced.
            param ([hashtable]$Value = @{})
            $entry = [ordered]@{
                Scope = 'Machine'; RegistryView = '64-bit'; KeyName = 'TestApp'; RegistryPath = "$script:MachinePath\TestApp"
                DisplayName = 'Test App'; DisplayVersion = '3.4.5'; Publisher = 'Contoso'; InstallDate = '20261005'
                InstallLocation = 'C:\Program Files\Test App'; UninstallString = ''; QuietUninstallString = ''
                WindowsInstaller = $false; SystemComponent = $false; BundleUpgradeCode = ''
            }
            foreach ($name in $Value.Keys) { $entry[$name] = $Value[$name] }
            [pscustomobject]$entry
        }

        function ConvertTo-StandInCopy {
            # A copy of the script in which each function named in -Function is replaced by the
            # definition given for it. The main block and every other function run as written.
            param ([hashtable]$Function)
            $tree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $text = $tree.Extent.Text
            $replaced = @($tree.EndBlock.Statements | Where-Object {
                    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Function.ContainsKey($_.Name)
                })
            if ($replaced.Count -ne $Function.Count) { throw 'Every stand-in must replace a function the script defines.' }
            # From the end backwards, so every offset still points where it did.
            foreach ($original in @($replaced | Sort-Object -Property { $_.Extent.StartOffset } -Descending)) {
                $text = $text.Substring(0, $original.Extent.StartOffset) + $Function[$original.Name] + $text.Substring($original.Extent.EndOffset)
            }
            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder
            $copy = Join-Path -Path $folder -ChildPath 'Get-UninstallEntry.ps1'
            [IO.File]::WriteAllText($copy, $text, [System.Text.UTF8Encoding]::new($false))
            $copy
        }

        function Invoke-UnderTest {
            param ([hashtable]$Parameters, [string]$Path = $script:ScriptPath)
            $all = & $Path @Parameters 3>&1 2>&1
            $exitCode = $LASTEXITCODE
            [pscustomobject]@{
                Output   = @($all | Where-Object {
                        $_ -isnot [System.Management.Automation.WarningRecord] -and
                        $_ -isnot [System.Management.Automation.ErrorRecord]
                    })
                Warnings = (@($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message) -join "`n")
                Errors   = (@($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" }) -join "`n")
                ExitCode = $exitCode
            }
        }
    }

    AfterAll {
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($script:TestRoot, $false)
        $parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:TestParent)
        if ($null -ne $parent) {
            $empty = $parent.SubKeyCount -eq 0 -and $parent.ValueCount -eq 0
            $parent.Dispose()
            if ($empty) { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey($script:TestParent, $false) }
        }
    }

    Context 'Reading the registry' {

        It 'reads each value with its type, and the full path of the key' {
            $bundle = Get-TestGuid
            Write-TestEntry -KeyName 'Reader App' -Value @{
                DisplayName = 'Reader App'; DisplayVersion = '3.4.5'; Publisher = 'Contoso'; WindowsInstaller = 1
                SystemComponent = 1; BundleUpgradeCode = @($bundle, (Get-TestGuid)); UninstallString = 'C:\Apps\uninstall.exe'
            }

            $entry = Read-TestKey | Where-Object KeyName -EQ 'Reader App'

            $entry.DisplayName | Should -Be 'Reader App'
            $entry.DisplayVersion | Should -Be '3.4.5'
            $entry.WindowsInstaller | Should -BeTrue
            $entry.SystemComponent | Should -BeTrue
            $entry.BundleUpgradeCode | Should -Be $bundle
            $entry.RegistryPath | Should -Be "$script:MachinePath\Reader App"
            $entry.Scope | Should -Be 'Machine'
            $entry.RegistryView | Should -Be '64-bit'
        }

        It 'skips an entry without a DisplayName, as Windows does' {
            Write-TestEntry -KeyName 'No Name' -Value @{ DisplayVersion = '3.4.5' }
            Write-TestEntry -KeyName 'Blank Name' -Value @{ DisplayName = '   ' }

            @(Read-TestKey | Where-Object { $_.KeyName -in 'No Name', 'Blank Name' }).Count | Should -Be 0
        }

        It 'returns nothing when the Uninstall key does not exist' {
            @(Read-UninstallKey -Hive CurrentUser -View Default -SubKey ('{0}\Missing' -f $script:TestRoot) -Scope User `
                    -RegistryView User -RegistryPath 'HKEY_CURRENT_USER\Missing').Count | Should -Be 0
        }

        It 'reads both machine views and the user hive on 64-bit Windows, one machine view on 32-bit' {
            @(Get-UninstallSource -Is64BitWindows $true).RegistryView | Should -Be @('64-bit', '32-bit', 'User')
            @(Get-UninstallSource -Is64BitWindows $false).RegistryView | Should -Be @('32-bit', 'User')
        }
    }

    Context 'Installer and Intune settings' {

        It 'gives an MSI an MSI detection rule and msiexec /x' {
            $code = Get-TestGuid
            $entry = Get-TestEntry @{ KeyName = $code.ToLowerInvariant(); WindowsInstaller = $true; UninstallString = "MsiExec.exe /X$code" }

            $report = ConvertTo-UninstallReport -Entry $entry

            $report.Installer | Should -Be 'MSI'
            $report.ProductCode | Should -Be $code
            $report.IntuneUninstallCommand | Should -BeExactly ('msiexec /x "{0}" /qn /norestart' -f $code)
            $report.IntuneDetection | Should -Be ('MSI product code {0}, product version greater than or equal to 3.4.5' -f $code)
            $report.IntuneInstallBehavior | Should -Be 'System'
        }

        It 'gives Inno Setup /VERYSILENT and keeps the arguments it already has' {
            $entry = Get-TestEntry @{
                KeyName = 'Test App_is1'; UninstallString = '"C:\Program Files\Test App\unins000.exe" /LOG'
                QuietUninstallString = '"C:\Program Files\Test App\unins000.exe" /SILENT'
            }

            $report = ConvertTo-UninstallReport -Entry $entry

            $report.Installer | Should -Be 'Inno Setup'
            $report.IntuneUninstallCommand | Should -BeExactly '"C:\Program Files\Test App\unins000.exe" /LOG /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
        }

        It 'recognises NSIS from its uninstaller, and quotes a path Windows left unquoted' {
            $folder = Join-Path -Path $TestDrive -ChildPath 'Program Files (x86)\Test App'
            $null = New-Item -ItemType Directory -Path $folder -Force
            $uninstaller = Join-Path -Path $folder -ChildPath 'uninstall.exe'
            [IO.File]::WriteAllBytes($uninstaller, [Text.Encoding]::ASCII.GetBytes('MZ <assemblyIdentity name="Nullsoft.NSIS.exehead"/>'))

            $report = ConvertTo-UninstallReport -Entry (Get-TestEntry @{ UninstallString = $uninstaller })

            $report.Installer | Should -Be 'NSIS'
            $report.IntuneUninstallCommand | Should -BeExactly ('"{0}" /S' -f $uninstaller)
            ($report.Notes -join ' ') | Should -Match '_\?='
        }

        It 'uses a WiX Burn bundle''s own quiet uninstall, and says its key changes with each release' {
            $command = '"C:\ProgramData\Package Cache\Test\setup.exe" /uninstall /quiet'
            $entry = Get-TestEntry @{ BundleUpgradeCode = (Get-TestGuid); QuietUninstallString = $command; UninstallString = '"C:\ProgramData\Package Cache\Test\setup.exe" /uninstall' }

            $report = ConvertTo-UninstallReport -Entry $entry

            $report.Installer | Should -Be 'WiX Burn'
            $report.IntuneUninstallCommand | Should -BeExactly $command
            ($report.Notes -join ' ') | Should -Match 'bundle ID'
        }

        It 'flags a Squirrel app as per-user, with a path no other user shares' {
            $entry = Get-TestEntry @{
                Scope = 'User'; RegistryView = 'User'; UninstallString = '"C:\Users\Example\AppData\Local\TestApp\Update.exe" --uninstall'
                QuietUninstallString = '"C:\Users\Example\AppData\Local\TestApp\Update.exe" --uninstall -s'
            }

            $report = ConvertTo-UninstallReport -Entry $entry
            $notes = $report.Notes -join ' '

            $report.Installer | Should -Be 'Squirrel'
            $report.IntuneInstallBehavior | Should -Be 'User'
            $report.IntuneDetection | Should -Match '^Registry: HKEY_CURRENT_USER\\Software\\'
            $notes | Should -Match 'per user only'
            $notes | Should -Match '%LOCALAPPDATA%'
        }

        It 'gives a 32-bit entry the native key path, with the 32-bit switch set' {
            $entry = Get-TestEntry @{
                RegistryView = '32-bit'; RegistryPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\TestApp'
            }

            $report = ConvertTo-UninstallReport -Entry $entry

            $report.IntuneDetection | Should -BeExactly ('Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TestApp, ' +
                'value DisplayVersion, version comparison, greater than or equal to 3.4.5, associated with a 32-bit app on 64-bit clients: Yes')
            $report.RegistryPath | Should -Match 'WOW6432Node'
        }

        It 'compares a version it cannot parse as a string, and an absent one by the key alone' {
            (ConvertTo-UninstallReport -Entry (Get-TestEntry @{ DisplayVersion = '2026 R1' })).IntuneDetection |
                Should -Match 'string comparison, equals 2026 R1'
            (ConvertTo-UninstallReport -Entry (Get-TestEntry @{ DisplayVersion = '' })).IntuneDetection |
                Should -Match 'TestApp, key exists'
        }

        It 'says so when no silent uninstall is known' {
            $report = ConvertTo-UninstallReport -Entry (Get-TestEntry @{ UninstallString = '"C:\Program Files\Test App\remove.exe"' })

            $report.Installer | Should -Be 'Unknown'
            $report.IntuneUninstallCommand | Should -BeNullOrEmpty
            ($report.Notes -join ' ') | Should -Match 'No silent uninstall is known'
        }

        It 'points a hidden entry at its visible parent' {
            $report = ConvertTo-UninstallReport -Entry (Get-TestEntry @{ SystemComponent = $true })

            $report.Hidden | Should -BeTrue
            ($report.Notes -join ' ') | Should -Match 'visible parent entry'
        }

        It 'suggests nothing for an entry the install removed' {
            $report = ConvertTo-UninstallReport -Entry (Get-TestEntry @{ KeyName = 'Old_is1' }) -Change Removed

            $report.Change | Should -Be 'Removed'
            $report.IntuneDetection | Should -BeNullOrEmpty
            $report.IntuneUninstallCommand | Should -BeNullOrEmpty
            $report.IntuneInstallBehavior | Should -BeNullOrEmpty
        }
    }

    Context 'Comparing two points in time' {

        It 'returns what was added, changed and removed, and nothing that stayed the same' {
            $same = Get-TestEntry @{ KeyName = 'Same' }
            $upgraded = Get-TestEntry @{ KeyName = 'Upgraded'; DisplayVersion = '1.2.3' }
            $gone = Get-TestEntry @{ KeyName = 'Gone' }
            $new = Get-TestEntry @{ KeyName = 'New' }
            $after = Get-TestEntry @{ KeyName = 'Upgraded'; DisplayVersion = '1.3.0' }

            $changes = @(Compare-UninstallSnapshot -Reference @($same, $upgraded, $gone) -Difference @($same, $after, $new))

            $changes.Count | Should -Be 3
            ($changes | Where-Object Change -EQ 'Added').Entry.KeyName | Should -Be 'New'
            ($changes | Where-Object Change -EQ 'Removed').Entry.KeyName | Should -Be 'Gone'
            $changed = $changes | Where-Object Change -EQ 'Changed'
            $changed.Entry.KeyName | Should -Be 'Upgraded'
            $changed.ChangedValues | Should -Be 'DisplayVersion: 1.2.3 -> 1.3.0'
        }

        It 'treats the same key name in another registry view as another app' {
            $before = Get-TestEntry @{ KeyName = 'TestApp'; RegistryView = '32-bit' }
            $after = Get-TestEntry @{ KeyName = 'TestApp'; RegistryView = '64-bit' }

            $changes = @(Compare-UninstallSnapshot -Reference @($before) -Difference @($after))

            @($changes.Change | Sort-Object) | Should -Be @('Added', 'Removed')
        }
    }

    Context 'Snapshot files' {

        It 'reads names outside ASCII exactly as they were written' {
            # Windows PowerShell would read a file without a byte order mark in the system code page.
            $name = 'Test App' + [char]0x00AE + [char]0x00A0 + '64'
            $file = Join-Path -Path $TestDrive -ChildPath 'unicode.json'
            $snapshot = [ordered]@{ Format = 'UninstallSnapshot'; Version = 1; Created = 'now'; Entries = @(Get-TestEntry @{ DisplayName = $name; KeyName = "$name`_is1" }) }
            [IO.File]::WriteAllText($file, (ConvertTo-Json -InputObject $snapshot -Depth 4), [System.Text.UTF8Encoding]::new($false))

            $entries = @(Read-UninstallSnapshot -Path $file)

            $entries.Count | Should -Be 1
            $entries[0].DisplayName | Should -BeExactly $name
            $entries[0].KeyName | Should -BeExactly "$name`_is1"
        }

        It 'refuses <Label> with a reason' -ForEach @(
            @{ Label = 'an empty object'; Content = '{}'; Reason = 'not a snapshot this script wrote' }
            @{ Label = 'an array'; Content = '[]'; Reason = 'not a snapshot this script wrote' }
            @{ Label = 'text that is not JSON'; Content = 'not json'; Reason = 'not valid JSON' }
            @{ Label = 'another format version'; Content = '{"Format":"UninstallSnapshot","Version":2,"Entries":[]}'; Reason = 'format version 2' }
        ) {
            $file = Join-Path -Path $TestDrive -ChildPath 'bad.json'
            [IO.File]::WriteAllText($file, $Content)

            { Read-UninstallSnapshot -Path $file } | Should -Throw -ExpectedMessage "*$Reason*"
        }
    }

    Context 'The script' {

        It 'lists this machine''s entries, each with Intune settings, and exits 0' {
            $result = Invoke-UnderTest @{}

            $result.ExitCode | Should -Be 0
            $result.Errors | Should -BeNullOrEmpty
            $result.Output.Count | Should -BeGreaterThan 0
            @($result.Output | Where-Object { -not $_.DisplayName -or -not $_.IntuneInstallBehavior }).Count | Should -Be 0
        }

        It 'lists every entry, and exits 0, when reading one uninstaller throws <Type>' -ForEach @(
            # What File.ReadAllBytes throws under Windows PowerShell for an app execution alias in
            # WindowsApps, a reparse point it cannot open, line break included; and for a file the
            # user may not read.
            @{ Type = 'System.IO.IOException'; Message = "The file cannot be accessed by the system.`r`n" }
            @{ Type = 'System.UnauthorizedAccessException'; Message = 'Access to the path is denied.' }
        ) {
            $alias = 'C:\Users\Example\AppData\Local\Microsoft\WindowsApps\testapp.exe'
            Write-TestEntry -Folder 'Unreadable' -KeyName 'Alias App' -Value @{ DisplayName = 'Alias App'; UninstallString = ('"{0}" uninstall' -f $alias) }
            Write-TestEntry -Folder 'Unreadable' -KeyName 'Other App' -Value @{ DisplayName = 'Other App'; UninstallString = '"C:\Program Files\Other App\remove.exe"' }

            # Stand-ins: the test key in place of the real Uninstall keys, and an uninstaller
            # check that fails for the alias the way the real read does.
            $source = @'
function Get-UninstallSource {
    param ([bool]$Is64BitWindows)
    @{ Hive = 'CurrentUser'; View = 'Default'; SubKey = '<SubKey>'; Scope = 'Machine'; RegistryView = '64-bit'; RegistryPath = '<RegistryPath>' }
}
'@
            $nsis = @'
function Test-NsisUninstaller {
    param ([string]$Path)
    if ($Path -ne '<Alias>') { return $false }
    # Thrown from a .NET method, as File.ReadAllBytes throws it, so PowerShell wraps it the same way.
    $exception = New-Object -TypeName '<Type>' -ArgumentList '<Message>'
    [System.Runtime.ExceptionServices.ExceptionDispatchInfo]::Capture($exception).Throw()
}
'@
            $copy = ConvertTo-StandInCopy @{
                'Get-UninstallSource'  = $source.Replace('<SubKey>', "$script:TestRoot\Unreadable").Replace('<RegistryPath>', $script:MachinePath)
                'Test-NsisUninstaller' = $nsis.Replace('<Alias>', $alias).Replace('<Type>', $Type).Replace('<Message>', $Message)
            }

            $result = Invoke-UnderTest @{} -Path $copy

            $result.ExitCode | Should -Be 0
            $result.Errors | Should -BeNullOrEmpty
            @($result.Output.DisplayName) | Should -Be @('Alias App', 'Other App')
            $result.Output[0].Installer | Should -Be 'Unknown'
            $result.Output[0].Notes | Where-Object { $_ -like '*could not be read*' } |
                Should -BeExactly ('The uninstaller could not be read, so its installer was not recognised: {0}' -f $Message.Trim())
            ($result.Output[1].Notes -join ' ') | Should -Not -Match 'could not be read'
            $result.Warnings | Should -BeExactly ('Cannot read the uninstaller of Alias App, so its installer was not recognised: {0}' -f $Message.Trim())
        }

        It 'returns nothing, and exits 0, when no entry matches -Name' {
            $result = Invoke-UnderTest @{ Name = ('No such app {0}' -f [guid]::NewGuid().ToString('n')) }

            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }

        It 'saves a snapshot that compares clean straight away' {
            $file = Join-Path -Path $TestDrive -ChildPath 'before.json'

            $save = Invoke-UnderTest @{ SaveSnapshot = $file }
            $compare = Invoke-UnderTest @{ CompareSnapshot = $file }

            $save.ExitCode | Should -Be 0
            (Get-Content -LiteralPath $file -Raw | ConvertFrom-Json).Format | Should -Be 'UninstallSnapshot'
            $compare.ExitCode | Should -Be 0
            $compare.Output.Count | Should -Be 0
            $compare.Warnings | Should -Match 'No Uninstall entry changed'
        }

        It 'shows an entry missing from the snapshot as added, with its Intune settings' {
            $file = Join-Path -Path $TestDrive -ChildPath 'pruned.json'
            $null = Invoke-UnderTest @{ SaveSnapshot = $file }
            $snapshot = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
            $dropped = @($snapshot.Entries)[0]
            $snapshot.Entries = @(@($snapshot.Entries) | Select-Object -Skip 1)
            [IO.File]::WriteAllText($file, (ConvertTo-Json -InputObject $snapshot -Depth 4), [System.Text.UTF8Encoding]::new($false))

            $result = Invoke-UnderTest @{ CompareSnapshot = $file }

            $result.ExitCode | Should -Be 0
            $added = @($result.Output | Where-Object { $_.Change -eq 'Added' })
            $added.Count | Should -Be 1
            $added[0].DisplayName | Should -Be $dropped.DisplayName
            $added[0].IntuneDetection | Should -Not -BeNullOrEmpty
        }

        It 'writes nothing under -WhatIf' {
            $file = Join-Path -Path $TestDrive -ChildPath 'whatif.json'

            $result = Invoke-UnderTest @{ SaveSnapshot = $file; WhatIf = $true }

            $result.ExitCode | Should -Be 0
            Test-Path -LiteralPath $file | Should -BeFalse
        }

        It 'exits 1 with the reason when the snapshot folder does not exist' {
            $file = Join-Path -Path $TestDrive -ChildPath 'missing\before.json'

            $result = Invoke-UnderTest @{ SaveSnapshot = $file }

            $result.ExitCode | Should -Be 1
            $result.Errors | Should -Match 'does not exist'
        }

        It 'returns exit code 1 to a caller that starts it with -File' {
            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder
            $bad = Join-Path -Path $folder -ChildPath 'bad.json'
            $stdin = Join-Path -Path $folder -ChildPath 'stdin.txt'
            [IO.File]::WriteAllText($bad, '{}')
            [IO.File]::WriteAllText($stdin, '')

            # Start-Process joins arguments with spaces and quotes none of them.
            $arguments = '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $script:ScriptPath),
            '-CompareSnapshot', ('"{0}"' -f $bad)
            $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
                -RedirectStandardInput $stdin -RedirectStandardOutput (Join-Path -Path $folder -ChildPath 'out.txt') `
                -RedirectStandardError (Join-Path -Path $folder -ChildPath 'err.txt')

            $process.ExitCode | Should -Be 1
        }
    }
}
