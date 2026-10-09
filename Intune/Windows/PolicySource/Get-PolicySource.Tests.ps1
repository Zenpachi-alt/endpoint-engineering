# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-PolicySource.ps1.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, with the constants
    they read, and tested on their own. Every registry read goes through a root
    key the functions are given, so PolicyManager, the enrollments and the live
    policy values are built under a test key in HKEY_CURRENT_USER\Software and
    removed afterwards. RSoP results, GPO cache entries and Preferences items
    are built here as the script's own readers return them. Registry.pol files
    and Preferences history are written to TestDrive.

    The script is also run as a file, as a technician starts it: unelevated it
    must stop at the elevation check, and elevated, as in CI, it must finish.

    GUIDs are generated at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Intune\Windows\PolicySource\Get-PolicySource.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or later, matching the script under test.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeDiscovery {
    # Worked out here, where -Skip is read. The Windows identity API throws on
    # Linux, even inside a Describe that is skipped there.
    $script:IsElevated = $false
    if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
        $script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

Describe 'Get-PolicySource' -Skip:([Environment]::OSVersion.Platform -ne 'Win32NT') {

    BeforeAll {
        $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-PolicySource.ps1'

        # Every top-level function of the script and the constants they read, without its main block.
        # The script runs under Set-StrictMode -Version Latest, so each function gets it as its first
        # statement here too: without strict mode, reading a property of $null passes silently in a
        # test and stops the script on a device.
        $parseErrors = $null
        $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw "Get-PolicySource.ps1 does not parse: $($parseErrors[0].Message)" }
        foreach ($statement in $syntaxTree.EndBlock.Statements) {
            if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $text = $statement.Extent.Text
                $at = $statement.Body.ParamBlock.Extent.EndOffset - $statement.Extent.StartOffset
                $text = $text.Substring(0, $at) + "`nSet-StrictMode -Version Latest`n" + $text.Substring($at)
                . ([scriptblock]::Create($text))
            }
            elseif ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $statement.Left.Extent.Text -match '^\$(PolicyManagerPath|PoliciesPath|VerdictRank)$') {
                Set-Variable -Name $Matches[1] -Scope Script -Value (& ([scriptblock]::Create($statement.Right.Extent.Text)))
            }
        }
        $script:LogFile = $null

        $script:TestParent = 'Software\EndpointEngineeringTests'
        $script:TestRoot = '{0}\{1}' -f $script:TestParent, [guid]::NewGuid().ToString('n')
        $script:Root = $null

        function Get-TestGuid {
            [guid]::NewGuid().ToString('B').ToUpperInvariant()
        }

        function Write-TestValue {
            # Values under the test root: ints become DWORDs, longs QWORDs, byte arrays binary, arrays REG_MULTI_SZ.
            param ([string]$Path, [hashtable]$Value = @{})
            $key = $script:Root.CreateSubKey($Path)
            try {
                foreach ($name in $Value.Keys) {
                    $data = $Value[$name]
                    if ($data -is [int]) { $key.SetValue($name, $data, [Microsoft.Win32.RegistryValueKind]::DWord) }
                    elseif ($data -is [long]) { $key.SetValue($name, $data, [Microsoft.Win32.RegistryValueKind]::QWord) }
                    elseif ($data -is [byte[]]) { $key.SetValue($name, $data, [Microsoft.Win32.RegistryValueKind]::Binary) }
                    elseif ($data -is [array]) { $key.SetValue($name, [string[]]$data, [Microsoft.Win32.RegistryValueKind]::MultiString) }
                    else { $key.SetValue($name, [string]$data, [Microsoft.Win32.RegistryValueKind]::String) }
                }
            }
            finally {
                $key.Dispose()
            }
        }

        function Get-TestPolicy {
            # An MDM setting as Get-MdmPolicy returns it, with any property replaced.
            param ([hashtable]$Property = @{})
            $policy = [ordered]@{
                Name = 'Area/Setting'; Value = '1'; Source = 'Intune'; SourceKind = 'Intune'; Leftover = $false; AdmxBacked = $false
                RedirectKey = ''; RedirectValue = ''; BlockKey = ''; BlockValue = ''
            }
            foreach ($name in $Property.Keys) { $policy[$name] = $Property[$name] }
            [pscustomobject]$policy
        }

        function Get-TestGpEntry {
            # A Group Policy registry setting as the script's readers return it.
            param ([string]$Key, [string]$ValueName, [string]$Value, [int]$Precedence = 1, [string]$GpoName = 'Baseline GPO')
            [pscustomobject]@{ Key = $Key; ValueName = $ValueName; Value = $Value; Precedence = $Precedence; GpoName = $GpoName }
        }

        function Invoke-Resolve {
            param ([object[]]$Mdm = @(), [object[]]$Applied = @(), [object[]]$Cached = @(), [object[]]$Preference = @(), [bool]$MdmWinsOverGp = $true)
            # Whole, even with one row: Windows PowerShell 5.1 gives a lone object no Count.
            , @(Resolve-PolicySource -Mdm $Mdm -GpApplied $Applied -GpCached $Cached -Preference $Preference -Root $script:Root -MdmWinsOverGp $MdmWinsOverGp)
        }

        function Get-TestRegistryPol {
            # A Registry.pol file: the PReg header, then [key;value;type;size;data] in UTF-16LE.
            param ([object[]]$Record)
            $unicode = [Text.Encoding]::Unicode
            $stream = New-Object -TypeName System.IO.MemoryStream
            $writer = New-Object -TypeName System.IO.BinaryWriter -ArgumentList $stream
            $writer.Write([uint32]0x67655250)
            $writer.Write([uint32]1)
            foreach ($record in $Record) {
                $writer.Write($unicode.GetBytes('[' + $record.Key + [char]0 + ';' + $record.Name + [char]0 + ';'))
                $writer.Write([uint32]$record.Type)
                $writer.Write($unicode.GetBytes(';'))
                $writer.Write([uint32]$record.Data.Length)
                $writer.Write($unicode.GetBytes(';'))
                # An empty array reaches the method as null, so write data only when there is some.
                if ($record.Data.Length -gt 0) { $writer.Write([byte[]]$record.Data) }
                $writer.Write($unicode.GetBytes(']'))
            }
            $writer.Flush()
            # The leading comma keeps the array whole; output would otherwise unroll it into bytes.
            , $stream.ToArray()
        }

        function Get-DwordByte { param ([uint32]$Value) , [BitConverter]::GetBytes($Value) }
        function Get-StringByte { param ([string]$Value) , [Text.Encoding]::Unicode.GetBytes($Value + [char]0) }
    }

    BeforeEach {
        $script:Root = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(('{0}\{1}' -f $script:TestRoot, [guid]::NewGuid().ToString('n')))
    }

    AfterEach {
        if ($null -ne $script:Root) { $script:Root.Dispose() }
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

    Context 'Reading values' {

        It 'reads policy data stored as bytes as the same text as the value in the registry' {
            Write-TestValue -Path 'SOFTWARE\Policies\Values' -Value @{
                Dword = 7; Big = -1; Quad = [long]5000000000; Text = 'On'; List = @('a', 'b'); Blob = [byte[]](1, 2, 3)
            }
            $cases = @(
                , @('Dword', 4, (Get-DwordByte 7))
                , @('Big', 4, (Get-DwordByte ([uint32]::MaxValue)))
                , @('Quad', 11, [BitConverter]::GetBytes([uint64]5000000000))
                , @('Text', 1, (Get-StringByte 'On'))
                , @('List', 7, [Text.Encoding]::Unicode.GetBytes("a$([char]0)b$([char]0)$([char]0)"))
                , @('Blob', 3, [byte[]](1, 2, 3))
            )
            foreach ($case in $cases) {
                $live = Get-LiveValue -Root $script:Root -Key 'SOFTWARE\Policies\Values' -Name $case[0]
                ConvertFrom-PolicyValue -Data ([byte[]]$case[2]) -Type $case[1] | Should -Be $live -Because $case[0]
            }
        }

        It 'reads a big-endian DWORD and keeps unknown data as base64' {
            ConvertFrom-PolicyValue -Data ([byte[]](0, 0, 1, 0)) -Type 5 | Should -Be '256'
            ConvertFrom-PolicyValue -Data ([byte[]](9, 9)) -Type 0 | Should -Be ([Convert]::ToBase64String([byte[]](9, 9)))
            ConvertFrom-PolicyValue -Data ([byte[]]@()) -Type 0 | Should -Be ''
        }

        It 'gives nothing for a value or key that is not there' {
            Get-LiveValue -Root $script:Root -Key 'SOFTWARE\Policies\Missing' -Name 'Value' | Should -BeNullOrEmpty
            Write-TestValue -Path 'SOFTWARE\Policies\Present' -Value @{ Other = 1 }
            Get-LiveValue -Root $script:Root -Key 'SOFTWARE\Policies\Present' -Name 'Value' | Should -BeNullOrEmpty
        }

        It 'shows an ADMX state as Enabled or Disabled, with its data' {
            Format-MdmValue -Value '<enabled/><data id="Level" value="2"/><data id="Mode" value="On"/>' | Should -Be 'Enabled: Level=2; Mode=On'
            Format-MdmValue -Value '<enabled/>' | Should -Be 'Enabled'
            Format-MdmValue -Value '<disabled/>' | Should -Be 'Disabled'
            Format-MdmValue -Value '3' | Should -Be '3'
            Test-AdmxState -Value '<disabled/>' | Should -BeTrue
            Test-AdmxState -Value '1' | Should -BeFalse
        }

        It 'compares key paths with or without a hive and in any case' {
            Get-LocationId -Key 'HKEY_LOCAL_MACHINE\Software\Policies\X\' -ValueName 'V' |
                Should -Be (Get-LocationId -Key 'SOFTWARE\POLICIES\X' -ValueName 'v')
        }
    }

    Context 'Registry.pol files' {

        It 'reads each record with its key, value name and value' {
            $bytes = Get-TestRegistryPol -Record @(
                @{ Key = 'Software\Policies\Test'; Name = 'Level'; Type = 4; Data = (Get-DwordByte 3) }
                @{ Key = 'Software\Policies\Test'; Name = 'Server'; Type = 1; Data = (Get-StringByte 'sync.contoso.com') }
            )
            $entries = @(ConvertFrom-RegistryPol -Bytes $bytes)

            $entries.Count | Should -Be 2
            $entries[0].Key | Should -Be 'Software\Policies\Test'
            $entries[0].ValueName | Should -Be 'Level'
            $entries[0].Value | Should -Be '3'
            $entries[1].Value | Should -Be 'sync.contoso.com'
        }

        It 'refuses a file without the PReg signature' {
            { ConvertFrom-RegistryPol -Bytes ([byte[]](1, 2, 3, 4, 5, 6, 7, 8)) -Source 'Test file' } |
                Should -Throw '*Test file is not a registry policy file*'
        }

        It 'refuses a file cut short, saying where' {
            $bytes = Get-TestRegistryPol -Record @(@{ Key = 'Software\Policies\Test'; Name = 'Level'; Type = 4; Data = (Get-DwordByte 3) })
            $short = $bytes[0..($bytes.Length - 5)]
            { ConvertFrom-RegistryPol -Bytes ([byte[]]$short) -Source 'Test file' } | Should -Throw '*Test file is malformed*'
        }

        It 'reads only the computer settings of applied GPOs from the cache, skipping keys and instructions' {
            $applied = Get-TestGuid
            $gone = Get-TestGuid
            foreach ($guid in $applied, $gone) {
                $machine = Join-Path -Path $TestDrive -ChildPath "DataStore\0\sysvol\contoso.com\Policies\$guid\Machine"
                $null = New-Item -Path $machine -ItemType Directory -Force
                [IO.File]::WriteAllBytes((Join-Path -Path $machine -ChildPath 'Registry.pol'), (Get-TestRegistryPol -Record @(
                            @{ Key = 'Software\Policies\Test'; Name = 'Level'; Type = 4; Data = (Get-DwordByte 3) }
                            @{ Key = 'Software\Policies\Test'; Name = ''; Type = 0; Data = [byte[]]@() }
                            @{ Key = 'Software\Policies\Test'; Name = '**del.Old'; Type = 1; Data = (Get-StringByte ' ') }
                        )))
                $user = Join-Path -Path $TestDrive -ChildPath "DataStore\0\sysvol\contoso.com\Policies\$guid\User"
                $null = New-Item -Path $user -ItemType Directory -Force
                [IO.File]::WriteAllBytes((Join-Path -Path $user -ChildPath 'Registry.pol'), (Get-TestRegistryPol -Record @(
                            @{ Key = 'Software\Policies\User'; Name = 'Mine'; Type = 4; Data = (Get-DwordByte 1) }
                        )))
            }

            $entries = @(Get-GpoCacheEntry -Directory (Join-Path -Path $TestDrive -ChildPath 'DataStore') -AppliedGpo @{ $applied = 'Baseline GPO' })

            $entries.Count | Should -Be 1
            $entries[0].ValueName | Should -Be 'Level'
            $entries[0].Value | Should -Be '3'
            $entries[0].GpoName | Should -Be 'Baseline GPO'
        }

        It 'gives nothing when there is no cache' {
            @(Get-GpoCacheEntry -Directory (Join-Path -Path $TestDrive -ChildPath 'NoCache') -AppliedGpo @{}).Count | Should -Be 0
        }
    }

    Context 'Group Policy Preferences history' {

        It 'reads computer registry items of applied GPOs, with DWORDs from hexadecimal' {
            $applied = Get-TestGuid
            $gone = Get-TestGuid
            foreach ($guid in $applied, $gone) {
                $folder = Join-Path -Path $TestDrive -ChildPath "History\$guid\Machine\Preferences\Registry"
                $null = New-Item -Path $folder -ItemType Directory -Force
                Set-Content -LiteralPath (Join-Path -Path $folder -ChildPath 'Registry.xml') -Encoding UTF8 -Value @'
<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings>
  <Registry name="Level">
    <Properties action="U" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Policies\Pref" name="Level" type="REG_DWORD" value="0000001a"/>
  </Registry>
  <Collection name="Group">
    <Registry name="Mode">
      <Properties action="R" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Policies\Pref" name="Mode" type="REG_SZ" value="Strict"/>
    </Registry>
  </Collection>
  <Registry name="Gone">
    <Properties action="D" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Policies\Pref" name="Gone" type="REG_SZ" value=""/>
  </Registry>
  <Registry name="User">
    <Properties action="U" hive="HKEY_CURRENT_USER" key="Software\Policies\Pref" name="User" type="REG_SZ" value="x"/>
  </Registry>
</RegistrySettings>
'@
            }

            $items = @(Get-PreferenceRegistryItem -Directory (Join-Path -Path $TestDrive -ChildPath 'History') -AppliedGpo @{ $applied = 'Preferences GPO' } |
                    Sort-Object -Property ValueName)

            $items.Count | Should -Be 2
            $items[0].ValueName | Should -Be 'Level'
            $items[0].Value | Should -Be '26'
            $items[1].ValueName | Should -Be 'Mode'
            $items[1].Value | Should -Be 'Strict'
            $items[1].GpoName | Should -Be 'Preferences GPO'
        }
    }

    Context 'Reading PolicyManager' {

        BeforeEach {
            $script:Intune = Get-TestGuid
            $script:Windows = Get-TestGuid
            $script:Owner = Get-TestGuid
            Write-TestValue -Path "SOFTWARE\Microsoft\Enrollments\$script:Intune" -Value @{ ProviderID = 'MS DM Server'; EnrollmentType = 6 }
            Write-TestValue -Path "SOFTWARE\Microsoft\Enrollments\$script:Windows" -Value @{ EnrollmentType = 1; Altitude = 1000 }
            Write-TestValue -Path 'SOFTWARE\Microsoft\Enrollments\Status' -Value @{ Other = 1 }
            $pm = 'SOFTWARE\Microsoft\PolicyManager'

            # A setting that keeps its value in current, mapped to the GP value MDMWinsOverGP blocks.
            Write-TestValue -Path "$pm\default\Update\ActiveHoursStart" -Value @{
                GPBlockingRegKeyPath = 'Software\Policies\Microsoft\Windows\WindowsUpdate'; GPBlockingRegValueName = 'ActiveHoursStart'
            }
            Write-TestValue -Path "$pm\current\device\Update" -Value @{
                ActiveHoursStart = 9; ActiveHoursStart_WinningProvider = $script:Intune; ActiveHoursStart_ProviderSet = 1
            }

            # A setting stored at its registry location: current holds only its metadata.
            Write-TestValue -Path "$pm\default\Storage\Redirected" -Value @{
                RegKeyPathRedirect = 'SOFTWARE\Policies\Microsoft\Storage'; RegValueNameRedirect = 'Redirected'
            }
            Write-TestValue -Path "$pm\current\device\Storage" -Value @{ Redirected_WinningProvider = $script:Intune; Redirected_ProviderSet = 1 }
            Write-TestValue -Path "$pm\providers\$script:Intune\default\device\Storage" -Value @{ Redirected = 5; Redirected_LastWrite = 1 }

            # An ADMX-backed setting, and Windows' own tuning with a '/' in its name.
            Write-TestValue -Path "$pm\default\ADMX_Test\Admx" -Value @{
                RegKeyPathRedirect = 'SOFTWARE\Policies\Microsoft\AdmxTest'; RegValueNameRedirect = 'Admx'; AdmxMetadataDevice = [byte[]](1)
            }
            Write-TestValue -Path "$pm\current\device\ADMX_Test" -Value @{
                Admx = '<enabled/>'; Admx_WinningProvider = $script:Intune; Admx_ADMXInstanceData = 'x'
            }
            Write-TestValue -Path "$pm\default\knobs\Power/Tuning" -Value @{ RegKeyPathRedirect = 'SOFTWARE\Test\Power'; RegValueNameRedirect = 'Tuning' }
            Write-TestValue -Path "$pm\current\device\knobs" -Value @{ 'Power/Tuning_WinningProvider' = $script:Windows }
            Write-TestValue -Path "$pm\providers\$script:Windows\default\device\knobs" -Value @{ 'Power/Tuning' = 3 }

            # An ingested ADMX setting, whose metadata lives under AdmxDefault.
            Write-TestValue -Path "$pm\AdmxDefault\$script:Owner\App~Policy~App\Sync" -Value @{
                RegKeyPathRedirect = 'SOFTWARE\Policies\Vendor\App'; RegValueNameRedirect = 'Sync'; AdmxMetadataDevice = [byte[]](1)
            }
            Write-TestValue -Path "$pm\current\device\App~Policy~App" -Value @{ Sync = '<disabled/>'; Sync_WinningProvider = $script:Intune }

            # A setting whose winner is not an enrollment.
            Write-TestValue -Path "$pm\default\Other\Orphan" -Value @{ Behavior = 1 }
            Write-TestValue -Path "$pm\current\device\Other" -Value @{ Orphan = 1 }

            $script:Policies = @(Get-MdmPolicy -Root $script:Root -Source (Get-EnrollmentSource -Root $script:Root))
        }

        It 'names Intune, Windows itself, and skips keys that are not enrollments' {
            $sources = Get-EnrollmentSource -Root $script:Root
            $sources[$script:Intune].Label | Should -Be 'Intune'
            $sources[$script:Windows].Label | Should -Be 'Windows'
            $sources[$script:Windows].Kind | Should -Be 'Windows'
            $sources.ContainsKey('Status') | Should -BeFalse
        }

        It 'returns each setting once, not its metadata' {
            ($script:Policies.Name | Sort-Object) -join ',' |
                Should -Be 'ADMX_Test/Admx,App~Policy~App/Sync,knobs/Power/Tuning,Other/Orphan,Storage/Redirected,Update/ActiveHoursStart'
        }

        It 'reads the value from current, or from the winning provider when current holds only metadata' {
            ($script:Policies | Where-Object Name -EQ 'Update/ActiveHoursStart').Value | Should -Be '9'
            ($script:Policies | Where-Object Name -EQ 'Storage/Redirected').Value | Should -Be '5'
            ($script:Policies | Where-Object Name -EQ 'knobs/Power/Tuning').Value | Should -Be '3'
        }

        It 'maps each setting to its registry value and the GP value it blocks' {
            $update = $script:Policies | Where-Object Name -EQ 'Update/ActiveHoursStart'
            $update.BlockKey | Should -Be 'Software\Policies\Microsoft\Windows\WindowsUpdate'
            $update.BlockValue | Should -Be 'ActiveHoursStart'
            $update.RedirectKey | Should -BeNullOrEmpty

            $storage = $script:Policies | Where-Object Name -EQ 'Storage/Redirected'
            $storage.RedirectKey | Should -Be 'SOFTWARE\Policies\Microsoft\Storage'
            $storage.AdmxBacked | Should -BeFalse
        }

        It 'marks ADMX-backed settings, built in or ingested, and reads ingested metadata from AdmxDefault' {
            ($script:Policies | Where-Object Name -EQ 'ADMX_Test/Admx').AdmxBacked | Should -BeTrue
            $ingested = $script:Policies | Where-Object Name -EQ 'App~Policy~App/Sync'
            $ingested.AdmxBacked | Should -BeTrue
            $ingested.RedirectKey | Should -Be 'SOFTWARE\Policies\Vendor\App'
            $ingested.Value | Should -Be '<disabled/>'
        }

        It 'credits each setting to its winning enrollment' {
            ($script:Policies | Where-Object Name -EQ 'Update/ActiveHoursStart').Source | Should -Be 'Intune'
            ($script:Policies | Where-Object Name -EQ 'knobs/Power/Tuning').SourceKind | Should -Be 'Windows'
            ($script:Policies | Where-Object Name -EQ 'Other/Orphan').Source | Should -Be 'Unknown'
        }

        It 'skips the copy of a list setting PolicyManager keeps beside it' {
            $pm = 'SOFTWARE\Microsoft\PolicyManager'
            Write-TestValue -Path "$pm\default\Defender\AsrRules" -Value @{ Behavior = 1 }
            Write-TestValue -Path "$pm\current\device\Defender" -Value @{
                AsrRules = '<enabled/>'; AsrRules_WinningProvider = $script:Intune; AsrRules_AsrRulesList_ListSet = 'x'
            }
            $names = @(Get-MdmPolicy -Root $script:Root -Source (Get-EnrollmentSource -Root $script:Root)).Name

            $names | Should -Contain 'Defender/AsrRules'
            @($names | Where-Object { $_ -like '*ListSet' }).Count | Should -Be 0
        }

        It 'credits knobs to Windows even when PolicyManager records no winner' {
            $pm = 'SOFTWARE\Microsoft\PolicyManager'
            Write-TestValue -Path "$pm\default\knobs\Power/Orphaned" -Value @{ Behavior = 1 }
            Write-TestValue -Path "$pm\current\device\knobs" -Value @{ 'Power/Orphaned_ProviderSet' = '' }
            $knob = @(Get-MdmPolicy -Root $script:Root -Source (Get-EnrollmentSource -Root $script:Root)) |
                Where-Object Name -EQ 'knobs/Power/Orphaned'

            $knob.SourceKind | Should -Be 'Windows'
            $knob.Leftover | Should -BeFalse
        }

        It 'marks a setting with neither a winning enrollment nor a value as a leftover, but not one with a value' {
            $pm = 'SOFTWARE\Microsoft\PolicyManager'
            Write-TestValue -Path "$pm\default\Storage\Gone" -Value @{ Behavior = 1 }
            Write-TestValue -Path "$pm\current\device\Storage" -Value @{ Gone_ProviderSet = '' }
            $policies = @(Get-MdmPolicy -Root $script:Root -Source (Get-EnrollmentSource -Root $script:Root))

            $gone = $policies | Where-Object Name -EQ 'Storage/Gone'
            $gone.Leftover | Should -BeTrue
            $gone.Source | Should -Be 'None'
            $gone.SourceKind | Should -Be 'Leftover'
            $gone.Value | Should -BeNullOrEmpty

            $orphan = $policies | Where-Object Name -EQ 'Other/Orphan'
            $orphan.Leftover | Should -BeFalse
            $orphan.Source | Should -Be 'Unknown'
        }

        It 'gives nothing on a device without MDM policy' {
            $script:Root.DeleteSubKeyTree('SOFTWARE\Microsoft\PolicyManager')
            @(Get-MdmPolicy -Root $script:Root -Source @{}).Count | Should -Be 0
        }
    }

    Context 'Verdicts' {

        It 'Agree when Group Policy and Intune set the same value' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Storage' -Value @{ Redirected = 5 }
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{ Name = 'Storage/Redirected'; Value = '5'; RedirectKey = 'SOFTWARE\Policies\Microsoft\Storage'; RedirectValue = 'Redirected' }) `
                -Applied @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Storage' -ValueName 'Redirected' -Value '5')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'Agree'
            $rows[0].Setting | Should -Be 'Storage/Redirected'
            $rows[0].Gpo | Should -Be 'Baseline GPO'
        }

        It 'Conflict when both apply different values, saying whose value the registry holds' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value @{ ActiveHoursStart = 8 }
            $rows = Invoke-Resolve -MdmWinsOverGp $false -Mdm @(Get-TestPolicy @{
                    Name = 'Update/ActiveHoursStart'; Value = '9'; BlockKey = 'Software\Policies\Microsoft\Windows\WindowsUpdate'; BlockValue = 'ActiveHoursStart'
                }) -Applied @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'ActiveHoursStart' -Value '8')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'Conflict'
            $rows[0].LiveValue | Should -Be '8'
            $rows[0].GpValue | Should -Be '8'
            $rows[0].MdmValue | Should -Be '9'
            $rows[0].Note | Should -BeLike '*holds the value of Group Policy*MDMWinsOverGP is off*'
        }

        It 'OverriddenByMdm when a GPO holds a setting that was not applied and Intune sets it' {
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'Update/ActiveHoursStart'; Value = '9'; BlockKey = 'Software\Policies\Microsoft\Windows\WindowsUpdate'; BlockValue = 'ActiveHoursStart'
                }) -Cached @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'ActiveHoursStart' -Value '7' -GpoName 'Update GPO')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'OverriddenByMdm'
            $rows[0].Gpo | Should -Be 'Update GPO'
            $rows[0].GpSource | Should -Be 'GPO, not applied'
            $rows[0].Note | Should -BeLike '*the values differ*MDMWinsOverGP is on*'
        }

        It 'OverriddenByMdm when the setting not applied lies under the key of an Intune ADMX setting' {
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'ADMX_TerminalServer/TS_ENCRYPTION_POLICY'; Value = '<enabled/>'; AdmxBacked = $true
                    RedirectKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                }) -Cached @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'MinEncryptionLevel' -Value '3')

            $row = $rows | Where-Object Verdict -EQ 'OverriddenByMdm'
            $row.MdmSetting | Should -Be 'ADMX_TerminalServer/TS_ENCRYPTION_POLICY'
            $row.MdmSource | Should -Be 'Intune'
        }

        It 'NotApplied when a GPO holds a setting that was not applied and nothing explains it' {
            $rows = Invoke-Resolve -Cached @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Cryptography' -ValueName 'Strength' -Value '2')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'NotApplied'
            $rows[0].Setting | Should -Be 'Software\Policies\Microsoft\Cryptography\Strength'
        }

        It 'Both when Intune sends an ADMX state, without comparing it' {
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'ADMX_Test/Admx'; Value = '<enabled/><data id="Level" value="2"/>'; AdmxBacked = $true
                    RedirectKey = 'SOFTWARE\Policies\Microsoft\AdmxTest'; RedirectValue = 'Admx'
                }) -Applied @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\AdmxTest' -ValueName 'Admx' -Value '1')

            $rows[0].Verdict | Should -Be 'Both'
            $rows[0].MdmValue | Should -Be 'Enabled: Level=2'
        }

        It 'GpOnly, naming the winning GPO and the GPOs that lost on precedence' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\System' -Value @{ EnableSmartScreen = 1 }
            $rows = Invoke-Resolve -Applied @(
                Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\System' -ValueName 'EnableSmartScreen' -Value '1' -Precedence 2 -GpoName 'Old GPO'
                Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\System' -ValueName 'EnableSmartScreen' -Value '1' -Precedence 1 -GpoName 'New GPO'
                Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\System' -ValueName 'EnableSmartScreen' -Value '0' -Precedence 3 -GpoName 'Oldest GPO'
            )

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'GpOnly'
            $rows[0].Gpo | Should -Be 'New GPO'
            $rows[0].OverriddenGpo | Should -Be 'Old GPO; Oldest GPO'
            $rows[0].Note | Should -BeNullOrEmpty
        }

        It 'GpOnly from Preferences, and notes a value written over Group Policy' {
            Write-TestValue -Path 'SOFTWARE\Policies\Pref' -Value @{ Level = 4 }
            $rows = Invoke-Resolve -Preference @(Get-TestGpEntry -Key 'SOFTWARE\Policies\Pref' -ValueName 'Level' -Value '26' -GpoName 'Preferences GPO')

            $rows[0].Verdict | Should -Be 'GpOnly'
            $rows[0].GpSource | Should -Be 'Preferences'
            $rows[0].Note | Should -BeLike '*something wrote it after Group Policy*'
        }

        It 'MdmOnly with no registry value, for a setting Windows reads from PolicyManager' {
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{ Name = 'Defender/AllowRealtimeMonitoring'; BlockKey = 'Software\Policies\Microsoft\Windows Defender'; BlockValue = 'DisableRealtimeMonitoring' })

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'MdmOnly'
            $rows[0].RegistryPath | Should -BeNullOrEmpty
            $rows[0].Note | Should -BeLike '*reads this setting from PolicyManager*'
        }

        It 'MdmOnly for the values under the key of an Intune ADMX setting' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\LLTD' -Value @{ EnableLLTDIO = 0; AllowLLTDIOOnDomain = 0 }
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'ADMX_LinkLayerTopologyDiscovery/LLTD_EnableLLTDIO'; Value = '<disabled/>'; AdmxBacked = $true
                    RedirectKey = 'SOFTWARE\Policies\Microsoft\Windows\LLTD'; RedirectValue = 'EnableLLTDIO'
                })

            $rows.Count | Should -Be 2
            @($rows | Where-Object Verdict -NE 'MdmOnly').Count | Should -Be 0
            ($rows | Where-Object Setting -Like '*AllowLLTDIOOnDomain').MdmSetting | Should -Be 'ADMX_LinkLayerTopologyDiscovery/LLTD_EnableLLTDIO'
        }

        It 'notes when the registry holds a value other than the one the MDM set' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Storage' -Value @{ Redirected = 1 }
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{ Name = 'Storage/Redirected'; Value = '5'; RedirectKey = 'SOFTWARE\Policies\Microsoft\Storage'; RedirectValue = 'Redirected' })

            $rows[0].Verdict | Should -Be 'MdmOnly'
            $rows[0].Note | Should -BeLike '*something wrote it after the MDM*'
        }

        It 'Unclaimed for a policy value no source sets, and GpOnly for wireless profiles' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Appx' -Value @{ Stray = 1 }
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy' -Value @{ Profile = 'x' }
            $rows = Invoke-Resolve

            ($rows | Where-Object Setting -Like '*Appx\Stray').Verdict | Should -Be 'Unclaimed'
            $wireless = $rows | Where-Object Setting -Like '*Wireless*'
            $wireless.Verdict | Should -Be 'GpOnly'
            $wireless.GpSource | Should -Be 'Wireless profile'
        }

        It 'credits a value two enrollments write to the external MDM rather than Windows' {
            $rows = Invoke-Resolve -Mdm @(
                Get-TestPolicy @{ Name = 'Windows/One'; Source = 'Windows'; SourceKind = 'Windows'; RedirectKey = 'SOFTWARE\Test\Shared'; RedirectValue = 'Value' }
                Get-TestPolicy @{ Name = 'Intune/Two'; RedirectKey = 'SOFTWARE\Test\Shared'; RedirectValue = 'Value' }
            )

            $rows.Count | Should -Be 1
            $rows[0].MdmSource | Should -Be 'Intune'
            $rows[0].Note | Should -BeLike '*2 MDM settings write this value*'
        }

        It 'Leftover for values a removed MDM setting left behind, matched by value or by key' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Value @{ DisablePasswordSaving = 1; SecurityLayer = 2 }
            $rows = Invoke-Resolve -Mdm @(
                Get-TestPolicy @{
                    Name = 'RemoteDesktopServices/DoNotAllowPasswordSaving'; Value = $null; Source = 'None'; SourceKind = 'Leftover'; Leftover = $true
                    RedirectKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; RedirectValue = 'DisablePasswordSaving'
                }
                Get-TestPolicy @{
                    Name = 'ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY'; Value = $null; Source = 'None'; SourceKind = 'Leftover'; Leftover = $true
                    AdmxBacked = $true; RedirectKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                }
            )

            @($rows | Where-Object Verdict -NE 'Leftover').Count | Should -Be 0
            $byValue = $rows | Where-Object RegistryPath -Like '*\DisablePasswordSaving'
            $byValue.Setting | Should -Be 'RemoteDesktopServices/DoNotAllowPasswordSaving'
            $byValue.LiveValue | Should -Be '1'
            $byValue.MatchedBy | Should -Be 'Value'
            $byValue.MdmSource | Should -Be 'None'
            $byKey = $rows | Where-Object RegistryPath -Like '*\SecurityLayer'
            $byKey.MatchedBy | Should -Be 'Key'
            $byKey.MdmSetting | Should -Be 'ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY'
            ($rows | Where-Object Setting -EQ 'ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY' | Where-Object { -not $_.LiveValue }).Note |
                Should -BeLike '*no MDM applies it now*'
        }

        It 'never takes a leftover for the source of a value' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Storage' -Value @{ Redirected = 5 }
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'Storage/Redirected'; Value = $null; Source = 'None'; SourceKind = 'Leftover'; Leftover = $true
                    RedirectKey = 'SOFTWARE\Policies\Microsoft\Storage'; RedirectValue = 'Redirected'
                }) -Applied @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Storage' -ValueName 'Redirected' -Value '5')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'GpOnly'
            $rows[0].Note | Should -BeLike '*PolicyManager also lists Storage/Redirected*no MDM applies it now*'
        }

        It 'NotApplied, naming a leftover that may still keep the GPO setting from applying' {
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'ADMX_TerminalServer/TS_USER_AUTHENTICATION_POLICY'; Value = $null; Source = 'None'; SourceKind = 'Leftover'; Leftover = $true
                    AdmxBacked = $true; RedirectKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; RedirectValue = 'UserAuthentication'
                }) -Cached @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows NT\Terminal Services' -ValueName 'UserAuthentication' -Value '1')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'NotApplied'
            $rows[0].MatchedBy | Should -Be 'Value'
            $rows[0].MdmSetting | Should -Be 'ADMX_TerminalServer/TS_USER_AUTHENTICATION_POLICY'
            $rows[0].Note | Should -BeLike '*no MDM applies any more*MDMWinsOverGP is on*'
        }

        It 'gives one row to a setting that writes one value and blocks Group Policy at another' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Value @{ AllowTelemetry_PolicyManager = 3 }
            $rows = Invoke-Resolve -Mdm @(Get-TestPolicy @{
                    Name = 'System/AllowTelemetry'; Value = '3'
                    RedirectKey = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'; RedirectValue = 'AllowTelemetry_PolicyManager'
                    BlockKey = 'Software\Policies\Microsoft\Windows\DataCollection'; BlockValue = 'AllowTelemetry'
                }) -Cached @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\DataCollection' -ValueName 'AllowTelemetry' -Value '1')

            $rows.Count | Should -Be 1
            $rows[0].Verdict | Should -Be 'OverriddenByMdm'
            $rows[0].MatchedBy | Should -Be 'Value'
            $rows[0].Note | Should -BeLike '*the values differ*writes its own value to HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry_PolicyManager: 3.'
        }

        It 'compares the GPO value with the registry when the MDM sends an ADMX state' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\OneDrive' -Value @{ SilentAccountConfig = 1; BlockExternalSync = 1 }
            $admx = @{ Value = '<enabled/>'; AdmxBacked = $true; RedirectKey = 'SOFTWARE\Policies\Microsoft\OneDrive' }
            $rows = Invoke-Resolve -Mdm @(
                Get-TestPolicy ($admx + @{ Name = 'OneDrive/SilentAccountConfig'; RedirectValue = 'SilentAccountConfig' })
                Get-TestPolicy ($admx + @{ Name = 'OneDrive/BlockExternalSync'; RedirectValue = 'BlockExternalSync' })
            ) -Cached @(Get-TestGpEntry -Key 'SOFTWARE\Policies\Microsoft\OneDrive' -ValueName 'SilentAccountConfig' -Value '0') `
                -Applied @(Get-TestGpEntry -Key 'SOFTWARE\Policies\Microsoft\OneDrive' -ValueName 'BlockExternalSync' -Value '1')

            ($rows | Where-Object Setting -EQ 'OneDrive/SilentAccountConfig').Note | Should -BeLike '*the GPO wants 0, the registry holds 1*'
            $both = $rows | Where-Object Setting -EQ 'OneDrive/BlockExternalSync'
            $both.Verdict | Should -Be 'Both'
            $both.Note | Should -BeLike '*the GPO wants the value the registry holds*'
        }

        It 'says a match by key is weaker, and keeps the note short when many settings share the key' {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Shared' -Value @{ Written = 1; ByGp = 0 }
            $policies = foreach ($letter in 'A', 'B', 'C', 'D', 'E') {
                Get-TestPolicy @{ Name = "Admx/$letter"; Value = '<enabled/>'; AdmxBacked = $true; RedirectKey = 'SOFTWARE\Policies\Microsoft\Shared' }
            }
            $rows = Invoke-Resolve -Mdm @($policies) -Applied @(Get-TestGpEntry -Key 'SOFTWARE\Policies\Microsoft\Shared' -ValueName 'ByGp' -Value '0')

            $byKey = $rows | Where-Object Setting -Like '*\Written'
            $byKey.Verdict | Should -Be 'MdmOnly'
            $byKey.MatchedBy | Should -Be 'Key'
            $byKey.Note | Should -BeLike 'Matched by key only: one of the 5 MDM ADMX settings*'
            ($rows | Where-Object Setting -Like '*\ByGp').Note | Should -BeLike '*Admx/A, Admx/B, Admx/C and 2 more.'
        }

        It 'shows the main columns by default' {
            $rows = Invoke-Resolve -Cached @(Get-TestGpEntry -Key 'Software\Policies\Test' -ValueName 'Level' -Value '1')
            @($rows[0].PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames) -join ',' |
                Should -Be 'Verdict,Setting,LiveValue,GpValue,Gpo,MdmValue,MdmSource'
        }
    }

    Context 'Selecting' {

        BeforeEach {
            Write-TestValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Appx' -Value @{ Stray = 1 }
            $script:Rows = Invoke-Resolve -Mdm @(
                Get-TestPolicy @{ Name = 'knobs/Power/Tuning'; Source = 'Windows'; SourceKind = 'Windows'; RedirectKey = 'SOFTWARE\Test\Power'; RedirectValue = 'Tuning' }
                Get-TestPolicy @{ Name = 'Update/ActiveHoursStart'; Value = '9'; BlockKey = 'Software\Policies\Microsoft\Windows\WindowsUpdate'; BlockValue = 'ActiveHoursStart' }
            ) -Cached @(Get-TestGpEntry -Key 'Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'ActiveHoursStart' -Value '7' -GpoName 'Update GPO')
        }

        It 'leaves out what Windows provisions for itself unless asked, and puts the decisions first' {
            $default = @(Select-PolicySource -Row $script:Rows)
            ($default.Verdict) -join ',' | Should -Be 'OverriddenByMdm,Unclaimed'

            @(Select-PolicySource -Row $script:Rows -IncludeWindowsInternal).Count | Should -Be 3
        }

        It 'filters by verdict, and by wildcard on the setting, registry path or GPO' {
            @(Select-PolicySource -Row $script:Rows -Verdict Unclaimed).Setting | Should -BeLike '*Appx\Stray'
            @(Select-PolicySource -Row $script:Rows -Filter '*Update GPO*').Setting | Should -Be 'Update/ActiveHoursStart'
            @(Select-PolicySource -Row $script:Rows -Filter 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\*').Count | Should -Be 1
        }

        It 'shows leftovers by default, after MdmOnly and before Unclaimed' {
            $rows = Invoke-Resolve -Mdm @(
                Get-TestPolicy @{ Name = 'Storage/Gone'; Value = $null; Source = 'None'; SourceKind = 'Leftover'; Leftover = $true }
                Get-TestPolicy @{ Name = 'Storage/Kept'; Value = '1' }
            )
            (@(Select-PolicySource -Row $rows).Verdict) -join ',' | Should -Be 'MdmOnly,Leftover,Unclaimed'
        }

        It 'gives nothing, not an empty row, when nothing matches' {
            @(Select-PolicySource -Row $script:Rows -Filter '*NoSuchSetting*').Count | Should -Be 0
            @(Select-PolicySource -Row @()).Count | Should -Be 0
        }
    }

    Context 'Running the script' {

        It 'stops unelevated with exit code 1 and says why' -Skip:$script:IsElevated {
            # Continue, not the caller's Stop: Windows PowerShell 5.1 turns the
            # child's error output into a terminating error under Stop.
            $ErrorActionPreference = 'Continue'
            $powershell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $output = @(& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:ScriptPath -LogDirectory $TestDrive 2>&1)
            $exitCode = $LASTEXITCODE
            $text = (@($output | ForEach-Object { [string]$_ }) -join '') -replace '\s', ''

            $exitCode | Should -Be 1
            $text | Should -BeLike '*RunthisfromanelevatedPowerShell*'
            Join-Path -Path $TestDrive -ChildPath 'Get-PolicySource.log' | Should -FileContentMatch '\[ERROR\]'
        }

        It 'finishes elevated with exit code 0' -Skip:(-not $script:IsElevated) {
            $ErrorActionPreference = 'Continue'
            $powershell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $output = @(& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:ScriptPath -LogDirectory $TestDrive 2>&1)
            $exitCode = $LASTEXITCODE
            $errors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })

            $exitCode | Should -Be 0 -Because (@($output | ForEach-Object { [string]$_ }) -join "`n")
            $errors.Count | Should -Be 0
            Join-Path -Path $TestDrive -ChildPath 'Get-PolicySource.log' | Should -FileContentMatch 'Finished in'
        }
    }
}
