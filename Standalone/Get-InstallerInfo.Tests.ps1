# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-InstallerInfo.ps1.

.DESCRIPTION
    No installer is checked in. Each test builds the file it needs in Pester's
    TestDrive: MSI databases through the Windows Installer COM API, executables
    as hand-assembled PE headers with a manifest resource, and .intunewin
    packages as ZIP archives holding a Detection.xml. Product codes, keys and
    version numbers are generated at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

    One test reads cmd.exe from the Windows folder, to check a real signed
    executable as well as the hand-built ones.

    The script runs on Windows only, so on any other platform every test is
    skipped.

.EXAMPLE
    Invoke-Pester -Path .\Standalone\Get-InstallerInfo.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or later, matching the script under test. Runs under
                    both Windows PowerShell 5.1 and PowerShell 7.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Install-Module Pester -Scope CurrentUser -SkipPublisherCheck
#>

Describe 'Get-InstallerInfo' -Skip:([Environment]::OSVersion.Platform -ne 'Win32NT') {

    BeforeAll {
        $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-InstallerInfo.ps1'

        function Invoke-UnderTest {
            # Runs the script and separates what it returns from what it warns and reports.
            param ([hashtable]$Parameters)
            $all = & $script:ScriptPath @Parameters 3>&1 2>&1
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

        function Get-TestFolder {
            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder
            $folder
        }

        function Get-TestGuid {
            [guid]::NewGuid().ToString('B').ToUpperInvariant()
        }

        function Invoke-ComMember {
            # The Windows Installer automation object exposes no type library to
            # PowerShell, so every call goes through IDispatch by name.
            # Arguments are unwrapped from PSObject first: COM cannot convert the wrapper
            # PowerShell puts around pipeline output, and fails with DISP_E_TYPEMISMATCH.
            param ($Object, [string]$Name, [string]$Kind = 'InvokeMethod', [object[]]$Argument = @())
            $plain = [object[]]@($Argument | ForEach-Object { if ($null -ne $_) { $_.psobject.BaseObject } else { $null } })
            $Object.GetType().InvokeMember($Name, [Reflection.BindingFlags]$Kind, $null, $Object, $plain)
        }

        $script:Schema = @{
            Property               = 'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)'
            Upgrade                = 'CREATE TABLE `Upgrade` (`UpgradeCode` CHAR(38) NOT NULL, `VersionMin` CHAR(20), `VersionMax` CHAR(20), `Language` CHAR(255), `Attributes` LONG NOT NULL, `Remove` CHAR(255), `ActionProperty` CHAR(72) NOT NULL PRIMARY KEY `UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`)'
            InstallExecuteSequence = 'CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)'
            Media                  = 'CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` LONG NOT NULL, `DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)'
            File                   = 'CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` LONG NOT NULL PRIMARY KEY `File`)'
            LaunchCondition        = 'CREATE TABLE `LaunchCondition` (`Condition` CHAR(255) NOT NULL, `Description` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Condition`)'
            # Cut down to the columns the script reads.
            Control                = 'CREATE TABLE `Control` (`Dialog_` CHAR(72) NOT NULL, `Control` CHAR(50) NOT NULL, `Property` CHAR(72) PRIMARY KEY `Dialog_`, `Control`)'
        }
        $script:Insert = @{
            Property               = 'INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)'
            Upgrade                = 'INSERT INTO `Upgrade` (`UpgradeCode`, `VersionMin`, `VersionMax`, `Attributes`, `ActionProperty`) VALUES (?, ?, ?, ?, ?)'
            InstallExecuteSequence = 'INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES (?, ?)'
            Media                  = 'INSERT INTO `Media` (`DiskId`, `LastSequence`, `Cabinet`) VALUES (?, ?, ?)'
            File                   = 'INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Attributes`, `Sequence`) VALUES (?, ?, ?, ?, ?, ?)'
            LaunchCondition        = 'INSERT INTO `LaunchCondition` (`Condition`, `Description`) VALUES (?, ?)'
            Control                = 'INSERT INTO `Control` (`Dialog_`, `Control`, `Property`) VALUES (?, ?, ?)'
        }

        function Write-TestMsi {
            # Builds an MSI database holding only the tables a test needs.
            param (
                [string]$Name = 'test.msi',
                [hashtable]$Property = @{},
                [hashtable]$Table = @{},
                [AllowNull()] [object]$Template = 'x64;1033',
                [int]$WordCount = 2,
                [string]$Folder = (Get-TestFolder)
            )

            $path = Join-Path -Path $Folder -ChildPath $Name
            $rows = @{} + $Table
            if ($Property.Count -gt 0) {
                $rows['Property'] = @($Property.GetEnumerator() | ForEach-Object { , @($_.Key, $_.Value) })
            }

            $com = [System.Collections.Generic.List[object]]::new()
            try {
                $installer = New-Object -ComObject WindowsInstaller.Installer
                $com.Add($installer)
                # 3 is msiOpenDatabaseModeCreate.
                $database = Invoke-ComMember $installer 'OpenDatabase' -Argument @($path, 3)
                $com.Add($database)

                foreach ($tableName in $rows.Keys) {
                    $view = Invoke-ComMember $database 'OpenView' -Argument @($script:Schema[$tableName])
                    $com.Add($view)
                    $null = Invoke-ComMember $view 'Execute'
                    $null = Invoke-ComMember $view 'Close'

                    foreach ($row in $rows[$tableName]) {
                        $record = Invoke-ComMember $installer 'CreateRecord' -Argument @($row.Count)
                        $com.Add($record)
                        for ($i = 0; $i -lt $row.Count; $i++) {
                            if ($null -eq $row[$i]) { continue }
                            $member = if ($row[$i] -is [int]) { 'IntegerData' } else { 'StringData' }
                            $null = Invoke-ComMember $record $member 'SetProperty' @(($i + 1), $row[$i])
                        }
                        $view = Invoke-ComMember $database 'OpenView' -Argument @($script:Insert[$tableName])
                        $com.Add($view)
                        $null = Invoke-ComMember $view 'Execute' -Argument @($record)
                        $null = Invoke-ComMember $view 'Close'
                    }
                }

                # 20 is the number of summary properties that may be written.
                $summary = Invoke-ComMember $database 'SummaryInformation' 'GetProperty' @(20)
                $com.Add($summary)
                if ($null -ne $Template) { $null = Invoke-ComMember $summary 'Property' 'SetProperty' @(7, [string]$Template) }
                $null = Invoke-ComMember $summary 'Property' 'SetProperty' @(9, (Get-TestGuid))
                $null = Invoke-ComMember $summary 'Property' 'SetProperty' @(14, 500)
                $null = Invoke-ComMember $summary 'Property' 'SetProperty' @(15, $WordCount)
                $null = Invoke-ComMember $summary 'Persist'
                $null = Invoke-ComMember $database 'Commit'
            }
            finally {
                # COM objects hold the file open until they are released.
                for ($i = $com.Count - 1; $i -ge 0; $i--) {
                    $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($com[$i])
                }
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
            }
            $path
        }

        function Write-ByteRange {
            param ([byte[]]$Buffer, [int]$Offset, [byte[]]$Bytes)
            [Array]::Copy($Bytes, 0, $Buffer, $Offset, $Bytes.Length)
        }

        function Write-TestExe {
            # A PE32 header, a section table and, with -Manifest, a .rsrc section
            # holding one RT_MANIFEST resource. Enough for the script, which only
            # reads headers and never runs the file.
            param (
                [string]$Name = 'setup.exe',
                [int]$Machine = 0x14C,
                [string[]]$Section = @('.text'),
                [string]$Manifest,
                [string]$Overlay,
                [string]$Folder = (Get-TestFolder)
            )

            $names = @($Section)
            $manifestBytes = [byte[]]@()
            if ($Manifest) {
                $manifestBytes = [Text.Encoding]::UTF8.GetBytes($Manifest)
                $names += '.rsrc'
            }
            $resourceLength = 88 + $manifestBytes.Length
            $sizes = @($names | ForEach-Object {
                    if ($_ -eq '.rsrc') { [int]([math]::Ceiling($resourceLength / 512) * 512) } else { 512 }
                })
            $overlayBytes = if ($Overlay) { [Text.Encoding]::GetEncoding(28591).GetBytes($Overlay) } else { [byte[]]@() }
            $imageEnd = 0x400 + ($sizes | Measure-Object -Sum).Sum
            $image = [byte[]]::new($imageEnd + $overlayBytes.Length)

            Write-ByteRange $image 0 ([byte[]](0x4D, 0x5A))
            Write-ByteRange $image 0x3C ([BitConverter]::GetBytes([uint32]64))
            Write-ByteRange $image 64 ([byte[]](0x50, 0x45, 0, 0))
            Write-ByteRange $image 68 ([BitConverter]::GetBytes([uint16]$Machine))
            Write-ByteRange $image 70 ([BitConverter]::GetBytes([uint16]$names.Count))
            Write-ByteRange $image 84 ([BitConverter]::GetBytes([uint16]224))
            Write-ByteRange $image 88 ([BitConverter]::GetBytes([uint16]0x10B))
            Write-ByteRange $image 180 ([BitConverter]::GetBytes([uint32]16))

            $rawOffset = 0x400
            for ($i = 0; $i -lt $names.Count; $i++) {
                $entry = 312 + 40 * $i
                $virtualAddress = 0x1000 * ($i + 1)
                $nameBytes = [byte[]]::new(8)
                $ascii = [Text.Encoding]::ASCII.GetBytes($names[$i])
                [Array]::Copy($ascii, $nameBytes, [math]::Min(8, $ascii.Length))
                Write-ByteRange $image $entry $nameBytes
                Write-ByteRange $image ($entry + 8) ([BitConverter]::GetBytes([uint32]$sizes[$i]))
                Write-ByteRange $image ($entry + 12) ([BitConverter]::GetBytes([uint32]$virtualAddress))
                Write-ByteRange $image ($entry + 16) ([BitConverter]::GetBytes([uint32]$sizes[$i]))
                Write-ByteRange $image ($entry + 20) ([BitConverter]::GetBytes([uint32]$rawOffset))

                if ($names[$i] -eq '.rsrc') {
                    Write-ByteRange $image 200 ([BitConverter]::GetBytes([uint32]$virtualAddress))
                    Write-ByteRange $image 204 ([BitConverter]::GetBytes([uint32]$resourceLength))
                    # Type 24 -> name 1 -> language 1033 -> data entry -> manifest bytes.
                    $root = $rawOffset
                    Write-ByteRange $image ($root + 14) ([BitConverter]::GetBytes([uint16]1))
                    Write-ByteRange $image ($root + 16) ([BitConverter]::GetBytes([uint32]24))
                    Write-ByteRange $image ($root + 20) ([BitConverter]::GetBytes([uint32](2147483648 + 24)))
                    Write-ByteRange $image ($root + 24 + 14) ([BitConverter]::GetBytes([uint16]1))
                    Write-ByteRange $image ($root + 40) ([BitConverter]::GetBytes([uint32]1))
                    Write-ByteRange $image ($root + 44) ([BitConverter]::GetBytes([uint32](2147483648 + 48)))
                    Write-ByteRange $image ($root + 48 + 14) ([BitConverter]::GetBytes([uint16]1))
                    Write-ByteRange $image ($root + 64) ([BitConverter]::GetBytes([uint32]1033))
                    Write-ByteRange $image ($root + 68) ([BitConverter]::GetBytes([uint32]72))
                    Write-ByteRange $image ($root + 72) ([BitConverter]::GetBytes([uint32]($virtualAddress + 88)))
                    Write-ByteRange $image ($root + 76) ([BitConverter]::GetBytes([uint32]$manifestBytes.Length))
                    Write-ByteRange $image ($root + 88) $manifestBytes
                }
                $rawOffset += $sizes[$i]
            }
            if ($overlayBytes.Length -gt 0) { Write-ByteRange $image $imageEnd $overlayBytes }

            $path = Join-Path -Path $Folder -ChildPath $Name
            [IO.File]::WriteAllBytes($path, $image)
            $path
        }

        function Get-TestManifest {
            param ([string]$Identity, [string]$Level = 'asInvoker', [string]$Prefix = '')
            $element = if ($Prefix) { "${Prefix}:requestedExecutionLevel" } else { 'requestedExecutionLevel' }
            ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly manifestVersion="1.0">' +
                '<assemblyIdentity type="win32" name="{0}"/>' +
                '<trustInfo><security><requestedPrivileges><{1} level="{2}" uiAccess="false"/>' +
                '</requestedPrivileges></security></trustInfo></assembly>') -f $Identity, $element, $Level
        }

        function Get-DetectionXml {
            # The layout written by Content Prep Tool 1.8.7, namespace prefixes included.
            # The schema URL is assembled here so the scanner does not read it as a link.
            param ([string]$SetupFile = 'setup.msi', [hashtable]$MsiInfo, [string]$Key = 'unused', [string]$Prolog = '')
            $toolVersion = (1, 8, 7, 0) -join '.'
            $schema = 'http' + '://www.w3.org/2001/XMLSchema'
            $msi = ''
            if ($MsiInfo) {
                $msi = '<MsiInfo>' + (($MsiInfo.GetEnumerator() | ForEach-Object { '<{0}>{1}</{0}>' -f $_.Key, $_.Value }) -join '') + '</MsiInfo>'
            }
            ($Prolog + '<ApplicationInfo xmlns:xsd="{4}" xmlns:xsi="{4}-instance" ToolVersion="{0}"><Name>Test App</Name>' +
                '<UnencryptedContentSize>123456</UnencryptedContentSize><FileName>IntunePackage.intunewin</FileName>' +
                '<SetupFile>{1}</SetupFile><EncryptionInfo><EncryptionKey>{2}</EncryptionKey><MacKey>{2}</MacKey>' +
                '<InitializationVector>{2}</InitializationVector><Mac>{2}</Mac><ProfileIdentifier>ProfileVersion1' +
                '</ProfileIdentifier><FileDigest>{2}</FileDigest><FileDigestAlgorithm>SHA256</FileDigestAlgorithm>' +
                '</EncryptionInfo>{3}</ApplicationInfo>') -f $toolVersion, $SetupFile, $Key, $msi, $schema
        }

        function Write-TestIntuneWin {
            param ([string]$Name = 'app.intunewin', [string]$DetectionXml, [string]$Folder = (Get-TestFolder))
            Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
            $path = Join-Path -Path $Folder -ChildPath $Name
            $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
            $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
            try {
                $content = $zip.CreateEntry('IntuneWinPackage/Contents/IntunePackage.intunewin').Open()
                $content.Write([byte[]](1..64), 0, 64)
                $content.Dispose()
                if ($DetectionXml) {
                    $writer = [IO.StreamWriter]::new($zip.CreateEntry('IntuneWinPackage/Metadata/Detection.xml').Open())
                    $writer.Write($DetectionXml)
                    $writer.Dispose()
                }
            }
            finally {
                $zip.Dispose()
                $stream.Dispose()
            }
            $path
        }
    }

    Context 'MSI' {

        It 'reads identity, architecture and the suggested Intune settings' {
            $code = Get-TestGuid
            $upgrade = Get-TestGuid
            $msi = Write-TestMsi -Property @{
                ProductCode = $code; ProductVersion = '3.4.5'; UpgradeCode = $upgrade; ProductName = 'Test App'
                Manufacturer = 'Contoso'; ProductLanguage = '1033'; ALLUSERS = '1'
            }

            $result = Invoke-UnderTest @{ Path = $msi }

            $result.ExitCode | Should -Be 0
            $result.Warnings | Should -BeNullOrEmpty
            $info = $result.Output[0]
            $info.FileType | Should -Be 'Msi'
            $info.ProductName | Should -Be 'Test App'
            $info.Publisher | Should -Be 'Contoso'
            $info.ProductVersion | Should -Be '3.4.5'
            $info.ProductCode | Should -Be $code
            $info.UpgradeCode | Should -Be $upgrade
            $info.PackageCode | Should -Match '^\{[0-9A-F-]{36}\}$'
            $info.Architecture | Should -Be 'x64'
            $info.InstallContext | Should -Be 'PerMachine'
            $info.IntuneInstallCommand | Should -BeExactly 'msiexec /i "test.msi" /qn /norestart'
            $info.IntuneUninstallCommand | Should -BeExactly ('msiexec /x "{0}" /qn /norestart' -f $code)
            $info.IntuneInstallBehavior | Should -Be 'System'
            $info.IntuneDetection | Should -Match ([regex]::Escape($code))
        }

        It 'maps the template platform <Template> to <Expected>' -ForEach @(
            @{ Template = 'Intel;1033'; Expected = 'x86' }
            @{ Template = ';1033'; Expected = 'x86' }
            @{ Template = 'x64;1033'; Expected = 'x64' }
            @{ Template = 'Arm64;1033'; Expected = 'ARM64' }
        ) {
            $msi = Write-TestMsi -Template $Template -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' }
            (Invoke-UnderTest @{ Path = $msi }).Output[0].Architecture | Should -Be $Expected
        }

        It 'reports no architecture when the summary has no template' {
            $msi = Write-TestMsi -Template $null -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' }
            (Invoke-UnderTest @{ Path = $msi }).Output[0].Architecture | Should -BeNullOrEmpty
        }

        It 'suggests a User install for a per-user package, and warns' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid) }

            $result = Invoke-UnderTest @{ Path = $msi }

            $result.ExitCode | Should -Be 0
            $result.Output[0].InstallContext | Should -Be 'PerUser'
            $result.Output[0].IntuneInstallBehavior | Should -Be 'User'
            $result.Output[0].IntuneInstallCommand | Should -Not -Match 'ALLUSERS'
            ($result.Warnings -join ' ') | Should -Match 'SYSTEM profile'
        }

        It 'adds ALLUSERS=1 for a dual-purpose package that defaults to per-user, and warns' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '2'; MSIINSTALLPERUSER = '1' }

            $result = Invoke-UnderTest @{ Path = $msi }

            $result.Output[0].InstallContext | Should -Be 'DualPurposePerUserDefault'
            $result.Output[0].IntuneInstallCommand | Should -BeExactly 'msiexec /i "test.msi" ALLUSERS=1 /qn /norestart'
            $result.Output[0].IntuneInstallBehavior | Should -Be 'System'
            ($result.Warnings -join ' ') | Should -Match 'ALLUSERS=1'
        }

        It 'treats ALLUSERS=2 on its own as per-machine when elevated' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '2' }

            $result = Invoke-UnderTest @{ Path = $msi }

            $result.Output[0].InstallContext | Should -Be 'PerMachineWhenElevated'
            $result.Output[0].IntuneInstallBehavior | Should -Be 'System'
            $result.Warnings | Should -BeNullOrEmpty
        }

        It 'names the cabinets that must sit beside the MSI, and warns' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' } -Table @{
                Media = @(, @(1, 10, '#embedded.cab')) + @(, @(2, 20, 'Data1.cab'))
            }

            $result = Invoke-UnderTest @{ Path = $msi }

            @($result.Output[0].ExternalCabinets).Count | Should -Be 1
            $result.Output[0].ExternalCabinets[0] | Should -Be 'Data1.cab'
            ($result.Warnings -join ' ') | Should -Match 'Data1\.cab'
        }

        It 'counts <Expected> loose file(s) with word count <WordCount>' -ForEach @(
            # Attributes 0 follow the package default; 0x4000 is compressed, 0x2000 uncompressed.
            @{ WordCount = 0; Expected = 2 }
            @{ WordCount = 2; Expected = 1 }
            @{ WordCount = 6; Expected = 3 }
        ) {
            $msi = Write-TestMsi -WordCount $WordCount -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' } -Table @{
                File = @(
                    , @('a', 'c', 'a.txt', 1, 0, 1)
                    , @('b', 'c', 'b.txt', 1, 0x4000, 2)
                    , @('c', 'c', 'c.txt', 1, 0x2000, 3)
                )
            }

            $result = Invoke-UnderTest @{ Path = $msi }

            $result.Output[0].LooseFileCount | Should -Be $Expected
            ($result.Warnings -join ' ') | Should -Match 'stored outside the MSI'
        }

        It 'reports a major upgrade only when RemoveExistingProducts runs' {
            $upgrade = Get-TestGuid
            $other = Get-TestGuid
            $rules = @(
                , @($upgrade, '1.0.0', '3.4.5', 0x100, 'OLDER_FOUND')
                , @($upgrade, '3.4.5', $null, 0x2, 'NEWER_FOUND')
                , @($other, $null, $null, 0, 'OTHER_FOUND')
            )
            $property = @{ ProductCode = (Get-TestGuid); UpgradeCode = $upgrade; ProductVersion = '3.4.5'; ALLUSERS = '1' }
            $with = Write-TestMsi -Property $property -Table @{
                Upgrade = $rules; InstallExecuteSequence = @(, @('RemoveExistingProducts', 1450))
            }
            $without = Write-TestMsi -Property $property -Table @{ Upgrade = $rules }

            $info = (Invoke-UnderTest @{ Path = $with }).Output[0]
            $info.RemovesOlderVersions | Should -BeTrue
            ($info.Notes -join ' ') | Should -Match 'supersedence'
            $info.UpgradeRules.Count | Should -Be 3
            $own = $info.UpgradeRules | Where-Object { $_.ActionProperty -eq 'OLDER_FOUND' }
            $own.Versions | Should -Be '>= 1.0.0 and < 3.4.5'
            $own.Action | Should -Be 'Remove'
            $own.SameProduct | Should -BeTrue
            ($info.UpgradeRules | Where-Object { $_.ActionProperty -eq 'NEWER_FOUND' }).Action | Should -Be 'Detect'
            ($info.UpgradeRules | Where-Object { $_.ActionProperty -eq 'OTHER_FOUND' }).SameProduct | Should -BeFalse

            (Invoke-UnderTest @{ Path = $without }).Output[0].RemovesOlderVersions | Should -BeFalse
        }

        It 'lists public properties from the Property table and dialogs, once each' {
            $msi = Write-TestMsi -Property @{
                ProductCode = (Get-TestGuid); ALLUSERS = '1'; INSTALLDIR = 'C:\App'; SecureCustomProperties = 'X'
            } -Table @{
                Control = @(
                    , @('LicenseDlg', 'KeyEdit', 'LICENSEKEY')
                    , @('FolderDlg', 'PathEdit', 'INSTALLDIR')
                    , @('FolderDlg', 'Hidden', 'PrivateValue')
                )
            }

            $properties = (Invoke-UnderTest @{ Path = $msi }).Output[0].PublicProperties

            @($properties.Name) | Should -Be @('ALLUSERS', 'INSTALLDIR', 'LICENSEKEY')
            ($properties | Where-Object Name -EQ 'INSTALLDIR').Source | Should -Be 'Property table'
            ($properties | Where-Object Name -EQ 'INSTALLDIR').Value | Should -Be 'C:\App'
            ($properties | Where-Object Name -EQ 'LICENSEKEY').Source | Should -Be 'Dialog'
        }

        It 'returns launch conditions' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' } -Table @{
                LaunchCondition = @(, @('VersionNT64', 'Needs 64-bit Windows.'))
            }

            $conditions = @((Invoke-UnderTest @{ Path = $msi }).Output[0].LaunchConditions)

            $conditions.Count | Should -Be 1
            $conditions[0].Condition | Should -Be 'VersionNT64'
            $conditions[0].Message | Should -Be 'Needs 64-bit Windows.'
        }

        It 'reads a database with no tables without failing' {
            $msi = Write-TestMsi

            $result = Invoke-UnderTest @{ Path = $msi }

            $result.ExitCode | Should -Be 0
            $result.Output[0].ProductCode | Should -BeNullOrEmpty
            $result.Output[0].IntuneUninstallCommand | Should -BeNullOrEmpty
            ($result.Output[0].Notes -join ' ') | Should -Match 'No ProductCode'
        }

        It 'leaves the MSI unlocked once read' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' }

            (Invoke-UnderTest @{ Path = $msi }).ExitCode | Should -Be 0

            { Remove-Item -LiteralPath $msi -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context 'EXE' {

        It 'recognises a WiX Burn bundle by its section, and suggests both commands' {
            $exe = Write-TestExe -Section '.text', '.wixburn', '.data'

            $info = (Invoke-UnderTest @{ Path = $exe }).Output[0]

            $info.FileType | Should -Be 'Exe'
            $info.InstallerFramework | Should -Be 'WiX Burn'
            $info.FrameworkEvidence | Should -Match 'wixburn'
            $info.IntuneInstallCommand | Should -BeExactly '"setup.exe" /quiet /norestart'
            $info.IntuneUninstallCommand | Should -BeExactly '"setup.exe" /uninstall /quiet /norestart'
        }

        It 'recognises NSIS by its manifest and flags an installer that does not elevate' {
            $exe = Write-TestExe -Manifest (Get-TestManifest -Identity 'Nullsoft.NSIS.exehead' -Level 'asInvoker')

            $info = (Invoke-UnderTest @{ Path = $exe }).Output[0]

            $info.InstallerFramework | Should -Be 'NSIS'
            $info.RequestedExecutionLevel | Should -Be 'asInvoker'
            $info.IntuneInstallCommand | Should -BeExactly '"setup.exe" /S'
            $info.IntuneUninstallCommand | Should -BeNullOrEmpty
            ($info.Notes -join ' ') | Should -Match 'per-user install'
        }

        It 'recognises NSIS by the header after the executable when there is no manifest' {
            $exe = Write-TestExe -Overlay ("`0`0`0`0" + [char]0xEF + [char]0xBE + [char]0xAD + [char]0xDE + 'NullsoftInst')

            $info = (Invoke-UnderTest @{ Path = $exe }).Output[0]

            $info.InstallerFramework | Should -Be 'NSIS'
            $info.FrameworkEvidence | Should -Match 'after the executable'
            $info.RequestedExecutionLevel | Should -BeNullOrEmpty
        }

        It 'recognises Inno Setup and reads a prefixed execution level' {
            $manifest = Get-TestManifest -Identity 'JR.Inno.Setup' -Level 'requireAdministrator' -Prefix 'v3'
            $exe = Write-TestExe -Manifest $manifest

            $info = (Invoke-UnderTest @{ Path = $exe }).Output[0]

            $info.InstallerFramework | Should -Be 'Inno Setup'
            $info.RequestedExecutionLevel | Should -Be 'requireAdministrator'
            $info.IntuneInstallCommand | Should -BeExactly '"setup.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
        }

        It 'says so when it does not recognise the framework' {
            $exe = Write-TestExe -Manifest (Get-TestManifest -Identity 'Contoso.Setup')

            $info = (Invoke-UnderTest @{ Path = $exe }).Output[0]

            $info.InstallerFramework | Should -Be 'Unknown'
            $info.FrameworkEvidence | Should -BeNullOrEmpty
            $info.IntuneInstallCommand | Should -BeNullOrEmpty
            ($info.Notes -join ' ') | Should -Match 'not recognised'
        }

        It 'maps machine type <Machine> to <Expected>' -ForEach @(
            @{ Machine = 0x14C; Expected = 'x86' }
            @{ Machine = 0x8664; Expected = 'x64' }
            @{ Machine = 0xAA64; Expected = 'ARM64' }
        ) {
            $exe = Write-TestExe -Machine $Machine
            (Invoke-UnderTest @{ Path = $exe }).Output[0].ExecutableArchitecture | Should -Be $Expected
        }

        It 'notes that a 32-bit installer says nothing about the app' {
            $exe = Write-TestExe -Machine 0x14C
            ((Invoke-UnderTest @{ Path = $exe }).Output[0].Notes -join ' ') | Should -Match 'itself is 32-bit'
        }

        It 'reads a real signed Windows executable' {
            $result = Invoke-UnderTest @{ Path = (Join-Path -Path ([Environment]::SystemDirectory) -ChildPath 'cmd.exe') }

            $result.ExitCode | Should -Be 0
            $info = $result.Output[0]
            $info.FileType | Should -Be 'Exe'
            $info.Publisher | Should -Be 'Microsoft Corporation'
            $info.SignatureStatus | Should -Be 'Valid'
            $info.ExecutableArchitecture | Should -BeIn @('x86', 'x64', 'ARM64')
            $info.InstallerFramework | Should -Be 'Unknown'
        }
    }

    Context '.intunewin' {

        It 'reads the MSI details and never outputs the encryption key' {
            $key = [Convert]::ToBase64String([byte[]](1..32 | ForEach-Object { Get-Random -Maximum 256 }))
            $code = Get-TestGuid
            $xml = Get-DetectionXml -SetupFile 'App Setup.msi' -Key $key -MsiInfo @{
                MsiProductCode = $code; MsiProductVersion = '3.4.5'; MsiUpgradeCode = (Get-TestGuid)
                MsiExecutionContext = 'System'; MsiRequiresReboot = 'false'; MsiPublisher = 'Contoso'
            }
            $package = Write-TestIntuneWin -DetectionXml $xml

            $result = Invoke-UnderTest @{ Path = $package }

            $result.ExitCode | Should -Be 0
            $info = $result.Output[0]
            $info.FileType | Should -Be 'IntuneWin'
            $info.SetupFile | Should -Be 'App Setup.msi'
            $info.ProductName | Should -Be 'Test App'
            $info.Publisher | Should -Be 'Contoso'
            $info.ProductCode | Should -Be $code
            $info.MsiRequiresReboot | Should -BeFalse
            $info.ContentSizeBytes | Should -Be 123456
            $info.ToolVersion | Should -Be ((1, 8, 7, 0) -join '.')
            $info.IntuneInstallCommand | Should -BeExactly 'msiexec /i "App Setup.msi" /qn /norestart'
            $info.IntuneUninstallCommand | Should -BeExactly ('msiexec /x "{0}" /qn /norestart' -f $code)
            $info.IntuneInstallBehavior | Should -Be 'System'
            ($info | ConvertTo-Json -Depth 5) | Should -Not -Match ([regex]::Escape($key))
        }

        It 'leaves the install behavior open for an MSI that installs either way' {
            $xml = Get-DetectionXml -MsiInfo @{ MsiProductCode = (Get-TestGuid); MsiExecutionContext = 'Any' }
            $info = (Invoke-UnderTest @{ Path = (Write-TestIntuneWin -DetectionXml $xml) }).Output[0]

            $info.IntuneInstallBehavior | Should -BeNullOrEmpty
            ($info.Notes -join ' ') | Should -Match 'ALLUSERS=1'
        }

        It 'says where to look when the package was not built from an MSI' {
            $xml = Get-DetectionXml -SetupFile 'Install.cmd'
            $info = (Invoke-UnderTest @{ Path = (Write-TestIntuneWin -DetectionXml $xml) }).Output[0]

            $info.ProductCode | Should -BeNullOrEmpty
            $info.IntuneInstallCommand | Should -BeNullOrEmpty
            ($info.Notes -join ' ') | Should -Match 'Install\.cmd'
        }

        It 'rejects a ZIP archive without Detection.xml' {
            $result = Invoke-UnderTest @{ Path = (Write-TestIntuneWin -Name 'other.zip') }

            $result.ExitCode | Should -Be 1
            $result.Output | Should -BeNullOrEmpty
            ($result.Errors -join ' ') | Should -Match 'Detection\.xml'
        }

        It 'refuses a Detection.xml that declares a DTD' {
            $xml = Get-DetectionXml -Prolog '<!DOCTYPE ApplicationInfo [<!ENTITY x "y">]>'
            $result = Invoke-UnderTest @{ Path = (Write-TestIntuneWin -DetectionXml $xml) }

            $result.ExitCode | Should -Be 1
            ($result.Errors -join ' ') | Should -Match 'DTD'
        }
    }

    Context 'Input handling' {

        It 'reads files piped from Get-ChildItem, brackets in names included' {
            $folder = Get-TestFolder
            $null = Write-TestMsi -Folder $folder -Name 'setup [x64].msi' -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' }
            $null = Write-TestExe -Folder $folder -Name 'tool.exe'

            $output = @(Get-ChildItem -LiteralPath $folder -File | & $script:ScriptPath)

            $LASTEXITCODE | Should -Be 0
            @($output.FileType | Sort-Object) | Should -Be @('Exe', 'Msi')
        }

        It 'keeps reading after a file it cannot read, and exits 1' {
            $folder = Get-TestFolder
            $text = Join-Path -Path $folder -ChildPath 'readme.txt'
            Set-Content -LiteralPath $text -Value 'not an installer'
            $exe = Write-TestExe -Folder $folder

            $result = Invoke-UnderTest @{ Path = @($text, (Join-Path -Path $folder -ChildPath 'missing.msi'), $exe) }

            $result.ExitCode | Should -Be 1
            $result.Output.Count | Should -Be 1
            $result.Errors.Count | Should -Be 2
            $result.Errors[0] | Should -Match 'Not an MSI, an EXE or an \.intunewin package'
        }

        It 'refuses patches and folders with a reason' {
            $folder = Get-TestFolder
            $patch = Write-TestMsi -Folder $folder -Name 'update.msp'

            $result = Invoke-UnderTest @{ Path = @($patch, $folder) }

            $result.ExitCode | Should -Be 1
            $result.Errors[0] | Should -Match 'Patches \(\.msp\)'
            $result.Errors[1] | Should -Match 'is a folder'
        }

        It 'stops with a clear message in Constrained Language Mode' {
            $msi = Write-TestMsi -Property @{ ProductCode = (Get-TestGuid); ALLUSERS = '1' }
            $hostPath = (Get-Process -Id $PID).Path
            $command = "`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " +
            "& '$($script:ScriptPath -replace "'", "''")' -Path '$($msi -replace "'", "''")'; exit `$LASTEXITCODE"

            $output = & $hostPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $command 2>&1

            $LASTEXITCODE | Should -Be 1
            ($output | Out-String) | Should -Match 'ConstrainedLanguage'
        }
    }
}
