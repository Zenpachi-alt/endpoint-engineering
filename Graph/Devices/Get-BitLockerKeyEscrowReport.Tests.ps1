# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-BitLockerKeyEscrowReport.ps1: what it asks Graph for,
    and how it joins devices to keys and decides each device's status.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without running
    its main block, and Get-GraphCollection is replaced by a stand-in tenant
    held in memory. Nothing reaches Graph and no module is needed.

    The stand-in answers only the two collections the script is meant to
    read, and records every request, so a request for the key property, or
    for anything else, fails the tests.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Devices\Get-BitLockerKeyEscrowReport.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-BitLockerKeyEscrowReport.ps1'

    # Every top-level function of the script, without the main block.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Get-BitLockerKeyEscrowReport.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }

    $script:Base = 'https://graph.microsoft.com/v1.0'
    $script:DevicesUri = "$script:Base/deviceManagement/managedDevices"
    $script:KeysUri = "$script:Base/informationProtection/bitlocker/recoveryKeys"
    $script:Reads = [System.Collections.Generic.List[object]]::new()

    # Defined after the script's functions, so it replaces the helper. It
    # takes only the parameters the script passes, so a new one fails here.
    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })
        if ($script:Failures.ContainsKey($Uri)) { throw $script:Failures[$Uri] }

        $source = switch ($Uri) {
            $script:DevicesUri { $script:Devices }
            $script:KeysUri { $script:Keys }
            default { throw "The stand-in tenant has no collection at $Uri" }
        }

        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in @($source)) { $items.Add($entry) }
        return , $items
    }

    function Get-StandInDevice {
        # A managedDevice as Graph v1.0 returns it.
        param (
            [string]$Name = 'DESKTOP-EXAMPLE',
            [string]$EntraId = [guid]::NewGuid().ToString(),
            [string]$OperatingSystem = 'Windows',
            [object]$IsEncrypted = $true,
            [object]$LastSync = '2026-09-20T08:00:00Z'
        )

        [pscustomobject]@{
            id                = [guid]::NewGuid().ToString()
            deviceName        = $Name
            userPrincipalName = 'user@contoso.com'
            operatingSystem   = $OperatingSystem
            azureADDeviceId   = $EntraId
            isEncrypted       = $IsEncrypted
            lastSyncDateTime  = $LastSync
        }
    }

    function Get-StandInKey {
        # A bitlockerRecoveryKey as the list returns it: never with the key.
        param (
            [string]$DeviceId,
            [object]$VolumeType = 'operatingSystemVolume',
            [object]$Created = '2026-09-01T10:00:00Z',
            [string]$Id = [guid]::NewGuid().ToString()
        )

        [pscustomobject]@{
            id              = $Id
            createdDateTime = $Created
            deviceId        = $DeviceId
            volumeType      = $VolumeType
        }
    }

    function Get-SingleRecord {
        # Runs the join and returns the only record it makes.
        param ([object[]]$Device, [object[]]$Key = @())

        $records = @(ConvertTo-EscrowReport -Device $Device -Key $Key)
        if ($records.Count -ne 1) { throw "Expected one record, got $($records.Count)." }
        $records[0]
    }
}

Describe 'Get-EscrowReportData' {

    BeforeEach {
        $script:Reads.Clear()
        $script:Devices = @()
        $script:Keys = @()
        $script:Failures = @{}
    }

    It 'reads every managed device and every recovery key, and nothing else' {
        $script:Devices = @(Get-StandInDevice)
        $script:Keys = @(Get-StandInKey -DeviceId $script:Devices[0].azureADDeviceId)

        $data = Get-EscrowReportData -BaseUri $script:Base -MaximumAttempt 3

        @($script:Reads | ForEach-Object Uri) | Should -Be @($script:DevicesUri, $script:KeysUri)
        @($script:Reads | ForEach-Object MaximumAttempt) | Should -Be @(3, 3)
        $data.Devices.Count | Should -Be 1
        $data.Keys.Count | Should -Be 1
    }

    It 'never asks for the key itself' {
        $null = Get-EscrowReportData -BaseUri $script:Base

        $script:Reads | Where-Object { $_.Uri -match '[?&]\$select|key\b(?!s)' } | Should -BeNullOrEmpty
    }

    It 'names the roles that may list keys when the listing is refused' {
        $refused = [System.Exception]::new("HTTP 403 from GET $script:KeysUri after 1 attempt(s): Authorization_RequestDenied")
        $refused.Data['StatusCode'] = 403
        $script:Failures[$script:KeysUri] = $refused

        { Get-EscrowReportData -BaseUri $script:Base } | Should -Throw -ExpectedMessage '*HTTP 403*Global Reader*Intune Administrator*Authorization_RequestDenied*'
    }

    It 'passes on any other failure unchanged' {
        $unavailable = [System.Exception]::new('HTTP 503 from GET after 5 attempt(s)')
        $unavailable.Data['StatusCode'] = 503
        $script:Failures[$script:KeysUri] = $unavailable

        { Get-EscrowReportData -BaseUri $script:Base } | Should -Throw -ExpectedMessage 'HTTP 503 from GET after 5 attempt(s)'
    }
}

Describe 'The report' {

    BeforeAll {
        # The body of the main block's try, without the catch around it,
        # whose exit would end the test run.
        $try = $syntaxTree.EndBlock.Statements[-1]
        if ($try -isnot [System.Management.Automation.Language.TryStatementAst]) { throw 'The main block is not a try statement.' }
        $body = $try.Body.Extent.Text
        $script:MainBlock = [scriptblock]::Create($body.Substring(1, $body.Length - 2))

        $script:SignIns = [System.Collections.Generic.List[object]]::new()
        $script:Scopes = [ordered]@{ 'Example.Read.All' = @('Example.ReadWrite.All') }

        # Signs nothing in: the stand-in tenant needs no session. Records what
        # it was asked for.
        function Connect-GraphSession {
            param ($Scope, $TenantId, [switch]$UseDeviceCode)

            $script:SignIns.Add([pscustomobject]@{
                    Scope         = $Scope
                    TenantId      = $TenantId
                    UseDeviceCode = $UseDeviceCode.IsPresent
                    ReadsBefore   = $script:Reads.Count
                })
            $false
        }

        function Invoke-Report {
            # Runs the main block as the script would with these parameters,
            # and separates what it returns, warns and says verbosely.
            param ([string[]]$StatusFilter, [string]$CsvFolder, [string]$Tenant = '', [switch]$DeviceCode)

            # The main block reads the script's parameters and settings from
            # the scope that runs it.
            Set-Variable -Name 'Status' -Value $StatusFilter
            Set-Variable -Name 'CsvPath' -Value $CsvFolder
            Set-Variable -Name 'TenantId' -Value $Tenant
            Set-Variable -Name 'UseDeviceCode' -Value $DeviceCode
            Set-Variable -Name 'MaximumRetryCount' -Value 5
            Set-Variable -Name 'GraphBaseUri' -Value $script:Base
            Set-Variable -Name 'RequiredScopes' -Value $script:Scopes
            Set-Variable -Name 'KeyCountWarningThreshold' -Value 150
            Set-Variable -Name 'VerbosePreference' -Value 'Continue'
            Set-Variable -Name 'ErrorActionPreference' -Value 'Stop'

            $all = @(& $script:MainBlock 3>&1 4>&1)
            [pscustomobject]@{
                Rows     = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.VerboseRecord] })
                Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)
                Verbose  = @($all | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object Message)
            }
        }
    }

    BeforeEach {
        $script:Reads.Clear()
        $script:SignIns.Clear()
        $script:Failures = @{}

        $escrowed = Get-StandInDevice -Name 'ESCROWED'
        $missing = Get-StandInDevice -Name 'MISSING'
        $phone = Get-StandInDevice -Name 'PHONE' -OperatingSystem 'iOS'
        $script:Devices = @($escrowed, $missing, $phone)
        $script:Keys = @(
            Get-StandInKey -DeviceId $escrowed.azureADDeviceId
            # A key of a device Intune does not manage.
            Get-StandInKey -DeviceId ([guid]::NewGuid().ToString())
        )
    }

    It 'signs in once, before reading, with its scopes and the tenant and sign-in method it was given' {
        $tenant = [guid]::NewGuid().ToString()

        $null = Invoke-Report -Tenant $tenant -DeviceCode

        $script:SignIns | Should -HaveCount 1
        $script:SignIns[0].ReadsBefore | Should -Be 0
        [object]::ReferenceEquals($script:SignIns[0].Scope, $script:Scopes) | Should -BeTrue
        $script:SignIns[0].TenantId | Should -Be $tenant
        $script:SignIns[0].UseDeviceCode | Should -BeTrue
    }

    It 'returns one row per Windows device' {
        $run = Invoke-Report

        @($run.Rows | ForEach-Object DeviceName | Sort-Object) | Should -Be @('ESCROWED', 'MISSING')
        $run.Warnings | Should -BeNullOrEmpty
    }

    It 'keeps only the statuses -Status names' {
        $run = Invoke-Report -StatusFilter 'MissingKey'

        @($run.Rows | ForEach-Object DeviceName) | Should -Be @('MISSING')
    }

    It 'counts each status, and the keys of devices it does not report' {
        $run = Invoke-Report

        $run.Verbose | Should -Contain 'Escrowed: 1'
        $run.Verbose | Should -Contain 'MissingKey: 1'
        $run.Verbose | Should -Contain '1 key(s) belong to devices Intune does not manage as Windows devices, and are not reported.'
    }

    It 'names the devices close to the limit of 200 keys' {
        $crowded = Get-StandInDevice -Name 'CROWDED'
        $script:Devices = @($script:Devices) + $crowded
        $script:Keys = @($script:Keys) + @(1..150 | ForEach-Object { Get-StandInKey -DeviceId $crowded.azureADDeviceId })

        $run = Invoke-Report

        $run.Warnings | Should -HaveCount 1
        $run.Warnings[0] | Should -BeLike '1 device(s) hold 150 or more recovery keys*CROWDED (150).'
    }

    It 'warns when no device matches' {
        $run = Invoke-Report -StatusFilter 'NoEntraDevice'

        $run.Rows | Should -BeNullOrEmpty
        $run.Warnings | Should -Contain 'No devices matched. Check -Status, or whether the tenant has Windows devices enrolled.'
    }

    It 'writes the rows it returns to a timestamped CSV, with no key column' {
        $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $folder

        $run = Invoke-Report -CsvFolder $folder

        $file = @(Get-ChildItem -LiteralPath $folder -Filter 'BitLockerKeyEscrowReport-*.csv')
        $file | Should -HaveCount 1
        $csv = @(Import-Csv -LiteralPath $file[0].FullName)
        $csv | Should -HaveCount $run.Rows.Count
        @($csv[0].PSObject.Properties.Name) | Should -Not -Contain 'Key'
    }
}

Describe 'ConvertTo-VolumeKind' {

    It 'reads <Value> as <Expected>' -ForEach @(
        @{ Value = 'operatingSystemVolume'; Expected = 'OperatingSystem' }
        @{ Value = 1; Expected = 'OperatingSystem' }
        @{ Value = 'fixedDataVolume'; Expected = 'FixedData' }
        @{ Value = '2'; Expected = 'FixedData' }
        @{ Value = 'removableDataVolume'; Expected = 'Removable' }
        @{ Value = 'unknownFutureValue'; Expected = 'Unknown' }
        @{ Value = $null; Expected = 'Unknown' }
    ) {
        ConvertTo-VolumeKind -VolumeType $Value | Should -Be $Expected
    }
}

Describe 'ConvertTo-EscrowReport' {

    Context 'status' {

        It 'is Escrowed when Entra ID holds an OS volume key' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Key (Get-StandInKey -DeviceId $device.azureADDeviceId)

            $record.Status | Should -Be 'Escrowed'
            $record.OsVolumeKeyCount | Should -Be 1
        }

        It 'is Escrowed when a key is held, whatever Intune reports about encryption' {
            $device = Get-StandInDevice -IsEncrypted $false

            $record = Get-SingleRecord -Device $device -Key (Get-StandInKey -DeviceId $device.azureADDeviceId)

            $record.Status | Should -Be 'Escrowed'
        }

        It 'is MissingKey for an encrypted device with no key' {
            $record = Get-SingleRecord -Device (Get-StandInDevice)

            $record.Status | Should -Be 'MissingKey'
            $record.KeyCount | Should -Be 0
            $record.KeyIds | Should -Be ''
        }

        It 'is MissingKey for an encrypted device with only a fixed data volume key' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Key (Get-StandInKey -DeviceId $device.azureADDeviceId -VolumeType 'fixedDataVolume')

            $record.Status | Should -Be 'MissingKey'
            $record.FixedDataKeyCount | Should -Be 1
            $record.KeyCount | Should -Be 1
        }

        It 'is NotEncrypted for a device Intune reports as <Case>, with no key' -ForEach @(
            @{ Case = 'not encrypted'; Value = $false }
            @{ Case = 'unknown'; Value = $null }
        ) {
            $record = Get-SingleRecord -Device (Get-StandInDevice -IsEncrypted $Value)

            $record.Status | Should -Be 'NotEncrypted'
        }

        It 'is NoEntraDevice for a device whose Entra device ID is <Case>' -ForEach @(
            @{ Case = 'missing'; Value = '' }
            @{ Case = 'all zeros'; Value = [guid]::Empty.ToString() }
            @{ Case = 'not a GUID'; Value = 'unknown' }
        ) {
            $script:Orphan = Get-StandInKey -DeviceId $Value

            $record = Get-SingleRecord -Device (Get-StandInDevice -EntraId $Value) -Key $script:Orphan

            $record.Status | Should -Be 'NoEntraDevice'
            $record.KeyCount | Should -Be 0
        }
    }

    Context 'joining devices to keys' {

        It 'matches the Entra device ID without regard to case' {
            $device = Get-StandInDevice
            $device.azureADDeviceId = $device.azureADDeviceId.ToUpperInvariant()

            $record = Get-SingleRecord -Device $device -Key (Get-StandInKey -DeviceId $device.azureADDeviceId.ToLowerInvariant())

            $record.Status | Should -Be 'Escrowed'
        }

        It 'counts only the keys of the device itself' {
            $mine = Get-StandInDevice -Name 'MINE'
            $other = Get-StandInDevice -Name 'OTHER'
            $keys = @(
                Get-StandInKey -DeviceId $mine.azureADDeviceId
                Get-StandInKey -DeviceId $other.azureADDeviceId
                Get-StandInKey -DeviceId $other.azureADDeviceId -VolumeType 'fixedDataVolume'
            )

            $records = @(ConvertTo-EscrowReport -Device @($mine, $other) -Key $keys)

            ($records | Where-Object DeviceName -EQ 'MINE').KeyCount | Should -Be 1
            ($records | Where-Object DeviceName -EQ 'OTHER').KeyCount | Should -Be 2
        }

        It 'reports only Windows devices' {
            $devices = @((Get-StandInDevice -Name 'PC'), (Get-StandInDevice -Name 'PHONE' -OperatingSystem 'iOS'), (Get-StandInDevice -Name 'MAC' -OperatingSystem 'macOS'))

            $records = @(ConvertTo-EscrowReport -Device $devices -Key @())

            @($records | ForEach-Object DeviceName) | Should -Be @('PC')
        }

        It 'returns nothing for an empty tenant' {
            @(ConvertTo-EscrowReport -Device @() -Key @()) | Should -HaveCount 0
        }
    }

    Context 'the record' {

        It 'lists the key IDs in lower case and in order, as Entra ID shows them' {
            $device = Get-StandInDevice
            $ids = @([guid]::NewGuid().ToString().ToUpperInvariant(), [guid]::NewGuid().ToString().ToUpperInvariant())
            $keys = @($ids | ForEach-Object { Get-StandInKey -DeviceId $device.azureADDeviceId -Id $_ })

            $record = Get-SingleRecord -Device $device -Key $keys

            $record.KeyIds | Should -BeExactly ((@($ids | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)) -join '; ')
        }

        It 'gives the date of the latest key in UTC, from text or from a DateTime' {
            $device = Get-StandInDevice
            $keys = @(
                Get-StandInKey -DeviceId $device.azureADDeviceId -Created '2026-09-01T10:00:00Z'
                Get-StandInKey -DeviceId $device.azureADDeviceId -Created ([datetime]::new(2026, 9, 15, 12, 0, 0, [DateTimeKind]::Utc))
                Get-StandInKey -DeviceId $device.azureADDeviceId -Created '2026-09-10T10:00:00+02:00'
            )

            $record = Get-SingleRecord -Device $device -Key $keys

            $record.LatestKeyDateTime | Should -Be ([datetime]::new(2026, 9, 15, 12, 0, 0, [DateTimeKind]::Utc))
            $record.LatestKeyDateTime.Kind | Should -Be 'Utc'
        }

        It 'counts days since the last sync, and leaves them empty for a device that never synced' {
            $recent = Get-StandInDevice -Name 'RECENT' -LastSync ([datetime]::UtcNow.AddDays(-3).ToString('o'))
            $never = Get-StandInDevice -Name 'NEVER' -LastSync $null

            $records = @(ConvertTo-EscrowReport -Device @($recent, $never) -Key @())

            ($records | Where-Object DeviceName -EQ 'RECENT').DaysSinceLastSync | Should -Be 3
            ($records | Where-Object DeviceName -EQ 'NEVER').DaysSinceLastSync | Should -BeNullOrEmpty
        }

        It 'has no property that could hold a recovery key' {
            $device = Get-StandInDevice

            $record = Get-SingleRecord -Device $device -Key (Get-StandInKey -DeviceId $device.azureADDeviceId)

            @($record.PSObject.Properties.Name) | Should -Not -Contain 'Key'
            @($record.PSObject.Properties.Name) | Should -Not -Contain 'RecoveryKey'
        }
    }
}
