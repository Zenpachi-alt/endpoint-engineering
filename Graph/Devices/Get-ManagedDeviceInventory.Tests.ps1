# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Get-ManagedDeviceInventory.ps1: the record it makes of
    each device, the filters it applies after the devices arrive, and what it
    asks Graph for.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without its main
    block, and Get-GraphCollection is replaced by a stand-in tenant held in
    memory that records every request. Nothing reaches Graph and no module is
    needed.

    The main block runs as the script runs it, after its own param block,
    settings and constants, because it decides on -StaleAfterDays by whether
    the parameter was bound, and a value of its own would not show that.

    The script's Graph helpers are tested by Templates/Script-Template.Tests.ps1.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Devices\Get-ManagedDeviceInventory.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-ManagedDeviceInventory.ps1'

    # Every top-level function of the script, without the main block. The
    # script runs under Set-StrictMode -Version Latest, so each function gets
    # it as its first statement here too.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Get-ManagedDeviceInventory.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $text = $statement.Extent.Text
            $at = $statement.Body.ParamBlock.Extent.EndOffset - $statement.Extent.StartOffset
            . ([scriptblock]::Create($text.Substring(0, $at) + "`nSet-StrictMode -Version Latest`n" + $text.Substring($at)))
        }
    }

    $script:Base = 'https://graph.microsoft.com/v1.0'
    $script:Reads = [System.Collections.Generic.List[object]]::new()

    # The script takes the time from the clock, so the stand-in tenant is
    # dated from it too. Whole seconds, as Graph sends them.
    $clock = [datetime]::UtcNow
    $script:Now = [datetime]::new($clock.Year, $clock.Month, $clock.Day, $clock.Hour, $clock.Minute, $clock.Second, [DateTimeKind]::Utc)

    # Defined after the script's functions, so it replaces the helper. It
    # takes only the parameters the script passes, so a new one fails here.
    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })
        if ($Uri -notlike "$script:Base/deviceManagement/managedDevices?*") { throw "The stand-in tenant has no collection at $Uri" }

        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($device in @($script:Devices)) { $items.Add($device) }
        return , $items
    }

    function Get-StandInDevice {
        # A managedDevice as Graph v1.0 returns it.
        param (
            [string]$Name = 'PC01',
            [object]$OperatingSystem = 'Windows',
            [string]$ComplianceState = 'compliant',
            [string]$Ownership = 'company',
            [object]$DaysSinceSync = 3
        )

        $sync = $null
        if ($null -ne $DaysSinceSync) { $sync = $script:Now.AddDays(-$DaysSinceSync).ToString('yyyy-MM-ddTHH:mm:ssZ') }

        [pscustomobject]@{
            id                        = [guid]::NewGuid().ToString()
            deviceName                = $Name
            userPrincipalName         = 'user{0}@{1}' -f (Get-Random -Minimum 100 -Maximum 999), 'contoso.com'
            userDisplayName           = 'Example User'
            operatingSystem           = $OperatingSystem
            osVersion                 = '10.0.26100.1000'
            complianceState           = $ComplianceState
            managedDeviceOwnerType    = $Ownership
            managementAgent           = 'mdm'
            deviceEnrollmentType      = 'windowsAzureADJoin'
            deviceRegistrationState   = 'registered'
            enrolledDateTime          = '2025-01-15T09:00:00Z'
            lastSyncDateTime          = $sync
            manufacturer              = 'Example'
            model                     = 'Example Laptop'
            serialNumber              = 'PF{0}' -f (Get-Random -Minimum 10000000 -Maximum 99999999)
            isEncrypted               = $true
            isSupervised              = $false
            totalStorageSpaceInBytes  = 512GB
            freeStorageSpaceInBytes   = 123456789012
            deviceCategoryDisplayName = 'Unknown'
            azureADDeviceId           = [guid]::NewGuid().ToString()
        }
    }
}

Describe 'ConvertTo-DeviceRecord' {

    It 'flattens a device into the documented columns, in order' {
        $record = ConvertTo-DeviceRecord -Device (Get-StandInDevice)

        @($record.PSObject.Properties | ForEach-Object { $_.Name }) | Should -Be @(
            'DeviceName', 'UserPrincipalName', 'UserDisplayName', 'OperatingSystem', 'OsVersion', 'ComplianceState',
            'Ownership', 'ManagementAgent', 'EnrollmentType', 'RegistrationState', 'EnrolledDateTime',
            'LastSyncDateTime', 'DaysSinceLastSync', 'Manufacturer', 'Model', 'SerialNumber', 'IsEncrypted',
            'IsSupervised', 'StorageTotalGB', 'StorageFreeGB', 'Category', 'EntraDeviceId', 'IntuneDeviceId'
        )
    }

    It 'takes ownership from managedDeviceOwnerType and the IDs from id and azureADDeviceId' {
        $device = Get-StandInDevice -Ownership 'personal'

        $record = ConvertTo-DeviceRecord -Device $device

        $record.Ownership | Should -Be 'personal'
        $record.IntuneDeviceId | Should -Be $device.id
        $record.EntraDeviceId | Should -Be $device.azureADDeviceId
    }

    It 'gives storage in GB to one decimal, and nothing when Intune reports none' {
        $device = Get-StandInDevice
        $record = ConvertTo-DeviceRecord -Device $device

        $record.StorageTotalGB | Should -Be 512
        $record.StorageFreeGB | Should -Be 115

        $device.totalStorageSpaceInBytes = 0
        $device.PSObject.Properties.Remove('freeStorageSpaceInBytes')
        $record = ConvertTo-DeviceRecord -Device $device

        $record.StorageTotalGB | Should -BeNullOrEmpty
        $record.StorageFreeGB | Should -BeNullOrEmpty
    }

    It 'counts days since the last sync, and leaves them empty for a device that never synced' {
        (ConvertTo-DeviceRecord -Device (Get-StandInDevice -DaysSinceSync 45)).DaysSinceLastSync | Should -Be 45

        $never = ConvertTo-DeviceRecord -Device (Get-StandInDevice -DaysSinceSync $null)
        $never.DaysSinceLastSync | Should -BeNullOrEmpty
        $never.LastSyncDateTime | Should -BeNullOrEmpty
    }

    It 'gives both timestamps in UTC, from text or from a DateTime as PowerShell 7.0 to 7.4 parse it' {
        $device = Get-StandInDevice
        $device.lastSyncDateTime = $script:Now.AddDays(-5)
        $device.enrolledDateTime = [datetime]::new(2025, 1, 15, 9, 0, 0, [DateTimeKind]::Unspecified)

        $record = ConvertTo-DeviceRecord -Device $device

        $record.LastSyncDateTime.Kind | Should -Be 'Utc'
        $record.DaysSinceLastSync | Should -Be 5
        $record.EnrolledDateTime | Should -Be ([datetime]::new(2025, 1, 15, 9, 0, 0, [DateTimeKind]::Utc))
        $record.EnrolledDateTime.Kind | Should -Be 'Utc'
    }
}

Describe 'The main block' {

    BeforeAll {
        # The script as it runs, but for its module check and its final
        # catch: its param block, its settings and constants, and the body of
        # its main try. -StaleAfterDays applies only when it is bound, and
        # this way it is bound only when a test passes it.
        $try = $syntaxTree.EndBlock.Statements[-1]
        if ($try -isnot [System.Management.Automation.Language.TryStatementAst]) { throw 'The main block is not a try statement.' }
        $body = $try.Body.Extent.Text
        if (@($try.Body.FindAll({ param ($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true)).Count -gt 0) {
            throw 'The main block has an exit statement, which would end the test run.'
        }

        $settings = @($syntaxTree.EndBlock.Statements |
                Where-Object {
                    $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $_ -isnot [System.Management.Automation.Language.TryStatementAst]
                } |
                ForEach-Object { $_.Extent.Text })

        $paramBlock = $syntaxTree.ParamBlock
        $script:MainBlock = [scriptblock]::Create((@(
                    @($paramBlock.Attributes | ForEach-Object { $_.Extent.Text })
                    $paramBlock.Extent.Text
                    $settings
                    $body.Substring(1, $body.Length - 2)
                ) -join "`n"))

        $script:SignIns = [System.Collections.Generic.List[object]]::new()

        # Signs nothing in: the stand-in tenant needs no session.
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

        function Invoke-Inventory {
            # Runs the script with these arguments, and separates what it
            # returns and warns from why it failed.
            param ([hashtable]$Argument = @{})

            $all = [System.Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                & $script:MainBlock @Argument 3>&1 | ForEach-Object { $all.Add($_) }
            }
            catch {
                $failure = $_.Exception.Message
            }

            [pscustomobject]@{
                Rows     = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
                Names    = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.DeviceName })
                Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
                Failure  = $failure
            }
        }
    }

    BeforeEach {
        $script:Reads.Clear()
        $script:SignIns.Clear()

        # One device for each value the filters tell apart.
        $script:Devices = @(
            Get-StandInDevice -Name 'WIN-CURRENT' -DaysSinceSync 3
            Get-StandInDevice -Name 'WIN-STALE' -ComplianceState 'noncompliant' -DaysSinceSync 45
            Get-StandInDevice -Name 'WIN-NEVER' -ComplianceState 'noncompliant' -Ownership 'personal' -DaysSinceSync $null
            Get-StandInDevice -Name 'MAC' -OperatingSystem 'macOS' -Ownership 'personal' -DaysSinceSync 31
            Get-StandInDevice -Name 'PHONE' -OperatingSystem 'iOS' -ComplianceState 'inGracePeriod' -Ownership 'personal' -DaysSinceSync 10
            Get-StandInDevice -Name 'NO-OS' -OperatingSystem $null -ComplianceState 'unknown' -Ownership 'unknown' -DaysSinceSync 100
        )
    }

    It 'signs in once, before reading, and returns every device when no filter is given' {
        $run = Invoke-Inventory

        $script:SignIns | Should -HaveCount 1
        $script:SignIns[0].ReadsBefore | Should -Be 0
        [string[]]@($script:SignIns[0].Scope.Keys) | Should -Be @('DeviceManagementManagedDevices.Read.All')
        $run.Names | Should -Be @('WIN-CURRENT', 'WIN-STALE', 'WIN-NEVER', 'MAC', 'PHONE', 'NO-OS')
        $run.Failure | Should -BeNullOrEmpty
    }

    It 'reads every device in one request, with $top and no filter of its own' {
        $null = Invoke-Inventory -Argument @{ OperatingSystem = 'Windows'; ComplianceState = 'noncompliant'; MaximumRetryCount = 3 }

        $script:Reads | Should -HaveCount 1
        $script:Reads[0].Uri | Should -BeExactly "$script:Base/deviceManagement/managedDevices?`$top=200"
        $script:Reads[0].MaximumAttempt | Should -Be 3
    }

    It 'sends -Filter to the service, URL-encoded, with -PageSize as $top' {
        $filter = "operatingSystem eq 'Windows'"

        $null = Invoke-Inventory -Argument @{ Filter = $filter; PageSize = 50 }

        $query = ($script:Reads[0].Uri -split '\?', 2)[1]
        $query | Should -Not -Match ' '
        @($query -split '&') | Should -Be @('$top=50', "`$filter=$([uri]::EscapeDataString($filter))")
        [uri]::UnescapeDataString(($query -split '&')[1].Substring(8)) | Should -BeExactly $filter
    }

    It '-OperatingSystem keeps the systems named, without regard to case, and never a device with none' {
        $run = Invoke-Inventory -Argument @{ OperatingSystem = 'windows', 'IOS' }

        $run.Names | Should -Be @('WIN-CURRENT', 'WIN-STALE', 'WIN-NEVER', 'PHONE')
    }

    It '-ComplianceState keeps the states named' {
        $run = Invoke-Inventory -Argument @{ ComplianceState = 'noncompliant', 'inGracePeriod' }

        $run.Names | Should -Be @('WIN-STALE', 'WIN-NEVER', 'PHONE')
    }

    It '-Ownership keeps the ownership types named' {
        $run = Invoke-Inventory -Argument @{ Ownership = 'personal' }

        $run.Names | Should -Be @('WIN-NEVER', 'MAC', 'PHONE')
    }

    It '-StaleAfterDays keeps devices that have not synced for at least that many days, and those that never synced' {
        $run = Invoke-Inventory -Argument @{ StaleAfterDays = 31 }

        $run.Names | Should -Be @('WIN-STALE', 'WIN-NEVER', 'MAC', 'NO-OS')
    }

    It '-StaleAfterDays <Days> <Outcome> a device last synced 31 days ago' -ForEach @(
        @{ Days = 30; Outcome = 'keeps'; Kept = $true }
        @{ Days = 31; Outcome = 'keeps'; Kept = $true }
        @{ Days = 32; Outcome = 'leaves out'; Kept = $false }
    ) {
        $run = Invoke-Inventory -Argument @{ StaleAfterDays = $Days }

        $run.Names -contains 'MAC' | Should -Be $Kept
    }

    It 'applies every filter given, together' {
        $run = Invoke-Inventory -Argument @{ OperatingSystem = 'Windows'; ComplianceState = 'noncompliant'; Ownership = 'company'; StaleAfterDays = 30 }

        $run.Names | Should -Be @('WIN-STALE')
    }

    It 'warns, and returns nothing, when no device matches' {
        $run = Invoke-Inventory -Argument @{ OperatingSystem = 'macOS'; Ownership = 'company' }

        $run.Rows | Should -HaveCount 0
        $run.Warnings | Should -Be @('No devices matched. Check the filters, or whether the tenant has enrolled devices.')
        $run.Failure | Should -BeNullOrEmpty
    }

    It 'writes the rows it returns to ManagedDeviceInventory-<time>.csv in -CsvPath' {
        $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $folder

        $run = Invoke-Inventory -Argument @{ Ownership = 'personal'; CsvPath = $folder }

        $files = @(Get-ChildItem -LiteralPath $folder -File)
        $files | Should -HaveCount 1
        $files[0].Name | Should -Match '^ManagedDeviceInventory-\d{8}-\d{6}\.csv$'
        @(Import-Csv -LiteralPath $files[0].FullName | ForEach-Object { $_.DeviceName }) | Should -Be $run.Names
    }

    It 'refuses <Case>, before signing in' -ForEach @(
        @{ Case = 'a compliance state Intune does not have'; Argument = @{ ComplianceState = 'compliantish' }; Named = 'ComplianceState' }
        @{ Case = 'an ownership type Intune does not have'; Argument = @{ Ownership = 'shared' }; Named = 'Ownership' }
        @{ Case = '-StaleAfterDays 0'; Argument = @{ StaleAfterDays = 0 }; Named = 'StaleAfterDays' }
        @{ Case = 'an empty -OperatingSystem'; Argument = @{ OperatingSystem = @('') }; Named = 'OperatingSystem' }
    ) {
        $run = Invoke-Inventory -Argument $Argument

        $run.Failure | Should -BeLike "*parameter '$Named'*"
        $script:SignIns | Should -HaveCount 0
    }
}
