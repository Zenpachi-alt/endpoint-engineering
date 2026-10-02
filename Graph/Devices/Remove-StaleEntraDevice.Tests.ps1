# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Remove-StaleEntraDevice.ps1: which devices it leaves
    alone and why, what each stage decides, what it sends when it disables or
    deletes, and what it refuses to do.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without running
    its main block, and Get-GraphCollection and Invoke-GraphRequestWithRetry
    are replaced by a stand-in tenant held in memory. The stand-in applies
    the changes it is sent, so a device that was disabled or deleted can be
    seen to be, and it records every request, so a change to a device that
    should have been left alone fails here. Nothing reaches Graph and no
    module is needed.

    The script is also started as a file, in a child process, for its exit
    code and its message. The test that gets past the script's module check
    is skipped where Microsoft.Graph.Authentication is not installed.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Devices\Remove-StaleEntraDevice.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Microsoft.Graph.Authentication 2.0.0 or later, optional,
                    for one test of the script run as a file.
#>

BeforeDiscovery {
    # The script loads the module before anything else, so it gets as far as
    # its own checks only where the module is installed for the PowerShell
    # that runs the tests.
    $script:ModuleAvailable = [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
            Where-Object { $_.Version -ge [version]'2.0.0' })
}

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Remove-StaleEntraDevice.ps1'
    $script:ScriptPath = $scriptPath

    # Every top-level function of the script, without the main block.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Remove-StaleEntraDevice.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }

    $script:Base = 'https://graph.microsoft.com/v1.0'
    $script:Format = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    $script:GroupId = [guid]::NewGuid().ToString()

    # The main block takes the time from the clock, so the stand-in tenant is
    # dated from it too. Whole seconds, as Graph sends them.
    $clock = [datetime]::UtcNow
    $script:Now = [datetime]::new($clock.Year, $clock.Month, $clock.Day, $clock.Hour, $clock.Minute, $clock.Second, [DateTimeKind]::Utc)

    $script:Reads = [System.Collections.Generic.List[object]]::new()
    $script:Writes = [System.Collections.Generic.List[object]]::new()
    $script:Devices = [System.Collections.Generic.List[object]]::new()

    function Get-GraphFailure {
        # The exception the real helper throws: the status in Data.
        param ([int]$StatusCode, [string]$Message)

        $exception = [System.Exception]::new("HTTP $StatusCode from Graph after 1 attempt(s): $Message")
        $exception.Data['StatusCode'] = $StatusCode
        $exception
    }

    # Defined after the script's functions, so they replace the helpers. They
    # take only the parameters the script passes, so a new one fails here.
    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })

        $kind = if ($Uri -like "$script:Base/devices?*") { 'devices' }
        elseif ($Uri -eq "$script:Base/deviceManagement/managedDevices") { 'managedDevices' }
        elseif ($Uri -eq "$script:Base/informationProtection/bitlocker/recoveryKeys") { 'recoveryKeys' }
        elseif ($Uri -eq "$script:Base/groups/$script:GroupId/transitiveMembers?`$select=id&`$top=999") { 'members' }
        else { throw "The stand-in tenant has no collection at $Uri" }

        if ($script:ReadFailures.ContainsKey($kind)) { throw $script:ReadFailures[$kind] }

        $items = [System.Collections.Generic.List[object]]::new()
        switch ($kind) {
            'devices' { foreach ($entry in @($script:Devices)) { $items.Add($entry) } }
            'managedDevices' { foreach ($entry in @($script:ManagedDevices)) { $items.Add($entry) } }
            'recoveryKeys' { foreach ($entry in @($script:Keys)) { $items.Add($entry) } }
            'members' { foreach ($entry in @($script:Members)) { $items.Add([pscustomobject]@{ id = $entry }) } }
        }
        return , $items
    }

    function Invoke-GraphRequestWithRetry {
        param ([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', [hashtable]$Body, [int]$MaximumAttempt)

        $path = ($Uri -split '\?', 2)[0]
        $objectId = ($path -split '/')[-1]
        $found = @($script:Devices | Where-Object { $_.id -eq $objectId })

        if ($Method -eq 'GET') {
            $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })

            if ($path -eq "$script:Base/groups/$script:GroupId") {
                if ($script:ReadFailures.ContainsKey('group')) { throw $script:ReadFailures['group'] }
                if ($null -eq $script:Group) { throw (Get-GraphFailure -StatusCode 404 -Message 'Request_ResourceNotFound') }
                return $script:Group
            }
            if ($path -like "$script:Base/devices/*") {
                if ($found.Count -eq 0) { throw (Get-GraphFailure -StatusCode 404 -Message 'Request_ResourceNotFound') }
                return $found[0]
            }
            throw "The stand-in tenant has nothing at $Uri"
        }

        $script:Writes.Add([pscustomobject]@{
                Method      = $Method
                Uri         = $Uri
                Body        = $Body
                ObjectId    = $objectId
                ReadsBefore = $script:Reads.Count
            })
        if ($script:WriteFailures.ContainsKey($objectId)) { throw $script:WriteFailures[$objectId] }
        if ($path -notlike "$script:Base/devices/*" -or $found.Count -eq 0) {
            throw (Get-GraphFailure -StatusCode 404 -Message 'Request_ResourceNotFound')
        }

        switch ($Method) {
            'PATCH' { foreach ($name in @($Body.Keys)) { $found[0].$name = $Body[$name] } }
            'DELETE' { $null = $script:Devices.Remove($found[0]) }
            default { throw "The stand-in tenant does not take $Method." }
        }
        return $null
    }

    function Get-StandInDevice {
        # A device as Graph v1.0 returns it with the script's $select.
        param (
            [string]$Name = 'PC01',
            [object]$TrustType = 'AzureAd',
            [object]$Enabled = $true,
            [object]$DaysSinceActivity = 200,
            [object]$ProfileType = 'RegisteredDevice',
            [object]$Restricted = $null,
            [switch]$Autopilot
        )

        $signIn = $null
        if ($null -ne $DaysSinceActivity) { $signIn = $script:Now.AddDays(-$DaysSinceActivity).ToString('yyyy-MM-ddTHH:mm:ssZ') }

        $physicalIds = @('[HWID]:h:example')
        if ($Autopilot) { $physicalIds += "[ZTDID]:$([guid]::NewGuid())" }

        [pscustomobject]@{
            id                            = [guid]::NewGuid().ToString()
            deviceId                      = [guid]::NewGuid().ToString()
            displayName                   = $Name
            accountEnabled                = $Enabled
            approximateLastSignInDateTime = $signIn
            trustType                     = $TrustType
            profileType                   = $ProfileType
            physicalIds                   = $physicalIds
            operatingSystem               = 'Windows'
            operatingSystemVersion        = '10.0.26100.1000'
            isManaged                     = $false
            isManagementRestricted        = $Restricted
            registrationDateTime          = '2023-01-15T09:00:00Z'
        }
    }

    function Get-StandInManagedDevice {
        # A managedDevice as Graph v1.0 returns it, for an Entra device.
        param ([Parameter(Mandatory)]$Device, [object]$DaysSinceSync = 300)

        $sync = $null
        if ($null -ne $DaysSinceSync) { $sync = $script:Now.AddDays(-$DaysSinceSync).ToString('yyyy-MM-ddTHH:mm:ssZ') }

        [pscustomobject]@{
            id               = [guid]::NewGuid().ToString()
            deviceName       = $Device.displayName
            azureADDeviceId  = $Device.deviceId
            lastSyncDateTime = $sync
        }
    }

    function Get-StandInKey {
        # A bitlockerRecoveryKey as the list returns it: never with the key.
        param ([Parameter(Mandatory)]$Device)

        [pscustomobject]@{
            id              = [guid]::NewGuid().ToString()
            createdDateTime = '2025-02-01T10:00:00Z'
            deviceId        = $Device.deviceId
            volumeType      = 'operatingSystemVolume'
        }
    }

    function Initialize-StandInTenant {
        # An empty tenant that refuses nothing.
        $script:Reads.Clear()
        $script:Writes.Clear()
        $script:Devices.Clear()
        $script:ManagedDevices = @()
        $script:Keys = @()
        $script:Members = @()
        $script:Group = [pscustomobject]@{ id = $script:GroupId; displayName = 'Example exclusions' }
        $script:ReadFailures = @{}
        $script:WriteFailures = @{}
    }

    function Add-StandInDevice {
        # Puts devices in the tenant and hands them back.
        param ([Parameter(Mandatory)][object[]]$Device)

        foreach ($entry in $Device) { $script:Devices.Add($entry) }
    }

    function Get-Fact {
        # The facts about every device in the stand-in tenant.
        param ([string[]]$Excluded = @())

        $excludedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($id in $Excluded) { $null = $excludedIds.Add($id) }

        @(Get-DeviceFact -Device @($script:Devices) -ManagedDevice @($script:ManagedDevices) -Key @($script:Keys) `
                -ExcludedId $excludedIds -Now $script:Now)
    }

    function Get-SingleFact {
        # The facts about the only device in the stand-in tenant.
        param ([string[]]$Excluded = @())

        $facts = @(Get-Fact -Excluded $Excluded)
        if ($facts.Count -ne 1) { throw "Expected one device, got $($facts.Count)." }
        $facts[0]
    }

    function Get-Entry {
        # A device's line in a disabled-device file, as the script reads it.
        param ([Parameter(Mandatory)]$Device, [double]$DaysDisabled = 61)

        [pscustomobject]@{
            ObjectId         = $Device.id
            DisplayName      = $Device.displayName
            DisabledDateTime = $script:Now.AddDays(-$DaysDisabled)
        }
    }

    function Get-DisabledFile {
        # Writes a disabled-device file as the script does, and returns its
        # path. Each row is an object ID and the text of the date.
        param ([object[]]$Row = @(), [string]$Header = '"ObjectId","DeviceId","DisplayName","DisabledDateTime","ApproximateLastSignInDateTime"')

        $file = Join-Path -Path $TestDrive -ChildPath "$([guid]::NewGuid().ToString('n')).csv"
        $lines = @($Header) + @($Row | ForEach-Object { '"{0}","","{1}","{2}",""' -f $_.ObjectId, $_.DisplayName, $_.Disabled })
        Set-Content -LiteralPath $file -Value $lines
        $file
    }

    function Get-FileRow {
        # One row for Get-DisabledFile: a device, disabled so many days ago.
        param ([Parameter(Mandatory)]$Device, [double]$DaysDisabled = 61)

        [pscustomobject]@{
            ObjectId    = $Device.id
            DisplayName = $Device.displayName
            Disabled    = $script:Now.AddDays(-$DaysDisabled).ToString($script:Format, [cultureinfo]::InvariantCulture)
        }
    }
}

Describe 'Read-DisabledDeviceFile' {

    BeforeEach {
        Initialize-StandInTenant
        $script:Device = Get-StandInDevice
    }

    It 'reads each device with the time it was disabled, in UTC' {
        $file = Get-DisabledFile -Row (Get-FileRow -Device $script:Device -DaysDisabled 61)

        $entries = @(Read-DisabledDeviceFile -Path $file -Format $script:Format -Now $script:Now)

        $entries | Should -HaveCount 1
        $entries[0].ObjectId | Should -Be $script:Device.id
        $entries[0].DisplayName | Should -Be 'PC01'
        $entries[0].DisabledDateTime | Should -Be $script:Now.AddDays(-61)
        $entries[0].DisabledDateTime.Kind | Should -Be 'Utc'
    }

    It 'counts a device listed in two files from its later date' {
        $earlier = Get-DisabledFile -Row (Get-FileRow -Device $script:Device -DaysDisabled 200)
        $later = Get-DisabledFile -Row (Get-FileRow -Device $script:Device -DaysDisabled 10)

        $entries = @(Read-DisabledDeviceFile -Path $earlier, $later -Format $script:Format -Now $script:Now)

        $entries | Should -HaveCount 1
        $entries[0].DisabledDateTime | Should -Be $script:Now.AddDays(-10)
    }

    It 'refuses a date in the form <Case>, naming the line' -ForEach @(
        @{ Case = 'a spreadsheet saves'; Text = '05/10/2026 10:15' }
        @{ Case = 'without the T and Z'; Text = '2026-05-10 10:15:00' }
        @{ Case = 'with an offset'; Text = '2026-05-10T10:15:00+02:00' }
        @{ Case = 'of nothing'; Text = '' }
    ) {
        $row = Get-FileRow -Device $script:Device
        $row.Disabled = $Text
        $file = Get-DisabledFile -Row $row

        { Read-DisabledDeviceFile -Path $file -Format $script:Format -Now $script:Now } |
            Should -Throw -ExpectedMessage "*line 2: DisabledDateTime '$Text' is not in the form*spreadsheet*"
    }

    It 'refuses a date in the future' {
        $file = Get-DisabledFile -Row (Get-FileRow -Device $script:Device -DaysDisabled -1)

        { Read-DisabledDeviceFile -Path $file -Format $script:Format -Now $script:Now } |
            Should -Throw -ExpectedMessage '*line 2: DisabledDateTime*is in the future.'
    }

    It 'refuses an object ID that is <Case>' -ForEach @(
        @{ Case = 'a name'; Text = 'PC01' }
        @{ Case = 'all zeros'; Text = [guid]::Empty.ToString() }
        @{ Case = 'empty'; Text = '' }
    ) {
        $row = Get-FileRow -Device $script:Device
        $row.ObjectId = $Text
        $file = Get-DisabledFile -Row $row

        { Read-DisabledDeviceFile -Path $file -Format $script:Format -Now $script:Now } |
            Should -Throw -ExpectedMessage "*line 2: '$Text' is not a device object ID."
    }

    It 'refuses a file without the columns, such as the report' {
        $file = Get-DisabledFile -Header '"DisplayName","Status","Reason","ObjectId"' -Row (Get-FileRow -Device $script:Device)

        { Read-DisabledDeviceFile -Path $file -Format $script:Format -Now $script:Now } |
            Should -Throw -ExpectedMessage "*has no column 'DisabledDateTime'*StaleEntraDevice-Disabled-*not its report."
    }

    It 'refuses a file that lists no devices' {
        $file = Get-DisabledFile

        { Read-DisabledDeviceFile -Path $file -Format $script:Format -Now $script:Now } |
            Should -Throw -ExpectedMessage '*lists no devices.'
    }

    It 'refuses the whole set when one line of one file is wrong' {
        $good = Get-DisabledFile -Row (Get-FileRow -Device $script:Device)
        $row = Get-FileRow -Device (Get-StandInDevice)
        $row.Disabled = '10/05/2026'
        $bad = Get-DisabledFile -Row $row

        { Read-DisabledDeviceFile -Path $good, $bad -Format $script:Format -Now $script:Now } | Should -Throw
    }
}

Describe 'Get-ExclusionGroup' {

    BeforeEach {
        Initialize-StandInTenant
    }

    It 'returns the group name and every member, nested ones included' {
        $member = [guid]::NewGuid().ToString()
        $script:Members = @($member)

        $group = Get-ExclusionGroup -GroupId $script:GroupId -BaseUri $script:Base -MaximumAttempt 2

        $group.DisplayName | Should -Be 'Example exclusions'
        $group.MemberIds.Contains($member.ToUpperInvariant()) | Should -BeTrue
        $script:Reads[1].Uri | Should -BeLike '*/transitiveMembers?*'
        @($script:Reads | ForEach-Object MaximumAttempt) | Should -Be @(2, 2)
    }

    It 'says the group was not found, rather than passing on a 404' {
        $script:Group = $null

        { Get-ExclusionGroup -GroupId $script:GroupId -BaseUri $script:Base } |
            Should -Throw -ExpectedMessage "No group has the object ID '$script:GroupId'*Nothing was changed."
    }

    It 'fails when the <Case> cannot be read, rather than excluding nothing' -ForEach @(
        @{ Case = 'group'; Kind = 'group' }
        @{ Case = 'membership'; Kind = 'members' }
    ) {
        $script:ReadFailures[$Kind] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'

        { Get-ExclusionGroup -GroupId $script:GroupId -BaseUri $script:Base } |
            Should -Throw -ExpectedMessage '*HTTP 403*Authorization_RequestDenied'
    }
}

Describe 'Get-StaleDeviceData' {

    BeforeEach {
        Initialize-StandInTenant
    }

    It 'reads every device, every managed device and the key list, and nothing else' {
        $device = Get-StandInDevice
        Add-StandInDevice -Device $device
        $script:ManagedDevices = @(Get-StandInManagedDevice -Device $device)
        $script:Keys = @(Get-StandInKey -Device $device)

        $data = Get-StaleDeviceData -BaseUri $script:Base -MaximumAttempt 3

        $script:Reads | Should -HaveCount 3
        $script:Reads[0].Uri | Should -BeLike "$script:Base/devices?*"
        $script:Reads[1].Uri | Should -Be "$script:Base/deviceManagement/managedDevices"
        $script:Reads[2].Uri | Should -Be "$script:Base/informationProtection/bitlocker/recoveryKeys"
        @($script:Reads | ForEach-Object MaximumAttempt) | Should -Be @(3, 3, 3)
        $data.Devices.Count | Should -Be 1
        $data.ManagedDevices.Count | Should -Be 1
        $data.Keys.Count | Should -Be 1
    }

    It 'selects every property a guard depends on' {
        $null = Get-StaleDeviceData -BaseUri $script:Base

        foreach ($property in 'id', 'deviceId', 'accountEnabled', 'approximateLastSignInDateTime', 'trustType', 'profileType',
            'physicalIds', 'isManagementRestricted') {
            $script:Reads[0].Uri | Should -Match "[?&]\`$select=[^&]*\b$property\b"
        }
    }

    It 'never asks for a recovery key itself' {
        $null = Get-StaleDeviceData -BaseUri $script:Base

        $script:Reads | Where-Object { $_.Uri -like '*recoveryKeys*' -and $_.Uri -match '[?&]\$select|key\b(?!s)' } | Should -BeNullOrEmpty
    }

    It 'stops, and says what is missing, when <Case> are refused' -ForEach @(
        @{ Case = 'Intune managed devices'; Kind = 'managedDevices'; Expected = '*Intune managed devices was refused*Intune role*nothing was changed*' }
        @{ Case = 'recovery keys'; Kind = 'recoveryKeys'; Expected = '*BitLocker recovery keys was refused*Cloud Device Administrator*nothing was changed*' }
    ) {
        $script:ReadFailures[$Kind] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'

        { Get-StaleDeviceData -BaseUri $script:Base } | Should -Throw -ExpectedMessage $Expected
    }

    It 'passes on any other failure of <Kind> unchanged' -ForEach @(
        @{ Kind = 'devices' }
        @{ Kind = 'managedDevices' }
        @{ Kind = 'recoveryKeys' }
    ) {
        $script:ReadFailures[$Kind] = Get-GraphFailure -StatusCode 503 -Message 'ServiceUnavailable'

        { Get-StaleDeviceData -BaseUri $script:Base } |
            Should -Throw -ExpectedMessage 'HTTP 503 from Graph after 1 attempt(s): ServiceUnavailable'
    }
}

Describe 'Get-DeviceFact' {

    BeforeEach {
        Initialize-StandInTenant
    }

    It 'finds nothing against an Entra joined device that is only stale' {
        Add-StandInDevice -Device (Get-StandInDevice -DaysSinceActivity 200)

        $fact = Get-SingleFact

        $fact.Guards | Should -HaveCount 0
        $fact.DaysSinceActivity | Should -Be 200
        $fact.JoinType | Should -Be 'Microsoft Entra joined'
        $fact.ObjectId | Should -Be $script:Devices[0].id
        $fact.ObjectId | Should -Not -Be $script:Devices[0].deviceId
    }

    It 'reads the activity timestamp as a DateTime too, as PowerShell 7.0 to 7.4 parse it' {
        $device = Get-StandInDevice
        $device.approximateLastSignInDateTime = $script:Now.AddDays(-150)
        Add-StandInDevice -Device $device

        $fact = Get-SingleFact

        $fact.DaysSinceActivity | Should -Be 150
        $fact.ApproximateLastSignInDateTime.Kind | Should -Be 'Utc'
    }

    Context 'the exclusion group' {

        It 'guards a member, whatever the case of its object ID' {
            Add-StandInDevice -Device (Get-StandInDevice)

            $fact = Get-SingleFact -Excluded $script:Devices[0].id.ToUpperInvariant()

            $fact.Excluded | Should -BeTrue
            $fact.Guards | Should -Be @('in the exclusion group')
        }

        It 'says to enable a member that is disabled' {
            Add-StandInDevice -Device (Get-StandInDevice -Enabled $false)

            (Get-SingleFact -Excluded $script:Devices[0].id).Guards |
                Should -Be @('in the exclusion group, and disabled: enable it again if it is in use')
        }

        It 'does not guard a device by its device ID, which is not what a group holds' {
            Add-StandInDevice -Device (Get-StandInDevice)

            (Get-SingleFact -Excluded $script:Devices[0].deviceId).Guards | Should -HaveCount 0
        }

        It 'guards nothing when there is no group' {
            Add-StandInDevice -Device (Get-StandInDevice)

            $fact = Get-DeviceFact -Device @($script:Devices) -ManagedDevice @() -Key @() -ExcludedId $null -Now $script:Now

            $fact.Excluded | Should -BeFalse
            $fact.Guards | Should -HaveCount 0
        }
    }

    Context 'Windows Autopilot' {

        It 'guards a registered device' {
            Add-StandInDevice -Device (Get-StandInDevice -Autopilot)

            $fact = Get-SingleFact

            $fact.AutopilotRegistered | Should -BeTrue
            $fact.Guards | Should -Be @('registered with Windows Autopilot')
        }

        It 'finds the marker written as <Marker>' -ForEach @(
            @{ Marker = '[ZTDID]' }
            @{ Marker = '[ZTDId]' }
            @{ Marker = '[ztdid]' }
        ) {
            $device = Get-StandInDevice
            $device.physicalIds = @('[HWID]:h:example', "$($Marker):$([guid]::NewGuid())")
            Add-StandInDevice -Device $device

            (Get-SingleFact).AutopilotRegistered | Should -BeTrue
        }

        It 'does not take <Case> for a registration' -ForEach @(
            @{ Case = 'other physical IDs'; Value = @('[HWID]:h:example', '[GID]:g:example', '[OrderId]:example') }
            @{ Case = 'no physical IDs'; Value = @() }
            @{ Case = 'a missing property'; Value = $null }
        ) {
            $device = Get-StandInDevice
            $device.physicalIds = $Value
            Add-StandInDevice -Device $device

            (Get-SingleFact).AutopilotRegistered | Should -BeFalse
        }
    }

    Context 'join and profile type' {

        It 'guards a hybrid joined device' {
            Add-StandInDevice -Device (Get-StandInDevice -TrustType 'ServerAd')

            (Get-SingleFact).Guards | Should -Be @('Microsoft Entra hybrid joined, so it is removed in on-premises Active Directory')
        }

        It 'does not guard a <TrustType> device' -ForEach @(
            @{ TrustType = 'AzureAd' }
            @{ TrustType = 'Workplace' }
            @{ TrustType = $null }
        ) {
            Add-StandInDevice -Device (Get-StandInDevice -TrustType $TrustType)

            (Get-SingleFact).Guards | Should -HaveCount 0
        }

        It 'guards the profile type <ProfileType>' -ForEach @(
            @{ ProfileType = 'Printer' }
            @{ ProfileType = 'SecureVM' }
            @{ ProfileType = 'Shared' }
            @{ ProfileType = 'IoT' }
        ) {
            Add-StandInDevice -Device (Get-StandInDevice -ProfileType $ProfileType)

            (Get-SingleFact).Guards | Should -Be @("profile type $ProfileType")
        }

        It 'does not guard a device with no profile type' {
            Add-StandInDevice -Device (Get-StandInDevice -ProfileType $null)

            (Get-SingleFact).Guards | Should -HaveCount 0
        }

        It 'guards a device in a restricted management administrative unit' {
            Add-StandInDevice -Device (Get-StandInDevice -Restricted $true)

            (Get-SingleFact).Guards | Should -Be @('in a restricted management administrative unit')
        }
    }

    Context 'Intune' {

        It 'guards a device Intune still holds, and says when it last synced' {
            Add-StandInDevice -Device (Get-StandInDevice)
            $script:ManagedDevices = @(Get-StandInManagedDevice -Device $script:Devices[0] -DaysSinceSync 300)

            $fact = Get-SingleFact

            $fact.HasIntuneRecord | Should -BeTrue
            $fact.IntuneLastSyncDateTime | Should -Be $script:Now.AddDays(-300)
            $fact.Guards | Should -Be @('still in Intune, last synced 300 day(s) ago')
        }

        It 'matches the Entra device ID without regard to case, and takes the latest of several records' {
            Add-StandInDevice -Device (Get-StandInDevice)
            $old = Get-StandInManagedDevice -Device $script:Devices[0] -DaysSinceSync 400
            $new = Get-StandInManagedDevice -Device $script:Devices[0] -DaysSinceSync 90
            $new.azureADDeviceId = $new.azureADDeviceId.ToUpperInvariant()
            $script:ManagedDevices = @($old, $new)

            (Get-SingleFact).Guards | Should -Be @('still in Intune, last synced 90 day(s) ago')
        }

        It 'guards a device whose Intune record never synced' {
            Add-StandInDevice -Device (Get-StandInDevice)
            $script:ManagedDevices = @(Get-StandInManagedDevice -Device $script:Devices[0] -DaysSinceSync $null)

            (Get-SingleFact).Guards | Should -Be @('still in Intune, never synced')
        }

        It 'does not guard a device for the Intune record of another' {
            Add-StandInDevice -Device (Get-StandInDevice)
            $script:ManagedDevices = @(Get-StandInManagedDevice -Device (Get-StandInDevice))

            $fact = Get-SingleFact

            $fact.HasIntuneRecord | Should -BeFalse
            $fact.Guards | Should -HaveCount 0
        }
    }

    Context 'activity and keys' {

        It 'guards a device with no activity timestamp' {
            Add-StandInDevice -Device (Get-StandInDevice -DaysSinceActivity $null)

            $fact = Get-SingleFact

            $fact.DaysSinceActivity | Should -BeNullOrEmpty
            $fact.Guards | Should -Be @('no activity timestamp')
        }

        It 'counts the keys of the device itself, which is not a guard here' {
            $mine = Get-StandInDevice -Name 'MINE'
            $other = Get-StandInDevice -Name 'OTHER'
            Add-StandInDevice -Device $mine, $other
            $upper = Get-StandInKey -Device $mine
            $upper.deviceId = $upper.deviceId.ToUpperInvariant()
            $script:Keys = @((Get-StandInKey -Device $mine), $upper, (Get-StandInKey -Device $other))

            $facts = Get-Fact

            ($facts | Where-Object DisplayName -EQ 'MINE').RecoveryKeyCount | Should -Be 2
            ($facts | Where-Object DisplayName -EQ 'OTHER').RecoveryKeyCount | Should -Be 1
            ($facts | Where-Object DisplayName -EQ 'MINE').Guards | Should -HaveCount 0
        }

        It 'lists every guard that applies' {
            $device = Get-StandInDevice -TrustType 'ServerAd' -DaysSinceActivity $null -Autopilot
            Add-StandInDevice -Device $device
            $script:ManagedDevices = @(Get-StandInManagedDevice -Device $device -DaysSinceSync 30)

            (Get-SingleFact -Excluded $device.id).Guards | Should -HaveCount 5
        }
    }
}

Describe 'Get-DisableCandidate' {

    BeforeEach {
        Initialize-StandInTenant
    }

    It 'reports nothing for a device active <Days> day(s) ago with 120 days' -ForEach @(
        @{ Days = 0 }
        @{ Days = 119 }
        @{ Days = 120 }
    ) {
        Add-StandInDevice -Device (Get-StandInDevice -DaysSinceActivity $Days)

        @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now) | Should -HaveCount 0
    }

    It 'makes a device last active 121 days ago a Candidate' {
        Add-StandInDevice -Device (Get-StandInDevice -DaysSinceActivity 121)

        $records = @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)

        $records | Should -HaveCount 1
        $records[0].Status | Should -Be 'Candidate'
        $records[0].Reason | Should -Be ''
        $records[0].DaysSinceActivity | Should -Be 121
        $records[0].ObjectId | Should -Be $script:Devices[0].id
    }

    It 'follows -StaleAfterDays' {
        Add-StandInDevice -Device (Get-StandInDevice -DaysSinceActivity 200)

        @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 365 -Now $script:Now) | Should -HaveCount 0
        @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 199 -Now $script:Now) | Should -HaveCount 1
    }

    It 'skips a guarded device, with every reason' {
        $device = Get-StandInDevice -TrustType 'ServerAd' -Autopilot
        Add-StandInDevice -Device $device

        $record = @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)[0]

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: registered with Windows Autopilot; Microsoft Entra hybrid joined, so it is removed in on-premises Active Directory.'
    }

    It 'skips a device with no activity timestamp, rather than taking never for stale' {
        Add-StandInDevice -Device (Get-StandInDevice -DaysSinceActivity $null)

        $record = @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)[0]

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: no activity timestamp.'
    }

    It 'reports a stale device that is already disabled as AlreadyDisabled' {
        Add-StandInDevice -Device (Get-StandInDevice -Enabled $false)

        $record = @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)[0]

        $record.Status | Should -Be 'AlreadyDisabled'
        $record.Reason | Should -BeLike 'Disabled before this run*'
    }

    It 'skips a guarded device even when it is already disabled' {
        Add-StandInDevice -Device (Get-StandInDevice -Enabled $false -TrustType 'ServerAd')

        @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)[0].Status | Should -Be 'Skipped'
    }

    It 'makes a stale device that holds recovery keys a Candidate: disabling keeps them' {
        Add-StandInDevice -Device (Get-StandInDevice)
        $script:Keys = @(Get-StandInKey -Device $script:Devices[0])

        $record = @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)[0]

        $record.Status | Should -Be 'Candidate'
        $record.RecoveryKeyCount | Should -Be 1
    }

    It 'returns nothing for an empty tenant' {
        @(Get-DisableCandidate -Fact @() -StaleAfterDays 120 -Now $script:Now) | Should -HaveCount 0
    }
}

Describe 'Get-DeleteCandidate' {

    BeforeAll {
        function Get-DeleteRecord {
            # Decides about the one device in the file, with the defaults.
            param ([Parameter(Mandatory)]$Entry, [string[]]$Excluded = @(), [hashtable]$Option = @{})

            $records = @(Get-DeleteCandidate -Entry @($Entry) -Fact (Get-Fact -Excluded $Excluded) -StaleAfterDays 120 -GraceDays 60 `
                    -Now $script:Now @Option)
            if ($records.Count -ne 1) { throw "Expected one record, got $($records.Count)." }
            $records[0]
        }
    }

    BeforeEach {
        Initialize-StandInTenant
        $script:Device = Get-StandInDevice -Enabled $false -DaysSinceActivity 200
        Add-StandInDevice -Device $script:Device
    }

    It 'makes a device a Candidate when it is disabled, past its grace period and nothing speaks against it' {
        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device -DaysDisabled 61)

        $record.Status | Should -Be 'Candidate'
        $record.Reason | Should -Be ''
        $record.DaysDisabled | Should -Be 61
        $record.DisabledDateTime | Should -Be $script:Now.AddDays(-61)
    }

    It 'keeps a device disabled <Days> day(s) ago in its grace period of 60' -ForEach @(
        @{ Days = 0 }
        @{ Days = 59 }
        @{ Days = 59.9 }
    ) {
        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device -DaysDisabled $Days)

        $record.Status | Should -Be 'InGracePeriod'
        $record.Reason | Should -Be "Disabled $([int][Math]::Floor($Days)) day(s) ago; the grace period is 60."
    }

    It 'ends the grace period at 60 days exactly' {
        (Get-DeleteRecord -Entry (Get-Entry -Device $script:Device -DaysDisabled 60)).Status | Should -Be 'Candidate'
    }

    It 'follows -GraceDays' {
        $entry = Get-Entry -Device $script:Device -DaysDisabled 20

        $records = @(Get-DeleteCandidate -Entry @($entry) -Fact (Get-Fact) -StaleAfterDays 120 -GraceDays 14 -Now $script:Now)

        $records[0].Status | Should -Be 'Candidate'
    }

    It 'reports a device that no longer exists as Gone, from what the file says of it' {
        $missing = Get-StandInDevice -Name 'MISSING'

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $missing)

        $record.Status | Should -Be 'Gone'
        $record.DisplayName | Should -Be 'MISSING'
        $record.ObjectId | Should -Be $missing.id
    }

    It 'finds the device whatever the case of the object ID in the file' {
        $entry = Get-Entry -Device $script:Device
        $entry.ObjectId = $entry.ObjectId.ToUpperInvariant()

        (Get-DeleteRecord -Entry $entry).Status | Should -Be 'Candidate'
    }

    It 'leaves alone a device that was enabled again' {
        $script:Device.accountEnabled = $true

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device)

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: enabled again since it was disabled.'
    }

    It 'leaves alone a device that has been active since it was disabled' {
        $script:Device.approximateLastSignInDateTime = $script:Now.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device -DaysDisabled 61)

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: active since it was disabled.'
    }

    It 'leaves alone a device that is not stale, whatever a hand-made file says' {
        $script:Device.approximateLastSignInDateTime = $script:Now.AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device -DaysDisabled 61)

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: active 90 day(s) ago, which is within -StaleAfterDays 120.'
    }

    It 'leaves alone a device that holds recovery keys, and says what deleting would cost' {
        $script:Keys = @((Get-StandInKey -Device $script:Device), (Get-StandInKey -Device $script:Device))

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device)

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: holds 2 BitLocker recovery key(s), which would be destroyed with it.'
        $record.RecoveryKeyCount | Should -Be 2
    }

    It 'makes a device with recovery keys a Candidate only with -IncludeDevicesWithRecoveryKey' {
        $script:Keys = @(Get-StandInKey -Device $script:Device)

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device) -Option @{ IncludeDevicesWithRecoveryKey = $true }

        $record.Status | Should -Be 'Candidate'
    }

    It 'leaves alone a device added to the exclusion group after it was disabled, and says to enable it' {
        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device) -Excluded $script:Device.id

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -Be 'Left alone: in the exclusion group, and disabled: enable it again if it is in use.'
    }

    It 'leaves alone a device that <Case> since it was disabled' -ForEach @(
        @{ Case = 'was enrolled in Intune'; Change = 'Intune'; Expected = '*still in Intune*' }
        @{ Case = 'was registered with Autopilot'; Change = 'Autopilot'; Expected = '*registered with Windows Autopilot*' }
        @{ Case = 'lost its activity timestamp'; Change = 'NoTimestamp'; Expected = '*no activity timestamp*' }
    ) {
        switch ($Change) {
            'Intune' { $script:ManagedDevices = @(Get-StandInManagedDevice -Device $script:Device -DaysSinceSync 2) }
            'Autopilot' { $script:Device.physicalIds = @("[ZTDID]:$([guid]::NewGuid())") }
            'NoTimestamp' { $script:Device.approximateLastSignInDateTime = $null }
        }

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device)

        $record.Status | Should -Be 'Skipped'
        $record.Reason | Should -BeLike $Expected
    }

    It 'does not let -IncludeDevicesWithRecoveryKey override any other reason' {
        $script:Device.accountEnabled = $true
        $script:Keys = @(Get-StandInKey -Device $script:Device)

        $record = Get-DeleteRecord -Entry (Get-Entry -Device $script:Device) -Option @{ IncludeDevicesWithRecoveryKey = $true }

        $record.Status | Should -Be 'Skipped'
    }

    It 'reports a reason to leave a device alone even inside its grace period' {
        $script:Keys = @(Get-StandInKey -Device $script:Device)

        (Get-DeleteRecord -Entry (Get-Entry -Device $script:Device -DaysDisabled 5)).Status | Should -Be 'Skipped'
    }

    It 'decides nothing about a device that is in no file' {
        $other = Get-StandInDevice -Name 'OTHER' -Enabled $false -DaysSinceActivity 900
        Add-StandInDevice -Device $other

        $records = @(Get-DeleteCandidate -Entry @(Get-Entry -Device $script:Device) -Fact (Get-Fact) -StaleAfterDays 120 -GraceDays 60 -Now $script:Now)

        @($records | ForEach-Object DisplayName) | Should -Be @('PC01')
    }
}

Describe 'Get-DeviceChange' {

    BeforeAll {
        function Get-Change {
            # What Get-DeviceChange says when the device now looks like this.
            param ([string]$Action, [object]$Enabled, [object]$DaysSinceActivity = 200)

            $record = [pscustomobject]@{ ApproximateLastSignInDateTime = $script:Now.AddDays(-200) }
            $signIn = $null
            if ($null -ne $DaysSinceActivity) { $signIn = $script:Now.AddDays(-$DaysSinceActivity).ToString('yyyy-MM-ddTHH:mm:ssZ') }
            $current = [pscustomobject]@{ accountEnabled = $Enabled; approximateLastSignInDateTime = $signIn }

            Get-DeviceChange -Record $record -Current $current -Action $Action
        }
    }

    It 'says nothing about a device that is as it was before <Action>' -ForEach @(
        @{ Action = 'Disable'; Enabled = $true }
        @{ Action = 'Delete'; Enabled = $false }
    ) {
        Get-Change -Action $Action -Enabled $Enabled | Should -BeNullOrEmpty
    }

    It 'stops Disable for a device someone else disabled' {
        Get-Change -Action Disable -Enabled $false | Should -Be 'Left alone: disabled by someone else since the run began.'
    }

    It 'stops Delete for a device that was enabled again' {
        Get-Change -Action Delete -Enabled $true | Should -Be 'Left alone: enabled again since the run began.'
    }

    It 'stops <Action> for a device whose activity timestamp moved' -ForEach @(
        @{ Action = 'Disable'; Enabled = $true }
        @{ Action = 'Delete'; Enabled = $false }
    ) {
        Get-Change -Action $Action -Enabled $Enabled -DaysSinceActivity 1 | Should -Be 'Left alone: active since the run began.'
    }
}

Describe 'Invoke-StaleDeviceAction' {

    BeforeAll {
        function Get-DisableBatch {
            # Records for the stand-in tenant, decided as the Disable stage does.
            @(Get-DisableCandidate -Fact (Get-Fact) -StaleAfterDays 120 -Now $script:Now)
        }

        function Get-DeleteBatch {
            # Records for the stand-in tenant, decided as the Delete stage
            # does, with every device in the file and past its grace period.
            $entries = @($script:Devices | ForEach-Object { Get-Entry -Device $_ -DaysDisabled 61 })
            @(Get-DeleteCandidate -Entry $entries -Fact (Get-Fact) -StaleAfterDays 120 -GraceDays 60 -Now $script:Now)
        }
    }

    BeforeEach {
        Initialize-StandInTenant
        $script:File = Join-Path -Path $TestDrive -ChildPath "$([guid]::NewGuid().ToString('n')).csv"
    }

    Context 'Disable' {

        It 'disables each Candidate with one PATCH, after reading it again, and leaves every other device alone' {
            $first = Get-StandInDevice -Name 'PC01'
            $second = Get-StandInDevice -Name 'PC02'
            $hybrid = Get-StandInDevice -Name 'PC03' -TrustType 'ServerAd'
            Add-StandInDevice -Device $first, $second, $hybrid
            $records = Get-DisableBatch

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File `
                -MaximumAttempt 3 -Confirm:$false

            $script:Writes | Should -HaveCount 2
            @($script:Writes | ForEach-Object Method) | Should -Be @('PATCH', 'PATCH')
            $script:Writes[0].Uri | Should -Be "$script:Base/devices/$($first.id)"
            $script:Writes[0].Body.Keys | Should -Be @('accountEnabled')
            $script:Writes[0].Body['accountEnabled'] | Should -BeFalse
            @($script:Writes | ForEach-Object ReadsBefore) | Should -Be @(1, 2)
            @($records | ForEach-Object Status) | Should -Be @('Disabled', 'Disabled', 'Skipped')
            $first.accountEnabled | Should -BeFalse
            $hybrid.accountEnabled | Should -BeTrue
        }

        It 'records the time on the record and in the file, in the only form the Delete stage reads' {
            $device = Get-StandInDevice
            Add-StandInDevice -Device $device
            $records = Get-DisableBatch

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            $records[0].AccountEnabled | Should -BeFalse
            $records[0].DisabledDateTime | Should -BeGreaterOrEqual $script:Now
            $entries = @(Read-DisabledDeviceFile -Path $script:File -Format $script:Format -Now ([datetime]::UtcNow.AddMinutes(1)))
            $entries | Should -HaveCount 1
            $entries[0].ObjectId | Should -Be $device.id
            $entries[0].DisplayName | Should -Be 'PC01'
            ([datetime]::UtcNow - $entries[0].DisabledDateTime).TotalMinutes | Should -BeLessThan 5
            @(Import-Csv -LiteralPath $script:File)[0].DisabledDateTime | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
        }

        It 'changes nothing under -WhatIf, marks what it would disable, and writes no file' {
            Add-StandInDevice -Device (Get-StandInDevice)
            $records = Get-DisableBatch

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -WhatIf

            $script:Writes | Should -HaveCount 0
            $script:Reads | Should -HaveCount 0
            $records[0].Status | Should -Be 'WouldDisable'
            Test-Path -LiteralPath $script:File | Should -BeFalse
        }

        It 'leaves alone a device that <Case> since it was listed' -ForEach @(
            @{ Case = 'someone else disabled'; Property = 'accountEnabled'; Expected = 'Left alone: disabled by someone else since the run began.' }
            @{ Case = 'became active'; Property = 'approximateLastSignInDateTime'; Expected = 'Left alone: active since the run began.' }
        ) {
            $device = Get-StandInDevice
            Add-StandInDevice -Device $device
            $records = Get-DisableBatch
            if ($Property -eq 'accountEnabled') { $device.accountEnabled = $false }
            else { $device.approximateLastSignInDateTime = $script:Now.ToString('yyyy-MM-ddTHH:mm:ssZ') }

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            $script:Writes | Should -HaveCount 0
            $records[0].Status | Should -Be 'Skipped'
            $records[0].Reason | Should -Be $Expected
            Test-Path -LiteralPath $script:File | Should -BeFalse
        }

        It 'reports a device deleted since it was listed as Gone, and carries on' {
            $first = Get-StandInDevice -Name 'PC01'
            $second = Get-StandInDevice -Name 'PC02'
            Add-StandInDevice -Device $first, $second
            $records = Get-DisableBatch
            $null = $script:Devices.Remove($first)

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            @($records | ForEach-Object Status) | Should -Be @('Gone', 'Disabled')
        }

        It 'stops at the first 403, names the roles, and attempts nothing after it' {
            $devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'), (Get-StandInDevice -Name 'PC03'))
            Add-StandInDevice -Device $devices
            $script:WriteFailures[$devices[0].id] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'
            $records = Get-DisableBatch

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            $script:Writes | Should -HaveCount 1
            $records[0].Status | Should -Be 'Failed'
            $records[0].Reason | Should -BeLike '*HTTP 403*Intune Administrator*Cloud Device Administrator*Authorization_RequestDenied*'
            @($records[1..2] | ForEach-Object Status) | Should -Be @('NotAttempted', 'NotAttempted')
            @($devices | ForEach-Object accountEnabled) | Should -Be @($true, $true, $true)
        }

        It 'records any other failure and carries on with the next device' {
            $devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'))
            Add-StandInDevice -Device $devices
            $script:WriteFailures[$devices[0].id] = Get-GraphFailure -StatusCode 400 -Message 'Request_BadRequest'
            $records = Get-DisableBatch

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            $records[0].Status | Should -Be 'Failed'
            $records[0].Reason | Should -BeLike '*HTTP 400*'
            $records[1].Status | Should -Be 'Disabled'
            @(Import-Csv -LiteralPath $script:File) | Should -HaveCount 1
        }

        It 'fails the device and stops the batch when the file cannot be written' {
            $devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'))
            Add-StandInDevice -Device $devices
            $records = Get-DisableBatch
            $nowhere = Join-Path -Path (Join-Path -Path $TestDrive -ChildPath 'no-such-folder') -ChildPath 'disabled.csv'

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $nowhere -Confirm:$false

            $script:Writes | Should -HaveCount 1
            $records[0].Status | Should -Be 'Failed'
            $records[0].Reason | Should -BeLike 'Disabled at *, but not written to*Add it to the file by hand, or enable the device again.'
            $records[1].Status | Should -Be 'NotAttempted'
            $devices[1].accountEnabled | Should -BeTrue
        }

        It 'refuses to disable without a file to record it in' {
            Add-StandInDevice -Device (Get-StandInDevice)
            $records = Get-DisableBatch

            { Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -Confirm:$false } |
                Should -Throw -ExpectedMessage '*needs -DisabledDeviceFile*'
            $script:Writes | Should -HaveCount 0
        }

        It 'sends nothing when no record is a Candidate' {
            Add-StandInDevice -Device (Get-StandInDevice -TrustType 'ServerAd')
            $records = Get-DisableBatch

            Invoke-StaleDeviceAction -Record $records -Action Disable -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            $script:Reads | Should -HaveCount 0
            $script:Writes | Should -HaveCount 0
        }
    }

    Context 'Delete' {

        It 'deletes each Candidate with one DELETE, after reading it again, and nothing else' {
            $first = Get-StandInDevice -Name 'PC01' -Enabled $false
            $second = Get-StandInDevice -Name 'PC02' -Enabled $false
            $enabled = Get-StandInDevice -Name 'PC03' -Enabled $true
            Add-StandInDevice -Device $first, $second, $enabled
            $records = Get-DeleteBatch

            Invoke-StaleDeviceAction -Record $records -Action Delete -BaseUri $script:Base -MaximumAttempt 3 -Confirm:$false

            @($script:Writes | ForEach-Object Method) | Should -Be @('DELETE', 'DELETE')
            @($script:Writes | ForEach-Object Uri) | Should -Be @("$script:Base/devices/$($first.id)", "$script:Base/devices/$($second.id)")
            @($script:Writes | ForEach-Object { $null -eq $_.Body }) | Should -Be @($true, $true)
            @($script:Writes | ForEach-Object ReadsBefore) | Should -Be @(1, 2)
            @($records | ForEach-Object Status) | Should -Be @('Deleted', 'Deleted', 'Skipped')
            @($script:Devices | ForEach-Object displayName) | Should -Be @('PC03')
        }

        It 'changes nothing under -WhatIf, and marks what it would delete' {
            Add-StandInDevice -Device (Get-StandInDevice -Enabled $false)
            $records = Get-DeleteBatch

            Invoke-StaleDeviceAction -Record $records -Action Delete -BaseUri $script:Base -WhatIf

            $script:Writes | Should -HaveCount 0
            $records[0].Status | Should -Be 'WouldDelete'
            $script:Devices | Should -HaveCount 1
        }

        It 'leaves alone a device that was <Case> since it was listed' -ForEach @(
            @{ Case = 'enabled again'; Property = 'accountEnabled'; Expected = 'Left alone: enabled again since the run began.' }
            @{ Case = 'active'; Property = 'approximateLastSignInDateTime'; Expected = 'Left alone: active since the run began.' }
        ) {
            $device = Get-StandInDevice -Enabled $false
            Add-StandInDevice -Device $device
            $records = Get-DeleteBatch
            if ($Property -eq 'accountEnabled') { $device.accountEnabled = $true }
            else { $device.approximateLastSignInDateTime = $script:Now.ToString('yyyy-MM-ddTHH:mm:ssZ') }

            Invoke-StaleDeviceAction -Record $records -Action Delete -BaseUri $script:Base -Confirm:$false

            $script:Writes | Should -HaveCount 0
            $records[0].Status | Should -Be 'Skipped'
            $records[0].Reason | Should -Be $Expected
            $script:Devices | Should -HaveCount 1
        }

        It 'reports a device that vanished between the read and the DELETE as Gone' {
            $device = Get-StandInDevice -Enabled $false
            Add-StandInDevice -Device $device
            $script:WriteFailures[$device.id] = Get-GraphFailure -StatusCode 404 -Message 'Request_ResourceNotFound'
            $records = Get-DeleteBatch

            Invoke-StaleDeviceAction -Record $records -Action Delete -BaseUri $script:Base -Confirm:$false

            $records[0].Status | Should -Be 'Gone'
            $records[0].Reason | Should -Be 'Deleted by someone else since the run began.'
        }

        It 'stops at the first 403 and deletes nothing after it' {
            $devices = @((Get-StandInDevice -Name 'PC01' -Enabled $false), (Get-StandInDevice -Name 'PC02' -Enabled $false))
            Add-StandInDevice -Device $devices
            $script:WriteFailures[$devices[0].id] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'
            $records = Get-DeleteBatch

            Invoke-StaleDeviceAction -Record $records -Action Delete -BaseUri $script:Base -Confirm:$false

            @($records | ForEach-Object Status) | Should -Be @('Failed', 'NotAttempted')
            $script:Devices | Should -HaveCount 2
        }

        It 'writes no disabled-device file' {
            Add-StandInDevice -Device (Get-StandInDevice -Enabled $false)
            $records = Get-DeleteBatch

            Invoke-StaleDeviceAction -Record $records -Action Delete -BaseUri $script:Base -DisabledDeviceFile $script:File -Confirm:$false

            $records[0].Status | Should -Be 'Deleted'
            Test-Path -LiteralPath $script:File | Should -BeFalse
        }
    }
}

Describe 'The scopes the script asks for' {

    BeforeAll {
        # The statements that build $RequiredScopes, from the script itself.
        $script:ScopeStatements = @(
            $syntaxTree.EndBlock.Statements |
                Where-Object {
                    $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $_ -isnot [System.Management.Automation.Language.TryStatementAst] -and
                    $_.Extent.Text -match '\$RequiredScopes\b'
                } |
                ForEach-Object { $_.Extent.Text }
        )

        function Get-RequestedScope {
            # The scopes a run with these parameters signs in with.
            param ([string]$StageName, [string]$Group = '', [switch]$DryRun)

            # The statements read the script's parameters from this scope.
            Set-Variable -Name 'Stage' -Value $StageName
            Set-Variable -Name 'ExcludeGroupId' -Value $Group
            Set-Variable -Name 'WhatIfPreference' -Value $DryRun.IsPresent
            foreach ($statement in $script:ScopeStatements) { . ([scriptblock]::Create($statement)) }

            [string[]]@($RequiredScopes.Keys)
        }
    }

    It 'finds the statements that build the scopes' {
        $script:ScopeStatements.Count | Should -BeGreaterOrEqual 3
    }

    It 'asks the Report stage for read scopes only' {
        Get-RequestedScope -StageName Report |
            Should -Be @('Device.Read.All', 'DeviceManagementManagedDevices.Read.All', 'BitlockerKey.ReadBasic.All')
    }

    It 'adds the group scope only with -ExcludeGroupId' {
        Get-RequestedScope -StageName Report -Group $script:GroupId | Should -Contain 'GroupMember.Read.All'
    }

    It 'adds Directory.AccessAsUser.All for -Stage <StageName>' -ForEach @(
        @{ StageName = 'Disable' }
        @{ StageName = 'Delete' }
    ) {
        Get-RequestedScope -StageName $StageName | Should -Contain 'Directory.AccessAsUser.All'
    }

    It 'does not ask for it under -WhatIf, which changes nothing' -ForEach @(
        @{ StageName = 'Disable' }
        @{ StageName = 'Delete' }
    ) {
        Get-RequestedScope -StageName $StageName -DryRun | Should -Not -Contain 'Directory.AccessAsUser.All'
    }

    It 'never asks for a scope that can read a recovery key' {
        Get-RequestedScope -StageName Delete -Group $script:GroupId | Should -Not -Contain 'BitlockerKey.Read.All'
    }
}

Describe 'The main block' {

    BeforeAll {
        # The body of the main block's try, without the catch around it,
        # whose exit would end the test run.
        $try = $syntaxTree.EndBlock.Statements[-1]
        if ($try -isnot [System.Management.Automation.Language.TryStatementAst]) { throw 'The main block is not a try statement.' }
        $body = $try.Body.Extent.Text
        $script:MainBlock = [scriptblock]::Create($body.Substring(1, $body.Length - 2))

        $script:SignIns = [System.Collections.Generic.List[object]]::new()
        $script:Scopes = [ordered]@{ 'Example.Read.All' = @('Example.ReadWrite.All') }

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

        function Invoke-Main {
            # Runs the main block as the script would with these parameters,
            # and separates what it returns, warns and reports.
            param (
                [string]$StageName = 'Report',
                [int]$Stale = 120,
                [int]$Grace = 60,
                [string[]]$File,
                [string]$Group = '',
                [int]$Maximum = 50,
                [switch]$WithKeys,
                [switch]$DryRun
            )

            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder

            # The main block reads the script's parameters and settings from
            # the scope that runs it.
            Set-Variable -Name 'Stage' -Value $StageName
            Set-Variable -Name 'StaleAfterDays' -Value $Stale
            Set-Variable -Name 'GraceDays' -Value $Grace
            Set-Variable -Name 'DisabledDevicePath' -Value $File
            Set-Variable -Name 'ExcludeGroupId' -Value $Group
            Set-Variable -Name 'MaximumDeviceCount' -Value $Maximum
            Set-Variable -Name 'IncludeDevicesWithRecoveryKey' -Value ([switch]$WithKeys.IsPresent)
            Set-Variable -Name 'OutputPath' -Value $folder
            Set-Variable -Name 'TenantId' -Value ''
            Set-Variable -Name 'UseDeviceCode' -Value ([switch]$false)
            Set-Variable -Name 'MaximumRetryCount' -Value 5
            Set-Variable -Name 'GraphBaseUri' -Value $script:Base
            Set-Variable -Name 'RequiredScopes' -Value $script:Scopes
            Set-Variable -Name 'DisabledDateTimeFormat' -Value $script:Format
            Set-Variable -Name 'AutopilotPhysicalIdPrefix' -Value '[ZTDID]'
            Set-Variable -Name 'ConfirmPreference' -Value 'None'
            Set-Variable -Name 'InformationPreference' -Value 'Continue'
            Set-Variable -Name 'ErrorActionPreference' -Value 'Stop'
            # Last, since every cmdlet after it honours -WhatIf. For the same
            # reason, values are read back with ForEach-Object { $_.Name }.
            Set-Variable -Name 'WhatIfPreference' -Value $DryRun.IsPresent

            $all = [System.Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                & $script:MainBlock 3>&1 6>&1 | ForEach-Object { $all.Add($_) }
            }
            catch {
                $failure = $_.Exception.Message
            }

            [pscustomobject]@{
                Rows        = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.InformationRecord] })
                Warnings    = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
                Information = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData })
                Failure     = $failure
                Files       = @(Get-ChildItem -LiteralPath $folder -File | Sort-Object { $_.Name })
            }
        }

        function Get-Row {
            # The returned record of one device, by name.
            param ($Run, [string]$Name)

            $rows = @($Run.Rows | Where-Object { $_.DisplayName -eq $Name })
            if ($rows.Count -ne 1) { throw "Expected one row for $Name, got $($rows.Count)." }
            $rows[0]
        }
    }

    BeforeEach {
        Initialize-StandInTenant
        $script:SignIns.Clear()

        # One device of each kind the stages tell apart.
        $script:Stale = Get-StandInDevice -Name 'STALE' -DaysSinceActivity 200
        $script:Active = Get-StandInDevice -Name 'ACTIVE' -DaysSinceActivity 5
        $script:Managed = Get-StandInDevice -Name 'MANAGED' -DaysSinceActivity 300
        $script:Hybrid = Get-StandInDevice -Name 'HYBRID' -TrustType 'ServerAd' -DaysSinceActivity 400
        $script:Keyed = Get-StandInDevice -Name 'KEYED' -DaysSinceActivity 250
        $script:Off = Get-StandInDevice -Name 'OFF' -DaysSinceActivity 365 -Enabled $false
        Add-StandInDevice -Device $script:Stale, $script:Active, $script:Managed, $script:Hybrid, $script:Keyed, $script:Off
        $script:ManagedDevices = @(Get-StandInManagedDevice -Device $script:Managed)
        $script:Keys = @(Get-StandInKey -Device $script:Keyed)
    }

    Context '-Stage Report' {

        It 'signs in once, with its scopes, before reading anything' {
            $null = Invoke-Main

            $script:SignIns | Should -HaveCount 1
            $script:SignIns[0].ReadsBefore | Should -Be 0
            [object]::ReferenceEquals($script:SignIns[0].Scope, $script:Scopes) | Should -BeTrue
        }

        It 'returns a record for every stale device, none for one in use, and writes nothing to the tenant' {
            $run = Invoke-Main

            @($run.Rows | ForEach-Object { $_.DisplayName }) | Should -Be @('STALE', 'MANAGED', 'HYBRID', 'KEYED', 'OFF')
            @($run.Rows | ForEach-Object { $_.Status }) | Should -Be @('Candidate', 'Skipped', 'Skipped', 'Candidate', 'AlreadyDisabled')
            $script:Writes | Should -HaveCount 0
            $run.Failure | Should -BeNullOrEmpty
            $run.Information | Should -Contain '6 device(s) in the tenant, 1 of them active within 120 days and not reported.'
            $run.Information | Should -Contain 'Stage Report: AlreadyDisabled 1, Candidate 2, Skipped 2.'
        }

        It 'writes the report, and no disabled-device file' {
            $run = Invoke-Main

            $run.Files | Should -HaveCount 1
            $run.Files[0].Name | Should -BeLike 'StaleEntraDevice-Report-*.csv'
            @(Import-Csv -LiteralPath $run.Files[0].FullName) | Should -HaveCount 5
        }

        It 'follows -StaleAfterDays' {
            $run = Invoke-Main -Stale 350

            @($run.Rows | ForEach-Object { $_.DisplayName }) | Should -Be @('HYBRID', 'OFF')
        }

        It 'warns that -Stage Disable would refuse more candidates than -MaximumDeviceCount, without failing' {
            $run = Invoke-Main -Maximum 1

            @($run.Warnings | Where-Object { $_ -like '2 device(s) are candidates, more than -MaximumDeviceCount 1*' }) | Should -HaveCount 1
            @($run.Rows | Where-Object { $_.Status -eq 'Candidate' }) | Should -HaveCount 2
            $run.Failure | Should -BeNullOrEmpty
        }

        It 'says so, and writes no file, when no device is stale' {
            $run = Invoke-Main -Stale 3000

            $run.Rows | Should -HaveCount 0
            $run.Files | Should -HaveCount 0
            $run.Information | Should -Contain 'Stage Report: no device to report.'
        }

        It 'refuses <Case>, before signing in' -ForEach @(
            @{ Case = '-DisabledDevicePath'; Option = @{ File = 'C:\Reports\disabled.csv' }; Expected = '-DisabledDevicePath is read only by -Stage Delete, and this run is -Stage Report.' }
            @{ Case = '-IncludeDevicesWithRecoveryKey'; Option = @{ WithKeys = $true }; Expected = '-IncludeDevicesWithRecoveryKey applies only to -Stage Delete, and this run is -Stage Report.' }
        ) {
            $run = Invoke-Main @Option

            $run.Failure | Should -Be $Expected
            $script:SignIns | Should -HaveCount 0
        }
    }

    Context 'the exclusion group' {

        It 'reads the group before any device, and leaves its members alone' {
            $script:Members = @($script:Stale.id)

            $run = Invoke-Main -StageName Disable -Group $script:GroupId

            $script:Reads[0].Uri | Should -BeLike "$script:Base/groups/$script:GroupId`?*"
            (Get-Row -Run $run -Name 'STALE').Status | Should -Be 'Skipped'
            (Get-Row -Run $run -Name 'STALE').Reason | Should -Be 'Left alone: in the exclusion group.'
            $script:Stale.accountEnabled | Should -BeTrue
            $run.Information | Should -Contain "Leaving alone the 1 member(s) of group 'Example exclusions'."
        }

        It 'stops before reading any device when the group <Case>' -ForEach @(
            @{ Case = 'does not exist'; Expected = 'No group has the object ID*' }
            @{ Case = 'cannot be read'; Expected = '*HTTP 403*' }
        ) {
            if ($Case -eq 'does not exist') { $script:Group = $null }
            else { $script:ReadFailures['members'] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied' }

            $run = Invoke-Main -StageName Disable -Group $script:GroupId

            $run.Failure | Should -BeLike $Expected
            @($script:Reads | Where-Object { $_.Uri -like "$script:Base/devices*" }) | Should -HaveCount 0
            $script:Writes | Should -HaveCount 0
        }

        It 'warns about a group with no members' {
            $run = Invoke-Main -Group $script:GroupId

            $run.Warnings | Should -Contain "Group 'Example exclusions' has no members, so it excludes nothing."
        }
    }

    Context '-Stage Disable' {

        It 'disables the candidates and no other device' {
            $run = Invoke-Main -StageName Disable

            @($script:Writes | ForEach-Object { $_.ObjectId }) | Should -Be @($script:Stale.id, $script:Keyed.id)
            @($script:Writes | ForEach-Object { $_.Method } | Select-Object -Unique) | Should -Be @('PATCH')
            @($run.Rows | ForEach-Object { $_.Status }) | Should -Be @('Disabled', 'Skipped', 'Skipped', 'Disabled', 'AlreadyDisabled')
            @($script:Devices | Where-Object { $_.accountEnabled -eq $true } | ForEach-Object { $_.displayName }) |
                Should -Be @('ACTIVE', 'MANAGED', 'HYBRID')
            $run.Failure | Should -BeNullOrEmpty
        }

        It 'writes the report and a disabled-device file that the Delete stage reads, and says to keep it' {
            $run = Invoke-Main -StageName Disable

            $names = @($run.Files | ForEach-Object { $_.Name -replace '\d{8}-\d{6}', '<stamp>' })
            $names | Should -HaveCount 2
            $names | Should -Contain 'StaleEntraDevice-Disable-<stamp>.csv'
            $names | Should -Contain 'StaleEntraDevice-Disabled-<stamp>.csv'
            $disabled = @($run.Files | Where-Object { $_.Name -like 'StaleEntraDevice-Disabled-*' })[0]
            $entries = @(Read-DisabledDeviceFile -Path $disabled.FullName -Format $script:Format -Now ([datetime]::UtcNow.AddMinutes(1)))
            @($entries | ForEach-Object { $_.ObjectId }) | Should -Be @($script:Stale.id, $script:Keyed.id)
            @($run.Warnings | Where-Object { $_ -like "Keep '*StaleEntraDevice-Disabled-*' as it is.*" }) | Should -HaveCount 1
        }

        It 'changes nothing under -WhatIf, and writes the report but no disabled-device file' {
            $run = Invoke-Main -StageName Disable -DryRun

            $script:Writes | Should -HaveCount 0
            (Get-Row -Run $run -Name 'STALE').Status | Should -Be 'WouldDisable'
            $run.Files | Should -HaveCount 1
            $run.Files[0].Name | Should -BeLike 'StaleEntraDevice-Disable-*.csv'
            $run.Failure | Should -BeNullOrEmpty
        }

        It 'refuses the whole batch when it is over -MaximumDeviceCount, and fails' {
            $run = Invoke-Main -StageName Disable -Maximum 1

            $script:Writes | Should -HaveCount 0
            $run.Failure | Should -BeLike '-Stage Disable would change 2 device(s), more than -MaximumDeviceCount 1, so none was changed.*'
            (Get-Row -Run $run -Name 'STALE').Status | Should -Be 'NotAttempted'
            (Get-Row -Run $run -Name 'STALE').Reason | Should -Be 'Not attempted: the batch of 2 is over -MaximumDeviceCount 1.'
            $run.Rows | Should -HaveCount 5
            $run.Files | Should -HaveCount 1
        }

        It 'refuses the batch under -WhatIf as well, so a preview shows what a run would do' {
            $run = Invoke-Main -StageName Disable -Maximum 1 -DryRun

            $run.Failure | Should -BeLike '-Stage Disable would change 2 device(s)*'
        }

        It 'accepts a batch of exactly -MaximumDeviceCount' {
            $run = Invoke-Main -StageName Disable -Maximum 2

            $script:Writes | Should -HaveCount 2
            $run.Failure | Should -BeNullOrEmpty
        }

        It 'stops before changing anything when <Kind> cannot be read' -ForEach @(
            @{ Kind = 'devices' }
            @{ Kind = 'managedDevices' }
            @{ Kind = 'recoveryKeys' }
        ) {
            $script:ReadFailures[$Kind] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'

            $run = Invoke-Main -StageName Disable

            $run.Failure | Should -BeLike '*HTTP 403*'
            $script:Writes | Should -HaveCount 0
        }

        It 'returns every record, then fails, when a device could not be disabled' {
            $script:WriteFailures[$script:Stale.id] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'

            $run = Invoke-Main -StageName Disable

            $run.Rows | Should -HaveCount 5
            $run.Failure | Should -Be '2 device(s) were not changed. See Status and Reason on the returned records.'
            $run.Files | Should -HaveCount 1
        }
    }

    Context '-Stage Delete' {

        BeforeEach {
            # As the tenant is some time after a Disable run: both candidates
            # disabled, and in the file.
            $script:Stale.accountEnabled = $false
            $script:Keyed.accountEnabled = $false
        }

        It 'needs a disabled-device file, and says so before signing in' {
            $run = Invoke-Main -StageName Delete

            $run.Failure | Should -BeLike '-Stage Delete needs -DisabledDevicePath*Devices are deleted only from that list.'
            $script:SignIns | Should -HaveCount 0
        }

        It 'refuses a file it cannot read exactly, before signing in' {
            $row = Get-FileRow -Device $script:Stale
            $row.Disabled = '05/10/2026 10:15'

            $run = Invoke-Main -StageName Delete -File (Get-DisabledFile -Row $row)

            $run.Failure | Should -BeLike "*DisabledDateTime '05/10/2026 10:15' is not in the form*"
            $script:SignIns | Should -HaveCount 0
        }

        It 'deletes a device from the file that is past its grace period, and nothing that is not in the file' {
            $file = Get-DisabledFile -Row (Get-FileRow -Device $script:Stale -DaysDisabled 61)

            $run = Invoke-Main -StageName Delete -File $file

            @($script:Writes | ForEach-Object { $_.Method }) | Should -Be @('DELETE')
            $script:Writes[0].ObjectId | Should -Be $script:Stale.id
            $run.Rows | Should -HaveCount 1
            $run.Rows[0].Status | Should -Be 'Deleted'
            @($script:Devices | ForEach-Object { $_.displayName }) | Should -Be @('ACTIVE', 'MANAGED', 'HYBRID', 'KEYED', 'OFF')
            $run.Failure | Should -BeNullOrEmpty
            $run.Files | Should -HaveCount 1
            $run.Files[0].Name | Should -BeLike 'StaleEntraDevice-Delete-*.csv'
        }

        It 'reports each device in the file, and deletes only the one nothing speaks against' {
            $gone = Get-StandInDevice -Name 'GONE'
            $file = Get-DisabledFile -Row @(
                Get-FileRow -Device $script:Stale -DaysDisabled 61
                Get-FileRow -Device $script:Keyed -DaysDisabled 61
                Get-FileRow -Device $script:Off -DaysDisabled 10
                Get-FileRow -Device $gone -DaysDisabled 61
            )

            $run = Invoke-Main -StageName Delete -File $file

            @($run.Rows | ForEach-Object { $_.Status }) | Should -Be @('Deleted', 'Skipped', 'InGracePeriod', 'Gone')
            (Get-Row -Run $run -Name 'KEYED').Reason | Should -BeLike '*holds 1 BitLocker recovery key(s)*'
            @($script:Writes | ForEach-Object { $_.ObjectId }) | Should -Be @($script:Stale.id)
            $run.Information | Should -Contain 'Stage Delete: Deleted 1, Gone 1, InGracePeriod 1, Skipped 1.'
        }

        It 'deletes a device with recovery keys only with -IncludeDevicesWithRecoveryKey' {
            $file = Get-DisabledFile -Row (Get-FileRow -Device $script:Keyed -DaysDisabled 61)

            $run = Invoke-Main -StageName Delete -File $file -WithKeys

            $run.Rows[0].Status | Should -Be 'Deleted'
            $script:Writes[0].ObjectId | Should -Be $script:Keyed.id
        }

        It 'follows -GraceDays' {
            $file = Get-DisabledFile -Row (Get-FileRow -Device $script:Stale -DaysDisabled 20)

            (Invoke-Main -StageName Delete -File $file).Rows[0].Status | Should -Be 'InGracePeriod'
            (Invoke-Main -StageName Delete -File $file -Grace 14).Rows[0].Status | Should -Be 'Deleted'
        }

        It 'leaves alone a device that was enabled again, or added to the exclusion group' {
            $script:Stale.accountEnabled = $true
            $script:Members = @($script:Keyed.id)
            $file = Get-DisabledFile -Row @((Get-FileRow -Device $script:Stale), (Get-FileRow -Device $script:Keyed))

            $run = Invoke-Main -StageName Delete -File $file -Group $script:GroupId -WithKeys

            $script:Writes | Should -HaveCount 0
            (Get-Row -Run $run -Name 'STALE').Reason | Should -Be 'Left alone: enabled again since it was disabled.'
            (Get-Row -Run $run -Name 'KEYED').Reason | Should -Be 'Left alone: in the exclusion group, and disabled: enable it again if it is in use.'
        }

        It 'changes nothing under -WhatIf' {
            $file = Get-DisabledFile -Row (Get-FileRow -Device $script:Stale -DaysDisabled 61)

            $run = Invoke-Main -StageName Delete -File $file -DryRun

            $script:Writes | Should -HaveCount 0
            $run.Rows[0].Status | Should -Be 'WouldDelete'
            $script:Devices | Should -HaveCount 6
        }

        It 'refuses the whole batch when it is over -MaximumDeviceCount, and deletes nothing' {
            $file = Get-DisabledFile -Row @((Get-FileRow -Device $script:Stale), (Get-FileRow -Device $script:Off))

            $run = Invoke-Main -StageName Delete -File $file -Maximum 1

            $script:Writes | Should -HaveCount 0
            $run.Failure | Should -BeLike '-Stage Delete would change 2 device(s), more than -MaximumDeviceCount 1, so none was changed.*'
            $script:Devices | Should -HaveCount 6
        }

        It 'never sends anything but a DELETE for a device in the file' {
            $file = Get-DisabledFile -Row @((Get-FileRow -Device $script:Stale), (Get-FileRow -Device $script:Off))

            $null = Invoke-Main -StageName Delete -File $file

            @($script:Writes | ForEach-Object { $_.Method } | Select-Object -Unique) | Should -Be @('DELETE')
            @($script:Writes | ForEach-Object { $_.ObjectId }) | Should -Be @($script:Stale.id, $script:Off.id)
        }
    }
}

Describe 'The script, run as a file' {

    BeforeAll {
        function Invoke-ScriptFile {
            # Starts the script with -File in a child process, as a scheduled
            # task would, so that its exit ends that process and not the test
            # run. Every case here is refused before the script signs in, so
            # nothing reaches Graph. The text comes back without white space,
            # because the host wraps long errors.
            param ([string[]]$Argument)

            # Continue, not the caller's Stop: Windows PowerShell 5.1 turns the
            # child's error output into a terminating error under Stop, which
            # is what the Windows PowerShell step in CI sets, and the test would
            # end there instead of reading the exit code.
            $ErrorActionPreference = 'Continue'
            $output = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $script:ScriptPath @Argument 2>&1)
            [pscustomobject]@{
                ExitCode = $LASTEXITCODE
                Text     = (@($output | ForEach-Object { [string]$_ }) -join '') -replace '\s', ''
            }
        }
    }

    It 'exits 1 and gives the reason, not an error of its own, when it refuses a request' -Skip:(-not $script:ModuleAvailable) {
        $run = Invoke-ScriptFile -Argument '-Stage', 'Delete'

        $run.ExitCode | Should -Be 1
        $run.Text | Should -BeLike '*Scriptfailed:-StageDeleteneeds-DisabledDevicePath*'
    }

    # PowerShell refuses these before the script's first line, so they need
    # no module: the error names the parameter and is not the script's own.
    It 'does not start with <Argument>' -ForEach @(
        @{ Argument = '-StaleAfterDays 29'; Named = 'StaleAfterDays' }
        @{ Argument = '-GraceDays 6'; Named = 'GraceDays' }
        @{ Argument = '-MaximumDeviceCount 0'; Named = 'MaximumDeviceCount' }
        @{ Argument = '-Stage Purge'; Named = 'Stage' }
        @{ Argument = '-ExcludeGroupId not-an-object-id'; Named = 'ExcludeGroupId' }
    ) {
        $run = Invoke-ScriptFile -Argument ($Argument -split ' ')

        $run.ExitCode | Should -Be 1
        $run.Text | Should -BeLike "*'$Named'*"
        $run.Text | Should -Not -BeLike '*Scriptfailed*'
        $run.Text | Should -Not -BeLike '*couldnotbeloaded*'
    }
}
