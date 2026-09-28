# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Add-GroupDeviceMember.ps1: how it reads and cleans the
    names, how it decides which device each name means, what it checks about
    the group, and what it sends when it adds devices.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, without running
    its main block, and Get-GraphCollection and Invoke-GraphRequestWithRetry
    are replaced by a stand-in tenant held in memory. The stand-in answers the
    device lookup by reading the filter the script sends, so a filter that
    names the wrong devices fails here. Nothing reaches Graph and no module is
    needed.

    Identifier-shaped values are built at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Groups\Add-GroupDeviceMember.Tests.ps1 -Output Detailed

.NOTES
    PowerShell    : 5.1 or 7.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
#>

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Add-GroupDeviceMember.ps1'

    # Every top-level function of the script, without the main block.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Add-GroupDeviceMember.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }

    $script:Base = 'https://graph.microsoft.com/v1.0'
    $script:Now = [datetime]::new(2026, 9, 28, 12, 0, 0, [DateTimeKind]::Utc)
    $script:Reads = [System.Collections.Generic.List[object]]::new()
    $script:Posts = [System.Collections.Generic.List[object]]::new()

    function Get-FilterName {
        # The names in a devices request's "displayName in (...)" filter.
        param ([string]$Uri)

        $query = ($Uri -split '\?', 2)[1]
        $filter = @($query -split '&' | Where-Object { $_ -like '$filter=*' })[0].Substring(8)
        $filter = [uri]::UnescapeDataString($filter)
        if ($filter -notmatch "^displayName in \((.*)\)$") { throw "Unexpected filter: $filter" }
        foreach ($match in [regex]::Matches($Matches[1], "'((?:[^']|'')*)'")) { $match.Groups[1].Value.Replace("''", "'") }
    }

    # Defined after the script's functions, so they replace the helpers. They
    # take only the parameters the script passes, so a new one fails here.
    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt)

        $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })

        $items = [System.Collections.Generic.List[object]]::new()
        if ($Uri -like "$script:Base/devices?*") {
            $wanted = @(Get-FilterName -Uri $Uri)
            foreach ($device in @($script:Devices)) { if ($wanted -contains $device.displayName) { $items.Add($device) } }
        }
        elseif ($Uri -eq "$script:Base/groups/$script:GroupId/members?`$select=id&`$top=999") {
            foreach ($member in @($script:Members)) { $items.Add([pscustomobject]@{ id = $member }) }
        }
        else {
            throw "The stand-in tenant has no collection at $Uri"
        }
        return , $items
    }

    function Invoke-GraphRequestWithRetry {
        param ([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', [hashtable]$Body, [int]$MaximumAttempt)

        if ($Method -eq 'POST') {
            $script:Posts.Add([pscustomobject]@{ Uri = $Uri; Body = $Body })
            $objectId = ($Body['@odata.id'] -split '/')[-1]
            if ($script:PostFailures.ContainsKey($objectId)) { throw $script:PostFailures[$objectId] }
            return $null
        }

        $script:Reads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt })
        if ($Uri -like "$script:Base/groups/$script:GroupId`?*") {
            if ($null -eq $script:Group) { throw (Get-GraphFailure -StatusCode 404 -Message 'Request_ResourceNotFound') }
            return $script:Group
        }
        throw "The stand-in tenant has nothing at $Uri"
    }

    function Get-GraphFailure {
        # The exception the real helper throws: the status in Data.
        param ([int]$StatusCode, [string]$Message)

        $exception = [System.Exception]::new("HTTP $StatusCode from Graph after 1 attempt(s): $Message")
        $exception.Data['StatusCode'] = $StatusCode
        $exception
    }

    function Get-StandInDevice {
        # A device as Graph v1.0 returns it with the script's $select.
        param (
            [string]$Name = 'PC01',
            [object]$TrustType = 'ServerAd',
            [object]$Enabled = $true,
            [object]$DaysSinceActivity = 3,
            [string]$Id = [guid]::NewGuid().ToString()
        )

        $signIn = $null
        if ($null -ne $DaysSinceActivity) { $signIn = $script:Now.AddDays(-$DaysSinceActivity).ToString('yyyy-MM-ddTHH:mm:ssZ') }

        [pscustomobject]@{
            id                            = $Id
            deviceId                      = [guid]::NewGuid().ToString()
            displayName                   = $Name
            trustType                     = $TrustType
            accountEnabled                = $Enabled
            approximateLastSignInDateTime = $signIn
            operatingSystem               = 'Windows'
            operatingSystemVersion        = '10.0.26100.1000'
        }
    }

    function Get-StandInGroup {
        param (
            [string[]]$GroupTypes = @(),
            [object]$SecurityEnabled = $true,
            [object]$MailEnabled = $false,
            [object]$Synced = $null
        )

        [pscustomobject]@{
            id                    = $script:GroupId
            displayName           = 'Example devices'
            groupTypes            = $GroupTypes
            securityEnabled       = $SecurityEnabled
            mailEnabled           = $MailEnabled
            onPremisesSyncEnabled = $Synced
        }
    }

    function Get-NameList {
        param ([string[]]$Name)
        @((ConvertTo-DeviceNameList -Name $Name).Names)
    }

    function Resolve-One {
        # Resolves one name against the given devices and returns its record.
        param ([string]$Name, [object[]]$Device, [hashtable]$Filter = @{})

        $records = @(Resolve-DeviceName -Name (Get-NameList -Name $Name) -Device $Device -Now $script:Now @Filter)
        if ($records.Count -ne 1) { throw "Expected one record, got $($records.Count)." }
        $records[0]
    }
}

Describe 'Reading the names' {

    Context 'ConvertTo-DeviceNameList' {

        It 'trims spaces and quotes and drops blank lines' {
            $list = ConvertTo-DeviceNameList -Name @('  PC01 ', '', '   ', '"PC02"', "'PC03'", $null)

            @($list.Names | ForEach-Object LookupName) | Should -Be @('PC01', 'PC02', 'PC03')
        }

        It 'looks up a fully qualified name by its host name, and reports it as given' {
            $list = ConvertTo-DeviceNameList -Name @('pc01.contoso.com')

            $list.Names[0].LookupName | Should -Be 'pc01'
            $list.Names[0].InputName | Should -Be 'pc01.contoso.com'
        }

        It 'keeps a name with a space whole, dots and all' {
            $list = ConvertTo-DeviceNameList -Name @('Alex iPhone 15.2')

            $list.Names[0].LookupName | Should -Be 'Alex iPhone 15.2'
        }

        It 'collapses duplicates without regard to case or domain, keeping the first spelling' {
            $list = ConvertTo-DeviceNameList -Name @('PC01', 'pc01', 'pc01.contoso.com', 'PC02')

            @($list.Names | ForEach-Object InputName) | Should -Be @('PC01', 'PC02')
            $list.DuplicateCount | Should -Be 2
        }

        It 'returns an empty list for no names' {
            (ConvertTo-DeviceNameList -Name @()).Names.Count | Should -Be 0
        }
    }

    Context 'Read-DeviceNameFile' {

        It 'reads a text file one name per line' {
            $file = Join-Path -Path $TestDrive -ChildPath 'names.txt'
            Set-Content -LiteralPath $file -Value @('PC01', 'PC02')

            @(Read-DeviceNameFile -Path $file) | Should -Be @('PC01', 'PC02')
        }

        It 'reads the only column of a CSV' {
            $file = Join-Path -Path $TestDrive -ChildPath 'single.csv'
            Set-Content -LiteralPath $file -Value @('Hostname', 'PC01', 'PC02')

            @(Read-DeviceNameFile -Path $file) | Should -Be @('PC01', 'PC02')
        }

        It 'reads the named column of a CSV, without regard to case' {
            $file = Join-Path -Path $TestDrive -ChildPath 'several.csv'
            Set-Content -LiteralPath $file -Value @('Site,Hostname', 'North,PC01', 'South,PC02')

            @(Read-DeviceNameFile -Path $file -ColumnName 'hostname') | Should -Be @('PC01', 'PC02')
        }

        It 'names the columns when a CSV has several and none was chosen' {
            $file = Join-Path -Path $TestDrive -ChildPath 'unnamed.csv'
            Set-Content -LiteralPath $file -Value @('Site,Hostname', 'North,PC01')

            { Read-DeviceNameFile -Path $file } | Should -Throw -ExpectedMessage '*2 columns: Site, Hostname*-ColumnName*'
        }

        It 'names the columns when the chosen one is missing' {
            $file = Join-Path -Path $TestDrive -ChildPath 'missing.csv'
            Set-Content -LiteralPath $file -Value @('Site,Hostname', 'North,PC01')

            { Read-DeviceNameFile -Path $file -ColumnName 'Name' } | Should -Throw -ExpectedMessage "*no column 'Name'*Site, Hostname*"
        }
    }
}

Describe 'Get-DeviceByDisplayName' {

    BeforeEach {
        $script:Reads.Clear()
        $script:Devices = @()
    }

    It 'asks for the names in batches of 15' {
        $names = @(1..16 | ForEach-Object { 'PC{0:d2}' -f $_ })

        $null = Get-DeviceByDisplayName -Name $names -BaseUri $script:Base -MaximumAttempt 3

        $script:Reads | Should -HaveCount 2
        @(Get-FilterName -Uri $script:Reads[0].Uri) | Should -Be $names[0..14]
        @(Get-FilterName -Uri $script:Reads[1].Uri) | Should -Be @('PC16')
        @($script:Reads | ForEach-Object MaximumAttempt) | Should -Be @(3, 3)
    }

    It 'escapes a quote in a name, and sends the filter URL-encoded' {
        $null = Get-DeviceByDisplayName -Name @("Alex's laptop") -BaseUri $script:Base

        $script:Reads[0].Uri | Should -Not -Match ' '
        @(Get-FilterName -Uri $script:Reads[0].Uri) | Should -Be @("Alex's laptop")
    }

    It 'selects what the filters and the report need' {
        $null = Get-DeviceByDisplayName -Name @('PC01') -BaseUri $script:Base

        foreach ($property in 'id', 'deviceId', 'displayName', 'trustType', 'accountEnabled', 'approximateLastSignInDateTime') {
            $script:Reads[0].Uri | Should -Match "[?&]\`$select=[^&]*\b$property\b"
        }
    }

    It 'returns every record by those names, duplicates included' {
        $script:Devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'))

        $found = Get-DeviceByDisplayName -Name @('PC01') -BaseUri $script:Base

        $found.Count | Should -Be 2
    }

    It 'sends nothing for no names' {
        $found = Get-DeviceByDisplayName -Name @() -BaseUri $script:Base

        $found.Count | Should -Be 0
        $script:Reads | Should -HaveCount 0
    }
}

Describe 'Resolve-DeviceName' {

    Context 'status' {

        It 'is NotFound when no record has the name' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -Name 'PC02')

            $record.Status | Should -Be 'NotFound'
            $record.ObjectId | Should -BeNullOrEmpty
            $record.CandidateCount | Should -Be 0
        }

        It 'is Matched for one record, and gives its object ID, not its device ID' {
            $device = Get-StandInDevice -Name 'PC01'

            $record = Resolve-One -Name 'PC01' -Device @($device)

            $record.Status | Should -Be 'Matched'
            $record.ObjectId | Should -Be $device.id
            $record.DeviceId | Should -Be $device.deviceId
            $record.ObjectId | Should -Not -Be $device.deviceId
        }

        It 'matches the name without regard to case' {
            $record = Resolve-One -Name 'pc01' -Device @(Get-StandInDevice -Name 'PC01')

            $record.Status | Should -Be 'Matched'
            $record.InputName | Should -Be 'pc01'
            $record.DisplayName | Should -Be 'PC01'
        }

        It 'is Ambiguous when two records pass, and chooses neither' {
            $first = Get-StandInDevice -Name 'PC01'
            $second = Get-StandInDevice -Name 'PC01'

            $record = Resolve-One -Name 'PC01' -Device @($first, $second)

            $record.Status | Should -Be 'Ambiguous'
            $record.ObjectId | Should -BeNullOrEmpty
            $record.CandidateObjectIds | Should -Be "$($first.id); $($second.id)"
            $record.Reason | Should -BeLike '2 records*-TrustType*'
        }

        It 'returns one record per name, in input order' {
            $devices = @((Get-StandInDevice -Name 'PC03'), (Get-StandInDevice -Name 'PC01'))

            $records = @(Resolve-DeviceName -Name (Get-NameList -Name 'PC01', 'PC02', 'PC03') -Device $devices -Now $script:Now)

            @($records | ForEach-Object InputName) | Should -Be @('PC01', 'PC02', 'PC03')
            @($records | ForEach-Object Status) | Should -Be @('Matched', 'NotFound', 'Matched')
        }
    }

    Context 'trust type' {

        It 'excludes a device of another trust type, and says which' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -TrustType 'AzureAd') -Filter @{ TrustType = @('ServerAd') }

            $record.Status | Should -Be 'Excluded'
            $record.Reason | Should -Be 'Failed the filters: trust type AzureAd.'
            $record.TrustType | Should -Be 'AzureAd'
            $record.ObjectId | Should -BeNullOrEmpty
        }

        It 'excludes a device with no trust type' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -TrustType $null) -Filter @{ TrustType = @('ServerAd') }

            $record.Reason | Should -Be 'Failed the filters: no trust type.'
        }

        It 'keeps any of several trust types' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -TrustType 'AzureAd') -Filter @{ TrustType = @('ServerAd', 'AzureAd') }

            $record.Status | Should -Be 'Matched'
        }

        It 'settles a duplicate name, and reports the record it set aside' {
            $hybrid = Get-StandInDevice -TrustType 'ServerAd'
            $registered = Get-StandInDevice -TrustType 'Workplace'

            $record = Resolve-One -Name 'PC01' -Device @($registered, $hybrid) -Filter @{ TrustType = @('ServerAd') }

            $record.Status | Should -Be 'Matched'
            $record.ObjectId | Should -Be $hybrid.id
            $record.JoinType | Should -Be 'Microsoft Entra hybrid joined'
            $record.CandidateCount | Should -Be 2
            $record.Reason | Should -Be '1 other record(s) by this name failed the filters: trust type Workplace.'
        }

        It 'names <TrustType> as <JoinType>' -ForEach @(
            @{ TrustType = 'ServerAd'; JoinType = 'Microsoft Entra hybrid joined' }
            @{ TrustType = 'AzureAd'; JoinType = 'Microsoft Entra joined' }
            @{ TrustType = 'Workplace'; JoinType = 'Microsoft Entra registered' }
            @{ TrustType = ''; JoinType = '' }
        ) {
            ConvertTo-JoinType -TrustType $TrustType | Should -Be $JoinType
        }
    }

    Context 'activity' {

        It 'keeps a device active <Days> day(s) ago within 30 days' -ForEach @(
            @{ Days = 0 }
            @{ Days = 29 }
            @{ Days = 30 }
        ) {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -DaysSinceActivity $Days) -Filter @{ ActiveWithinDays = 30 }

            $record.Status | Should -Be 'Matched'
            $record.DaysSinceActivity | Should -Be $Days
        }

        It 'excludes a device last active 31 days ago, and says so' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -DaysSinceActivity 31) -Filter @{ ActiveWithinDays = 30 }

            $record.Status | Should -Be 'Excluded'
            $record.Reason | Should -Be 'Failed the filters: last active 31 days ago.'
        }

        It 'excludes a device with no activity timestamp' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -DaysSinceActivity $null) -Filter @{ ActiveWithinDays = 30 }

            $record.Status | Should -Be 'Excluded'
            $record.Reason | Should -Be 'Failed the filters: no activity recorded.'
        }

        It 'ignores activity when no window is given' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -DaysSinceActivity $null)

            $record.Status | Should -Be 'Matched'
            $record.DaysSinceActivity | Should -BeNullOrEmpty
        }

        It 'reads the timestamp as a DateTime too, as PowerShell 7.0 to 7.4 parse it' {
            $device = Get-StandInDevice
            $device.approximateLastSignInDateTime = $script:Now.AddDays(-5)

            $record = Resolve-One -Name 'PC01' -Device @($device) -Filter @{ ActiveWithinDays = 30 }

            $record.Status | Should -Be 'Matched'
            $record.ApproximateLastSignInDateTime.Kind | Should -Be 'Utc'
        }

        It 'settles a re-imaged device: the stale record drops out' {
            $current = Get-StandInDevice -DaysSinceActivity 2
            $stale = Get-StandInDevice -DaysSinceActivity 200

            $record = Resolve-One -Name 'PC01' -Device @($stale, $current) -Filter @{ ActiveWithinDays = 30 }

            $record.ObjectId | Should -Be $current.id
        }
    }

    Context 'disabled devices' {

        It 'excludes a disabled device by default' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -Enabled $false)

            $record.Status | Should -Be 'Excluded'
            $record.Reason | Should -Be 'Failed the filters: disabled.'
        }

        It 'keeps a disabled device with -IncludeDisabled' {
            $record = Resolve-One -Name 'PC01' -Device @(Get-StandInDevice -Enabled $false) -Filter @{ IncludeDisabled = $true }

            $record.Status | Should -Be 'Matched'
            $record.AccountEnabled | Should -BeFalse
        }

        It 'lists every filter a device fails' {
            $device = Get-StandInDevice -TrustType 'Workplace' -Enabled $false -DaysSinceActivity 90

            $record = Resolve-One -Name 'PC01' -Device @($device) -Filter @{ TrustType = @('ServerAd'); ActiveWithinDays = 30 }

            $record.Reason | Should -Be 'Failed the filters: trust type Workplace, disabled, last active 90 days ago.'
        }
    }
}

Describe 'The target group' {

    BeforeAll {
        $script:GroupId = [guid]::NewGuid().ToString()
    }

    BeforeEach {
        $script:Reads.Clear()
        $script:Members = @()
    }

    Context 'Get-GroupRefusal' {

        It 'refuses a group that <Case>' -ForEach @(
            @{ Case = 'has dynamic membership'; Group = @{ GroupTypes = @('DynamicMembership') }; Expected = '*dynamic membership*' }
            @{ Case = 'is a Microsoft 365 group'; Group = @{ GroupTypes = @('Unified'); MailEnabled = $true }; Expected = '*Microsoft 365 group*' }
            @{ Case = 'is a distribution list'; Group = @{ SecurityEnabled = $false; MailEnabled = $true }; Expected = '*not a security group*' }
            @{ Case = 'is mail-enabled'; Group = @{ MailEnabled = $true }; Expected = '*mail-enabled*Exchange*' }
            @{ Case = 'is synced from on-premises'; Group = @{ Synced = $true }; Expected = '*on-premises Active Directory*' }
        ) {
            Get-GroupRefusal -Group (Get-StandInGroup @Group) | Should -BeLike $Expected
        }

        It 'accepts an assigned security group, including one no longer synced' -ForEach @(
            @{ Synced = $null }
            @{ Synced = $false }
        ) {
            Get-GroupRefusal -Group (Get-StandInGroup -Synced $Synced) | Should -BeNullOrEmpty
        }
    }

    Context 'Get-TargetGroup' {

        It 'returns the group name and its direct members' {
            $script:Group = Get-StandInGroup
            $member = [guid]::NewGuid().ToString()
            $script:Members = @($member)

            $group = Get-TargetGroup -GroupId $script:GroupId -BaseUri $script:Base -MaximumAttempt 2

            $group.DisplayName | Should -Be 'Example devices'
            $group.MemberIds.Contains($member.ToUpperInvariant()) | Should -BeTrue
            @($script:Reads | ForEach-Object MaximumAttempt) | Should -Be @(2, 2)
        }

        It 'says the group was not found, rather than passing on a 404' {
            $script:Group = $null

            { Get-TargetGroup -GroupId $script:GroupId -BaseUri $script:Base } | Should -Throw -ExpectedMessage "No group has the object ID '$script:GroupId'*"
        }

        It 'refuses a dynamic group by name, before reading its members' {
            $script:Group = Get-StandInGroup -GroupTypes 'DynamicMembership'

            { Get-TargetGroup -GroupId $script:GroupId -BaseUri $script:Base } | Should -Throw -ExpectedMessage "Group 'Example devices' has dynamic membership*"
            @($script:Reads | Where-Object Uri -Like '*/members*') | Should -HaveCount 0
        }
    }
}

Describe 'Add-DeviceToGroup' {

    BeforeAll {
        $script:GroupId = [guid]::NewGuid().ToString()

        function Get-ResolvedBatch {
            # Records for the given devices, resolved as the main block would.
            param ([object[]]$Device)
            @(Resolve-DeviceName -Name (Get-NameList -Name @($Device | ForEach-Object displayName)) -Device $Device -Now $script:Now)
        }

        function Get-TargetGroupStandIn {
            param ([string[]]$Member = @())
            $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($id in $Member) { $null = $ids.Add($id) }
            [pscustomobject]@{ Id = $script:GroupId; DisplayName = 'Example devices'; MemberIds = $ids }
        }
    }

    BeforeEach {
        $script:Posts.Clear()
        $script:PostFailures = @{}
    }

    It 'adds each Matched device by object ID, one request each' {
        $devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'))
        $records = Get-ResolvedBatch -Device $devices

        Add-DeviceToGroup -Record $records -Group (Get-TargetGroupStandIn) -BaseUri $script:Base -Confirm:$false

        $script:Posts | Should -HaveCount 2
        $script:Posts[0].Uri | Should -Be "$script:Base/groups/$script:GroupId/members/`$ref"
        $script:Posts[0].Body['@odata.id'] | Should -Be "$script:Base/directoryObjects/$($devices[0].id)"
        @($records | ForEach-Object Membership) | Should -Be @('Added', 'Added')
    }

    It 'skips current members and records that did not match' {
        $member = Get-StandInDevice -Name 'PC01'
        $new = Get-StandInDevice -Name 'PC02'
        $disabled = Get-StandInDevice -Name 'PC03' -Enabled $false
        $records = Get-ResolvedBatch -Device @($member, $new, $disabled)

        Add-DeviceToGroup -Record $records -Group (Get-TargetGroupStandIn -Member $member.id) -BaseUri $script:Base -Confirm:$false

        $script:Posts | Should -HaveCount 1
        @($records | ForEach-Object Membership) | Should -Be @('AlreadyMember', 'Added', $null)
    }

    It 'adds nothing under -WhatIf, and marks what it would add' {
        $records = Get-ResolvedBatch -Device @(Get-StandInDevice)

        Add-DeviceToGroup -Record $records -Group (Get-TargetGroupStandIn) -BaseUri $script:Base -WhatIf

        $script:Posts | Should -HaveCount 0
        $records[0].Membership | Should -Be 'WouldAdd'
    }

    It 'counts "already exists" as a member, as a retried request that landed returns it' {
        $device = Get-StandInDevice
        $script:PostFailures[$device.id] = Get-GraphFailure -StatusCode 400 -Message 'One or more added object references already exist for the following modified properties: members.'
        $records = Get-ResolvedBatch -Device @($device)

        Add-DeviceToGroup -Record $records -Group (Get-TargetGroupStandIn) -BaseUri $script:Base -Confirm:$false

        $records[0].Membership | Should -Be 'AlreadyMember'
    }

    It 'stops at the first 403, names the roles, and attempts nothing after it' {
        $devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'), (Get-StandInDevice -Name 'PC03'))
        $script:PostFailures[$devices[0].id] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'
        $records = Get-ResolvedBatch -Device $devices

        Add-DeviceToGroup -Record $records -Group (Get-TargetGroupStandIn) -BaseUri $script:Base -Confirm:$false

        $script:Posts | Should -HaveCount 1
        $records[0].Membership | Should -Be 'Failed'
        $records[0].MembershipDetail | Should -BeLike '*HTTP 403*Groups Administrator*Authorization_RequestDenied*'
        @($records[1..2] | ForEach-Object Membership) | Should -Be @('NotAttempted', 'NotAttempted')
    }

    It 'records any other failure and carries on with the next device' {
        $devices = @((Get-StandInDevice -Name 'PC01'), (Get-StandInDevice -Name 'PC02'))
        $script:PostFailures[$devices[0].id] = Get-GraphFailure -StatusCode 404 -Message 'Request_ResourceNotFound'
        $records = Get-ResolvedBatch -Device $devices

        Add-DeviceToGroup -Record $records -Group (Get-TargetGroupStandIn) -BaseUri $script:Base -Confirm:$false

        $records[0].Membership | Should -Be 'Failed'
        $records[0].MembershipDetail | Should -BeLike '*HTTP 404*'
        $records[1].Membership | Should -Be 'Added'
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
        $script:GroupId = [guid]::NewGuid().ToString()

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
                [string[]]$Name,
                [string]$File = '',
                [string[]]$Trust,
                [int]$Days = 0,
                [string]$Group = '',
                [switch]$DryRun
            )

            $folder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
            $null = New-Item -ItemType Directory -Path $folder

            # The main block reads the script's parameters and settings from
            # the scope that runs it.
            Set-Variable -Name 'Path' -Value $File
            Set-Variable -Name 'ColumnName' -Value ''
            Set-Variable -Name 'DeviceName' -Value $Name
            Set-Variable -Name 'TrustType' -Value $Trust
            Set-Variable -Name 'ActiveWithinDays' -Value $Days
            Set-Variable -Name 'IncludeDisabled' -Value ([switch]$false)
            Set-Variable -Name 'GroupId' -Value $Group
            Set-Variable -Name 'OutputPath' -Value $folder
            Set-Variable -Name 'TenantId' -Value ''
            Set-Variable -Name 'UseDeviceCode' -Value ([switch]$false)
            Set-Variable -Name 'MaximumRetryCount' -Value 5
            Set-Variable -Name 'GraphBaseUri' -Value $script:Base
            Set-Variable -Name 'RequiredScopes' -Value $script:Scopes
            Set-Variable -Name 'ImportCsvHeader' -Value 'Member object ID or user principal name [memberObjectIdOrUpn] Required'
            Set-Variable -Name 'ActivityTimestampResolutionDays' -Value 21
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
                Files       = @(Get-ChildItem -LiteralPath $folder -File | Sort-Object Name)
            }
        }
    }

    BeforeEach {
        $script:Reads.Clear()
        $script:Posts.Clear()
        $script:SignIns.Clear()
        $script:PostFailures = @{}
        $script:Group = Get-StandInGroup
        $script:Members = @()

        $script:Hybrid = Get-StandInDevice -Name 'PC01' -TrustType 'ServerAd'
        $script:Joined = Get-StandInDevice -Name 'PC02' -TrustType 'AzureAd'
        $script:Second = Get-StandInDevice -Name 'PC03' -TrustType 'ServerAd'
        $script:Devices = @($script:Hybrid, $script:Joined, $script:Second)
    }

    It 'signs in once, with its scopes, before reading anything' {
        $null = Invoke-Main -Name 'PC01'

        $script:SignIns | Should -HaveCount 1
        $script:SignIns[0].ReadsBefore | Should -Be 0
        [object]::ReferenceEquals($script:SignIns[0].Scope, $script:Scopes) | Should -BeTrue
    }

    It 'returns one record per name and writes nothing to the tenant without -GroupId' {
        $run = Invoke-Main -Name 'PC01', 'PC02', 'PC09' -Trust 'ServerAd'

        @($run.Rows | ForEach-Object Status) | Should -Be @('Matched', 'Excluded', 'NotFound')
        $script:Posts | Should -HaveCount 0
        $run.Information | Should -Contain 'Resolved 3 name(s): Matched 1, NotFound 1, Excluded 1, Ambiguous 0.'
        $run.Failure | Should -BeNullOrEmpty
    }

    It 'writes the report, and an import file with the exact template header and only Matched object IDs' {
        $run = Invoke-Main -Name 'PC01', 'PC02', 'PC03' -Trust 'ServerAd'

        @($run.Files | ForEach-Object Name) | Should -HaveCount 2
        $report = @($run.Files | Where-Object Name -NotLike '*-Import.csv')[0]
        $import = @($run.Files | Where-Object Name -Like '*-Import.csv')[0]

        @(Import-Csv -LiteralPath $report.FullName) | Should -HaveCount 3
        @(Get-Content -LiteralPath $import.FullName) | Should -Be @(
            'Member object ID or user principal name [memberObjectIdOrUpn] Required'
            $script:Hybrid.id
            $script:Second.id
        )
    }

    It 'warns that the portal wants two rows when the import file has one' {
        $run = Invoke-Main -Name 'PC01'

        $run.Warnings | Should -Contain 'The admin center asks for at least two members in an import file. Add a single device in the portal directly, or with -GroupId.'
    }

    It 'writes no import file when nothing matched, and warns' {
        $run = Invoke-Main -Name 'PC09'

        @($run.Files | Where-Object Name -Like '*-Import.csv') | Should -HaveCount 0
        $run.Warnings | Should -Contain 'No name resolved to a device that passed the filters. See Status and Reason on each record.'
    }

    It 'warns that an activity window under 21 days excludes devices in use' {
        $run = Invoke-Main -Name 'PC01' -Days 7

        @($run.Warnings | Where-Object { $_ -like '-ActiveWithinDays 7 is shorter*14 days*' }) | Should -HaveCount 1
    }

    It 'warns about duplicate names' {
        $run = Invoke-Main -Name 'PC01', 'pc01.contoso.com'

        $run.Rows | Should -HaveCount 1
        $run.Warnings | Should -Contain 'Collapsed 1 duplicate name(s); names are compared without regard to case or domain.'
    }

    It 'fails when the input holds no names' {
        $run = Invoke-Main -Name '', '  '

        $run.Failure | Should -Be '-DeviceName holds no device names.'
        $script:SignIns | Should -HaveCount 0
    }

    It 'reads the names from a file when given one' {
        $file = Join-Path -Path $TestDrive -ChildPath 'main-names.txt'
        Set-Content -LiteralPath $file -Value @('PC01', 'PC03')

        $run = Invoke-Main -File $file

        @($run.Rows | ForEach-Object Status) | Should -Be @('Matched', 'Matched')
    }

    Context 'with -GroupId' {

        It 'checks the group before looking up any device' {
            $script:Group = Get-StandInGroup -GroupTypes 'DynamicMembership'

            $run = Invoke-Main -Name 'PC01' -Group $script:GroupId

            $run.Failure | Should -BeLike "Group 'Example devices' has dynamic membership*"
            @($script:Reads | Where-Object Uri -Like '*/devices?*') | Should -HaveCount 0
        }

        It 'adds the Matched devices that are not members, and writes no import file' {
            $script:Members = @($script:Second.id)

            $run = Invoke-Main -Name 'PC01', 'PC02', 'PC03' -Trust 'ServerAd' -Group $script:GroupId

            @($run.Rows | ForEach-Object Membership) | Should -Be @('Added', $null, 'AlreadyMember')
            $script:Posts | Should -HaveCount 1
            $run.Information | Should -Contain "Group 'Example devices': Added 1, AlreadyMember 1."
            @($run.Files | Where-Object Name -Like '*-Import.csv') | Should -HaveCount 0
            $run.Failure | Should -BeNullOrEmpty
        }

        It 'adds nothing under -WhatIf, and still writes both files' {
            $run = Invoke-Main -Name 'PC01', 'PC03' -Group $script:GroupId -DryRun

            $script:Posts | Should -HaveCount 0
            @($run.Rows | ForEach-Object Membership) | Should -Be @('WouldAdd', 'WouldAdd')
            $run.Files | Should -HaveCount 2
        }

        It 'leaves current members out of the import file' {
            $script:Members = @($script:Hybrid.id)

            $run = Invoke-Main -Name 'PC01', 'PC03' -Group $script:GroupId -DryRun

            $import = @($run.Files | Where-Object Name -Like '*-Import.csv')[0]
            @(Get-Content -LiteralPath $import.FullName) | Should -Not -Contain $script:Hybrid.id
            @(Get-Content -LiteralPath $import.FullName) | Should -Contain $script:Second.id
        }

        It 'returns every record, then fails, when a device could not be added' {
            $script:PostFailures[$script:Hybrid.id] = Get-GraphFailure -StatusCode 403 -Message 'Authorization_RequestDenied'

            $run = Invoke-Main -Name 'PC01', 'PC03' -Group $script:GroupId

            $run.Rows | Should -HaveCount 2
            $run.Failure | Should -Be '2 device(s) were not added to the group. See Membership and MembershipDetail on the returned records.'
            @($run.Files | Where-Object Name -NotLike '*-Import.csv') | Should -HaveCount 1
        }
    }
}
