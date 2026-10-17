# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/zenpachi-alt/endpoint-engineering

#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
.SYNOPSIS
    Pester tests for Backup-IntuneConfiguration.ps1: the WindowsUpdates and
    PlatformScripts categories, the timestamp helpers, the Autopatch note in
    the index, and the scopes the script signs in with.

.DESCRIPTION
    The script's functions are loaded from its syntax tree, so its main block,
    which signs in to Graph and ends with exit, never runs. The script reads
    Graph only through Get-GraphObject and Get-GraphCollection. Both are
    replaced by stand-ins that serve a made-up tenant from memory, and the
    backup is written to Pester's TestDrive. Signing in goes through the
    script's real scope check, against stand-ins for Connect-MgGraph and
    Get-MgContext.

    That proves the script's own logic: which files it writes, what the index
    says, and how a failure stays contained. It cannot prove that Graph still
    answers as documented, because the stand-in tenant is built from that
    documentation; only a run against a real tenant shows that. Where a real
    tenant has answered otherwise, the stand-in answers as the tenant did: it
    refuses the assignments path of a macOS shell script. The other three
    categories are not covered yet.

    The script is also started as a file, in a child process, for the exit
    code and the message of a run that fails before it signs in. That gets
    past the script's module check, so it is skipped where
    Microsoft.Graph.Authentication is not installed.

    Identifier-shaped values are generated at run time, so this file passes
    Tools/Test-SensitiveContent.ps1 like any other.

.EXAMPLE
    Invoke-Pester -Path .\Graph\Configuration -Output Detailed

.NOTES
    PowerShell    : 7.2 or later, matching the script under test.
    Graph scopes  : None. Nothing reaches a tenant.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : Pester 5.5.0 or later.
                    Microsoft.Graph.Authentication 2.0.0 or later, optional,
                    for the test of the script run as a file. The other tests
                    do not need it: loading functions from the syntax tree
                    does not run the script's module check.
#>

BeforeDiscovery {
    # The script loads the module before anything else, so it gets as far as
    # its own checks only where the module is installed.
    $script:ModuleAvailable = [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
            Where-Object { $_.Version -ge [version]'2.0.0' })
}

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Backup-IntuneConfiguration.ps1'
    $script:ScriptPath = $scriptPath

    # Every top-level function of the script, without the main block.
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw "Backup-IntuneConfiguration.ps1 does not parse: $($parseErrors[0].Message)" }
    foreach ($statement in $syntaxTree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }

    # What the script's parameters would set. Its functions read these without
    # a scope prefix, so PowerShell finds them here. A test variable must never
    # share one of these names: variable names ignore case, so a helper called
    # $id would silently be the script's -Id filter.
    $script:Name = $null
    $script:Id = $null
    $script:CsvDelimiter = ','
    # Distinct values, so a test can tell they reached Graph and are not defaults.
    $script:GraphRequestOptions = @{ MaximumAttempt = 3; OnRetry = {} }

    function Initialize-BackupState {
        # A fresh backup folder and index, as the script's main block starts a run.
        $script:GraphBeta = 'https://graph.microsoft.com/beta'
        $script:GraphV1 = 'https://graph.microsoft.com/v1.0'
        $script:BackupRoot = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $script:BackupRoot
        $script:LogFile = Join-Path -Path $script:BackupRoot -ChildPath 'Backup.log'
        $script:Index = [System.Collections.Generic.List[object]]::new()
        $script:FailedCount = 0
        $script:CategoryErrors = 0
        $script:GroupCache = @{}
        $script:FilterCache = @{}
        $script:ResolveGroups = $true
        $script:MatchedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $script:MatchedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $script:SeenObjects = [System.Collections.Generic.List[object]]::new()
        $script:CollectionReads = [System.Collections.Generic.List[object]]::new()
    }

    function Get-StandInDriver {
        param ([string]$DriverName, [string]$DriverClass, [string]$ApprovalStatus, [string]$DeployDateTime)

        [pscustomobject]@{
            '@odata.type'         = '#microsoft.graph.windowsDriverUpdateInventory'
            id                    = [guid]::NewGuid().ToString()
            name                  = $DriverName
            # Four parts like a real driver version, but not the shape of an IP address.
            version               = '10.0.26100.1'
            manufacturer          = 'Contoso'
            releaseDateTime       = '2026-08-01T00:00:00Z'
            driverClass           = $DriverClass
            applicableDeviceCount = 12
            approvalStatus        = $ApprovalStatus
            category              = 'recommended'
            deployDateTime        = $DeployDateTime
        }
    }

    function Initialize-StandInTenant {
        # A made-up tenant shaped like the examples in the Graph documentation,
        # varied enough that every branch of the category runs. A date the
        # script compares with today is set relative to today, so no test
        # starts failing on a future date with no change to the code.
        $lastYear = [datetime]::UtcNow.AddYears(-1).ToString('o')
        $inTwoYears = [datetime]::UtcNow.AddYears(2).ToString('o')
        $modified = '2026-09-01T08:00:00Z'
        $includedGroup = [guid]::NewGuid().ToString()
        $excludedGroup = [guid]::NewGuid().ToString()
        $manualProfile = [guid]::NewGuid().ToString()
        $automaticProfile = [guid]::NewGuid().ToString()

        $script:Groups = @{ $includedGroup = 'Autopatch Test ring'; $excludedGroup = 'Kiosks' }
        $script:Assignments = @(
            [pscustomobject]@{
                target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $includedGroup }
            }
            [pscustomobject]@{
                target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $excludedGroup }
            }
        )

        $script:Tenant = @{
            windowsFeatureUpdateProfiles = @(
                [pscustomobject]@{
                    '@odata.type'                = '#microsoft.graph.windowsFeatureUpdateProfile'
                    id                           = [guid]::NewGuid().ToString()
                    displayName                  = 'Windows Autopatch - DSS policy - Release A - Phase 1'
                    featureUpdateVersion         = 'Windows 11, version 24H2'
                    deployableContentDisplayName = 'Windows 11, version 24H2'
                    endOfSupportDate             = $inTwoYears
                    lastModifiedDateTime         = $modified
                    rolloutSettings              = [pscustomobject]@{
                        offerStartDateTimeInUTC = '2026-09-02T00:00:00Z'
                        offerEndDateTimeInUTC   = '2026-09-30T00:00:00Z'
                        offerIntervalInDays     = 7
                    }
                }
                [pscustomobject]@{
                    '@odata.type'                = '#microsoft.graph.windowsFeatureUpdateProfile'
                    id                           = [guid]::NewGuid().ToString()
                    displayName                  = 'Pin 23H2'
                    featureUpdateVersion         = 'Windows 11, version 23H2'
                    deployableContentDisplayName = $null
                    endOfSupportDate             = $lastYear
                    lastModifiedDateTime         = $modified
                    rolloutSettings              = $null
                }
            )
            windowsQualityUpdatePolicies = @(
                [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.windowsQualityUpdatePolicy'
                    id                   = [guid]::NewGuid().ToString()
                    displayName          = 'Quality - Broad'
                    hotpatchEnabled      = $true
                    lastModifiedDateTime = $modified
                    approvalSettings     = @(
                        [pscustomobject]@{
                            windowsQualityUpdateCadence  = 'monthly'
                            windowsQualityUpdateCategory = 'security'
                            approvalMethodType           = 'automatic'
                            deferredDeploymentInDay      = 7
                        }
                        [pscustomobject]@{
                            windowsQualityUpdateCadence  = 'outOfBand'
                            windowsQualityUpdateCategory = 'nonSecurity'
                            approvalMethodType           = 'manual'
                            deferredDeploymentInDay      = 0
                        }
                    )
                }
                [pscustomobject]@{
                    '@odata.type'        = '#microsoft.graph.windowsQualityUpdatePolicy'
                    id                   = [guid]::NewGuid().ToString()
                    displayName          = 'Quality - Kiosks'
                    hotpatchEnabled      = $false
                    lastModifiedDateTime = $modified
                    approvalSettings     = @()
                }
            )
            windowsQualityUpdateProfiles = @(
                [pscustomobject]@{
                    '@odata.type'                = '#microsoft.graph.windowsQualityUpdateProfile'
                    id                           = [guid]::NewGuid().ToString()
                    displayName                  = 'Expedite September'
                    deployableContentDisplayName = $null
                    lastModifiedDateTime         = $modified
                    expeditedUpdateSettings      = [pscustomobject]@{
                        qualityUpdateRelease  = '2026-09-09T00:00:00Z'
                        daysUntilForcedReboot = 2
                    }
                }
            )
            windowsDriverUpdateProfiles  = @(
                [pscustomobject]@{
                    '@odata.type'            = '#microsoft.graph.windowsDriverUpdateProfile'
                    id                       = $manualProfile
                    displayName              = 'Drivers - Manual'
                    approvalType             = 'manual'
                    deploymentDeferralInDays = 0
                    lastModifiedDateTime     = $modified
                    inventorySyncStatus      = [pscustomobject]@{
                        driverInventorySyncState   = 'failure'
                        lastSuccessfulSyncDateTime = '2026-08-01T00:00:00Z'
                    }
                }
                [pscustomobject]@{
                    '@odata.type'            = '#microsoft.graph.windowsDriverUpdateProfile'
                    id                       = $automaticProfile
                    displayName              = 'Drivers - Automatic'
                    approvalType             = 'automatic'
                    deploymentDeferralInDays = 3
                    lastModifiedDateTime     = $modified
                    inventorySyncStatus      = [pscustomobject]@{ driverInventorySyncState = 'success' }
                }
            )
        }

        # A Windows and a macOS platform script, assigned like the policies above.
        $script:Tenant['deviceManagementScripts'] = @(
            [pscustomobject]@{
                '@odata.type'         = '#microsoft.graph.deviceManagementScript'
                id                    = [guid]::NewGuid().ToString()
                displayName           = 'Set the time zone'
                fileName              = 'Set-TimeZone.ps1'
                scriptContent         = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Set-TimeZone -Id 'UTC'`n"))
                runAsAccount          = 'system'
                runAs32Bit            = $false
                enforceSignatureCheck = $false
                lastModifiedDateTime  = $modified
            }
        )
        $script:Tenant['deviceShellScripts'] = @(
            [pscustomobject]@{
                '@odata.type'        = '#microsoft.graph.deviceShellScript'
                id                   = [guid]::NewGuid().ToString()
                displayName          = 'Enable the firewall'
                fileName             = 'enable-firewall.sh'
                scriptContent        = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("#!/bin/sh`necho on`n"))
                runAsAccount         = 'system'
                executionFrequency   = 'PT0S'
                retryCount           = 3
                lastModifiedDateTime = $modified
            }
        )
        # Set to make the service leave out an expanded assignments list.
        $script:ExpandIgnored = $false

        $script:DriverInventories = @{
            $manualProfile    = @(
                Get-StandInDriver -DriverName 'Contoso Audio' -DriverClass 'Audio' -ApprovalStatus 'approved' -DeployDateTime '2026-09-03T00:00:00Z'
                Get-StandInDriver -DriverName 'Contoso Net' -DriverClass 'Net' -ApprovalStatus 'declined'
                Get-StandInDriver -DriverName 'Contoso Firmware' -DriverClass 'Firmware' -ApprovalStatus 'needsReview'
                Get-StandInDriver -DriverName 'Contoso Display' -DriverClass 'Display' -ApprovalStatus 'approved' -DeployDateTime '2026-09-05T00:00:00Z'
            )
            $automaticProfile = @()
        }

        # A request for one of these URIs fails, as Graph would with an error.
        $script:FailingUris = [System.Collections.Generic.List[string]]::new()
    }

    # The script's two Graph readers, replaced. Defined after the script's own
    # functions, so these are the ones its code calls. A request the stand-in
    # tenant cannot answer throws, so a test fails loudly when the script asks
    # for something unexpected.
    function Get-GraphObject {
        param ([Parameter(Mandatory)][string]$Uri)

        if ($script:FailingUris -contains $Uri) { throw "HTTP 500 from GET $Uri" }

        if ($Uri -match '/groups/([^/?]+)\?' -and $script:Groups.ContainsKey($Matches[1])) {
            return [pscustomobject]@{ id = $Matches[1]; displayName = $script:Groups[$Matches[1]] }
        }

        # An object with its assignments expanded, the one way the service
        # returns those of a macOS shell script.
        $expand = '?$expand=assignments'
        if ($Uri.EndsWith($expand)) {
            $expanded = (Get-GraphObject -Uri $Uri.Substring(0, $Uri.Length - $expand.Length)).PSObject.Copy()
            if (-not $script:ExpandIgnored) {
                $expanded | Add-Member -NotePropertyName 'assignments' -NotePropertyValue @($script:Assignments)
            }
            return $expanded
        }

        foreach ($segment in $script:Tenant.Keys) {
            foreach ($object in $script:Tenant[$segment]) {
                if ($Uri -eq "$script:GraphBeta/deviceManagement/$segment/$($object.id)") { return $object }
            }
        }

        throw "The stand-in tenant has no object at $Uri"
    }

    function Get-GraphCollection {
        param ([Parameter(Mandatory)][string]$Uri, [int]$MaximumAttempt, [scriptblock]$OnRetry)

        $script:CollectionReads.Add([pscustomobject]@{ Uri = $Uri; MaximumAttempt = $MaximumAttempt; OnRetry = $OnRetry })
        if ($script:FailingUris -contains $Uri) { throw "HTTP 403 from GET $Uri" }

        $source = $null
        switch -Regex ($Uri.Replace("$script:GraphBeta/deviceManagement/", '')) {
            # Documented, but refused by the service, as a real tenant showed.
            '^deviceShellScripts/[^/]+/assignments$' {
                throw "HTTP 400 from GET $Uri after 1 attempt(s): No OData route exists"
            }
            '^(\w+)$' { $source = $script:Tenant[$Matches[1]] }
            '^\w+/[^/]+/assignments$' { $source = $script:Assignments }
            '^\w+/([^/]+)/driverInventories$' { $source = $script:DriverInventories[$Matches[1]] }
        }
        if ($null -eq $source) { throw "The stand-in tenant has no collection at $Uri" }

        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $source) { $items.Add($entry) }
        return , $items
    }

    function Invoke-CategoryBackup {
        # Runs one category as the script would, filtered when -NameFilter or
        # -IdFilter is given, and separates what it warns and reports. Not
        # -Category, which would be the script's own parameter of that name.
        param (
            [Parameter(Mandatory)][ValidateSet('WindowsUpdates', 'PlatformScripts')][string]$CategoryName,
            [string[]]$NameFilter,
            [string[]]$IdFilter
        )

        # The script's functions read -Name and -Id from the scope that calls them.
        Set-Variable -Name 'Name' -Value $NameFilter
        Set-Variable -Name 'Id' -Value $IdFilter
        Set-Variable -Name 'ErrorActionPreference' -Value 'Stop'

        $backup = @{ WindowsUpdates = 'Backup-WindowsUpdate'; PlatformScripts = 'Backup-PlatformScript' }[$CategoryName]
        $all = @(& $backup 3>&1 2>&1)
        [pscustomobject]@{
            Rows     = @($script:Index)
            Root     = Join-Path -Path $script:BackupRoot -ChildPath $CategoryName
            Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)
            Errors   = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
            Log      = Get-Content -LiteralPath $script:LogFile -Raw
        }
    }

    function Get-IndexRow {
        param ([object]$Run, [string]$DisplayName)

        $rows = @($Run.Rows | Where-Object DisplayName -EQ $DisplayName)
        if ($rows.Count -ne 1) { throw "Expected one index row for '$DisplayName', found $($rows.Count)." }
        $rows[0]
    }

    function Get-BackupFile {
        param ([object]$Row, [string]$FileName)

        Join-Path -Path (Join-Path -Path $script:BackupRoot -ChildPath $Row.Folder) -ChildPath $FileName
    }
}

Describe 'Timestamps' {

    It 'formats <Case> as UTC' -ForEach @(
        @{ Case = 'a Graph timestamp'; Value = '2026-03-01T10:15:00Z' }
        @{ Case = 'a timestamp with an offset'; Value = '2026-03-01T12:15:00+02:00' }
        @{ Case = 'a UTC DateTime'; Value = [datetime]::new(2026, 3, 1, 10, 15, 0, [DateTimeKind]::Utc) }
        @{ Case = 'a local DateTime'; Value = [datetime]::new(2026, 3, 1, 10, 15, 0, [DateTimeKind]::Utc).ToLocalTime() }
        @{ Case = 'a DateTime of unspecified kind'; Value = [datetime]::new(2026, 3, 1, 10, 15, 0, [DateTimeKind]::Unspecified) }
    ) {
        Format-UtcDate -Value $Value | Should -BeExactly '01.03.2026 10:15 UTC'
    }

    It 'returns text that is not a timestamp unchanged, and nothing as an empty string' {
        Format-UtcDate -Value 'not a timestamp' | Should -BeExactly 'not a timestamp'
        Format-UtcDate -Value $null | Should -BeExactly ''
        Format-UtcDate -Value '' | Should -BeExactly ''
    }

    # ConvertTo-UtcDateTime is one of the Graph helpers, tested in
    # Templates/Script-Template.Tests.ps1.
}

Describe 'The Autopatch note in the index' {

    BeforeEach {
        Initialize-BackupState
        $script:Item = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); lastModifiedDateTime = $null }
    }

    It 'is added to an object named like a policy Windows Autopatch creates' {
        Invoke-ItemBackup -Category 'WindowsUpdates' -Item $script:Item -CategoryRoot $script:BackupRoot `
            -DisplayName 'Windows Autopatch - DSS policy - Release A - Phase 1' -Body {}

        $script:Index[0].Notes | Should -BeLike 'Named like a policy Windows Autopatch creates*'
        $script:Index[0].Status | Should -Be 'OK'
    }

    It 'is not added to any other name' {
        Invoke-ItemBackup -Category 'ConfigurationProfiles' -Item $script:Item -CategoryRoot $script:BackupRoot `
            -DisplayName 'Pilot - Update ring' -Body {}

        $script:Index[0].Notes | Should -BeNullOrEmpty
    }

    It 'stays on the row of an object that fails, beside the error' {
        $reported = @(Invoke-ItemBackup -Category 'WindowsUpdates' -Item $script:Item -CategoryRoot $script:BackupRoot `
                -DisplayName 'Windows Autopatch - DSS policy - Release A - Phase 1' -Body { throw 'HTTP 500 from GET the policy' } 2>&1)

        $script:Index[0].Status | Should -Be 'Failed'
        $script:Index[0].Notes | Should -BeLike 'Named like a policy Windows Autopatch creates* | HTTP 500 from GET the policy'
        $reported | Should -HaveCount 1
    }
}

Describe 'The WindowsUpdates category' {

    Context 'A tenant with every policy type' {

        BeforeAll {
            Initialize-StandInTenant
            Initialize-BackupState
            $script:Run = Invoke-CategoryBackup -CategoryName WindowsUpdates
        }

        It 'backs up all seven policies without a failure, a warning or an error' {
            $script:Run.Rows | Should -HaveCount 7
            $script:Run.Rows.Status | Should -Not -Contain 'Failed'
            $script:FailedCount | Should -Be 0
            $script:CategoryErrors | Should -Be 0
            $script:Run.Warnings | Should -BeNullOrEmpty
            $script:Run.Errors | Should -BeNullOrEmpty
        }

        It 'files <Pattern> policies under WindowsUpdates/<TypeFolder>' -ForEach @(
            @{ Pattern = 'Feature update'; TypeFolder = 'FeatureUpdates'; Expected = 2 }
            @{ Pattern = 'Quality update'; TypeFolder = 'QualityUpdates'; Expected = 2 }
            @{ Pattern = 'Expedited quality update'; TypeFolder = 'ExpeditedQualityUpdates'; Expected = 1 }
            @{ Pattern = 'Driver update'; TypeFolder = 'DriverUpdates'; Expected = 2 }
        ) {
            $rows = @($script:Run.Rows | Where-Object { $_.SubType -like "$Pattern*" })

            $rows | Should -HaveCount $Expected
            foreach ($row in $rows) {
                (($row.Folder -split '[\\/]')[0..1] -join '/') | Should -Be "WindowsUpdates/$TypeFolder"
            }
        }

        It 'saves every policy and its assignments' {
            foreach ($row in $script:Run.Rows) {
                Get-BackupFile -Row $row -FileName 'policy.json' | Should -Exist
                Get-BackupFile -Row $row -FileName 'assignments.json' | Should -Exist
            }
        }

        It 'saves a policy as Graph returned it' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Windows Autopatch - DSS policy - Release A - Phase 1'
            $saved = Get-Content -LiteralPath (Get-BackupFile -Row $row -FileName 'policy.json') -Raw | ConvertFrom-Json

            $saved.featureUpdateVersion | Should -Be 'Windows 11, version 24H2'
            $saved.rolloutSettings.offerIntervalInDays | Should -Be 7
        }

        It 'resolves assignments to group names, as the other categories do' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Quality - Broad'

            $row.AssignmentCount | Should -Be 2
            $row.Assignments | Should -BeExactly 'Include: Autopatch Test ring; Exclude: Kiosks'
        }

        It 'notes the policy named like an Autopatch one, and no other' {
            $noted = @($script:Run.Rows | Where-Object Notes -Like '*Windows Autopatch creates*')

            $noted | Should -HaveCount 1
            $noted[0].DisplayName | Should -Be 'Windows Autopatch - DSS policy - Release A - Phase 1'
        }

        It 'summarises a feature update policy by its version and gradual rollout' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Windows Autopatch - DSS policy - Release A - Phase 1'

            $row.SubType | Should -Be 'Feature update'
            $row.Notes | Should -BeLike '*| Windows 11, version 24H2, gradual rollout from 02.09.2026 00:00 UTC to 30.09.2026 00:00 UTC, 7 day(s) between groups'
        }

        It 'falls back to the version setting, and says when an update is offered at once' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Pin 23H2'

            $row.Notes | Should -BeLike 'Windows 11, version 23H2, offered as soon as possible |*'
        }

        It 'notes a target version past end of support, and leaves the backup OK' {
            $expired = Get-IndexRow -Run $script:Run -DisplayName 'Pin 23H2'
            $current = Get-IndexRow -Run $script:Run -DisplayName 'Windows Autopatch - DSS policy - Release A - Phase 1'

            $expired.Notes | Should -BeLike '*| Target version out of support since *'
            $expired.Status | Should -Be 'OK'
            $current.Notes | Should -Not -BeLike '*out of support*'
        }

        It 'summarises hotpatch and every approval rule of a quality update policy' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Quality - Broad'

            $row.SubType | Should -Be 'Quality update'
            $row.Notes | Should -BeExactly 'Hotpatch: on | Approvals: security monthly: automatic after 7 day(s); nonSecurity outOfBand: manual'
        }

        It 'says only that hotpatch is off for a policy without approval rules' {
            (Get-IndexRow -Run $script:Run -DisplayName 'Quality - Kiosks').Notes | Should -BeExactly 'Hotpatch: off'
        }

        It 'summarises an expedited quality update' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Expedite September'

            $row.SubType | Should -Be 'Expedited quality update'
            $row.Notes | Should -BeExactly 'Expedites 09.09.2026 00:00 UTC; restart forced after 2 day(s)'
        }

        It 'saves every driver with its approval status, as JSON and as CSV' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Drivers - Manual'
            $json = @(Get-Content -LiteralPath (Get-BackupFile -Row $row -FileName 'driverInventories.json') -Raw | ConvertFrom-Json)
            $csv = @(Import-Csv -LiteralPath (Get-BackupFile -Row $row -FileName 'driverInventories.csv'))

            $json | Should -HaveCount 4
            $csv | Should -HaveCount 4
            ($csv[0].PSObject.Properties.Name -join ',') |
                Should -BeExactly 'name,version,manufacturer,driverClass,category,approvalStatus,deployDateTime,releaseDateTime,applicableDeviceCount,id'
            ($csv | Where-Object name -EQ 'Contoso Net').approvalStatus | Should -Be 'declined'
        }

        It 'counts the drivers of a policy by approval status' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Drivers - Manual'

            $row.SubType | Should -Be 'Driver update - manual approval'
            $row.Notes | Should -BeLike '*| 4 driver(s): 2 approved, 1 declined, 1 needsReview'
        }

        It 'marks a driver policy Warning when its inventory did not sync' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Drivers - Manual'

            $row.Status | Should -Be 'Warning'
            $row.Notes | Should -BeLike "Driver inventory sync state is 'failure'*"
        }

        It 'records the deferral of automatic approval, and saves an empty inventory as an empty list' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Drivers - Automatic'

            $row.Status | Should -Be 'OK'
            $row.Notes | Should -BeExactly 'Approved drivers offered after 3 day(s) | 0 driver(s)'
            (Get-Content -LiteralPath (Get-BackupFile -Row $row -FileName 'driverInventories.json') -Raw).Trim() | Should -BeExactly '[]'
            Get-BackupFile -Row $row -FileName 'driverInventories.csv' | Should -Not -Exist
        }

        It "passes the run's retry settings to every list it reads" {
            # Lists, assignments and driver inventories: 4 + 7 + 2 reads.
            $script:CollectionReads | Should -HaveCount 13
            foreach ($read in $script:CollectionReads) {
                $read.MaximumAttempt | Should -Be $script:GraphRequestOptions.MaximumAttempt -Because $read.Uri
                [object]::ReferenceEquals($read.OnRetry, $script:GraphRequestOptions.OnRetry) | Should -BeTrue -Because $read.Uri
            }
        }
    }

    Context 'Failures and filters' {

        BeforeEach {
            Initialize-StandInTenant
            Initialize-BackupState
        }

        It 'counts and reports a policy type that cannot be listed, and backs up the others' {
            $script:FailingUris.Add("$script:GraphBeta/deviceManagement/windowsQualityUpdatePolicies")

            $run = Invoke-CategoryBackup -CategoryName WindowsUpdates

            $script:CategoryErrors | Should -Be 1
            $script:FailedCount | Should -Be 0
            $run.Rows | Should -HaveCount 5
            $run.Rows.SubType | Should -Not -Contain 'Quality update'
            $run.Errors | Should -HaveCount 1
            $run.Errors[0] | Should -BeLike 'WindowsUpdates (windowsQualityUpdatePolicies): listing failed - HTTP 403*'
            $run.Log | Should -BeLike '*`[ERROR`] WindowsUpdates (windowsQualityUpdatePolicies): listing failed*'
        }

        It 'fails only the policy whose driver inventory cannot be read, and keeps what it did read' {
            $manualProfile = ($script:Tenant.windowsDriverUpdateProfiles | Where-Object displayName -EQ 'Drivers - Manual').id
            $script:FailingUris.Add("$script:GraphBeta/deviceManagement/windowsDriverUpdateProfiles/$manualProfile/driverInventories")

            $run = Invoke-CategoryBackup -CategoryName WindowsUpdates
            $failed = Get-IndexRow -Run $run -DisplayName 'Drivers - Manual'

            $script:FailedCount | Should -Be 1
            $script:CategoryErrors | Should -Be 0
            $run.Rows | Should -HaveCount 7
            $failed.Status | Should -Be 'Failed'
            $failed.Notes | Should -BeLike '*HTTP 403 from GET*driverInventories'
            Get-BackupFile -Row $failed -FileName 'policy.json' | Should -Exist
            (Get-IndexRow -Run $run -DisplayName 'Drivers - Automatic').Status | Should -Be 'OK'
            $run.Errors | Should -HaveCount 1
        }

        It 'backs up only what -Name selects, and creates no folder for a type with nothing selected' {
            $run = Invoke-CategoryBackup -CategoryName WindowsUpdates -NameFilter 'Drivers - *'

            @($run.Rows.DisplayName | Sort-Object) | Should -Be @('Drivers - Automatic', 'Drivers - Manual')
            Join-Path -Path $run.Root -ChildPath 'FeatureUpdates' | Should -Not -Exist
            Join-Path -Path $run.Root -ChildPath 'QualityUpdates' | Should -Not -Exist
        }

        It 'backs up only what -Id selects' {
            $expediteProfile = $script:Tenant.windowsQualityUpdateProfiles[0].id

            $run = Invoke-CategoryBackup -CategoryName WindowsUpdates -IdFilter $expediteProfile

            $run.Rows | Should -HaveCount 1
            $run.Rows[0].DisplayName | Should -Be 'Expedite September'
        }
    }
}

Describe 'The PlatformScripts category' {

    Context 'A tenant with a Windows and a macOS script' {

        BeforeAll {
            Initialize-StandInTenant
            Initialize-BackupState
            $script:Run = Invoke-CategoryBackup -CategoryName PlatformScripts
        }

        It 'backs up both scripts without a failure, a warning or an error' {
            $script:Run.Rows | Should -HaveCount 2
            $script:Run.Rows.Status | Should -Be @('OK', 'OK')
            $script:FailedCount | Should -Be 0
            $script:Run.Warnings | Should -BeNullOrEmpty
            $script:Run.Errors | Should -BeNullOrEmpty
        }

        It 'saves the <Platform> script, its definition and its assignments under PlatformScripts/<Platform>' -ForEach @(
            @{ Platform = 'Windows'; DisplayName = 'Set the time zone'; FileName = 'Set-TimeZone.ps1' }
            @{ Platform = 'macOS'; DisplayName = 'Enable the firewall'; FileName = 'enable-firewall.sh' }
        ) {
            $row = Get-IndexRow -Run $script:Run -DisplayName $DisplayName

            (($row.Folder -split '[\\/]')[0..1] -join '/') | Should -Be "PlatformScripts/$Platform"
            Get-BackupFile -Row $row -FileName 'script.json' | Should -Exist
            Get-BackupFile -Row $row -FileName $FileName | Should -Exist
            Get-BackupFile -Row $row -FileName 'assignments.json' | Should -Exist
        }

        It 'reads the assignments of a macOS script expanded on it, not from the path the service refuses' {
            $row = Get-IndexRow -Run $script:Run -DisplayName 'Enable the firewall'
            $saved = @(Get-Content -LiteralPath (Get-BackupFile -Row $row -FileName 'assignments.json') -Raw | ConvertFrom-Json)

            $saved | Should -HaveCount 2
            $row.AssignmentCount | Should -Be 2
            $row.Assignments | Should -BeExactly 'Include: Autopatch Test ring; Exclude: Kiosks'
            $script:CollectionReads.Uri | Should -Not -Match '/deviceShellScripts/[^/]+/assignments'
        }

        It 'reads the assignments of a Windows script from its assignments path' {
            $windowsScript = $script:Tenant.deviceManagementScripts[0].id

            $script:CollectionReads.Uri | Should -Contain "$script:GraphBeta/deviceManagement/deviceManagementScripts/$windowsScript/assignments"
        }
    }

    Context 'Failures' {

        BeforeEach {
            Initialize-StandInTenant
            Initialize-BackupState
        }

        It 'fails a macOS script whose assignments cannot be read, and keeps the script it already saved' {
            $macScript = $script:Tenant.deviceShellScripts[0].id
            $script:FailingUris.Add("$script:GraphBeta/deviceManagement/deviceShellScripts/$macScript" + '?$expand=assignments')

            $run = Invoke-CategoryBackup -CategoryName PlatformScripts
            $failed = Get-IndexRow -Run $run -DisplayName 'Enable the firewall'

            $script:FailedCount | Should -Be 1
            $failed.Status | Should -Be 'Failed'
            $failed.Notes | Should -BeLike 'HTTP 500 from GET *expand=assignments'
            Get-BackupFile -Row $failed -FileName 'enable-firewall.sh' | Should -Exist
            (Get-IndexRow -Run $run -DisplayName 'Set the time zone').Status | Should -Be 'OK'
        }

        It 'fails a macOS script when the service leaves out its assignments, rather than record none' {
            $script:ExpandIgnored = $true

            $run = Invoke-CategoryBackup -CategoryName PlatformScripts
            $failed = Get-IndexRow -Run $run -DisplayName 'Enable the firewall'

            $failed.Status | Should -Be 'Failed'
            $failed.Notes | Should -BeLike "*returned no 'assignments' list."
            $failed.AssignmentCount | Should -Be ''
            $run.Errors | Should -HaveCount 1
        }
    }
}

Describe 'Signing in' {

    BeforeAll {
        # Stand-ins for the two SDK cmdlets the shared Connect-GraphSession
        # calls, so the scopes the script asks for meet the real check.
        function Get-MgContext { $script:Session }

        function Connect-MgGraph {
            [CmdletBinding()]
            param ([string[]]$Scopes, [string]$TenantId, [switch]$NoWelcome, [switch]$UseDeviceCode)

            $script:SignIns.Add([pscustomobject]@{
                    Scopes        = $Scopes
                    TenantId      = $TenantId
                    NoWelcome     = $NoWelcome.IsPresent
                    UseDeviceCode = $UseDeviceCode.IsPresent
                })
            $script:Session = Get-StandInSession -Scopes $Scopes
        }

        function Get-StandInSession {
            param ([string[]]$Scopes)

            [pscustomobject]@{
                AuthType = 'Delegated'
                Scopes   = $Scopes
                TenantId = $script:SessionTenant
                Account  = 'admin@contoso.com'
                AppName  = $null
            }
        }

        $script:SessionTenant = [guid]::NewGuid().ToString()
        $script:SignIns = [System.Collections.Generic.List[object]]::new()
        $script:ReadScopes = @('DeviceManagementConfiguration.Read.All', 'DeviceManagementScripts.Read.All',
            'GroupMember.Read.All')
    }

    BeforeEach {
        Initialize-BackupState
        $script:SignIns.Clear()
        $script:Session = $null

        # What the script's parameters would set, at their defaults.
        $script:Category = @('Remediations', 'PlatformScripts', 'ConfigurationProfiles', 'CompliancePolicies', 'WindowsUpdates')
        $script:IncludeDeviceRunStates = [switch]$false
        $script:SkipGroupNameResolution = [switch]$false
        $script:TenantId = $null
    }

    It 'asks only for the read scopes the run needs, with a browser unless told otherwise' {
        Connect-GraphForBackup | Should -BeTrue

        $script:SignIns.Count | Should -Be 1
        $script:SignIns[0].Scopes | Should -Be $script:ReadScopes
        $script:SignIns[0].UseDeviceCode | Should -BeFalse
    }

    It 'signs in with a device code when -UseDeviceCode is given' {
        Connect-GraphForBackup -UseDeviceCode | Should -BeTrue

        $script:SignIns[0].UseDeviceCode | Should -BeTrue
    }

    It 'reuses a session that holds GroupMember.ReadWrite.All for the group names' {
        $script:Session = Get-StandInSession -Scopes @(
            'DeviceManagementConfiguration.Read.All', 'DeviceManagementScripts.Read.All', 'GroupMember.ReadWrite.All')

        Connect-GraphForBackup | Should -BeFalse
        $script:SignIns.Count | Should -Be 0
    }

    It 'does not take the permission to wipe devices for the permission to read them' {
        # PrivilegedOperations.All allows remote actions such as a wipe. It
        # does not allow reading devices, which the run states need.
        $script:IncludeDeviceRunStates = [switch]$true
        $script:Session = Get-StandInSession -Scopes ($script:ReadScopes +
            'DeviceManagementManagedDevices.PrivilegedOperations.All')

        Connect-GraphForBackup 3>$null | Should -BeTrue
        $script:SignIns[0].Scopes | Should -Contain 'DeviceManagementManagedDevices.Read.All'
        $script:SignIns[0].Scopes | Should -Not -Contain 'DeviceManagementManagedDevices.PrivilegedOperations.All'
    }
}

Describe 'The script, run as a file' -Skip:(-not $script:ModuleAvailable) {

    It 'exits 1 and gives the reason when the output folder cannot be created' {
        # Started with -File in a child process, as a scheduled task would,
        # so that its exit ends that process and not the test run. A folder
        # cannot be created below a file, and the script finds that out
        # before it signs in, so nothing reaches Graph. The text comes back
        # without white space, because the host wraps long errors.
        $file = Join-Path -Path $TestDrive -ChildPath 'not-a-folder.txt'
        Set-Content -LiteralPath $file -Value 'A file, where the backup was told to put a folder.'

        # Continue, not the caller's Stop: Windows PowerShell 5.1 turns the
        # child's error output into a terminating error under Stop, which
        # is what the Windows PowerShell step in CI sets, and the test would
        # end there instead of reading the exit code.
        $ErrorActionPreference = 'Continue'
        $output = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $script:ScriptPath `
                -OutputPath (Join-Path -Path $file -ChildPath 'Backups') 2>&1)
        $exitCode = $LASTEXITCODE
        $text = (@($output | ForEach-Object { [string]$_ }) -join '') -replace '\s', ''

        $exitCode | Should -Be 1
        $text | Should -BeLike '*FATAL:*'
    }
}
