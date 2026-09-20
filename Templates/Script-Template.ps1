# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

# Declare the lowest version this script actually needs. Admin-side tooling is
# not limited to Windows PowerShell - raise this to 7.0 when the script uses
# PowerShell 7 syntax, and CI will stop holding it to 5.1.
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    One line describing what the script does.

.DESCRIPTION
    What the script reads, what it changes, what it deliberately leaves alone,
    and any assumptions it makes about the environment it runs in.

.PARAMETER TenantId
    Entra ID tenant ID (GUID) or a verified domain name to authenticate against.

.PARAMETER GroupId
    Object ID of the target Entra ID group.

.PARAMETER OutputPath
    Existing directory to write the result report to. Defaults to the user's
    temp directory.

.EXAMPLE
    .\Verb-Noun.ps1 -TenantId '<TenantId>' -GroupId '<GroupId>' -WhatIf

    Reports what would change without modifying anything.

.EXAMPLE
    .\Verb-Noun.ps1 -TenantId 'contoso.onmicrosoft.com' -GroupId '<GroupId>' -Verbose

    Applies the change and logs each step.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : YYYY-MM-DD

    PowerShell    : 5.1 or 7. Keep this line and the #Requires line in step.
    Graph scopes  : DeviceManagementManagedDevices.ReadWrite.All
                    Group.Read.All
    Admin consent : Required
    Licensing     : Microsoft Intune Plan 1
                    Microsoft Entra ID P1 (only if targeting dynamic groups)
    Modules       : Microsoft.Graph.Authentication
                    Microsoft.Graph.DeviceManagement
    Role required : Intune Administrator (or a custom role with the equivalent
                    device management permissions)

.LINK
    https://learn.microsoft.com/graph/api/overview
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory, HelpMessage = 'Entra ID tenant ID (GUID) or verified domain name.')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory, HelpMessage = 'Object ID (GUID) of the target group.')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$GroupId,

    [Parameter()]
    [ValidateScript({
        if (Test-Path -Path $_ -PathType Container) { $true }
        else { throw "OutputPath '$_' does not exist or is not a directory." }
    })]
    [string]$OutputPath = $env:TEMP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Narrowest set of scopes this script actually needs.
$RequiredScopes = @(
    'DeviceManagementManagedDevices.ReadWrite.All'
    'Group.Read.All'
)

# Only disconnect a session this script opened; leave an existing one intact.
$ConnectionOpenedHere = $false

try {
    #region Connect to Microsoft Graph
    $context = Get-MgContext

    if (-not $context -or $context.TenantId -ne $TenantId) {
        Write-Verbose "Connecting to Microsoft Graph in tenant '$TenantId'."
        Connect-MgGraph -TenantId $TenantId -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
        $ConnectionOpenedHere = $true
        $context = Get-MgContext -ErrorAction Stop
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for tenant '$TenantId'."
    }

    # Consent can succeed partially - verify rather than assume.
    $missingScopes = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missingScopes) {
        throw "The Graph session is missing required scope(s): $($missingScopes -join ', '). Reconnect and grant admin consent."
    }
    #endregion

    #region Work
    Write-Verbose "Retrieving target objects for group '$GroupId'."
    # $targets = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop

    # Gate every write, change, or delete behind ShouldProcess so -WhatIf and
    # -Confirm behave correctly.
    if ($PSCmdlet.ShouldProcess($GroupId, 'Describe the change being made here')) {
        Write-Verbose 'Applying change.'
        # Do the work here, with -ErrorAction Stop on every cmdlet.
    }
    #endregion

    #region Report
    $reportFile = Join-Path -Path $OutputPath -ChildPath "Verb-Noun-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    Write-Verbose ('Report path: {0}' -f $reportFile)

    # $results | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    #endregion
}
catch {
    Write-Error -Message "Script failed: $($_.Exception.Message)" -ErrorRecord $_
    exit 1
}
finally {
    if ($ConnectionOpenedHere -and (Get-MgContext)) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            Write-Verbose 'Disconnected from Microsoft Graph.'
        }
        catch {
            Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
        }
    }
}
