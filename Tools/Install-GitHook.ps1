# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Points this clone's git hooks at the versioned hooks in Tools/Hooks.

.DESCRIPTION
    Git does not copy hooks when a repository is cloned, so a hook that lives in
    .git/hooks exists only on the machine that created it. This script sets
    core.hooksPath to the versioned Tools/Hooks folder instead, so every clone
    gets the same checks by running one command.

    Installed hooks:
      pre-commit  Runs Tools/Test-SensitiveContent.ps1 against staged content
                  and blocks the commit if anything is found.

    The change is local to the clone: core.hooksPath is written to the
    repository's own git config, not to the global one.

.PARAMETER Uninstall
    Removes the core.hooksPath setting and returns git to its default
    .git/hooks folder.

.EXAMPLE
    .\Tools\Install-GitHook.ps1

    Enables the versioned hooks in this clone.

.EXAMPLE
    .\Tools\Install-GitHook.ps1 -Uninstall -WhatIf

    Shows what removing the setting would do.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.0
    Last updated  : 2026-09-20

    PowerShell    : 5.1 or 7. Declared as 5.1 so it runs on any clone.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : None. Requires git on PATH.
    Role required : None. Does not need elevation.

    Exit codes    : 0 success, 1 failure.

    A hook is a convenience, not a control. It can be skipped with
    --no-verify, and it never runs in CI - the same scan runs there instead.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param (
    [Parameter()]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if (-not (Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue)) {
        throw 'git was not found on PATH. Install git, or add it to PATH, and run this again.'
    }

    $repositoryRoot = Split-Path -Path $PSScriptRoot -Parent

    $insideRepository = & git -C $repositoryRoot rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0 -or $insideRepository -ne 'true') {
        throw "'$repositoryRoot' is not a git working tree."
    }

    if ($Uninstall) {
        if ($PSCmdlet.ShouldProcess($repositoryRoot, 'Unset core.hooksPath')) {
            & git -C $repositoryRoot config --unset core.hooksPath
            if ($LASTEXITCODE -gt 1) {
                throw "git config --unset failed with exit code $LASTEXITCODE."
            }
            Write-Output 'Removed core.hooksPath. Git is back to using .git/hooks.'
        }

        exit 0
    }

    $hooksPath = Join-Path -Path $repositoryRoot -ChildPath 'Tools\Hooks'
    if (-not (Test-Path -LiteralPath $hooksPath -PathType Container)) {
        throw "Hook folder '$hooksPath' does not exist."
    }

    $preCommit = Join-Path -Path $hooksPath -ChildPath 'pre-commit'
    if (-not (Test-Path -LiteralPath $preCommit -PathType Leaf)) {
        throw "Hook '$preCommit' does not exist."
    }

    if ($PSCmdlet.ShouldProcess($repositoryRoot, "Set core.hooksPath to 'Tools/Hooks'")) {
        & git -C $repositoryRoot config core.hooksPath 'Tools/Hooks'
        if ($LASTEXITCODE -ne 0) {
            throw "git config failed with exit code $LASTEXITCODE."
        }

        # Keep the executable bit in the index so the hook works on Linux and
        # macOS clones as well.
        & git -C $repositoryRoot update-index --chmod=+x --add 'Tools/Hooks/pre-commit' 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'Could not mark Tools/Hooks/pre-commit executable in the index. It is not yet tracked, or git refused the update. Run: git update-index --chmod=+x Tools/Hooks/pre-commit'
        }

        Write-Output "core.hooksPath set to 'Tools/Hooks'. The pre-commit scan runs on the next commit."
    }

    exit 0
}
catch {
    Write-Error -Message "Hook installation failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
