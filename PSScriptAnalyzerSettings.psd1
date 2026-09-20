<#
    PSScriptAnalyzer settings for this repository.

    Local use:
        Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1

    These settings apply to every script regardless of the PowerShell version it
    targets. Admin-side tooling may use PowerShell 7 syntax freely; only scripts
    that declare '#Requires -Version 5.1' are additionally checked against
    Windows PowerShell, using PSScriptAnalyzerSettings.WindowsPowerShell.psd1.

    CI treats Error, Warning and ParseError as failures, so only rules that
    indicate a real defect are enabled here. Purely cosmetic formatting rules
    (PSPlaceOpenBrace, PSUseConsistentIndentation, PSUseConsistentWhitespace and
    friends) are deliberately left off: style is handled by .editorconfig and
    Invoke-Formatter, not by a failing build.
#>
@{
    IncludeDefaultRules = $true

    Severity = @(
        'ParseError'
        'Error'
        'Warning'
    )
}
