# SPDX-FileCopyrightText: 2026 Tomasz Pietryka
# SPDX-License-Identifier: MIT
# Source: https://github.com/Zenpachi-alt/endpoint-engineering

#Requires -Version 5.1

<#
.SYNOPSIS
    Reads what an Intune Win32 app needs from an MSI, an EXE installer or an
    .intunewin package: product and upgrade codes, install context, silent
    switches, and suggested install, uninstall and detection settings.

.DESCRIPTION
    Read-only. Nothing is installed, extracted or changed, and no file is ever
    executed. The file type is recognised from its content, not its extension.

    MSI         Opened read-only through msi.dll. Reads the Property table,
                the summary information, and the Upgrade, Media, File,
                LaunchCondition, Control and InstallExecuteSequence tables.
    EXE         Reads the version resource, the embedded manifest and the
                file headers. Recognises Inno Setup, NSIS, WiX Burn and
                InstallShield, and reports the evidence each match rests on.
    .intunewin  Reads Metadata\Detection.xml, the unencrypted part of a
                package made by the Microsoft Win32 Content Prep Tool. The
                encryption key kept in that file is never output.

    Every result carries Intune* properties: install command, uninstall
    command, install behavior and detection rule, wherever the file holds
    enough to suggest them. They are starting points to test on a virtual
    machine, not settings to paste unread.

    Findings that make a deployment fail are written as warnings and kept in
    Notes: a per-user MSI deployed as System, cabinets or files that must sit
    beside the MSI, a signature that no longer matches the file.

.PARAMETER Path
    One or more installer files. Wildcards are accepted.

.PARAMETER LiteralPath
    One or more installer files, used exactly as typed. Get-ChildItem output
    piped into the script binds here.

.EXAMPLE
    .\Get-InstallerInfo.ps1 -Path .\setup.msi

    Everything the MSI holds that matters to an Intune deployment.

.EXAMPLE
    .\Get-InstallerInfo.ps1 -Path .\setup.msi | Select-Object -Property Intune*

    Only the suggested Intune settings.

.EXAMPLE
    (.\Get-InstallerInfo.ps1 -Path .\setup.msi).PublicProperties

    The public properties that can be set on the msiexec command line, and
    whether each comes from the Property table or from a dialog.

.EXAMPLE
    Get-ChildItem -Path .\Installers -File | .\Get-InstallerInfo.ps1 |
        Format-Table -Property FileType, ProductName, ProductVersion, InstallerFramework

    One line per installer in a folder.

.EXAMPLE
    .\Get-InstallerInfo.ps1 -Path \\SERVER-001\Packages\App.intunewin

    What an existing package was built from, without the source files.

.NOTES
    Author        : Tomasz Pietryka
    Version       : 1.0.1
    Last updated  : 2026-10-05

    PowerShell    : 5.1 or later. Packaging is often done on a clean virtual
                    machine that has only Windows PowerShell, and nothing here
                    needs PowerShell 7.
    Graph scopes  : None.
    Admin consent : Not applicable.
    Licensing     : None.
    Modules       : None.
    Role required : None. Runs as the signed-in user and reads only files that
                    user can read.

    Platform      : Windows only: msi.dll reads MSIs and Authenticode checks
                    signatures. Needs FullLanguage mode, because it calls .NET
                    directly and compiles a small msi.dll wrapper with
                    Add-Type, which Constrained Language Mode blocks.

    Exit codes    : 0 every file was read.
                    1 at least one file could not be read, or the script
                      could not start. Other files are still read and
                      returned.

    Limits        : Patches (.msp), transforms (.mst), merge modules (.msm),
                    MSIX and APPX packages are not read. An MSI wrapped inside
                    an EXE is not extracted. Public properties are those with
                    a default in the Property table or set by a dialog; a
                    property read only by a custom action is not visible.
                    Silent switches are each framework's defaults, which a
                    vendor can change. The architecture of an EXE is that of
                    the installer itself, not of the app it installs.
#>

[CmdletBinding(DefaultParameterSetName = 'Path')]
[OutputType([pscustomobject])]
param (
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path', ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string[]]$Path,

    [Parameter(Mandatory, ParameterSetName = 'LiteralPath', ValueFromPipelineByPropertyName)]
    [Alias('PSPath', 'FullName')]
    [ValidateNotNullOrEmpty()]
    [string[]]$LiteralPath
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $ExitSuccess = 0
    $ExitFailure = 1

    # Checked first: a .NET call in the wrong session fails with a far less useful message.
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        Write-Error -Message (('This session runs in {0} mode. The script calls .NET directly and compiles ' +
                'an msi.dll wrapper, which needs FullLanguage mode.') -f $ExecutionContext.SessionState.LanguageMode) -ErrorAction Continue
        exit $ExitFailure
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Write-Error -Message ('Get-InstallerInfo runs on Windows only: it reads MSIs through msi.dll and ' +
            'signatures through Authenticode.') -ErrorAction Continue
        exit $ExitFailure
    }

    $Run = @{ Failed = 0 }

    # One byte per character, so byte offsets and string offsets agree.
    $Latin1 = [Text.Encoding]::GetEncoding(28591)

    $MachineName = @{ 0x014C = 'x86'; 0x8664 = 'x64'; 0xAA64 = 'ARM64'; 0x01C4 = 'ARM'; 0x0200 = 'IA64' }

    # Default silent switches. UninstallArguments is set only where the same
    # file uninstalls; elsewhere the uninstaller is written during install.
    $FrameworkSwitch = @{
        'WiX Burn'      = @{ Install = '/quiet /norestart'; Uninstall = '/uninstall /quiet /norestart' }
        'NSIS'          = @{ Install = '/S'; Uninstall = $null }
        'Inno Setup'    = @{ Install = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'; Uninstall = $null }
        'InstallShield' = @{ Install = '/s /v"/qn"'; Uninstall = $null }
    }

    # Add-Type cannot replace a type already loaded in the session, so the
    # name carries a version. Change the C# below and the suffix changes too.
    $MsiReaderType = 'EndpointEngineering.InstallerInfo.MsiReaderV1'
    $MsiReaderSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace EndpointEngineering.InstallerInfo
{
    // Read-only access to an MSI database. MSIHANDLE is 32 bits wide even in a
    // 64-bit process, so handles are uint rather than IntPtr. Every handle is
    // closed before a method returns, so nothing keeps the file locked.
    public sealed class MsiReaderV1 : IDisposable
    {
        [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiOpenDatabaseW")]
        private static extern uint MsiOpenDatabase(string path, IntPtr persist, out uint database);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiDatabaseOpenViewW")]
        private static extern uint MsiDatabaseOpenView(uint database, string query, out uint view);

        [DllImport("msi.dll")]
        private static extern uint MsiViewExecute(uint view, uint record);

        [DllImport("msi.dll")]
        private static extern uint MsiViewFetch(uint view, out uint record);

        [DllImport("msi.dll")]
        private static extern uint MsiRecordGetFieldCount(uint record);

        [DllImport("msi.dll")]
        private static extern int MsiRecordIsNull(uint record, uint field);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiRecordGetStringW")]
        private static extern uint MsiRecordGetString(uint record, uint field, StringBuilder value, ref uint length);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiDatabaseIsTablePersistentW")]
        private static extern int MsiDatabaseIsTablePersistent(uint database, string table);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiGetSummaryInformationW")]
        private static extern uint MsiGetSummaryInformation(uint database, string path, uint updateCount, out uint summary);

        [DllImport("msi.dll", CharSet = CharSet.Unicode, EntryPoint = "MsiSummaryInfoGetPropertyW")]
        private static extern uint MsiSummaryInfoGetProperty(uint summary, uint property, out uint dataType,
            out int intValue, out long fileTime, StringBuilder value, ref uint length);

        [DllImport("msi.dll")]
        private static extern uint MsiCloseHandle(uint handle);

        private const uint Success = 0;
        private const uint MoreData = 234;
        private const uint NoMoreItems = 259;
        private const int TablePersistent = 1;
        private const uint TypeShort = 2;
        private const uint TypeLong = 3;
        private const uint TypeString = 30;

        private uint database;

        public MsiReaderV1(string path)
        {
            // A null persist argument is MSIDBOPEN_READONLY.
            Check(MsiOpenDatabase(path, IntPtr.Zero, out database));
        }

        public bool HasTable(string table)
        {
            return MsiDatabaseIsTablePersistent(database, table) == TablePersistent;
        }

        public List<string[]> Query(string sql)
        {
            List<string[]> rows = new List<string[]>();
            uint view;
            Check(MsiDatabaseOpenView(database, sql, out view));
            try
            {
                Check(MsiViewExecute(view, 0));
                while (true)
                {
                    uint record;
                    uint result = MsiViewFetch(view, out record);
                    if (result == NoMoreItems) { break; }
                    Check(result);
                    try
                    {
                        uint count = MsiRecordGetFieldCount(record);
                        string[] row = new string[count];
                        for (uint field = 1; field <= count; field++)
                        {
                            row[field - 1] = MsiRecordIsNull(record, field) != 0 ? null : GetString(record, field);
                        }
                        rows.Add(row);
                    }
                    finally
                    {
                        MsiCloseHandle(record);
                    }
                }
            }
            finally
            {
                MsiCloseHandle(view);
            }
            return rows;
        }

        // Indexed by property ID: 7 is the template, 9 the package code, 15 the word count.
        public object[] GetSummaryInformation()
        {
            object[] values = new object[20];
            uint summary;
            Check(MsiGetSummaryInformation(database, null, 0, out summary));
            try
            {
                for (uint id = 1; id < 20; id++)
                {
                    uint dataType;
                    int intValue;
                    long fileTime;
                    uint length = 256;
                    StringBuilder value = new StringBuilder((int)length);
                    uint result = MsiSummaryInfoGetProperty(summary, id, out dataType, out intValue, out fileTime, value, ref length);
                    if (result == MoreData)
                    {
                        length++;
                        value = new StringBuilder((int)length);
                        result = MsiSummaryInfoGetProperty(summary, id, out dataType, out intValue, out fileTime, value, ref length);
                    }
                    Check(result);
                    if (dataType == TypeString) { values[id] = value.ToString(); }
                    else if (dataType == TypeShort || dataType == TypeLong) { values[id] = intValue; }
                }
            }
            finally
            {
                MsiCloseHandle(summary);
            }
            return values;
        }

        public void Dispose()
        {
            if (database != 0)
            {
                MsiCloseHandle(database);
                database = 0;
            }
        }

        private static string GetString(uint record, uint field)
        {
            uint length = 256;
            StringBuilder value = new StringBuilder((int)length);
            uint result = MsiRecordGetString(record, field, value, ref length);
            if (result == MoreData)
            {
                length++;
                value = new StringBuilder((int)length);
                result = MsiRecordGetString(record, field, value, ref length);
            }
            Check(result);
            return value.ToString();
        }

        private static void Check(uint result)
        {
            if (result != Success) { throw new Win32Exception((int)result); }
        }
    }
}
'@

    function Get-ErrorText {
        # The message a reader needs, not the "Exception calling ..." wrapper
        # PowerShell puts around exceptions thrown by .NET methods.
        [CmdletBinding()]
        [OutputType([string])]
        param ([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

        $exception = $ErrorRecord.Exception
        while (($exception -is [System.Management.Automation.MethodInvocationException] -or
                $exception -is [System.Reflection.TargetInvocationException]) -and
            $null -ne $exception.InnerException) {
            $exception = $exception.InnerException
        }
        if ($exception -is [System.ComponentModel.Win32Exception]) {
            return '{0} (error {1})' -f $exception.Message, $exception.NativeErrorCode
        }
        $exception.Message
    }

    function Write-FileError {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)] [string]$Target,
            [Parameter(Mandatory)] [string]$Message
        )

        $Run.Failed += 1
        # Continue, not Stop: one unreadable file must not hide the others.
        Write-Error -Message ('{0}: {1}' -f $Target, $Message) -ErrorAction Continue
    }

    function Add-InstallerNote {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Note,
            [Parameter(Mandatory)] [string]$FileName,
            [Parameter(Mandatory)] [string]$Message,
            [Parameter()] [switch]$Hazard
        )

        $Note.Add($Message)
        if ($Hazard) { Write-Warning ('{0}: {1}' -f $FileName, $Message) }
    }

    function ConvertTo-CleanText {
        [CmdletBinding()]
        [OutputType([string])]
        param ([Parameter()] [AllowNull()] [AllowEmptyString()] [string]$Text)

        if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
        $Text.Trim()
    }

    function Read-FileRange {
        [CmdletBinding()]
        [OutputType([byte[]])]
        param (
            [Parameter(Mandatory)] [System.IO.Stream]$Stream,
            [Parameter(Mandatory)] [long]$Offset,
            [Parameter(Mandatory)] [long]$Count
        )

        if ($Offset -lt 0 -or $Offset -ge $Stream.Length -or $Count -le 0) { return , ([byte[]]::new(0)) }
        $length = [int][math]::Min($Count, $Stream.Length - $Offset)
        $buffer = [byte[]]::new($length)
        $null = $Stream.Seek($Offset, [IO.SeekOrigin]::Begin)
        $read = 0
        while ($read -lt $length) {
            $chunk = $Stream.Read($buffer, $read, $length - $read)
            if ($chunk -le 0) { break }
            $read += $chunk
        }
        # The comma stops PowerShell unrolling the array into single bytes.
        , $buffer
    }

    function Get-InstallerKind {
        [CmdletBinding()]
        [OutputType([string])]
        param ([Parameter(Mandatory)] [System.IO.FileInfo]$File)

        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $head = Read-FileRange -Stream $stream -Offset 0 -Count 8 }
        finally { $stream.Dispose() }

        if ($head.Length -ge 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A) { return 'Exe' }
        if ($head.Length -ge 4 -and [BitConverter]::ToString($head, 0, 4) -eq '50-4B-03-04') { return 'IntuneWin' }
        if ($head.Length -ge 8 -and [BitConverter]::ToString($head, 0, 8) -eq 'D0-CF-11-E0-A1-B1-1A-E1') {
            if ($File.Extension -in '.msp', '.mst', '.msm') {
                throw ('Patches (.msp), transforms (.mst) and merge modules (.msm) are not read. ' +
                    'Read the .msi they apply to.')
            }
            return 'Msi'
        }
        throw 'Not an MSI, an EXE or an .intunewin package.'
    }

    function Get-SignatureSummary {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param ([Parameter(Mandatory)] [string]$Path)

        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $signer = $null
        if ($null -ne $signature.SignerCertificate) {
            $signer = $signature.SignerCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
        [pscustomobject]@{
            Status = [string]$signature.Status
            Signer = $signer
        }
    }

    function Add-SignatureNote {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)] [pscustomobject]$Signature,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Note,
            [Parameter(Mandatory)] [string]$FileName
        )

        if ($Signature.Status -eq 'HashMismatch') {
            Add-InstallerNote -Note $Note -FileName $FileName -Hazard -Message (
                'The signature no longer matches the file: it changed after it was signed. Do not deploy it; ' +
                'download it again from the vendor.')
        }
    }

    #region MSI

    function Initialize-MsiReader {
        [CmdletBinding()]
        param ()

        if ($MsiReaderType -as [type]) { return }
        try {
            Add-Type -TypeDefinition $MsiReaderSource -ErrorAction Stop
        }
        catch {
            throw (('Could not compile the msi.dll reader: {0} Reading an MSI needs a session that allows ' +
                    'Add-Type.') -f $_.Exception.Message)
        }
    }

    function Get-MsiArchitecture {
        [CmdletBinding()]
        [OutputType([string])]
        param ([Parameter(Mandatory)] [AllowEmptyString()] [string]$Template)

        # The Template summary property reads like "x64;1033"; an empty platform is Intel.
        $platform = ($Template -split ';')[0].Trim()
        switch -Regex ($platform) {
            '^(Intel)?$' { return 'x86' }
            '^(x64|AMD64)$' { return 'x64' }
            '^Arm64$' { return 'ARM64' }
            '^Arm$' { return 'ARM' }
            '^Intel64$' { return 'IA64' }
        }
        $platform
    }

    function Read-MsiPackage {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param ([Parameter(Mandatory)] [System.IO.FileInfo]$File)

        Initialize-MsiReader
        $notes = [System.Collections.Generic.List[string]]::new()
        $name = $File.Name

        $reader = New-Object -TypeName $MsiReaderType -ArgumentList $File.FullName
        try {
            # Property names are case-sensitive in an MSI; a hashtable literal is not. A missing
            # key still reads as $null, as it would from a hashtable.
            $property = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
            if ($reader.HasTable('Property')) {
                foreach ($row in $reader.Query('SELECT `Property`, `Value` FROM `Property`')) {
                    $property[$row[0]] = $row[1]
                }
            }
            $summary = $reader.GetSummaryInformation()

            $upgradeRows = @()
            if ($reader.HasTable('Upgrade')) {
                $upgradeRows = @($reader.Query(
                        'SELECT `UpgradeCode`, `VersionMin`, `VersionMax`, `Attributes`, `ActionProperty` FROM `Upgrade`'))
            }
            $removesExisting = $false
            if ($reader.HasTable('InstallExecuteSequence')) {
                $removesExisting = @($reader.Query(('SELECT `Action` FROM `InstallExecuteSequence` ' +
                            'WHERE `Action` = ''RemoveExistingProducts'''))).Count -gt 0
            }

            $cabinets = @()
            if ($reader.HasTable('Media')) {
                $cabinets = @($reader.Query('SELECT `Cabinet` FROM `Media`') | ForEach-Object { $_[0] } |
                        Where-Object { $_ })
            }
            $fileRows = @()
            if ($reader.HasTable('File')) {
                $fileRows = @($reader.Query('SELECT `Attributes` FROM `File`'))
            }

            $launchConditions = @()
            if ($reader.HasTable('LaunchCondition')) {
                $launchConditions = @($reader.Query('SELECT `Condition`, `Description` FROM `LaunchCondition`') |
                        ForEach-Object { [pscustomobject]@{ Condition = $_[0]; Message = $_[1] } })
            }

            $dialogProperties = @()
            if ($reader.HasTable('Control')) {
                $dialogProperties = @($reader.Query('SELECT `Property` FROM `Control`') | ForEach-Object { $_[0] } |
                        Where-Object { $_ })
            }
        }
        finally {
            $reader.Dispose()
        }

        $productCode = $property['ProductCode']
        $productVersion = $property['ProductVersion']
        $upgradeCode = $property['UpgradeCode']

        # Install context: ALLUSERS decides, and MSIINSTALLPERUSER only counts when ALLUSERS is 2.
        $allUsers = $property['ALLUSERS']
        $installArguments = '/qn /norestart'
        $behavior = 'System'
        if ($allUsers -eq '1') {
            $context = 'PerMachine'
        }
        elseif ($allUsers -eq '2' -and $property['MSIINSTALLPERUSER'] -eq '1') {
            $context = 'DualPurposePerUserDefault'
            $installArguments = 'ALLUSERS=1 /qn /norestart'
            Add-InstallerNote -Note $notes -FileName $name -Hazard -Message (
                'Installs per-user by default, even when run as SYSTEM. The suggested install command adds ' +
                'ALLUSERS=1 to install for all users; a command without it installs into the SYSTEM profile.')
        }
        elseif ($allUsers -eq '2') {
            $context = 'PerMachineWhenElevated'
        }
        elseif ([string]::IsNullOrEmpty($allUsers)) {
            $context = 'PerUser'
            $behavior = 'User'
            Add-InstallerNote -Note $notes -FileName $name -Hazard -Message (
                'Per-user package (no ALLUSERS). Deployed as System it installs into the SYSTEM profile, where ' +
                'no user sees it. Use install behavior User, or test ALLUSERS=1 if the vendor supports it.')
        }
        else {
            $context = 'ALLUSERS={0}' -f $allUsers
            $behavior = $null
            Add-InstallerNote -Note $notes -FileName $name -Message (
                'ALLUSERS has the unusual value {0}. Test the install context on a virtual machine.' -f $allUsers)
        }

        # Upgrade table: which versions of which products this package finds or removes.
        $upgradeRules = @(foreach ($row in $upgradeRows) {
                $attributes = if ($row[3]) { [int]$row[3] } else { 0 }
                $range = @()
                if ($row[1]) { $range += ('{0} {1}' -f $(if ($attributes -band 0x100) { '>=' } else { '>' }), $row[1]) }
                if ($row[2]) { $range += ('{0} {1}' -f $(if ($attributes -band 0x200) { '<=' } else { '<' }), $row[2]) }
                [pscustomobject]@{
                    UpgradeCode    = $row[0]
                    Versions       = if ($range.Count -gt 0) { $range -join ' and ' } else { 'any' }
                    Action         = if ($attributes -band 0x2) { 'Detect' } else { 'Remove' }
                    ActionProperty = $row[4]
                    SameProduct    = [bool]($upgradeCode -and $row[0] -eq $upgradeCode)
                }
            })
        $removesOwn = @($upgradeRules | Where-Object { $_.SameProduct -and $_.Action -eq 'Remove' }).Count -gt 0
        $removesOlder = $removesExisting -and $removesOwn
        if ($removesOlder) {
            Add-InstallerNote -Note $notes -FileName $name -Message (
                'Removes older versions with the same upgrade code by itself. In Intune supersedence, ' +
                '"Uninstall previous version" can stay off.')
        }

        # Cabinets named without '#' are separate files; so are files stored uncompressed.
        $externalCabinets = @($cabinets | Where-Object { -not $_.StartsWith('#') })
        if ($externalCabinets.Count -gt 0) {
            Add-InstallerNote -Note $notes -FileName $name -Hazard -Message (
                'Needs {0} beside it. Put them in the package source folder with the MSI.' -f
                ($externalCabinets -join ', '))
        }
        $wordCount = if ($null -ne $summary[15]) { [int]$summary[15] } else { 0 }
        $compressedByDefault = ($wordCount -band 0x2) -ne 0
        $adminImage = ($wordCount -band 0x4) -ne 0
        $looseFileCount = 0
        foreach ($row in $fileRows) {
            $attributes = if ($row[0]) { [int]$row[0] } else { 0 }
            $compressed = if ($attributes -band 0x2000) { $false }
            elseif ($attributes -band 0x4000) { $true }
            else { $compressedByDefault }
            if ($adminImage -or -not $compressed) { $looseFileCount++ }
        }
        if ($looseFileCount -gt 0) {
            Add-InstallerNote -Note $notes -FileName $name -Hazard -Message ((
                    '{0} file(s) are stored outside the MSI, in the folder layout beside it. Package the whole ' +
                    'source folder, not the MSI alone.') -f $looseFileCount)
        }

        # Public properties have no lowercase letters: only those can be set on the command line.
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $publicProperties = [System.Collections.Generic.List[object]]::new()
        foreach ($key in $property.Keys) {
            if ($key -cnotmatch '[a-z]' -and $seen.Add($key)) {
                $publicProperties.Add([pscustomobject]@{ Name = $key; Value = $property[$key]; Source = 'Property table' })
            }
        }
        foreach ($key in $dialogProperties) {
            if ($key -cnotmatch '[a-z]' -and $seen.Add($key)) {
                $publicProperties.Add([pscustomobject]@{ Name = $key; Value = $null; Source = 'Dialog' })
            }
        }

        if ($property['ARPSYSTEMCOMPONENT'] -eq '1') {
            Add-InstallerNote -Note $notes -FileName $name -Message (
                'Hidden from Installed apps (ARPSYSTEMCOMPONENT=1). Detect it by product code, not by its ' +
                'display name in the registry.')
        }
        if ([string]::IsNullOrEmpty($productCode)) {
            Add-InstallerNote -Note $notes -FileName $name -Message (
                'No ProductCode: this database is not an installable product package.')
        }

        $signature = Get-SignatureSummary -Path $File.FullName
        Add-SignatureNote -Signature $signature -Note $notes -FileName $name

        # Decided here: a [string] parameter would turn a missing template into '', which reads as x86.
        $architecture = if ($null -ne $summary[7]) { Get-MsiArchitecture -Template $summary[7] } else { $null }
        $uninstallCommand = $null
        $detection = $null
        if ($productCode) {
            $uninstallCommand = 'msiexec /x "{0}" /qn /norestart' -f $productCode
            $detection = 'MSI product code {0}, product version greater than or equal to {1}' -f
            $productCode, $productVersion
        }

        [pscustomobject]@{
            Path                   = $File.FullName
            FileType               = 'Msi'
            ProductName            = $property['ProductName']
            Publisher              = $property['Manufacturer']
            ProductVersion         = $productVersion
            ProductCode            = $productCode
            UpgradeCode            = $upgradeCode
            PackageCode            = $summary[9]
            ProductLanguage        = $property['ProductLanguage']
            Architecture           = $architecture
            InstallContext         = $context
            RemovesOlderVersions   = $removesOlder
            UpgradeRules           = $upgradeRules
            LaunchConditions       = $launchConditions
            PublicProperties       = @($publicProperties | Sort-Object -Property Name)
            ExternalCabinets       = $externalCabinets
            LooseFileCount         = $looseFileCount
            SignatureStatus        = $signature.Status
            Signer                 = $signature.Signer
            IntuneInstallCommand   = 'msiexec /i "{0}" {1}' -f $name, $installArguments
            IntuneUninstallCommand = $uninstallCommand
            IntuneInstallBehavior  = $behavior
            IntuneDetection        = $detection
            Notes                  = $notes.ToArray()
        }
    }

    #endregion

    #region EXE

    function ConvertTo-FileOffset {
        [CmdletBinding()]
        [OutputType([long])]
        param (
            [Parameter(Mandatory)] [long]$Rva,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Section
        )

        foreach ($candidate in $Section) {
            $span = [math]::Max($candidate.VirtualSize, $candidate.RawSize)
            if ($Rva -ge $candidate.VirtualAddress -and $Rva -lt $candidate.VirtualAddress + $span) {
                return $Rva - $candidate.VirtualAddress + $candidate.RawOffset
            }
        }
        $null
    }

    function Get-ResourceDirectoryEntry {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter(Mandatory)] [System.IO.Stream]$Stream,
            [Parameter(Mandatory)] [long]$Offset
        )

        $header = Read-FileRange -Stream $Stream -Offset $Offset -Count 16
        if ($header.Length -lt 16) { return }
        $count = [math]::Min([BitConverter]::ToUInt16($header, 12) + [BitConverter]::ToUInt16($header, 14), 4096)
        $raw = Read-FileRange -Stream $Stream -Offset ($Offset + 16) -Count (8 * $count)
        for ($i = 0; $i + 8 -le $raw.Length; $i += 8) {
            $nameField = [BitConverter]::ToUInt32($raw, $i)
            $dataField = [BitConverter]::ToUInt32($raw, $i + 4)
            # The high bit marks a named entry in the first field and a subdirectory in the second.
            [pscustomobject]@{
                Id          = if ($nameField -band 2147483648) { $null } else { [int]$nameField }
                IsDirectory = ($dataField -band 2147483648) -ne 0
                Offset      = [long]($dataField -band 2147483647)
            }
        }
    }

    function Read-PeManifest {
        [CmdletBinding()]
        [OutputType([string])]
        param (
            [Parameter(Mandatory)] [System.IO.Stream]$Stream,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Section,
            [Parameter(Mandatory)] [long]$ResourceRva
        )

        if ($ResourceRva -eq 0) { return $null }
        $root = ConvertTo-FileOffset -Rva $ResourceRva -Section $Section
        if ($null -eq $root) { return $null }

        # Resource type 24 is RT_MANIFEST. Below it: a name level, then a language level.
        $type = @(Get-ResourceDirectoryEntry -Stream $Stream -Offset $root |
                Where-Object { $_.Id -eq 24 -and $_.IsDirectory })
        if ($type.Count -eq 0) { return $null }
        $resourceName = @(Get-ResourceDirectoryEntry -Stream $Stream -Offset ($root + $type[0].Offset) |
                Where-Object { $_.IsDirectory })
        if ($resourceName.Count -eq 0) { return $null }
        $language = @(Get-ResourceDirectoryEntry -Stream $Stream -Offset ($root + $resourceName[0].Offset) |
                Where-Object { -not $_.IsDirectory })
        if ($language.Count -eq 0) { return $null }

        $entry = Read-FileRange -Stream $Stream -Offset ($root + $language[0].Offset) -Count 16
        if ($entry.Length -lt 16) { return $null }
        $dataOffset = ConvertTo-FileOffset -Rva ([BitConverter]::ToUInt32($entry, 0)) -Section $Section
        $size = [BitConverter]::ToUInt32($entry, 4)
        if ($null -eq $dataOffset -or $size -eq 0 -or $size -gt 1MB) { return $null }
        [Text.Encoding]::UTF8.GetString((Read-FileRange -Stream $Stream -Offset $dataOffset -Count $size))
    }

    function Read-PeImage {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param ([Parameter(Mandatory)] [string]$Path)

        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $dos = Read-FileRange -Stream $stream -Offset 0 -Count 64
            if ($dos.Length -lt 64) { throw 'Too short to be a Windows executable.' }
            $peOffset = [long][BitConverter]::ToUInt32($dos, 0x3C)
            $coff = Read-FileRange -Stream $stream -Offset $peOffset -Count 24
            if ($coff.Length -lt 24 -or [BitConverter]::ToUInt32($coff, 0) -ne 0x4550) {
                throw 'Starts like a Windows executable but has no PE header.'
            }
            $machine = [int][BitConverter]::ToUInt16($coff, 4)
            $sectionCount = [BitConverter]::ToUInt16($coff, 6)
            $optionalSize = [BitConverter]::ToUInt16($coff, 20)

            $optional = Read-FileRange -Stream $stream -Offset ($peOffset + 24) -Count $optionalSize
            $directoryBase = 0
            if ($optional.Length -ge 2) {
                switch ([BitConverter]::ToUInt16($optional, 0)) {
                    0x10B { $directoryBase = 96 }    # PE32
                    0x20B { $directoryBase = 112 }   # PE32+
                }
            }
            if ($directoryBase -eq 0) { throw 'Unrecognised PE optional header.' }
            $resourceRva = [long]0
            if ($optional.Length -ge $directoryBase + 24 -and
                [BitConverter]::ToUInt32($optional, $directoryBase - 4) -gt 2) {
                $resourceRva = [BitConverter]::ToUInt32($optional, $directoryBase + 16)
            }

            $table = Read-FileRange -Stream $stream -Offset ($peOffset + 24 + $optionalSize) -Count (40 * $sectionCount)
            $sections = @(for ($i = 0; $i + 40 -le $table.Length; $i += 40) {
                    [pscustomobject]@{
                        Name           = $Latin1.GetString($table, $i, 8).TrimEnd([char]0)
                        VirtualSize    = [long][BitConverter]::ToUInt32($table, $i + 8)
                        VirtualAddress = [long][BitConverter]::ToUInt32($table, $i + 12)
                        RawSize        = [long][BitConverter]::ToUInt32($table, $i + 16)
                        RawOffset      = [long][BitConverter]::ToUInt32($table, $i + 20)
                    }
                })

            # Installers append their payload after the last section; its first bytes name the format.
            $imageEnd = [long]0
            foreach ($section in $sections) { $imageEnd = [math]::Max($imageEnd, $section.RawOffset + $section.RawSize) }

            [pscustomobject]@{
                Architecture = if ($MachineName.ContainsKey($machine)) { $MachineName[$machine] } else { '0x{0:X4}' -f $machine }
                SectionNames = @($sections | ForEach-Object { $_.Name })
                Manifest     = Read-PeManifest -Stream $stream -Section $sections -ResourceRva $resourceRva
                OverlayHead  = $Latin1.GetString((Read-FileRange -Stream $stream -Offset $imageEnd -Count 65536))
            }
        }
        finally {
            $stream.Dispose()
        }
    }

    function Find-InstallerFramework {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter(Mandatory)] [pscustomobject]$Image,
            [Parameter()] [AllowNull()] [AllowEmptyString()] [string]$ManifestIdentity,
            [Parameter(Mandatory)] [System.Diagnostics.FileVersionInfo]$Version
        )

        $versionText = @($Version.Comments, $Version.CompanyName, $Version.ProductName, $Version.FileDescription,
            $Version.InternalName, $Version.OriginalFilename) -join ' '

        # Strongest evidence first: a section only Burn writes, then each tool's own manifest
        # identity, then its data header, then text a vendor could also have typed.
        $evidence = [ordered]@{}
        if ($Image.SectionNames -contains '.wixburn') { $evidence['WiX Burn'] = 'a .wixburn section' }
        if ($ManifestIdentity -like 'Nullsoft.NSIS*') { $evidence['NSIS'] = "manifest identity $ManifestIdentity" }
        elseif ($Image.OverlayHead.Contains('NullsoftInst')) { $evidence['NSIS'] = 'an NSIS header after the executable' }
        if ($ManifestIdentity -eq 'JR.Inno.Setup') { $evidence['Inno Setup'] = "manifest identity $ManifestIdentity" }
        elseif ($Image.OverlayHead.Contains('Inno Setup Setup Data')) {
            $evidence['Inno Setup'] = 'Inno Setup data after the executable'
        }
        elseif ($Version.Comments -match 'Inno Setup') { $evidence['Inno Setup'] = 'the version comment' }
        if ($ManifestIdentity -match 'InstallShield') { $evidence['InstallShield'] = "manifest identity $ManifestIdentity" }
        elseif ($versionText -match 'InstallShield') {
            $evidence['InstallShield'] = 'the word InstallShield in the version resource (weak)'
        }

        if ($evidence.Count -eq 0) { return $null }
        $names = @($evidence.Keys)
        [pscustomobject]@{
            Name     = $names[0]
            Evidence = $evidence[$names[0]]
            Others   = @($names | Select-Object -Skip 1)
        }
    }

    function Read-ExeInstaller {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param ([Parameter(Mandatory)] [System.IO.FileInfo]$File)

        $notes = [System.Collections.Generic.List[string]]::new()
        $name = $File.Name
        $image = Read-PeImage -Path $File.FullName
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)

        # Manifests may prefix element names with a namespace alias, as in <v3:requestedExecutionLevel>.
        $identity = $null
        $level = $null
        if ($image.Manifest -and $image.Manifest -match '<(?:\w+:)?assemblyIdentity\b[^>]*?\bname\s*=\s*["'']([^"'']+)') {
            $identity = $Matches[1]
        }
        if ($image.Manifest -and $image.Manifest -match '<(?:\w+:)?requestedExecutionLevel\b[^>]*?\blevel\s*=\s*["''](\w+)') {
            $level = $Matches[1]
        }

        $framework = Find-InstallerFramework -Image $image -ManifestIdentity $identity -Version $version
        $installCommand = $null
        $uninstallCommand = $null
        if ($null -ne $framework) {
            $switches = $FrameworkSwitch[$framework.Name]
            $installCommand = '"{0}" {1}' -f $name, $switches.Install
            if ($switches.Uninstall) { $uninstallCommand = '"{0}" {1}' -f $name, $switches.Uninstall }
            if ($framework.Others.Count -gt 0) {
                Add-InstallerNote -Note $notes -FileName $name -Message (
                    'Also shows signs of {0}. Check which framework it really is before using the switches.' -f
                    ($framework.Others -join ', '))
            }

            switch ($framework.Name) {
                'WiX Burn' {
                    Add-InstallerNote -Note $notes -FileName $name -Message (
                        'WiX Burn bundle: the same file uninstalls with /uninstall, so keep it in the package.')
                }
                'NSIS' {
                    Add-InstallerNote -Note $notes -FileName $name -Message (
                        'NSIS switches are case-sensitive: /S, not /s. The uninstaller is written into the app ' +
                        'folder during install and takes /S as well.')
                    if ($level -eq 'asInvoker') {
                        Add-InstallerNote -Note $notes -FileName $name -Message (
                            'Runs without asking for elevation, which usually means a per-user install, as with ' +
                            'Electron apps. Run as SYSTEM it may install into the SYSTEM profile; check where a ' +
                            'test install puts the app.')
                    }
                }
                'Inno Setup' {
                    Add-InstallerNote -Note $notes -FileName $name -Message (
                        'Inno Setup writes unins000.exe into the app folder; it uninstalls with ' +
                        '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART.')
                }
                'InstallShield' {
                    Add-InstallerNote -Note $notes -FileName $name -Message (
                        '/s /v"/qn" suits Basic MSI projects. InstallScript projects need a recorded response ' +
                        'file instead: setup.exe /r once, then setup.exe /s /f1"<path>\setup.iss".')
                }
            }
        }
        else {
            Add-InstallerNote -Note $notes -FileName $name -Message (
                'Installer framework not recognised. Check the vendor documentation, or try /? on a test machine.')
        }
        Add-InstallerNote -Note $notes -FileName $name -Message (
            'An EXE carries no product code. Install it on a test machine and base detection on what it writes, ' +
            'such as DisplayVersion under the Uninstall registry key: Get-UninstallEntry.ps1 compares those keys ' +
            'before and after.')
        if ($image.Architecture -eq 'x86') {
            Add-InstallerNote -Note $notes -FileName $name -Message (
                'The installer itself is 32-bit. That says nothing about the app it installs.')
        }

        $signature = Get-SignatureSummary -Path $File.FullName
        Add-SignatureNote -Signature $signature -Note $notes -FileName $name

        $fileVersion = $null
        if ($version.FileMajorPart -or $version.FileMinorPart -or $version.FileBuildPart -or $version.FilePrivatePart) {
            $fileVersion = '{0}.{1}.{2}.{3}' -f $version.FileMajorPart, $version.FileMinorPart,
            $version.FileBuildPart, $version.FilePrivatePart
        }

        [pscustomobject]@{
            Path                    = $File.FullName
            FileType                = 'Exe'
            ProductName             = ConvertTo-CleanText -Text $version.ProductName
            Publisher               = ConvertTo-CleanText -Text $version.CompanyName
            ProductVersion          = ConvertTo-CleanText -Text $version.ProductVersion
            FileVersion             = $fileVersion
            FileDescription         = ConvertTo-CleanText -Text $version.FileDescription
            OriginalFilename        = ConvertTo-CleanText -Text $version.OriginalFilename
            ExecutableArchitecture  = $image.Architecture
            RequestedExecutionLevel = $level
            InstallerFramework      = if ($framework) { $framework.Name } else { 'Unknown' }
            FrameworkEvidence       = if ($framework) { $framework.Evidence } else { $null }
            SignatureStatus         = $signature.Status
            Signer                  = $signature.Signer
            IntuneInstallCommand    = $installCommand
            IntuneUninstallCommand  = $uninstallCommand
            IntuneInstallBehavior   = $null
            IntuneDetection         = $null
            Notes                   = $notes.ToArray()
        }
    }

    #endregion

    #region .intunewin

    function Get-XmlText {
        [CmdletBinding()]
        [OutputType([string])]
        param (
            [Parameter()] [AllowNull()] [System.Xml.XmlNode]$Node,
            [Parameter(Mandatory)] [string]$XPath
        )

        if ($null -eq $Node) { return $null }
        $match = $Node.SelectSingleNode($XPath)
        if ($null -eq $match) { return $null }
        ConvertTo-CleanText -Text $match.InnerText
    }

    function Read-IntuneWinPackage {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param ([Parameter(Mandatory)] [System.IO.FileInfo]$File)

        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction Stop
        $notes = [System.Collections.Generic.List[string]]::new()
        $name = $File.Name

        # The package may come from anywhere, so the XML may not define entities or fetch anything.
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $document = [System.Xml.XmlDocument]::new()

        $zip = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)
        try {
            $entry = $null
            foreach ($candidate in $zip.Entries) {
                if (($candidate.FullName -replace '\\', '/') -match '(^|/)Metadata/Detection\.xml$') {
                    $entry = $candidate
                    break
                }
            }
            if ($null -eq $entry) {
                throw ('A ZIP archive without Metadata/Detection.xml, so not an .intunewin package. MSIX and ' +
                    'APPX packages are not read.')
            }
            if ($entry.Length -gt 1MB) { throw ('Detection.xml is {0} bytes; a real one is a few kilobytes.' -f $entry.Length) }

            $stream = $entry.Open()
            try {
                $xmlReader = [System.Xml.XmlReader]::Create($stream, $settings)
                try { $document.Load($xmlReader) }
                finally { $xmlReader.Dispose() }
            }
            finally {
                $stream.Dispose()
            }
        }
        finally {
            $zip.Dispose()
        }

        $root = $document.DocumentElement
        if ($null -eq $root -or $root.LocalName -ne 'ApplicationInfo') {
            throw 'Detection.xml does not start with ApplicationInfo, so its layout is unknown.'
        }

        # Only identifying fields are read. EncryptionInfo holds the key to the content and stays put.
        $msi = $root.SelectSingleNode('MsiInfo')
        $setupFile = Get-XmlText -Node $root -XPath 'SetupFile'
        $productCode = Get-XmlText -Node $msi -XPath 'MsiProductCode'
        $productVersion = Get-XmlText -Node $msi -XPath 'MsiProductVersion'
        $msiContext = Get-XmlText -Node $msi -XPath 'MsiExecutionContext'
        $requiresReboot = Get-XmlText -Node $msi -XPath 'MsiRequiresReboot'
        $contentSize = Get-XmlText -Node $root -XPath 'UnencryptedContentSize'
        $toolVersion = ConvertTo-CleanText -Text $root.GetAttribute('ToolVersion')

        $installCommand = $null
        $uninstallCommand = $null
        $detection = $null
        $behavior = $null
        if ($null -ne $msi) {
            if ($setupFile -like '*.msi') { $installCommand = 'msiexec /i "{0}" /qn /norestart' -f $setupFile }
            if ($productCode) {
                $uninstallCommand = 'msiexec /x "{0}" /qn /norestart' -f $productCode
                $detection = 'MSI product code {0}, product version greater than or equal to {1}' -f
                $productCode, $productVersion
            }
            switch ($msiContext) {
                'System' { $behavior = 'System' }
                'User' { $behavior = 'User' }
                'Any' {
                    Add-InstallerNote -Note $notes -FileName $name -Message (
                        'The MSI can install per-user or per-machine (MsiExecutionContext Any). Read the MSI ' +
                        'itself with this script: if it defaults to per-user, a System install needs ALLUSERS=1.')
                }
            }
        }
        else {
            $source = if ($setupFile) { $setupFile } else { 'an unnamed setup file' }
            Add-InstallerNote -Note $notes -FileName $name -Message ((
                    'Built from {0}, not an MSI, so the package records no product details. Read the source ' +
                    'installer for those.') -f $source)
        }

        [pscustomobject]@{
            Path                   = $File.FullName
            FileType               = 'IntuneWin'
            SetupFile              = $setupFile
            ProductName            = Get-XmlText -Node $root -XPath 'Name'
            Publisher              = Get-XmlText -Node $msi -XPath 'MsiPublisher'
            ProductVersion         = $productVersion
            ProductCode            = $productCode
            UpgradeCode            = Get-XmlText -Node $msi -XPath 'MsiUpgradeCode'
            PackageCode            = Get-XmlText -Node $msi -XPath 'MsiPackageCode'
            MsiExecutionContext    = $msiContext
            MsiRequiresReboot      = if ($requiresReboot) { $requiresReboot -eq 'true' } else { $null }
            ContentSizeBytes       = if ($contentSize -match '^\d+$') { [long]$contentSize } else { $null }
            ToolVersion            = $toolVersion
            IntuneInstallCommand   = $installCommand
            IntuneUninstallCommand = $uninstallCommand
            IntuneInstallBehavior  = $behavior
            IntuneDetection        = $detection
            Notes                  = $notes.ToArray()
        }
    }

    #endregion

    function Read-InstallerTarget {
        # Resolves each path and reads every file it names. Exactly one of the two is set,
        # depending on the parameter set the caller used.
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param (
            [Parameter()] [AllowNull()] [string[]]$Path,
            [Parameter()] [AllowNull()] [string[]]$LiteralPath
        )

        $selectors = if ($LiteralPath) {
            @($LiteralPath | ForEach-Object { @{ LiteralPath = $_ } })
        }
        else {
            @($Path | ForEach-Object { @{ Path = $_ } })
        }

        foreach ($selector in $selectors) {
            $label = @($selector.Values)[0]
            try {
                $items = @(Get-Item @selector -Force -ErrorAction Stop)
            }
            catch {
                Write-FileError -Target $label -Message (Get-ErrorText -ErrorRecord $_)
                continue
            }
            if ($items.Count -eq 0) {
                Write-FileError -Target $label -Message 'No file matches.'
                continue
            }

            foreach ($item in $items) {
                if ($item.PSIsContainer) {
                    Write-FileError -Target $item.FullName -Message (
                        'This is a folder. Pipe Get-ChildItem -File into the script to read the installers in it.')
                    continue
                }
                try {
                    switch (Get-InstallerKind -File $item) {
                        'Msi' { Read-MsiPackage -File $item }
                        'Exe' { Read-ExeInstaller -File $item }
                        'IntuneWin' { Read-IntuneWinPackage -File $item }
                    }
                }
                catch {
                    Write-FileError -Target $item.FullName -Message (Get-ErrorText -ErrorRecord $_)
                }
            }
        }
    }

    $Run.ProcessRan = $false
}

process {
    $Run.ProcessRan = $true
    Read-InstallerTarget -Path $Path -LiteralPath $LiteralPath
}

end {
    # Started with -File while standard input is redirected, as automation usually starts it,
    # PowerShell runs the script as if something were piped into it: process runs once per
    # line of input, and never when there is none. The paths are bound all the same.
    if (-not $Run.ProcessRan -and
        ($PSBoundParameters.ContainsKey('Path') -or $PSBoundParameters.ContainsKey('LiteralPath'))) {
        Read-InstallerTarget -Path $Path -LiteralPath $LiteralPath
    }

    if ($Run.Failed -gt 0) { exit $ExitFailure }
    exit $ExitSuccess
}
