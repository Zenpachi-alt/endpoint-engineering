@echo off
rem SPDX-FileCopyrightText: 2026 Tomasz Pietryka
rem SPDX-License-Identifier: MIT
rem Source: https://github.com/zenpachi-alt/endpoint-engineering
rem
rem OOBE launcher for Get-AutopilotHardwareHash.ps1. Double-click from the USB
rem key, or run it from the Shift+F10 command prompt during OOBE. Collects into
rem a single shared AutopilotHWID.csv on the key, so one file covers the cart.

setlocal EnableExtensions

set "SCRIPT=%~dp0Get-AutopilotHardwareHash.ps1"

echo ==========================================
echo  Autopilot hardware hash collector
echo ==========================================
echo.

if not exist "%SCRIPT%" (
    echo ERROR: Get-AutopilotHardwareHash.ps1 was not found next to this file.
    echo Expected: %SCRIPT%
    echo.
    echo Copy both files to the root of the USB key and run this again.
    echo.
    pause
    exit /b 1
)

rem Give a USB key inserted after this prompt opened a chance to get a drive
rem letter. Harmless when every volume is already mounted. If the key itself
rem has no letter you cannot launch this file at all - run diskpart, then
rem rescan, then list volume by hand first.
echo Rescanning removable media...
set "DISKPART_SCRIPT=%TEMP%\autopilot-rescan.txt"
>"%DISKPART_SCRIPT%" echo rescan
>>"%DISKPART_SCRIPT%" echo automount enable
diskpart /s "%DISKPART_SCRIPT%" >nul 2>&1
del "%DISKPART_SCRIPT%" >nul 2>&1

echo.
set "TAG="
set /p "TAG=Group tag (press Enter to skip): "

echo.
echo Collecting. This takes a few seconds...
echo.

if defined TAG (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -OutputPath "%~dp0." -Append -GroupTag "%TAG%"
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -OutputPath "%~dp0." -Append
)

set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo Done. The device was added to AutopilotHWID.csv on this key.
) else (
    echo FAILED with exit code %RC%. Read the message above.
    echo A full log is in %%ProgramData%%\EndpointEngineering\Logs.
)

echo.
pause
exit /b %RC%
