@echo off
:: Remote Access Scanner Launcher
:: Double-click this file to run the scanner

:: Check if running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with Administrator rights...
) else (
    echo.
    echo =====================================================
    echo   TIP: For best results, right-click this file
    echo   and select "Run as Administrator"
    echo =====================================================
    echo.
    pause
)

:: Run the PowerShell script
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scan-RemoteAccess.ps1"

pause
