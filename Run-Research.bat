@echo off
:: Signature Research Tool Launcher
:: Use this to research new threats and update your signatures

echo.
echo  =====================================================
echo   SIGNATURE RESEARCH TOOL
echo   Scan the web for new remote access threats
echo  =====================================================
echo.
echo  This tool searches security blogs, forums, and
echo  threat intel sources to find new RATs and scam tools.
echo.
echo  Run this on YOUR PC (not customer PCs).
echo.

PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Signature-Research.ps1"

pause
