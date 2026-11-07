@echo off
REM DeadDrop Windows Single-Click Installer Wrapper
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
