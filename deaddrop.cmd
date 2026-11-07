@echo off
REM DeadDrop CLI Launcher for Windows
SET "DIR=%~dp0"
IF EXIST "%DIR%.venv\Scripts\deaddrop.exe" (
    "%DIR%.venv\Scripts\deaddrop.exe" %*
) ELSE IF EXIST "%DIR%.venv\Scripts\python.exe" (
    "%DIR%.venv\Scripts\python.exe" -m deaddrop.client.cli %*
) ELSE (
    python -m deaddrop.client.cli %*
)
