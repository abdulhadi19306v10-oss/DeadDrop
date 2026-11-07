# ==============================================================================
# DeadDrop - Single-Command Installer for Windows (PowerShell)
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "     DEADDROP - Zero-Knowledge 2FA Secure File Exchange             " -ForegroundColor Cyan
Write-Host "     Automated Single-Command Installer [Windows]                   " -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) {
    $ScriptDir = (Get-Location).Path
}
Set-Location $ScriptDir

# 1. Check Python
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Cyan
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Error: Python is not installed or not in your PATH." -ForegroundColor Red
    Write-Host "    Please install Python 3.11+ from https://www.python.org/downloads/"
    exit 1
}

$PyVersion = python --version
Write-Host "[OK] Detected $PyVersion" -ForegroundColor Green

# 2. Setup Virtual Environment
Write-Host "[2/5] Setting up virtual environment (.venv)..." -ForegroundColor Cyan
if (-not (Test-Path ".venv")) {
    python -m venv --system-site-packages .venv
    Write-Host "[OK] Created virtual environment at .venv" -ForegroundColor Green
}
if (Test-Path ".venv") {
    Write-Host "[OK] Virtual environment ready at .venv" -ForegroundColor Green
}

# 3. Install Dependencies & Package
Write-Host "[3/5] Installing DeadDrop dependencies and CLI tools..." -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip -q
& ".\.venv\Scripts\python.exe" -m pip install -e . -q
& ".\.venv\Scripts\python.exe" -m pip install pytest pytest-asyncio -q
Write-Host "[OK] Dependencies and entrypoint installed." -ForegroundColor Green

# 4. Configure Global 'deaddrop' Command in Windows PATH
Write-Host "[4/5] Configuring system-wide 'deaddrop' command..." -ForegroundColor Cyan
$WindowsAppsDir = "$env:LOCALAPPDATA\Microsoft\WindowsApps"
$GlobalWrapper = Join-Path $WindowsAppsDir "deaddrop.cmd"
$WrapperContent = "@echo off`r`n`"$ScriptDir\.venv\Scripts\deaddrop.exe`" %*"

try {
    [System.IO.File]::WriteAllText($GlobalWrapper, $WrapperContent)
    Write-Host "[OK] Installed global command to $GlobalWrapper" -ForegroundColor Green
} catch {
    Write-Host "[*] Note: WindowsApps write deferred. Root wrapper .\deaddrop.cmd is active." -ForegroundColor Yellow
}

# 5. Create Desktop Shortcut for GUI Application
Write-Host "[5/5] Creating Desktop Shortcut..." -ForegroundColor Cyan
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
    $ShortcutPath = Join-Path $DesktopPath "DeadDrop.lnk"
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = "$ScriptDir\.venv\Scripts\pythonw.exe"
    $Shortcut.Arguments = "`"$ScriptDir\run_app.py`""
    $Shortcut.WorkingDirectory = $ScriptDir
    $Shortcut.Description = "DeadDrop: Zero-Knowledge 2FA Secure File Exchange"
    $Shortcut.Save()
    Write-Host "[OK] Desktop shortcut created: $ShortcutPath" -ForegroundColor Green
} catch {
    Write-Host "[*] Desktop shortcut creation skipped." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "       DEADDROP INSTALLATION COMPLETED SUCCESSFULLY!                " -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "You can now run DeadDrop from ANY terminal or command prompt:"
Write-Host ""
Write-Host "  deaddrop send <file>       - Encrypt and upload a file via CLI" -ForegroundColor Cyan
Write-Host "  deaddrop receive <code>    - Unlock and download a file via CLI" -ForegroundColor Cyan
Write-Host "  deaddrop list              - List active drops" -ForegroundColor Cyan
Write-Host "  deaddrop burn <id>         - Shred a drop" -ForegroundColor Cyan
Write-Host "  deaddrop server            - Start relay server" -ForegroundColor Cyan
Write-Host "  deaddrop gui               - Launch PySide6 Desktop GUI" -ForegroundColor Cyan
Write-Host "  deaddrop lab               - Run security lab attack simulations" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or launch directly:"
Write-Host "  .\run_app.py               - Launch Desktop GUI" -ForegroundColor Yellow
Write-Host "  .\run_server.py            - Launch Cloud Relay Server" -ForegroundColor Yellow
Write-Host "====================================================================" -ForegroundColor Green
