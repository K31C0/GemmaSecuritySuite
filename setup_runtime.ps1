# setup_runtime.ps1 — Prepare an embedded Python for USB deployment.
#
# Run this ONCE on your build machine. It downloads the Python
# embeddable ZIP, enables pip + site-packages, and pre-installs
# all GemmaSecuritySuite dependencies into the runtime/ folder.
#
# After running, the entire runtime/ folder ships on the USB.
# The target machine needs ZERO Python installation.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File setup_runtime.ps1

param(
    [string]$PythonVersion = "3.12.9",
    [string]$Architecture  = "amd64"  # or "arm64"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeDir = Join-Path $ScriptDir "runtime"
$ZipFile = Join-Path $ScriptDir "python-embed.zip"
$PthFile = Join-Path $RuntimeDir "python312._pth"
$GetPipUrl = "https://bootstrap.pypa.io/get-pip.py"
$PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-$Architecture.zip"

Write-Host ""
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host "    GemmaSecuritySuite — Runtime Builder"
Write-Host "  =================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Python version : $PythonVersion ($Architecture)"
Write-Host "  Target folder  : $RuntimeDir"
Write-Host ""

# --- Clean existing runtime ---
if (Test-Path $RuntimeDir) {
    Write-Host "  [*] Removing existing runtime folder..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $RuntimeDir
}

# --- Download Python embeddable ---
Write-Host "  [1/5] Downloading Python embeddable ZIP..."
Invoke-WebRequest -Uri $PythonUrl -OutFile $ZipFile -UseBasicParsing
Write-Host "        Downloaded: $(((Get-Item $ZipFile).Length / 1MB).ToString('F1')) MB"

# --- Extract ---
Write-Host "  [2/5] Extracting to runtime\..."
Expand-Archive -Path $ZipFile -DestinationPath $RuntimeDir -Force
Remove-Item $ZipFile

# --- Enable site-packages (required for pip and installed packages) ---
Write-Host "  [3/5] Enabling site-packages in ._pth file..."
if (Test-Path $PthFile) {
    (Get-Content $PthFile) -replace '#import site', 'import site' | Set-Content $PthFile
    # Also add parent directory so our modules can be found
    Add-Content $PthFile "`n.."
    Add-Content $PthFile "..\Lib\site-packages"
} else {
    # Try to find the _pth file with a different name pattern
    $pthFiles = Get-ChildItem $RuntimeDir -Filter "python*._pth"
    if ($pthFiles.Count -gt 0) {
        $PthFile = $pthFiles[0].FullName
        Write-Host "        Found: $($pthFiles[0].Name)"
        (Get-Content $PthFile) -replace '#import site', 'import site' | Set-Content $PthFile
        Add-Content $PthFile "`n.."
        Add-Content $PthFile "..\Lib\site-packages"
    } else {
        Write-Host "  [!] WARNING: Could not find ._pth file. pip may not work." -ForegroundColor Yellow
    }
}

# --- Install pip ---
Write-Host "  [4/5] Installing pip..."
$GetPipFile = Join-Path $RuntimeDir "get-pip.py"
Invoke-WebRequest -Uri $GetPipUrl -OutFile $GetPipFile -UseBasicParsing
& "$RuntimeDir\python.exe" $GetPipFile --no-warn-script-location --quiet
Remove-Item $GetPipFile

# --- Install all dependencies ---
Write-Host "  [5/5] Installing GemmaSecuritySuite dependencies..."
$ReqFile = Join-Path $ScriptDir "requirements.txt"
if (Test-Path $ReqFile) {
    & "$RuntimeDir\python.exe" -m pip install -r $ReqFile --no-warn-script-location --quiet
    Write-Host "        All packages installed."
} else {
    Write-Host "  [!] WARNING: requirements.txt not found. Skipping package install." -ForegroundColor Yellow
}

# --- Summary ---
$RuntimeSize = ((Get-ChildItem $RuntimeDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB)
Write-Host ""
Write-Host "  =================================================" -ForegroundColor Green
Write-Host "    Runtime ready!"
Write-Host "  =================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Folder : $RuntimeDir"
Write-Host "  Size   : $($RuntimeSize.ToString('F0')) MB"
Write-Host "  Python : $RuntimeDir\python.exe"
Write-Host ""
Write-Host "  Next steps:"
Write-Host "    1. Copy the entire project folder (including runtime\) to a USB drive"
Write-Host "    2. On the target machine, double-click Launch.bat"
Write-Host ""
