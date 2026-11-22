# PPDF Hybrid System Launcher (PowerShell)
# Usage:
#   .\run.ps1 test
#   .\run.ps1 keygen
#   .\run.ps1 stage2 --evidence-dir "..\KetQua"
#   .\run.ps1 stage3 --evidence-dir "..\KetQua"
#   .\run.ps1 full --evidence-dir "..\KetQua"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONPATH = "$scriptDir;$($env:PYTHONPATH)"

# Use .venv if available
if (Test-Path "$scriptDir\.venv\Scripts\python.exe") {
    $pythonExe = "$scriptDir\.venv\Scripts\python.exe"
} else {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {
        $pythonExe = "C:\Users\ADMIN\AppData\Local\Python\bin\python.exe"
    }
}

& $pythonExe "$scriptDir\ppdf_main.py" $args
