param(
    [string]$PythonVersion = "3.12"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw "The Python launcher 'py' was not found. Install Python 3.12 and enable the Python Launcher."
    }

    Write-Host "Creating virtual environment with Python $PythonVersion ..."
    & py "-$PythonVersion" -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }

    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    Write-Host "Installing pinned dependencies ..."
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }

    & $VenvPython -m pip install -r requirements-benchmark.txt pytest
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

    Write-Host "Compiling project modules ..."
    & $VenvPython -m compileall -q attack_graph tests
    if ($LASTEXITCODE -ne 0) { throw "Python compilation failed." }

    Write-Host ""
    Write-Host "Setup complete."
    Write-Host "Activate the environment in this PowerShell session with:"
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    Write-Host "Dataset and Ollama model are separate downloads; see README.md."
}
finally {
    Pop-Location
}
