param(
    [string]$PythonVersion = "3.12"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $PyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($PyLauncher) {
        Write-Host "Creating virtual environment with Python $PythonVersion via py launcher ..."
        & $PyLauncher.Source "-$PythonVersion" -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Python $PythonVersion was not found or virtual environment creation failed. Install Python $PythonVersion or pass -PythonVersion 3.13." }
    } else {
        $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if (-not $PythonCommand) {
            throw "Python was not found. Install Python $PythonVersion (or 3.13) and enable the Python launcher."
        }
        $DetectedVersion = & $PythonCommand.Source --version
        Write-Host "Python launcher 'py' not found. Using $DetectedVersion from PATH."
        & $PythonCommand.Source -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
    }

    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    Write-Host "Installing pinned dependencies ..."
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }

    & $VenvPython -m pip install -r requirements-benchmark.txt pytest
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

    Write-Host "Compiling project modules ..."
    & $VenvPython -m compileall -q attack_graph tests
    if ($LASTEXITCODE -ne 0) { throw "Python compilation failed." }

    Write-Host "Running repository tests ..."
    & $VenvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Repository tests failed." }

    Write-Host ""
    Write-Host "Setup complete. Virtual environment, dependencies, compilation and tests passed."
    Write-Host "Activate the environment in this PowerShell session with:"
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    Write-Host "Dataset and Ollama model are separate downloads; see README.md."
}
finally {
    Pop-Location
}
