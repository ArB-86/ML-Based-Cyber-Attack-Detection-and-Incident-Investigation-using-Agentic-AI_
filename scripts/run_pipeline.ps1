param(
    [string]$DataDir = ".\data\raw\cicids2017",
    [string]$OutputDir = ".\outputs\run_001",
    [switch]$UseOllama,
    [string]$Model = "qwen2.5:7b-instruct",
    [ValidateRange(0, 100000)]
    [int]$MaxAgentInvestigations = 1,
    [switch]$AllIncidents
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    $ResolvedDataDir = (Resolve-Path $DataDir -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $ResolvedDataDir -PathType Container)) {
        throw "DataDir must be a directory: $DataDir"
    }

    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $VenvPython) {
        $Python = $VenvPython
    } else {
        $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if (-not $PythonCommand) {
            throw "Python was not found. Run scripts/setup_windows.ps1 first."
        }
        $Python = $PythonCommand.Source
    }

    Write-Host "Python executable: $Python"
    Write-Host "Validating CICIDS2017 input directory ..."
    & $Python scripts/validate_dataset.py $ResolvedDataDir
    if ($LASTEXITCODE -ne 0) {
        throw "Dataset validation failed. Fix the missing files/columns before running the pipeline."
    }

    $PipelineArgs = @(
        "-m", "attack_graph.pipeline",
        $ResolvedDataDir,
        "--output-dir", $OutputDir
    )

    if (-not $AllIncidents) {
        $PipelineArgs += @("--max-agent-investigations", "$MaxAgentInvestigations")
        Write-Host "Agent investigation limit: $MaxAgentInvestigations candidate incident(s)."
    } else {
        Write-Warning "All candidate incidents will receive agent investigation. This can trigger many local LLM calls."
    }

    if ($UseOllama) {
        $env:OLLAMA_MODEL = $Model
        Write-Host "Checking local Ollama and model $Model ..."
        & $Python -m attack_graph.ollama_reasoner --check
        if ($LASTEXITCODE -ne 0) {
            throw "Ollama is not ready. Start Ollama, pull the configured model, then retry."
        }
        $PipelineArgs += @(
            "--reasoner-callable",
            "attack_graph.ollama_reasoner:reasoner"
        )
    } else {
        Write-Warning "Ollama is disabled. This run will use deterministic tool-assisted investigation, not Qwen."
    }

    Write-Host "Starting canonical CICIDS2017 -> SOC incident pipeline ..."
    & $Python @PipelineArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Pipeline failed with exit code $LASTEXITCODE. Inspect the traceback and output manifest."
    }
}
finally {
    Pop-Location
}
