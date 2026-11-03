# ML-Based Cyber-Attack Detection and Incident Investigation using Agentic AI

A reproducible CICIDS2017 pipeline from network-flow CSVs to anomaly detection, event correlation, candidate incidents, an incident-linked attack graph and evidence-backed SOC investigation.

## Quick start (Windows PowerShell)

```powershell
git clone https://github.com/ArB-86/ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI_.git
cd ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI_

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-benchmark.txt
python -m pip install pytest
```

Download CICIDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html and extract its eight metadata-rich CSV files into `data/` at the repository root. Dataset files are not committed because of their size.

Then run the complete pipeline:

```powershell
python -m attack_graph.pipeline ".\data" --output-dir ".\soc_output"
pytest -q
```

The default run performs deterministic read-only evidence investigation. Optional Ollama/Qwen tool-using investigation requires the user to provide their own importable local reasoner callback via `--reasoner-callable module:function`; private bridge/runtime settings and credentials are intentionally not included.

See the complete README for the eight expected filenames, outputs, replay mode, AI callback contract and limitations.
