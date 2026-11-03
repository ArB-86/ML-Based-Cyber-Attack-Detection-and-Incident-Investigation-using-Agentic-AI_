# ML-Based Cyber-Attack Detection and SOC Incident Investigation

An end-to-end, reproducible research pipeline built around CICIDS2017 network-flow data:

**CICIDS2017 → preprocessing → Isolation Forest → behavioural detections → alert fusion → events → correlation → candidate incidents → attack graph → risk triage → evidence-scoped Agentic AI investigation → reports.**

The canonical entry point is `python -m attack_graph.pipeline`. The old compatibility modules delegate to this pipeline; do not run separate notebook/legacy workflows for the main experiment.

> **Research scope:** this project investigates labelled network-flow telemetry. It produces candidate incidents and network-level investigation leads. It does not prove successful authentication, endpoint compromise, lateral movement, data access, or exfiltration. A human analyst must validate findings against independent identity, EDR, firewall, DNS, and application telemetry.

## 1. Requirements

- Windows 10/11, Linux, or macOS.
- Python **3.12 or 3.13**.
- Git.
- The CICIDS2017 **MachineLearningCSV** dataset (downloaded separately; it is not stored in this repository).
- Ollama and a compatible local Qwen model for LLM-assisted investigation. The pipeline can also run in deterministic tool-assisted mode without Ollama.

The pinned Python environment is in `requirements-benchmark.txt`. The repository CI tests Python 3.12 and 3.13.

## 2. Clone and install

### Windows PowerShell

```powershell
git clone https://github.com/ArB-86/ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI_.git
cd ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI_

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup_windows.ps1
.\.venv\Scripts\Activate.ps1
```

The setup script creates `.venv`, installs the pinned dependencies and runs a Python compilation check. It does not download the dataset or an LLM.

### Linux / macOS

```bash
git clone https://github.com/ArB-86/ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI_.git
cd ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI_
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-benchmark.txt pytest
python -m compileall -q attack_graph tests
pytest -q
```

## 3. Download and arrange CICIDS2017

Download **MachineLearningCSV.zip** from the [official Canadian Institute for Cybersecurity CICIDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html). Extract the eight CSV files into one directory, for example:

```text
data/
└── raw/
    └── cicids2017/
        ├── Monday-WorkingHours.pcap_ISCX.csv
        ├── Tuesday-WorkingHours.pcap_ISCX.csv
        ├── Wednesday-workingHours.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
        ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
        ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
        └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

The filename spelling and capitalization above matter. In particular, the dataset export uses **Infilteration** in the filename. If the ZIP extracts the files into a nested folder, pass that nested folder as `--data-dir`.

Validate the eight files and their headers before starting the full run:

```powershell
python scripts/validate_dataset.py .\data\raw\cicids2017
```

The validator checks the expected filenames and the columns required by the current 69-feature pipeline. It reads CSV headers only; it does not load or process the full dataset.

The dataset is deliberately not committed to Git: it is large, and users should download the source archive and follow the dataset provider's citation and terms. Cite the dataset paper in academic work: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP, 2018.

## 4. Configure local Qwen / Ollama

Install [Ollama](https://ollama.com/download), start its local service, and download a Qwen model. Example:

```powershell
ollama pull qwen2.5:7b-instruct
ollama list
```

The repository includes `attack_graph.ollama_reasoner`; no external `D:\...\ollama_reasoner.py`, custom bridge module, API key, or third-party Python SDK is required.

By default the adapter uses:

- Host: `http://127.0.0.1:11434`
- Model: `qwen2.5:7b-instruct`
- Context allocation: `32768` tokens
- Request timeout: `900` seconds

You can override these with environment variables:

```powershell
$env:OLLAMA_HOST = "http://127.0.0.1:11434"
$env:OLLAMA_MODEL = "qwen2.5:7b-instruct"
$env:OLLAMA_NUM_CTX = "32768"
$env:OLLAMA_NUM_PREDICT = "4096"
$env:OLLAMA_TIMEOUT_SECONDS = "900"
python -m attack_graph.ollama_reasoner --check
```

The incident evidence bundle can be large. The adapter requests JSON output and sets `num_ctx` explicitly. Use a model/context size that your machine can support. If Ollama reports a context-length or memory error, reduce the context allocation only if the model still fits the request, or use a compatible higher-context model / machine; do not claim an LLM investigation passed when the reasoner failed.

Ollama API references: [Chat API](https://docs.ollama.com/api/chat) and [Qwen2.5 model library](https://ollama.com/library/qwen2.5).

## 5. Run the complete pipeline

### Recommended first run: process the dataset and LLM-investigate the top-priority incident

Windows PowerShell:

```powershell
.\scripts\run_pipeline.ps1 -DataDir .\data\raw\cicids2017 -OutputDir .\outputs\run_001 -UseOllama
```

The launcher validates the dataset, checks that the configured Ollama model is installed, and runs the canonical pipeline. By default it limits Agentic AI investigation to **one highest-priority candidate incident**. All candidate incidents and pipeline artefacts are still generated; only the LLM investigation is capped. This is the sensible first run because investigating every candidate with a local LLM can be expensive and slow.

Linux / macOS or direct CLI:

```bash
export OLLAMA_MODEL="qwen2.5:7b-instruct"
export OLLAMA_NUM_CTX="32768"
python -m attack_graph.pipeline ./data/raw/cicids2017 \
  --output-dir ./outputs/run_001 \
  --reasoner-callable attack_graph.ollama_reasoner:reasoner \
  --max-agent-investigations 1
```

### Run without an LLM

This runs the same detection, graph, incident, deterministic evidence-retrieval and report pipeline, but it is **not** a Qwen investigation:

```powershell
python -m attack_graph.pipeline .\data\raw\cicids2017 --output-dir .\outputs\deterministic_run
```

### Investigate every candidate incident with Qwen

Omit `--max-agent-investigations` in the direct CLI, or use `-AllIncidents` with the PowerShell launcher:

```powershell
.\scripts\run_pipeline.ps1 -DataDir .\data\raw\cicids2017 -OutputDir .\outputs\all_incidents -UseOllama -AllIncidents
```

This can make many LLM calls. Start with the one-incident run, inspect the output and resource use, then decide whether to increase the limit.

### Re-run downstream analysis without retraining Isolation Forest

After a successful full run, the saved prediction file can be used to re-run behavioural policy and downstream SOC analysis:

```powershell
python -m attack_graph.pipeline --reuse-predictions .\outputs\run_001\cicids_if_predictions_with_metadata.csv --output-dir .\outputs\replay_001 --reasoner-callable attack_graph.ollama_reasoner:reasoner --max-agent-investigations 1
```

Replay mode **does not retrain Isolation Forest** and does not recompute model performance metrics. It requires the saved `predicted_anomaly` column.

## 6. What the pipeline does

| Stage | What happens | Main output / purpose |
|---|---|---|
| Ingestion | Loads the eight metadata-rich CSVs in a fixed order and validates timestamps and labels. | Unified flow table |
| Preprocessing | Normalizes columns, removes fully empty and duplicate records, handles invalid values and prepares 69 numerical features. Preserves time, IP, port and protocol metadata. | Cleaned features + metadata |
| ML detection | Stratified train/validation/test split; train-only median imputation; Isolation Forest trained on benign training rows; threshold calibrated from the benign validation tail. | Anomaly scores and model alerts |
| Behavioural detection | Computes explainable rules independently of ground-truth labels. | Actionable, review-only and context signals |
| Alert fusion | Combines Isolation Forest alerts with the actionable brute-force rule; records detector provenance. | Unified alert-flow table |
| Event generation | Aggregates related alert flows using endpoint, protocol and bounded temporal grouping. | `attack_events.csv` |
| Correlation | Records same-source, same-target, same-service and directed host-pivot relationships. | `event_correlations.csv` |
| Incident formation | Forms bounded candidate groups only through selected temporal-source and host-pivot relationships. Other graph edges remain context. | Candidate incident dossiers |
| Attack graph | Builds typed host/event/service/detection/incident nodes and directed relationships. | `attack_graph.gexf` |
| Risk triage | Assigns a transparent analyst-priority score and provisional severity/confidence. | Incident ranking |
| Agentic AI | Retrieves incident, timeline, graph-neighbourhood and detection evidence. Qwen can request allowlisted, read-only tools. | Tool trace and evidence-linked findings |
| Validation/reporting | Checks model claims against event IDs, detector provenance, metadata and graph edges; unsupported claims are rejected. | JSON, CSV and Markdown report |

### Detection and incident policy

- Isolation Forest is trained on benign training-partition rows. The current implementation uses 200 trees, a maximum of 1,024 samples per tree, and a reproducible random seed.
- The train/validation/test split is stratified (70% / 15% / 15%). Imputation statistics are fit on the training partition only. The alert threshold is calibrated against the benign validation-score tail.
- `BRUTE_FORCE_PATTERN` is an actionable rule candidate when the configured repeated-flow threshold is met on an authentication-related service port.
- `PORT_SCAN` is placed in a secondary review queue; it does not independently create a primary incident.
- `HIGH_SOURCE_FANOUT`, `HORIZONTAL_SCAN`, and `DISTRIBUTED_DOS_PATTERN` are context signals, not standalone proof of an attack.
- Incident formation uses a maximum 60-second same-source temporal gap or a 120-second directed host-pivot gap, with a 900-second maximum campaign duration. Same-target and same-service relations remain context and do not merge incidents by themselves.
- Ground-truth `Label` is used for offline model evaluation and selecting benign training rows. It is **not** used to decide operational alerts, event correlations, incident grouping, graph construction, risk scoring, or agent findings.

### Agentic AI safety and evidence boundaries

The agent has four allowlisted read-only tools: `get_event`, `get_host_activity`, `get_service_activity`, and `get_correlated_events`. It is limited to two iterative LLM tool rounds, five requests per round, and eight LLM-directed requests overall. Tool execution is scoped to the currently investigated incident. The agent cannot run arbitrary shell commands, block IPs, isolate hosts, or change production systems.

Model findings must use a supported claim type and cite event IDs. The validator checks whether those IDs belong to the incident and whether the claim is supported by detector metadata, event metadata, context signals, or an exact directed graph edge. Unsupported or ambiguous proposals are rejected; accepted claims are rewritten into evidence-derived wording.

Network-flow evidence alone cannot establish successful login, credential compromise, endpoint process execution, lateral movement, privilege escalation, sensitive file access, exfiltration, or business impact. MITRE ATT&CK mappings are hypotheses, not confirmation. Analyst validation against independent telemetry is required before containment.

## 7. Generated outputs

The output directory contains the main artefacts below (some optional files are emitted only when the corresponding stage/data is present):

| File | Description |
|---|---|
| `pipeline_summary.json` | Dataset, model, detector, graph and incident metrics |
| `soc_pipeline_manifest.json` | Stage sequence/status, counts and artefact inventory |
| `cicids_if_predictions_with_metadata.csv` | Per-flow anomaly score, prediction, rule flags and alert provenance |
| `suspicious_flows_with_metadata.csv` | Primary alert flows selected for investigation |
| `review_candidates_with_metadata.csv` | Port-scan-only secondary review queue |
| `attack_events.csv` | Aggregated suspicious event records |
| `event_correlations.csv` | Typed event relationships and pivot evidence |
| `attack_graph.gexf` | Full incident-linked directed graph (open with Gephi or another GEXF viewer) |
| `incident_investigation.csv` | Event-to-incident mapping and triage fields |
| `incident_investigation.json` | Structured dossiers, agent traces, findings and ATT&CK hypotheses |
| `incident_investigation_report.md` | Human-readable SOC investigation report |

For an LLM-backed investigation, inspect `incident_investigation.json` and confirm the selected incident's investigator mode is `tool_assisted_llm`, `reasoner_calls` contain successful phases, and `reasoner_error` is null. A deterministic run is useful as a baseline, but must not be presented as a Qwen run.

## 8. Tests and reproducibility

```powershell
python -m compileall -q attack_graph tests
pytest -q
```

Tests use small in-memory fixtures and do not download CICIDS2017 or call Ollama. GitHub Actions runs the test suite on Python 3.12 and 3.13. A passing unit-test suite verifies code contracts; it does **not** prove that a full multi-million-row dataset run or a local LLM run has completed on your machine.

The pipeline writes run-specific artefacts under the output directory. Dataset files, virtual environments, model files, and generated outputs are excluded from Git.

## 9. Repository structure

```text
attack_graph/
  benchmark_if_attack_graph_pipeline.py   # canonical data/model runner
  pipeline.py                              # canonical CLI and config
  soc_detection.py                         # behavioural rules and alert fusion
  event_builder.py                         # flow schema + event adapter
  graph_builder.py                         # graph and GEXF adapter
  soc_investigation.py                     # correlation, incidents, graph, agent, reports
  ollama_reasoner.py                       # local Ollama/Qwen callback
scripts/
  setup_windows.ps1
  validate_dataset.py
  run_pipeline.ps1
tests/
requirements-benchmark.txt
```

## 10. Limitations and future work

This is a CICIDS2017 benchmark research system, not a production-ready SOC deployment. The dataset contains labelled network flows, not independent identity, EDR, process, file-access, or application audit events. Behavioural thresholds are dataset-informed and need recalibration against representative organisational telemetry. Fixed time buckets can miss behaviour crossing a bucket boundary; a production streaming system should use stateful rolling windows. Detection quality, incident reconstruction quality, and LLM evidence quality should be evaluated separately.

Do not report a priority score as compromise probability or treat a candidate incident as a confirmed breach. Preserve the data split and evaluation methodology when comparing experiments.
