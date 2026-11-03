from __future__ import annotations

import json

import pandas as pd
import pytest

from attack_graph.agentic_investigator import run
from attack_graph.soc_investigation import run_soc_investigation


def test_ai_only_stage_reuses_existing_events_graph_and_risk(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": "2017-07-03T10:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.9",
            "protocol": 6,
            "src_port": 51000,
            "dst_port": 22,
            "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN",
            "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.01,
        },
        {
            "timestamp": "2017-07-03T10:00:20Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.9",
            "protocol": 6,
            "src_port": 51001,
            "dst_port": 22,
            "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN",
            "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.02,
        },
    ])

    _, _, upstream_summary = run_soc_investigation(flows, tmp_path)
    assert upstream_summary["incident_count"] == 1

    events_path = tmp_path / "attack_events.csv"
    graph_path = tmp_path / "attack_graph.gexf"
    events_before = events_path.read_bytes()
    graph_before = graph_path.read_bytes()
    calls = []

    def fake_reasoner(context):
        calls.append(context)
        assert context["incident"]["incident_id"] == "INC-00001"
        assert context["timeline"]
        assert context["graph"]["member_event_nodes"]
        assert context["detections"]["reason_to_event_ids"]
        return {
            "tool_calls": [],
            "findings": [],
            "narrative": "Network-flow evidence needs independent analyst corroboration.",
        }

    result = run(tmp_path, reasoner=fake_reasoner, max_incidents=1)

    assert len(calls) == 1
    assert result["upstream_stages_reexecuted"] is False
    assert result["processed_incident_count"] == 1
    assert result["reasoner_enabled"] is True
    assert events_path.read_bytes() == events_before
    assert graph_path.read_bytes() == graph_before

    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    agent = payload["incidents"][0]["investigation_agent"]
    assert agent["mode"] == "tool_assisted_llm"
    assert agent["reasoner_calls"][0]["status"] == "success"
    assert agent["narrative"].startswith("Network-flow evidence")
    report = (tmp_path / "incident_investigation_report.md").read_text()
    assert "Tool-assisted agent investigation" in report
    assert "tool_assisted_llm" in report

    stage_summary = json.loads(
        (tmp_path / "agentic_investigation_summary.json").read_text()
    )
    assert stage_summary["stage"] == "agentic_ai_investigation_only"
    manifest = json.loads((tmp_path / "soc_pipeline_manifest.json").read_text())
    assert manifest["agentic_investigation_stage"]["upstream_stages_reexecuted"] is False


def test_ai_only_stage_fails_clearly_when_upstream_artifacts_are_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="attack_events.csv"):
        run(tmp_path, reasoner=lambda context: {}, max_incidents=1)


def test_ai_only_stage_rejects_zero_incident_limit(tmp_path):
    with pytest.raises(ValueError, match="positive integer"):
        run(tmp_path, reasoner=None, max_incidents=0)
