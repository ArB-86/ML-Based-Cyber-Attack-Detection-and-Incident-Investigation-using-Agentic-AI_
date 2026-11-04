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
        if "timeline" not in context:
            return {
                "tool_calls": [],
                "findings": [],
                "finding_disposition": "no_additional_findings_supported",
                "finding_disposition_reason": (
                    "The network-flow evidence needs independent authentication and endpoint corroboration."
                ),
                "narrative": "Network-flow evidence needs independent analyst corroboration.",
            }
        assert context["timeline"]
        assert context["graph"]["member_event_nodes"]
        assert context["detections"]["reason_to_event_ids"]
        return {
            "tool_calls": [],
            "preliminary_findings": [],
            "narrative": "Initial evidence retrieved; final synthesis follows.",
        }

    result = run(tmp_path, reasoner=fake_reasoner, max_incidents=1)

    assert len(calls) == 2
    assert result["upstream_stages_reexecuted"] is False
    assert result["processed_incident_count"] == 1
    assert result["reasoner_enabled"] is True
    assert events_path.read_bytes() == events_before
    assert graph_path.read_bytes() == graph_before

    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    agent = payload["incidents"][0]["investigation_agent"]
    assert agent["mode"] == "tool_assisted_llm"
    assert agent["reasoner_calls"][0]["status"] == "success"
    assert agent["model_narrative"].startswith("Network-flow evidence")
    assert agent["model_narrative_status"] == "proposed_unverified"
    report = (tmp_path / "incident_investigation_report.md").read_text()
    assert "Tool-assisted agent investigation" in report
    assert "LLM-proposed synthesis (unverified; analyst validation required)" in report
    assert "Network-flow evidence needs independent analyst corroboration." in report
    assert "tool_assisted_llm" in report

    stage_summary = json.loads(
        (tmp_path / "agentic_investigation_summary.json").read_text()
    )
    assert stage_summary["stage"] == "agentic_ai_investigation_only"
    assert stage_summary["agent_reasoner_calls"] == 2
    assert stage_summary["reasoner_executions_successful"] == 1
    assert stage_summary["llm_syntheses_successful"] == 1
    manifest = json.loads((tmp_path / "soc_pipeline_manifest.json").read_text())
    assert manifest["agentic_investigation_stage"]["upstream_stages_reexecuted"] is False


def test_ai_only_stage_fails_clearly_when_upstream_artifacts_are_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="attack_events.csv"):
        run(tmp_path, reasoner=lambda context: {}, max_incidents=1)


def test_ai_only_stage_rejects_zero_incident_limit(tmp_path):
    with pytest.raises(ValueError, match="positive integer"):
        run(tmp_path, reasoner=None, max_incidents=0)


def test_ai_only_summary_separates_current_run_from_preserved_dossier_counts(tmp_path):
    import networkx as nx

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

    _, _, upstream = run_soc_investigation(flows, tmp_path)
    assert upstream["incident_count"] == 1

    # Add a second, pre-existing dossier record sharing the same evidence.
    # This isolates summary-count behaviour from incident-formation policy.
    dossier_path = tmp_path / "incident_investigation.json"
    payload = json.loads(dossier_path.read_text())
    existing = json.loads(json.dumps(payload["incidents"][0]))
    existing["incident_id"] = "INC-99999"
    payload["incidents"].append(existing)
    payload["incident_count"] = len(payload["incidents"])
    dossier_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    graph_path = tmp_path / "attack_graph.gexf"
    graph = nx.read_gexf(graph_path)
    new_node = "incident:INC-99999"
    graph.add_node(
        new_node,
        node_type="incident",
        label="INC-99999",
        title=existing["title"],
    )
    for event_id in existing["event_ids"]:
        graph.add_edge(new_node, f"event:{event_id}", relation="contains", relations="contains")
    nx.write_gexf(graph, graph_path)

    def fake_reasoner(context):
        if "timeline" not in context:
            return {
                "tool_calls": [],
                "findings": [],
                "finding_disposition": "no_additional_findings_supported",
                "finding_disposition_reason": (
                    "The bounded network evidence does not support an additional claim."
                ),
                "narrative": "One incident was reviewed using bounded evidence.",
            }
        return {
            "tool_calls": [],
            "preliminary_findings": [],
            "narrative": "Initial evidence loaded for review.",
        }

    result = run(tmp_path, reasoner=fake_reasoner, max_incidents=1)

    assert result["processed_incident_count"] == 1
    assert result["counts_scope"] == "records_touched_by_this_run"
    assert result["agent_reasoner_calls"] == 2
    assert result["agent_investigations_executed"] == 1
    assert result["agent_investigations_successful"] == 1
    assert result["reasoner_executions_successful"] == 1
    assert result["llm_syntheses_successful"] == 1
    assert result["preserved_preexisting_agent_records"] == 1
    assert result["dossier_counts"]["agent_investigations_executed"] == 2

    payload = json.loads(dossier_path.read_text())
    modes = [
        item["investigation_agent"]["mode"]
        for item in payload["incidents"]
    ]
    assert modes.count("tool_assisted_llm") == 1
    assert modes.count("tool_assisted_deterministic") == 1
