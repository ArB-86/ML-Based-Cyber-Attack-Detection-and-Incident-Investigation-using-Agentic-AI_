import json

import networkx as nx
import pandas as pd
import pytest

from attack_graph import agentic_investigator


def _incident(incident_id, event_id, score):
    return {
        "incident_id": incident_id,
        "event_ids": [event_id],
        "title": "Test candidate incident",
        "start_time": "2026-01-01T10:00:00+00:00",
        "end_time": "2026-01-01T10:00:00+00:00",
        "duration_seconds": 0.0,
        "total_flows": 1,
        "detection_reasons": ["ISOLATION_FOREST_ANOMALY"],
        "review_reasons": [],
        "context_signals": [],
        "status": "open",
        "triage": {
            "priority_score": score,
            "risk_score": score,
            "severity": "LOW",
            "confidence": "LOW",
            "confidence_basis": "Test fixture only.",
            "components": {},
        },
        "graph_analysis": {"priority_score": score},
        "timeline": [],
        "attack_hypotheses": [],
        "recommended_actions": [],
    }


def test_run_can_investigate_an_explicitly_selected_incident(tmp_path, monkeypatch):
    incidents = [
        _incident("INC-HIGH", "EVT-1", 90.0),
        _incident("INC-SELECTED", "EVT-2", 40.0),
    ]
    (tmp_path / "incident_investigation.json").write_text(
        json.dumps({"incidents": incidents}), encoding="utf-8"
    )
    pd.DataFrame([
        {
            "event_id": "EVT-1", "start_time": "2026-01-01T10:00:00Z",
            "end_time": "2026-01-01T10:00:00Z", "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2", "protocol": 6, "flow_count": 1,
        },
        {
            "event_id": "EVT-2", "start_time": "2026-01-01T10:01:00Z",
            "end_time": "2026-01-01T10:01:00Z", "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4", "protocol": 6, "flow_count": 1,
        },
    ]).to_csv(tmp_path / "attack_events.csv", index=False)

    graph = nx.DiGraph()
    for incident, event_id in zip(incidents, ["EVT-1", "EVT-2"]):
        incident_node = f"incident:{incident['incident_id']}"
        event_node = f"event:{event_id}"
        graph.add_node(incident_node, node_type="incident")
        graph.add_node(event_node, node_type="event")
        graph.add_edge(incident_node, event_node, relation="contains")
    nx.write_gexf(graph, tmp_path / "attack_graph.gexf")

    investigated = []

    class FakeAgent:
        def __init__(self, tools, reasoner=None):
            self.tools = tools

        def investigate(self, incident_id):
            investigated.append(incident_id)
            return {
                "agent": "AgenticInvestigationAgent",
                "mode": "tool_assisted",
                "status": "completed",
                "reasoner_error": None,
                "reasoner_calls": [],
                "llm_tool_rounds": 0,
                "llm_tool_requests": 0,
                "llm_tool_calls_executed": 0,
                "tool_calls": [],
                "findings": [],
                "recommended_actions": [],
                "model_findings_accepted": 0,
                "model_findings_rejected": 0,
            }

    monkeypatch.setattr(agentic_investigator, "AgenticInvestigationAgent", FakeAgent)
    monkeypatch.setattr(agentic_investigator, "_write_report", lambda *args, **kwargs: None)

    result = agentic_investigator.run(
        tmp_path,
        max_incidents=1,
        incident_id="INC-SELECTED",
    )

    assert investigated == ["INC-SELECTED"]
    assert result["processed_incident_count"] == 1
    assert result["processed_incidents"][0]["incident_id"] == "INC-SELECTED"
    saved = json.loads((tmp_path / "incident_investigation.json").read_text(encoding="utf-8"))
    by_id = {item["incident_id"]: item for item in saved["incidents"]}
    assert by_id["INC-HIGH"]["investigation_agent"]["status"] == "skipped_by_limit"
    assert by_id["INC-SELECTED"]["investigation_agent"]["status"] == "completed"


def test_run_rejects_unknown_explicit_incident_id(tmp_path):
    (tmp_path / "incident_investigation.json").write_text(
        json.dumps({"incidents": []}), encoding="utf-8"
    )
    pd.DataFrame(columns=[
        "event_id", "start_time", "end_time", "src_ip", "dst_ip", "protocol", "flow_count"
    ]).to_csv(tmp_path / "attack_events.csv", index=False)
    nx.write_gexf(nx.DiGraph(), tmp_path / "attack_graph.gexf")

    with pytest.raises(KeyError, match="Unknown incident_id"):
        agentic_investigator.run(tmp_path, incident_id="INC-MISSING")
