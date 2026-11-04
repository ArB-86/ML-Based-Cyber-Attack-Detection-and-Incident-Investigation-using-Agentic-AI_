from attack_graph.investigation_presentation import (
    build_incident_explanation,
    build_pivot_sequences,
    build_plain_language_sequence,
    explain_detection_signals,
    validated_ai_findings,
)


def _finding(source="llm_semantic_validated", status="passed"):
    return {
        "claim": "A directed host-pivot graph relationship exists.",
        "source": source,
        "confidence": "low",
        "claim_semantics_independently_verified": True,
        "semantic_validation": {"status": status},
        "evidence_edges": [{
            "from": "event:EVT-1",
            "to": "event:EVT-2",
            "relation": "host_pivot",
            "gap_seconds": 60.0,
            "pivot_host": "10.0.0.2",
        }],
        "evidence_event_ids": ["EVT-1", "EVT-2"],
    }


def _incident():
    return {
        "incident_id": "INC-TEST",
        "title": "Repeated authentication-related flow pattern requiring validation",
        "start_time": "2026-01-01T10:00:00+00:00",
        "end_time": "2026-01-01T10:05:00+00:00",
        "event_ids": ["EVT-1", "EVT-2"],
        "total_flows": 24,
        "detection_reasons": ["BRUTE_FORCE_PATTERN", "ISOLATION_FOREST_ANOMALY"],
        "review_reasons": ["PORT_SCAN"],
        "context_signals": ["HIGH_SOURCE_FANOUT"],
        "triage": {"severity": "MEDIUM", "priority_score": 63.9, "confidence": "MEDIUM"},
        "graph_analysis": {
            "unique_sources": 2, "unique_targets": 4,
            "graph_event_links": 3, "pivot_hosts": ["10.0.0.2"],
        },
        "timeline": [
            {
                "event_id": "EVT-1", "timestamp": "2026-01-01T10:00:00Z",
                "source": "10.0.0.1", "destination": "10.0.0.2",
                "protocol": "6.0", "ports": [139, 445], "flows": 12,
            },
            {
                "event_id": "EVT-2", "timestamp": "2026-01-01T10:01:00Z",
                "source": "10.0.0.2", "destination": "203.0.113.5",
                "protocol": "6.0", "ports": [443], "flows": 1,
            },
        ],
        "investigation_agent": {"findings": [_finding()]},
    }


def test_only_independently_validated_llm_findings_are_shown():
    incident = _incident()
    rejected = _finding(status="failed")
    deterministic = _finding(source="host_pivot")
    incident["investigation_agent"]["findings"].extend([rejected, deterministic])
    assert validated_ai_findings(incident) == [_finding()]


def test_pivot_evidence_is_rendered_as_readable_flow_sequence():
    incident = _incident()
    finding = validated_ai_findings(incident)[0]
    timeline = {item["event_id"]: item for item in incident["timeline"]}
    rows = build_pivot_sequences(finding, timeline)
    assert len(rows) == 1
    assert rows[0]["incoming_source"] == "10.0.0.1"
    assert rows[0]["incoming_destination"] == "10.0.0.2"
    assert rows[0]["outgoing_source"] == "10.0.0.2"
    assert rows[0]["outgoing_destination"] == "203.0.113.5"
    assert rows[0]["gap_seconds"] == 60.0
    sentence = build_plain_language_sequence(rows[0])
    assert "12 network flows" in sentence
    assert "not proof" in sentence


def test_signal_types_are_explained_separately():
    signals = explain_detection_signals(_incident())
    assert "Repeated authentication-service traffic" in signals["Detected by the pipeline"][0]["label"]
    assert signals["Secondary review indicators"][0]["code"] == "PORT_SCAN"
    assert "Context only - not standalone detections" in signals


def test_incident_summary_uses_incident_and_graph_counts():
    result = build_incident_explanation(_incident())
    assert result["event_count"] == 2
    assert result["flow_count"] == 24
    assert "2 correlated event(s)" in result["summary"]
    assert len(result["ai_findings"]) == 1



def test_ai_investigation_report_explains_incident_and_exact_graph_sequence(tmp_path):
    from attack_graph.investigation_presentation import write_agentic_investigation_outputs

    incident = _incident()
    incident["investigation_agent"].update({
        "status": "completed",
        "mode": "tool_assisted_llm",
        "reasoner_execution_status": "succeeded",
        "model_synthesis_status": "validated_findings",
        "model_synthesis_successful": True,
        "model_findings_proposed": 1,
        "model_findings_accepted": 1,
        "model_findings_rejected": 0,
        "reasoner_calls": [{"phase": "plan"}, {"phase": "followup"}, {"phase": "final"}],
        "llm_tool_requests": 2,
        "llm_tool_calls_executed": 1,
        "plan": ["retrieve_incident_context", "inspect_chronological_event_timeline"],
        "tool_calls": [{
            "tool": "get_correlated_events",
            "status": "success",
            "evidence_refs": ["EVT-1", "EVT-2"],
        }],
        "recommended_actions": ["Review authentication success/failure logs for the incident window."],
    })
    paths = write_agentic_investigation_outputs(str(tmp_path), [incident])

    import json
    payload = json.loads((tmp_path / "agentic_investigation_explanation.json").read_text(encoding="utf-8"))
    report = (tmp_path / "agentic_investigation_report.md").read_text(encoding="utf-8")

    assert paths["markdown"].endswith("agentic_investigation_report.md")
    assert payload["incident_count"] == 1
    result = payload["incidents"][0]
    assert result["validated_findings"][0]["sequences"][0]["incoming_source"] == "10.0.0.1"
    assert result["validated_findings"][0]["sequences"][0]["outgoing_destination"] == "203.0.113.5"
    assert "## 1. Executive explanation" in report
    assert "Repeated authentication-service traffic" in report
    assert "10.0.0.1 to 10.0.0.2" in report
    assert "successful remote login" in report
    assert "Review authentication success/failure logs" in report
    assert "Reasoner phases: 3" in report
