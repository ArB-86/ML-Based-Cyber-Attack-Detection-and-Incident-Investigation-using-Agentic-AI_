"""Plain-language views of evidence-backed SOC investigation records.

This module has no Streamlit dependency so explanation logic can be tested
independently from the UI.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


SIGNAL_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "BRUTE_FORCE_PATTERN": (
        "Repeated authentication-service traffic",
        "The behavioural detector observed a repeated network-flow pattern on an authentication-related service. Flow records do not reveal whether any login succeeded.",
    ),
    "ISOLATION_FOREST_ANOMALY": (
        "Unusual network-flow behaviour",
        "Isolation Forest marked these flows as unusual compared with benign traffic patterns learned during training. An anomaly is a reason to investigate, not proof of an attack.",
    ),
    "PORT_SCAN": (
        "Possible port-scanning activity (review only)",
        "A secondary review heuristic matched a port-scan-like pattern. Confirm whether the source was an authorised scanner before treating it as suspicious.",
    ),
    "HIGH_SOURCE_FANOUT": (
        "One source contacted many destinations (context)",
        "This describes a broad communication pattern. It can occur during legitimate operations and is not an attack verdict by itself.",
    ),
    "HORIZONTAL_SCAN": (
        "Similar activity across multiple destinations (context)",
        "The pattern may be consistent with broad probing, but network-flow data alone cannot establish intent.",
    ),
    "DISTRIBUTED_DOS_PATTERN": (
        "Traffic pattern resembles distributed service pressure (context)",
        "This is a contextual signal only. Confirm service impact and source distribution with network and service telemetry.",
    ),
}

PLAN_LABELS: dict[str, str] = {
    "retrieve_incident_context": "Load incident details and risk assessment",
    "inspect_chronological_event_timeline": "Review the event timeline",
    "inspect_correlated_graph_neighborhood": "Inspect connected events in the attack graph",
    "cross_check_detection_provenance": "Check which detectors contributed evidence",
    "select_additional_read_only_tools": "Select relevant read-only investigation tools",
    "validate_finding_event_references": "Validate every proposed event reference",
    "synthesise_evidence_linked_findings": "Prepare an evidence-linked investigation summary",
}

TOOL_LABELS: dict[str, str] = {
    "get_incident": "Read incident context",
    "get_timeline": "Read chronological events",
    "get_graph_neighborhood": "Inspect connected graph events",
    "get_detection_evidence": "Check detector evidence",
    "get_event": "Inspect a specific event",
    "get_host_activity": "Inspect activity for a host",
    "get_service_activity": "Inspect activity for a service/port",
    "get_correlated_events": "Inspect exact event relationships",
}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _event_id(value: Any) -> str:
    return str(value or "").removeprefix("event:").strip()


def _event_map(incident: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("event_id")): item
        for item in _as_list(incident.get("timeline"))
        if isinstance(item, dict) and item.get("event_id") is not None
    }


def format_timestamp(value: Any) -> str:
    """Format an ISO timestamp as a readable UTC time without changing it."""
    if not value:
        return "Time not recorded"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")
    except (TypeError, ValueError):
        return str(value)


def protocol_name(value: Any) -> str:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        text = str(value or "Unknown").strip()
        return text.upper() if text.lower() in {"tcp", "udp", "icmp"} else text
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(number, f"IP protocol {number}")


def port_text(event: dict[str, Any] | None) -> str:
    if not event:
        return "Not recorded"
    ports = event.get("ports", event.get("dst_ports", []))
    if isinstance(ports, str):
        try:
            import ast
            ports = ast.literal_eval(ports)
        except (SyntaxError, ValueError):
            ports = [ports] if ports.strip() else []
    if not isinstance(ports, (list, tuple, set)):
        ports = [ports] if ports not in (None, "") else []
    cleaned: list[str] = []
    for port in ports:
        text = str(port).strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return ", ".join(cleaned) if cleaned else "Not recorded"


def validated_ai_findings(incident: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only LLM findings that passed the independent semantic gate."""
    investigation = incident.get("investigation_agent") or {}
    accepted: list[dict[str, Any]] = []
    for finding in _as_list(investigation.get("findings")):
        if not isinstance(finding, dict):
            continue
        validation = finding.get("semantic_validation") or {}
        if (
            finding.get("source") == "llm_semantic_validated"
            and validation.get("status") == "passed"
            and finding.get("claim_semantics_independently_verified") is True
        ):
            accepted.append(finding)
    return accepted


def explain_detection_signals(incident: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """Explain primary detections separately from review/context indicators."""
    result: dict[str, list[dict[str, str]]] = {}
    for category, field in (
        ("Detected by the pipeline", "detection_reasons"),
        ("Secondary review indicators", "review_reasons"),
        ("Context only - not standalone detections", "context_signals"),
    ):
        cards = []
        for raw in _as_list(incident.get(field)):
            code = str(raw)
            label, explanation = SIGNAL_EXPLANATIONS.get(
                code,
                (code.replace("_", " ").title(), "This signal was recorded in the incident evidence. Review supporting event records before drawing a conclusion."),
            )
            cards.append({"code": code, "label": label, "explanation": explanation})
        result[category] = cards
    return result


def build_pivot_sequences(
    finding: dict[str, Any], event_lookup: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Turn each exact validated graph edge into a readable flow sequence."""
    rows: list[dict[str, Any]] = []
    for edge in _as_list(finding.get("evidence_edges")):
        if not isinstance(edge, dict):
            continue
        source_id = _event_id(edge.get("from", edge.get("from_event")))
        target_id = _event_id(edge.get("to", edge.get("to_event")))
        source = event_lookup.get(source_id, {})
        target = event_lookup.get(target_id, {})
        pivot = str(edge.get("pivot_host") or "Unknown host")
        gap = edge.get("gap_seconds")
        try:
            gap_seconds: float | None = float(gap) if gap is not None else None
        except (TypeError, ValueError):
            gap_seconds = None
        rows.append({
            "pivot_host": pivot,
            "from_event_id": source_id,
            "from_time": format_timestamp(source.get("timestamp", source.get("start_time"))),
            "incoming_source": str(source.get("source", source.get("src_ip", "Unknown"))),
            "incoming_destination": str(source.get("destination", source.get("dst_ip", pivot))),
            "incoming_protocol": protocol_name(source.get("protocol")),
            "incoming_ports": port_text(source),
            "incoming_flows": source.get("flows", source.get("flow_count", "Not recorded")),
            "to_event_id": target_id,
            "to_time": format_timestamp(target.get("timestamp", target.get("start_time"))),
            "outgoing_source": str(target.get("source", target.get("src_ip", pivot))),
            "outgoing_destination": str(target.get("destination", target.get("dst_ip", "Unknown"))),
            "outgoing_protocol": protocol_name(target.get("protocol")),
            "outgoing_ports": port_text(target),
            "outgoing_flows": target.get("flows", target.get("flow_count", "Not recorded")),
            "gap_seconds": gap_seconds,
            "relation": str(edge.get("relation", "host_pivot")),
        })
    return rows


def build_plain_language_sequence(row: dict[str, Any]) -> str:
    """Explain one graph edge using its source event records, not LLM prose."""
    pivot = row.get("pivot_host", "the host")
    gap = row.get("gap_seconds")
    gap_text = f"{gap:g} seconds" if isinstance(gap, (int, float)) else "an unrecorded interval"
    incoming_count = row.get("incoming_flows", "an unknown number of")
    outgoing_count = row.get("outgoing_flows", "an unknown number of")
    incoming_word = "flow" if str(incoming_count) == "1" else "flows"
    outgoing_word = "flow" if str(outgoing_count) == "1" else "flows"
    return (
        f"Event {row.get('from_event_id')} records {incoming_count} network {incoming_word} "
        f"from {row.get('incoming_source')} to {pivot} over {row.get('incoming_protocol')} "
        f"port(s) {row.get('incoming_ports')}. The graph links it to event "
        f"{row.get('to_event_id')}, which records {outgoing_count} network {outgoing_word} "
        f"from {row.get('outgoing_source')} to {row.get('outgoing_destination')} over "
        f"{row.get('outgoing_protocol')} port(s) {row.get('outgoing_ports')}; the recorded "
        f"gap is {gap_text}. This is a connected network-flow sequence, not proof that "
        f"a remote login or lateral movement succeeded."
    )


def build_incident_explanation(incident: dict[str, Any]) -> dict[str, Any]:
    """Create a compact, analyst-readable explanation from stored evidence."""
    graph = incident.get("graph_analysis") or {}
    triage = incident.get("triage") or {}
    detections = explain_detection_signals(incident)
    primary_labels = [item["label"] for item in detections["Detected by the pipeline"]]
    review_labels = [item["label"] for item in detections["Secondary review indicators"]]
    event_count = len(_as_list(incident.get("event_ids")))
    flow_count = int(incident.get("total_flows") or 0)
    source_count = int(graph.get("unique_sources") or 0)
    target_count = int(graph.get("unique_targets") or 0)
    event_links = int(graph.get("graph_event_links") or 0)
    pivot_count = len(_as_list(graph.get("pivot_hosts")))

    if primary_labels:
        detection_sentence = "The pipeline raised this incident because " + " and ".join(
            label.lower() for label in primary_labels
        ) + "."
    else:
        detection_sentence = "The incident was imported from upstream records; no primary detector reason is recorded."

    summary = (
        f"{detection_sentence} The incident contains {event_count:,} correlated event(s) "
        f"representing {flow_count:,} network flow(s), observed from "
        f"{format_timestamp(incident.get('start_time'))} to "
        f"{format_timestamp(incident.get('end_time'))}. Across these events, the graph "
        f"records {source_count} source host(s), {target_count} destination host(s), "
        f"and {event_links} event-to-event relationship(s), including host-pivot "
        f"relationships involving {pivot_count} host(s)."
    )

    return {
        "summary": summary,
        "event_count": event_count,
        "flow_count": flow_count,
        "source_count": source_count,
        "target_count": target_count,
        "event_links": event_links,
        "pivot_host_count": pivot_count,
        "severity": str(triage.get("severity", "UNASSIGNED")),
        "priority_score": triage.get("priority_score", triage.get("risk_score")),
        "confidence": str(triage.get("confidence", "UNKNOWN")),
        "confidence_basis": str(triage.get("confidence_basis", "Not recorded.")),
        "detections": detections,
        "review_labels": review_labels,
        "ai_findings": validated_ai_findings(incident),
    }


def investigation_steps(investigation: dict[str, Any]) -> list[dict[str, str]]:
    steps: list[dict[str, str]] = []
    for plan_item in _as_list(investigation.get("plan")):
        key = str(plan_item)
        steps.append({"step": PLAN_LABELS.get(key, key.replace("_", " ").title()), "status": "Recorded in agent plan"})
    if not steps:
        steps = [
            {"step": "Load incident and evidence", "status": "Completed"},
            {"step": "Inspect timeline, graph and detector evidence", "status": "Completed"},
            {"step": "Validate findings against evidence", "status": "See validation result"},
        ]
    return steps


def readable_tool_trace(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for call in _as_list(investigation.get("tool_calls")):
        if not isinstance(call, dict):
            continue
        tool = str(call.get("tool", "unknown"))
        rows.append({
            "Action": TOOL_LABELS.get(tool, tool.replace("_", " ").title()),
            "Status": str(call.get("status", "unknown")).replace("_", " ").title(),
            "Evidence references": ", ".join(_as_list(call.get("evidence_refs"))[:8]) or "Not recorded",
        })
    return rows


def build_finding_explanation(
    finding: dict[str, Any], event_lookup: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Return a UI-neutral, analyst-readable representation of one validated claim."""
    sequences = build_pivot_sequences(finding, event_lookup)
    return {
        "title": (
            f"Potential pivot host: {sequences[0]['pivot_host']}"
            if sequences else str(finding.get("claim_type") or "Validated investigation finding").replace("_", " ").title()
        ),
        "claim": str(finding.get("claim", "")),
        "confidence": str(finding.get("confidence", "unknown")),
        "evidence_event_ids": [_event_id(value) for value in _as_list(finding.get("evidence_event_ids"))],
        "excluded_event_ids": [_event_id(value) for value in _as_list(finding.get("excluded_event_ids"))],
        "sequences": [
            {**row, "plain_language_explanation": build_plain_language_sequence(row)}
            for row in sequences
        ],
        "interpretation": (
            "The graph shows a directed relationship between two network-flow events involving this host. "
            "This is a lead for further investigation, not proof of a successful remote login, lateral movement or compromise."
        ),
    }


def build_agentic_incident_output(incident: dict[str, Any]) -> dict[str, Any]:
    """Build the complete, UI-neutral AI investigation result for one incident."""
    investigation = incident.get("investigation_agent") or {}
    base = build_incident_explanation(incident)
    event_lookup = _event_map(incident)
    findings = [
        build_finding_explanation(item, event_lookup)
        for item in validated_ai_findings(incident)
    ]
    steps = investigation_steps(investigation)
    trace = readable_tool_trace(investigation)
    actions = _as_list(incident.get("recommended_actions")) or _as_list(
        investigation.get("recommended_actions")
    )
    return {
        "incident_id": str(incident.get("incident_id", "")),
        "incident_title": str(incident.get("title", "Security incident")),
        "status": str(investigation.get("status", "not_run")),
        "mode": str(investigation.get("mode", "not_run")),
        "reasoner_execution_status": investigation.get("reasoner_execution_status"),
        "model_synthesis_status": investigation.get("model_synthesis_status"),
        "model_synthesis_successful": investigation.get("model_synthesis_successful") is True,
        "reasoner_calls": _as_list(investigation.get("reasoner_calls")),
        "llm_tool_requests": int(investigation.get("llm_tool_requests", 0) or 0),
        "llm_tool_calls_executed": int(investigation.get("llm_tool_calls_executed", 0) or 0),
        "observed_window": {
            "start_utc": format_timestamp(incident.get("start_time")),
            "end_utc": format_timestamp(incident.get("end_time")),
        },
        "incident_overview": base,
        "what_happened": base["summary"],
        "detection_explanations": base["detections"],
        "investigation_steps": steps,
        "tool_trace": trace,
        "validated_findings": findings,
        "finding_counts": {
            "proposed": int(investigation.get("model_findings_proposed", 0) or 0),
            "accepted": int(investigation.get("model_findings_accepted", 0) or 0),
            "rejected": int(investigation.get("model_findings_rejected", 0) or 0),
        },
        "analyst_next_steps": [str(item) for item in actions],
        "not_established": [
            "Successful authentication or login",
            "Credential compromise",
            "Remote process execution or lateral movement",
            "Endpoint compromise, data access or exfiltration",
        ],
        "model_narrative_unverified": (
            str(investigation.get("model_narrative"))
            if investigation.get("model_narrative") else None
        ),
        "limitations": (
            "The input contains network-flow telemetry. Findings are investigation leads and require "
            "corroboration using identity/authentication, firewall, DNS, application and EDR telemetry."
        ),
    }


def render_agentic_incident_markdown(result: dict[str, Any]) -> str:
    """Render the analyst-facing AI output as Markdown; no UI framework required."""
    overview = result["incident_overview"]
    lines = [
        f"# AI Investigation Result — {result['incident_id']}",
        "",
        f"**Incident:** {result['incident_title']}  ",
        f"**Status:** {result['status']}  ",
        f"**Investigation mode:** {result['mode']}  ",
        f"**Observed window:** {result['observed_window']['start_utc']} to {result['observed_window']['end_utc']}",
        "",
        "## 1. Executive explanation",
        "",
        result["what_happened"],
        "",
        f"**Priority:** {overview['severity']}  ",
        f"**Triage score:** {overview['priority_score']}/100 (analyst-priority heuristic, not compromise probability)  ",
        f"**Triage confidence:** {overview['confidence']} — {overview['confidence_basis']}",
        "",
        "## 2. Why the incident was raised",
        "",
    ]
    for category, cards in result["detection_explanations"].items():
        if not cards:
            continue
        lines.extend([f"### {category}", ""])
        for card in cards:
            lines.append(f"- **{card['label']}** ({card['code']}): {card['explanation']}")
        lines.append("")
    lines.extend(["## 3. What the AI investigator did", ""])
    for index, step in enumerate(result["investigation_steps"], start=1):
        lines.append(f"{index}. {step['step']}")
    lines.extend(["", "### Evidence tools used", ""])
    if result["tool_trace"]:
        lines.extend([
            "| Analyst-readable action | Result | Evidence references |",
            "|---|---|---|",
        ])
        for row in result["tool_trace"]:
            lines.append(
                f"| {row['Action']} | {row['Status']} | {row['Evidence references']} |"
            )
    else:
        lines.append("No tool-call trace was recorded.")
    lines.extend(["", "## 4. What the AI found", ""])
    findings = result["validated_findings"]
    if not findings:
        lines.append(
            "No model-generated finding passed independent validation. This is not proof that the incident is benign."
        )
    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### Finding {index}: {finding['title']}",
            "",
            f"**Confidence:** {finding['confidence'].title()}  ",
            f"**AI conclusion:** {finding['claim']}",
            "",
            "**What the underlying network records show:**",
            "",
        ])
        if finding["sequences"]:
            for sequence_index, sequence in enumerate(finding["sequences"], start=1):
                lines.extend([
                    f"{sequence_index}. {sequence['plain_language_explanation']}",
                    f"   - Supporting events: {sequence['from_event_id']} → {sequence['to_event_id']}.",
                ])
        else:
            lines.append(
                "The stored finding did not include a graph-edge sequence to expand. "
                f"Evidence events: {', '.join(finding['evidence_event_ids']) or 'not recorded'}."
            )
        lines.extend([
            "",
            f"**Evidence event IDs:** {', '.join(finding['evidence_event_ids']) or 'Not recorded'}",
        ])
        if finding["excluded_event_ids"]:
            lines.append(
                f"**References excluded by validation:** {', '.join(finding['excluded_event_ids'])}"
            )
        lines.extend(["", f"**Interpretation:** {finding['interpretation']}", ""])
    lines.extend(["## 5. What the SOC analyst should do next", ""])
    if result["analyst_next_steps"]:
        lines.extend(
            f"{index}. {action}"
            for index, action in enumerate(result["analyst_next_steps"], start=1)
        )
    else:
        lines.append("Review the event evidence and corroborate it using independent telemetry.")
    lines.extend([
        "",
        "## 6. What this investigation does not prove",
        "",
        "The available network-flow records do not establish:",
        "",
    ])
    lines.extend(f"- {item}" for item in result["not_established"])
    lines.extend([
        "",
        f"> **Evidence boundary:** {result['limitations']}",
        "",
        "## 7. AI execution and validation",
        "",
        f"- Reasoner phases: {len(result['reasoner_calls'])}",
        f"- Reasoner execution: {result['reasoner_execution_status'] or 'Not recorded'}",
        f"- Model synthesis: {result['model_synthesis_status'] or 'Not recorded'}",
        f"- Findings proposed / accepted / rejected: {result['finding_counts']['proposed']} / {result['finding_counts']['accepted']} / {result['finding_counts']['rejected']}",
        f"- LLM tool requests / executed: {result['llm_tool_requests']} / {result['llm_tool_calls_executed']}",
        "",
        "Only independently validated findings are shown in Section 4.",
        "",
    ])
    if result["model_narrative_unverified"]:
        lines.extend([
            "## Appendix: Model narrative",
            "",
            "> This is the model's narrative context. Validated conclusions are listed separately above.",
            "",
            str(result["model_narrative_unverified"]).replace("\n", "\n> "),
            "",
        ])
    return "\n".join(lines)


def write_agentic_investigation_outputs(
    output_dir: str, incidents: list[dict[str, Any]]
) -> dict[str, str]:
    """Write UI-neutral, selected-incident Markdown and JSON outputs."""
    import json
    from pathlib import Path

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    results = [build_agentic_incident_output(item) for item in incidents]
    payload = {
        "schema_version": "1.0",
        "stage": "agentic_ai_investigation",
        "incident_count": len(results),
        "incidents": results,
    }
    json_path = output_path / "agentic_investigation_explanation.json"
    markdown_path = output_path / "agentic_investigation_report.md"
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    reports = [render_agentic_incident_markdown(item) for item in results]
    markdown_path.write_text(
        "\n\n---\n\n".join(reports) + ("\n" if reports else ""),
        encoding="utf-8",
    )
    return {"json": str(json_path), "markdown": str(markdown_path)}
