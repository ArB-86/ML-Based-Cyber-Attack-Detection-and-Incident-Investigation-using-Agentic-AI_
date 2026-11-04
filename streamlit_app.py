"""SOC analyst workbench - human-readable Agentic AI investigation screen."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from attack_graph import ollama_reasoner
from attack_graph.agentic_investigator import run as run_agentic_investigation
from attack_graph.investigation_presentation import (
    build_incident_explanation,
    build_plain_language_sequence,
    build_pivot_sequences,
    format_timestamp,
    investigation_steps,
    readable_tool_trace,
    validated_ai_findings,
)


st.set_page_config(
    page_title="SOC Analyst Workbench | AI Investigation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container {padding-top: 1.6rem; padding-bottom: 2.5rem; max-width: 1500px;}
      .hero {padding: 1.25rem 1.4rem; border-radius: 14px; background: linear-gradient(120deg,#10243a,#173b58); color: white; margin-bottom: 1rem;}
      .hero p {color:#d7e6f3; margin-bottom:0;}
      .finding-title {font-weight:700; font-size:1.12rem;}
      div[data-testid="stMetric"] {background:#f4f7fb; border:1px solid #e4eaf1; padding:0.8rem 1rem; border-radius:12px;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def load_dossier(directory: str, dossier_mtime: float) -> dict[str, Any]:
    path = Path(directory) / "incident_investigation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("incidents"), list):
        raise ValueError("incident_investigation.json must contain an incidents array.")
    return payload


def priority_value(incident: dict[str, Any]) -> float:
    triage = incident.get("triage") or {}
    try:
        return float(triage.get("priority_score", triage.get("risk_score", 0.0)))
    except (TypeError, ValueError):
        return 0.0


def event_port_text(event: dict[str, Any]) -> str:
    ports = event.get("ports", [])
    return ", ".join(str(port) for port in ports) if isinstance(ports, list) and ports else "Not recorded"


def render_finding(finding: dict[str, Any], incident: dict[str, Any], index: int) -> None:
    host = "Unknown host"
    edges = finding.get("evidence_edges", [])
    if edges and isinstance(edges[0], dict):
        host = str(edges[0].get("pivot_host") or host)
    event_lookup = {
        str(event.get("event_id")): event
        for event in incident.get("timeline", [])
        if isinstance(event, dict) and event.get("event_id") is not None
    }
    sequences = build_pivot_sequences(finding, event_lookup)

    with st.container(border=True):
        left, right = st.columns([4, 1])
        with left:
            st.markdown(f"**{index}. Potential pivot host: {host}**")
            st.caption("The graph links traffic directed to this host with a separate event originating from the same host.")
        with right:
            st.warning(f"Confidence: {str(finding.get('confidence', 'unknown')).title()}")

        st.markdown("**What the evidence shows**")
        if not sequences:
            st.info("The finding passed semantic validation, but no event-level edge details were stored for display.")
        for sequence in sequences:
            st.write(build_plain_language_sequence(sequence))

        if sequences:
            table_rows = [{
                "Incoming event": row["from_event_id"],
                "Traffic into host": f"{row['incoming_source']} → {row['incoming_destination']}",
                "Inbound ports / flows": f"{row['incoming_ports']} / {row['incoming_flows']}",
                "Related event": row["to_event_id"],
                "Traffic from host": f"{row['outgoing_source']} → {row['outgoing_destination']}",
                "Outbound ports / flows": f"{row['outgoing_ports']} / {row['outgoing_flows']}",
                "Graph time gap": f"{row['gap_seconds']:g} sec" if row["gap_seconds"] is not None else "Unknown",
            } for row in sequences]
            st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

        excluded = finding.get("excluded_event_ids", [])
        if excluded:
            st.info("The validator excluded unsupported event reference(s): " + ", ".join(excluded))
        st.caption(
            "Validation: exact directed host-pivot edge check passed. This supports an investigation lead only; "
            "network flows do not prove successful login, remote execution, lateral movement or host compromise."
        )


def render_incident(incident: dict[str, Any]) -> None:
    investigation = incident.get("investigation_agent") or {}
    explanation = build_incident_explanation(incident)
    findings = validated_ai_findings(incident)

    st.markdown(
        '<div class="hero"><h2>AI-powered incident investigation</h2>'
        '<p>Understand what was detected, what the agent investigated, what the evidence supports, '
        'and what the analyst should check next.</p></div>',
        unsafe_allow_html=True,
    )
    st.title(f"{incident.get('incident_id', 'Incident')} · {incident.get('title', 'Security incident')}")
    st.caption(
        f"Observed window: {format_timestamp(incident.get('start_time'))} — "
        f"{format_timestamp(incident.get('end_time'))}"
    )

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Priority", explanation["severity"])
    score = explanation["priority_score"]
    m2.metric("Triage score", f"{float(score):.1f}/100" if score is not None else "Not scored")
    m3.metric("Events", f"{explanation['event_count']:,}")
    m4.metric("Network flows", f"{explanation['flow_count']:,}")
    m5.metric("AI findings validated", f"{len(findings)}")

    st.subheader("1. What happened?")
    st.write(explanation["summary"])
    if explanation["confidence_basis"]:
        st.info(f"**Why the incident has {explanation['confidence'].lower()} confidence:** {explanation['confidence_basis']}")
    st.caption("The triage score is an analyst-priority heuristic, not a probability that a host is compromised.")

    st.subheader("2. Why did the pipeline raise this incident?")
    for section, cards in explanation["detections"].items():
        if not cards:
            continue
        st.markdown(f"**{section}**")
        cols = st.columns(min(2, len(cards)))
        for idx, card in enumerate(cards):
            with cols[idx % len(cols)]:
                with st.container(border=True):
                    st.markdown(f"**{card['label']}**")
                    st.caption(card["code"])
                    st.write(card["explanation"])

    st.subheader("3. What did the AI investigator find?")
    st.caption("Only findings that passed independent semantic/evidence validation are shown here.")
    if findings:
        for idx, finding in enumerate(findings, start=1):
            render_finding(finding, incident, idx)
    else:
        st.warning(
            "No LLM finding passed validation for this incident. The evidence baseline remains available below; "
            "an empty finding list is not proof of benign activity."
        )

    with st.expander("Read the model's overall explanation", expanded=False):
        narrative = investigation.get("model_narrative") or investigation.get("narrative")
        if narrative:
            st.write(narrative)
            st.caption("This is narrative context. The finding cards above contain the claims independently checked against evidence.")
        else:
            st.write("No separate narrative was recorded by the reasoner.")

    st.subheader("4. What should the SOC analyst do next?")
    actions = incident.get("recommended_actions") or investigation.get("recommended_actions") or []
    if actions:
        for idx, action in enumerate(actions, start=1):
            st.markdown(f"**{idx}.** {action}")
    else:
        st.write("No specific action list was recorded. Review the evidence and corroborate it with independent telemetry.")

    st.subheader("5. What is not established by this evidence?")
    st.warning(
        "The available dataset contains network-flow records. It cannot confirm whether a login succeeded, "
        "credentials were compromised, a process executed remotely, data was accessed, or a host was compromised. "
        "Check identity/authentication and EDR telemetry before escalating or containing a host."
    )

    with st.expander("How the agent investigated", expanded=False):
        st.markdown("**Investigation plan**")
        for step in investigation_steps(investigation):
            st.markdown(f"- {step['step']}")
        st.markdown("**Read-only evidence-tool trace**")
        trace = readable_tool_trace(investigation)
        if trace:
            st.dataframe(pd.DataFrame(trace), use_container_width=True, hide_index=True)
        else:
            st.write("No tool-call trace recorded.")
        st.markdown("**Execution checks**")
        c1, c2, c3 = st.columns(3)
        c1.metric("Reasoner phases", len(investigation.get("reasoner_calls", [])))
        c2.metric("LLM tool requests", investigation.get("llm_tool_requests", 0))
        c3.metric("Tool calls executed", investigation.get("llm_tool_calls_executed", 0))
        st.caption(
            f"Mode: {investigation.get('mode', 'not run')} · "
            f"Reasoner: {investigation.get('reasoner_execution_status', 'not recorded')} · "
            f"Synthesis: {investigation.get('model_synthesis_status', 'not recorded')} · "
            f"Accepted/rejected: {investigation.get('model_findings_accepted', 0)}/"
            f"{investigation.get('model_findings_rejected', 0)}"
        )

    with st.expander("Inspect incident event timeline", expanded=False):
        timeline_rows = []
        for event in incident.get("timeline", []):
            if not isinstance(event, dict):
                continue
            timeline_rows.append({
                "Time (UTC)": format_timestamp(event.get("timestamp")),
                "Event ID": event.get("event_id"),
                "Source": event.get("source"),
                "Destination": event.get("destination"),
                "Protocol": event.get("protocol"),
                "Ports": event_port_text(event),
                "Flows": event.get("flows"),
                "Detection evidence": event.get("evidence"),
            })
        if timeline_rows:
            st.dataframe(pd.DataFrame(timeline_rows), use_container_width=True, hide_index=True)

    st.download_button(
        "Download this incident's investigation JSON",
        data=json.dumps(incident, indent=2, ensure_ascii=False, default=str),
        file_name=f"{incident.get('incident_id', 'incident')}_investigation.json",
        mime="application/json",
    )


# ---- Sidebar / data loading ----
st.sidebar.title("SOC analyst workbench")
st.sidebar.caption("Agentic AI investigation")
output_dir_text = st.sidebar.text_input(
    "Pipeline output folder",
    value="outputs/run_legacy_02908_agentic_merged",
)
output_dir = Path(output_dir_text).expanduser()
dossier_path = output_dir / "incident_investigation.json"
graph_path = output_dir / "attack_graph.gexf"
events_path = output_dir / "attack_events.csv"

if st.sidebar.button("Reload output files", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

if not output_dir.is_dir():
    st.error(f"Output folder not found: {output_dir.resolve()}")
    st.stop()
missing = [path.name for path in (dossier_path, graph_path, events_path) if not path.is_file()]
if missing:
    st.error("This folder is missing required upstream artefacts: " + ", ".join(missing))
    st.info("Select the pipeline output directory that contains attack_events.csv, attack_graph.gexf and incident_investigation.json.")
    st.stop()

try:
    payload = load_dossier(str(output_dir.resolve()), dossier_path.stat().st_mtime)
except Exception as exc:
    st.error(f"Could not load incident dossier: {type(exc).__name__}: {exc}")
    st.stop()

incidents = [item for item in payload["incidents"] if isinstance(item, dict)]
if not incidents:
    st.warning("No incidents are present in the selected output folder.")
    st.stop()
incidents.sort(key=lambda item: (priority_value(item), str(item.get("start_time", ""))), reverse=True)
incident_ids = [str(item.get("incident_id")) for item in incidents]
default_id = st.session_state.get("selected_incident_id")
if default_id not in incident_ids:
    default_id = "INC-02908" if "INC-02908" in incident_ids else incident_ids[0]

incident_lookup = {str(item.get("incident_id")): item for item in incidents}
selected_id = st.sidebar.selectbox(
    "Select incident",
    incident_ids,
    index=incident_ids.index(default_id),
    format_func=lambda value: (
        f"{value} · {incident_lookup[value].get('triage', {}).get('severity', 'N/A')} · "
        f"priority {priority_value(incident_lookup[value]):.1f}"
    ),
)
st.session_state["selected_incident_id"] = selected_id

st.sidebar.divider()
st.sidebar.markdown("**AI execution**")
st.sidebar.caption(
    "Runs only the selected incident. It does not rerun preprocessing, Isolation Forest, "
    "event generation, graph construction or risk scoring."
)
if st.sidebar.button("Run / re-run AI investigation", type="primary", use_container_width=True):
    try:
        with st.spinner("Checking Ollama and running the selected incident through the agent..."):
            ollama_reasoner.check_ollama()
            result = run_agentic_investigation(
                output_dir,
                reasoner=ollama_reasoner.reasoner,
                max_incidents=1,
                incident_id=selected_id,
            )
        st.cache_data.clear()
        st.session_state["selected_incident_id"] = selected_id
        st.sidebar.success(
            f"Completed {result['processed_incident_count']} incident(s). "
            f"Reasoner calls: {result['agent_reasoner_calls']}; "
            f"tool calls executed: {result['llm_tool_calls_executed']}."
        )
        st.rerun()
    except Exception as exc:
        st.sidebar.error(f"Investigation failed: {type(exc).__name__}: {exc}")

render_incident(selected)
