# graph.py
from langgraph.graph import StateGraph, START, END
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime
import json, uuid

from storage.schema import Alert
from agents.detect import detect
from agents.ioc_extract import extract_iocs
from agents.osint import enrich as osint_enrich
from agents.mitre import mitre_map
from agents.prioritize import score
from storage.es import persist_alert

class PipelineState(BaseModel):
    event: Dict[str, Any]
    alert: Alert | None = None

def node_detect(state: PipelineState) -> PipelineState:
    det = detect(json.dumps(state.event))
    state.alert = Alert(
        event_id=str(uuid.uuid4()),
        ts=datetime.utcnow(),
        raw=state.event,
        detection=det,
        iocs=[],
        osint={},
        mitre=[],
        severity="low",
    )
    return state

def node_extract(state: PipelineState) -> PipelineState:
    state.alert.iocs = extract_iocs(json.dumps(state.event))
    return state

def node_osint(state: PipelineState) -> PipelineState:
    state.alert.osint = osint_enrich(state.alert.iocs)
    return state

def node_mitre(state: PipelineState) -> PipelineState:
    state.alert.mitre = mitre_map(state.alert.osint, state.alert.detection.reason)
    return state

def node_prioritize(state: PipelineState) -> PipelineState:
    state.alert = score(state.alert)
    return state

def node_persist(state: PipelineState) -> PipelineState:
    persist_alert(state.alert)
    return state

def build_graph():
    g = StateGraph(PipelineState)
    g.add_node("detect", node_detect)
    g.add_node("extract", node_extract)
    g.add_node("osint", node_osint)
    g.add_node("mitre", node_mitre)
    g.add_node("prioritize", node_prioritize)
    g.add_node("persist", node_persist)

    g.add_edge(START, "detect")
    g.add_edge("detect", "extract")
    g.add_edge("extract", "osint")
    g.add_edge("osint", "mitre")
    g.add_edge("mitre", "prioritize")
    g.add_edge("prioritize", "persist")
    g.add_edge("persist", END)
    return g.compile()
