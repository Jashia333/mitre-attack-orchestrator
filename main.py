# main.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
from graph import build_graph, PipelineState

app = FastAPI(title="MITRE Attack Orchestrator")
graph = build_graph()

class EventIn(BaseModel):
    event: Dict[str, Any]

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ingest")
def ingest(evt: EventIn):
    # pass plain dict to the graph
    state_in = PipelineState(event=evt.event, alert=None).model_dump()
    out = graph.invoke(state_in)          # <-- returns a dict
    alert = out.get("alert")              # dict with our Alert fields
    return {"ok": True, "alert": alert}
