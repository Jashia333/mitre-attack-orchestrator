# app_gradio.py
# Run: uv run app_gradio.py   (or)   python app_gradio.py

import json
from collections import deque
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import gradio as gr
import pandas as pd

from graph import build_graph, PipelineState  # your existing code

# ---------- build pipeline once ----------
graph = build_graph()
alerts_db: deque[Dict[str, Any]] = deque(maxlen=200)  # rolling history


def _to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "model_dump"):  # Pydantic v2
        return obj.model_dump()
    if hasattr(obj, "dict"):        # Pydantic v1
        return obj.dict()
    if isinstance(obj, dict):
        return obj
    return json.loads(json.dumps(obj, default=str))


def _mk_summary_md(a: Dict[str, Any]) -> str:
    det = a.get("detection", {}) or {}
    sev = (a.get("severity") or "low").lower()
    sev_color = {
        "low": "#9ca3af",
        "medium": "#f59e0b",
        "high": "#f97316",
        "critical": "#ef4444",
    }.get(sev, "#9ca3af")

    src_ip = a.get("raw", {}).get("src_ip", "—")
    user = a.get("raw", {}).get("user", "—")
    evt = a.get("raw", {}).get("event", "—")
    ts = a.get("ts", "—")

    reason = det.get("reason", "—")
    label = det.get("label", "—")
    conf = det.get("confidence", "—")

    return f"""
<div style="border:1px solid #1f2b4a;border-radius:14px;padding:14px;background:#0f1730">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <div>
      <div style="font-size:18px;font-weight:600;margin-bottom:2px">Alert Summary</div>
      <div style="opacity:.8">Event time: <code>{ts}</code></div>
    </div>
    <div style="background:{sev_color}22;color:{sev_color};padding:4px 10px;border-radius:999px;font-weight:600">
      Severity: {sev.upper()}
    </div>
  </div>

  <div style="margin-top:12px">
    <div><b>Event:</b> {evt}</div>
    <div><b>User:</b> {user} &nbsp; | &nbsp; <b>Source IP:</b> <code>{src_ip}</code></div>
  </div>

  <div style="margin-top:12px">
    <div style="font-weight:600;margin-bottom:4px">Detection</div>
    <div><b>Label:</b> {label} &nbsp;&nbsp; <b>Confidence:</b> {conf}</div>
    <div style="opacity:.9;margin-top:6px">{reason}</div>
  </div>
</div>
"""


def _mk_iocs_df(a: Dict[str, Any]) -> pd.DataFrame:
    rows = a.get("iocs") or []
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["type", "value"])


def _mk_mitre_df(a: Dict[str, Any]) -> pd.DataFrame:
    rows = a.get("mitre") or []
    cols = ["tactic", "technique_id", "technique"]
    return pd.DataFrame(rows)[cols] if rows else pd.DataFrame(columns=cols)


def _mk_osint_df(a: Dict[str, Any]) -> pd.DataFrame:
    osint = a.get("osint") or {}
    rows: List[Dict[str, Any]] = []
    for indicator, info in osint.items():
        info = info or {}
        rows.append(
            {
                "indicator": indicator,
                "reputation": info.get("reputation", "unknown"),
                "sources": ", ".join(info.get("sources", [])),
                "last_seen": info.get("last_seen", ""),
                "tags": ", ".join(info.get("tags", [])),
            }
        )
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["indicator", "reputation", "sources", "last_seen", "tags"])


def _mk_recent_df() -> pd.DataFrame:
    rows = []
    for a in list(alerts_db)[:10]:
        rows.append(
            {
                "time": a.get("ts", ""),
                "severity": a.get("severity", ""),
                "label": (a.get("detection") or {}).get("label", ""),
                "event": (a.get("raw") or {}).get("event", ""),
                "source_ip": (a.get("raw") or {}).get("src_ip", ""),
            }
        )
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["time", "severity", "label", "event", "source_ip"])


def build_event_payload(
    src_ip: str,
    user: str,
    event_text: str,
    file_path: Optional[str],
    destination_ip: Optional[str],
    url: Optional[str],
    email: Optional[str],
    ts_iso: Optional[str],
) -> Dict[str, Any]:
    """
    Build the JSON payload from form fields.
    Only includes optional fields if provided.
    """
    evt: Dict[str, Any] = {
        "src_ip": src_ip.strip(),
        "user": user.strip(),
        "event": event_text.strip(),
    }

    if file_path and file_path.strip():
        evt["file_path"] = file_path.strip()
    if destination_ip and destination_ip.strip():
        evt["destination_ip"] = destination_ip.strip()
    if url and url.strip():
        evt["url"] = url.strip()
    if email and email.strip():
        evt["email"] = email.strip()

    # timestamp: now (UTC) if not provided
    if ts_iso and ts_iso.strip():
        evt["ts"] = ts_iso.strip()
    else:
        evt["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {"event": evt}


def run_pipeline_from_fields(
    src_ip: str,
    user: str,
    event_text: str,
    file_path: str,
    destination_ip: str,
    url: str,
    email: str,
    ts_iso: str,
):
    """
    Gradio callback for the form-based inputs.
    """
    # quick required checks
    if not event_text.strip():
        md = "❌ <b>Please enter an Event description.</b>"
        empty = pd.DataFrame()
        return md, empty, empty, empty, empty
    if not src_ip.strip():
        md = "❌ <b>Please enter a Source IP (src_ip).</b>"
        empty = pd.DataFrame()
        return md, empty, empty, empty, empty

    data = build_event_payload(
        src_ip=src_ip,
        user=user,
        event_text=event_text,
        file_path=file_path,
        destination_ip=destination_ip,
        url=url,
        email=email,
        ts_iso=ts_iso,
    )

    try:
        state_in = PipelineState(event=data["event"], alert=None).model_dump()
        out = graph.invoke(state_in)
        alert = out.get("alert") if isinstance(out, dict) else None
        if alert is None:
            md = "❌ <b>Pipeline returned no <code>alert</code>.</b>"
            empty = pd.DataFrame()
            return md, empty, empty, empty, empty

        a = _to_dict(alert)
        alerts_db.appendleft(a)

        md = _mk_summary_md(a)
        iocs_df = _mk_iocs_df(a)
        mitre_df = _mk_mitre_df(a)
        osint_df = _mk_osint_df(a)
        recent_df = _mk_recent_df()
        return md, iocs_df, mitre_df, osint_df, recent_df

    except Exception as e:
        md = f"❌ <b>Error running pipeline:</b> {e}"
        empty = pd.DataFrame()
        return md, empty, empty, empty, empty


# ---------- UI ----------
with gr.Blocks(title="MITRE Attack Orchestrator Demo") as demo:
    gr.Markdown("## MITRE Attack Orchestrator Demo\nFill in the event attributes → get a **human-readable** alert report.")

    with gr.Row():
        with gr.Column(scale=5):
            with gr.Group():
                src_ip = gr.Textbox(label="Source IP (required)", placeholder="e.g. 203.0.113.45")
                user = gr.Textbox(label="User", placeholder="e.g. alice")
                event_text = gr.Textbox(label="Event (required)", lines=3, placeholder="e.g. MULTIPLE FAILED LOGIN ATTEMPTS")
                ts_iso = gr.Textbox(label="Timestamp (ISO 8601, optional)", placeholder="e.g. 2025-08-14T10:45:00Z")

            with gr.Accordion("Optional IOCs / Fields", open=False):
                file_path = gr.Textbox(label="File Path", placeholder=r"C:\Users\Public\confidential_report.pdf")
                destination_ip = gr.Textbox(label="Destination IP", placeholder="e.g. 198.51.100.200")
                url = gr.Textbox(label="URL", placeholder="e.g. https://example.com/login")
                email = gr.Textbox(label="Email", placeholder="e.g. user@example.org")

            btn_run = gr.Button("Run Detection", variant="primary")

        with gr.Column(scale=7):
            summary_md = gr.Markdown()
            gr.Markdown("### IOCs")
            iocs_df = gr.Dataframe(interactive=False, wrap=True, row_count=(0, "dynamic"))
            gr.Markdown("### MITRE ATT&CK")
            mitre_df = gr.Dataframe(interactive=False, wrap=True, row_count=(0, "dynamic"))
            gr.Markdown("### OSINT Enrichment")
            osint_df = gr.Dataframe(interactive=False, wrap=True, row_count=(0, "dynamic"))
            gr.Markdown("### Recent Alerts")
            recent_df = gr.Dataframe(interactive=False, wrap=True, row_count=(0, "dynamic"))

    btn_run.click(
        run_pipeline_from_fields,
        inputs=[src_ip, user, event_text, file_path, destination_ip, url, email, ts_iso],
        outputs=[summary_md, iocs_df, mitre_df, osint_df, recent_df],
    )


if __name__ == "__main__":
    # Use Gradio default port to avoid collision with FastAPI
    demo.launch(server_name="localhost", server_port=9000)
