# agents/prioritize.py
from storage.schema import Alert

def score(alert: Alert) -> Alert:
    s = 0.0

    # Detection signalgit 
    if alert.detection.label == "malicious":
        s += 0.6
    elif alert.detection.label == "suspicious":
        s += 0.35

    # OSINT signal
    if any(f.reputation == "malicious" for f in alert.osint.values()):
        s += 0.2

   

    alert.severity = (
        "critical" if s >= 0.8 else
        "high"     if s >= 0.6 else
        "medium"   if s >= 0.4 else
        "low"
    )
    return alert
