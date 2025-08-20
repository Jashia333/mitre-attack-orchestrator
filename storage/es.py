# storage/es.py
import json, time
from storage.schema import Alert

def persist_alert(alert: Alert) -> None:
    # Replace with Elasticsearch/OpenSearch later.
    print("[ALERT]", json.dumps(alert.model_dump(), default=str)[:600])
    time.sleep(0.01)  # tiny IO-sim delay
