# tests/e2e_smoke.py
import json, sys, time
import requests

BASE = "http://localhost:8080"

def must(ok, msg):
    if not ok:
        print("[FAIL]", msg)
        sys.exit(1)

def main():
    # 1) health
    r = requests.get(f"{BASE}/health", timeout=5)
    must(r.ok and r.json().get("ok") is True, "health failed")

    # 2) ingest
    payload = {
        "event": {
            "src_ip": "203.0.113.45",
            "event": "multiple failed logins",
            "user": "alice",
            "ts": "2025-08-13T20:10:00Z"
        }
    }
    r = requests.post(f"{BASE}/ingest", json=payload, timeout=15)
    must(r.ok, f"/ingest status={r.status_code} body={r.text[:300]}")
    j = r.json()
    alert = j.get("alert", {})
    must(j.get("ok") is True and alert, "missing alert")

    # Basic assertions
    det = alert.get("detection", {})
    iocs = alert.get("iocs", [])
    osint = alert.get("osint", {})
    mitre = alert.get("mitre", [])
    sev = alert.get("severity")

    must(det.get("label") in {"benign","suspicious","malicious"}, "bad detection label")
    must(any(i.get("type")=="ip" for i in iocs), "no IP IOC found")
    must("203.0.113.45" in osint, "osint missing IP key")
    must(any(m.get("technique_id")=="T1110" for m in mitre), "MITRE T1110 not mapped")
    must(sev in {"low","medium","high","critical"}, "bad severity")

    print("[OK] e2e smoke passed")
    print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    main()
