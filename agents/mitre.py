# agents/mitre.py
from __future__ import annotations
from typing import List, Dict
from storage.schema import MitreMapping, OSINTFinding

# Minimal mapping rules. Expand as you add detections.
RULES = [
    # Credential Access
    ({"tags": {"brute-force"}}, {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}),
    ({"reason_contains": ["password spray", "credential stuffing"]},
     {"tactic": "Credential Access", "technique_id": "T1110.003", "technique": "Password Spraying"}),

    # Initial Access (phishing)
    ({"reason_contains": ["phish", "spearphish", "malicious attachment"]},
     {"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Spearphishing Attachment"}),
    ({"reason_contains": ["link click", "phishing link"]},
     {"tactic": "Initial Access", "technique_id": "T1566.002", "technique": "Spearphishing Link"}),

    # Lateral Movement
    ({"reason_contains": ["lateral", "remote service", "psexec", "winrm", "smb"]},
     {"tactic": "Lateral Movement", "technique_id": "T1021", "technique": "Remote Services"}),

    # Persistence
    ({"reason_contains": ["registry run key", "startup folder", "scheduled task"]},
     {"tactic": "Persistence", "technique_id": "T1060", "technique": "Registry Run Keys / Startup Folder"}),

    # Exfiltration
    ({"reason_contains": ["exfiltration", "data exfil", "large outbound"]},
     {"tactic": "Exfiltration", "technique_id": "T1041", "technique": "Exfiltration Over C2 Channel"}),
]

def mitre_map(osint: Dict[str, OSINTFinding], detection_reason: str) -> List[MitreMapping]:
    """Map OSINT tags and the detector's reason text to MITRE techniques."""
    # gather lowercase tags
    tags = set()
    for v in osint.values():
        for t in v.tags:
            tags.add(t.lower())

    reason = (detection_reason or "").lower()
    out: List[MitreMapping] = []

    for cond, mapping in RULES:
        ok = True
        want_tags = cond.get("tags")
        if want_tags and not want_tags.issubset(tags):
            ok = False
        substrs = cond.get("reason_contains")
        if ok and substrs and not any(s in reason for s in substrs):
            ok = False
        if ok:
            out.append(MitreMapping(**mapping))

    # dedupe by technique_id
    seen, uniq = set(), []
    for m in out:
        if m.technique_id not in seen:
            seen.add(m.technique_id); uniq.append(m)
    return uniq
