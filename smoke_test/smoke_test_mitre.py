from agents.ioc_extract import extract_iocs
from agents.osint import enrich
from agents.mitre import mitre_map

event_text = "Multiple failed logins from 203.0.113.45 against VPN portal"
iocs = extract_iocs(event_text)
osint = enrich(iocs)
reason = "Multiple failed logins from same IP; likely brute-force"

mappings = mitre_map(osint, reason)
print([f"{m.technique_id}:{m.technique} ({m.tactic})" for m in mappings])
