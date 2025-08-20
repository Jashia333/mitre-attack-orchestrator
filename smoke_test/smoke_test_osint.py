from agents.ioc_extract import extract_iocs
from agents.osint import enrich

s = "Failed logins from 203.0.113.45 against https://example.com/login; contact secops@example.org"
iocs = extract_iocs(s)
enriched = enrich(iocs)

print("IOCs:", [f"{i.type}:{i.value}" for i in iocs])
for k, v in enriched.items():
    print(k, "=>", v.model_dump())
