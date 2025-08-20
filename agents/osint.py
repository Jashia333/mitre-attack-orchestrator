# agents/osint.py
from __future__ import annotations
from typing import Dict
from datetime import datetime, timedelta

from storage.schema import IOC, OSINTFinding

# Simple in-memory cache: {ioc_value: (finding, expires_at)}
_CACHE: Dict[str, tuple[OSINTFinding, datetime]] = {}

# Heuristic examples you can replace with real API lookups.
# For demo/smoke: mark 203.0.113.0/24 (RFC 5737 TEST-NET-3) as "malicious" to simulate hits.
def _heuristic_lookup(ioc: IOC) -> OSINTFinding:
    if ioc.type == "ip" and ioc.value.startswith("203.0.113."):
        return OSINTFinding(
            reputation="malicious",
            sources=["HeuristicStub"],
            last_seen=datetime.utcnow(),
            tags=["brute-force"],
        )
    # Example: domains that look like obvious placeholders → unknown
    if ioc.type in {"domain", "url"} and ("example.com" in ioc.value or "example.org" in ioc.value):
        return OSINTFinding(reputation="unknown", sources=["HeuristicStub"])

    # Default
    return OSINTFinding(reputation="unknown", sources=[])

def _get_cached(ioc_value: str) -> OSINTFinding | None:
    hit = _CACHE.get(ioc_value)
    if not hit:
        return None
    finding, exp = hit
    if datetime.utcnow() > exp:
        _CACHE.pop(ioc_value, None)
        return None
    return finding

def _set_cache(ioc_value: str, finding: OSINTFinding, ttl_seconds: int = 600) -> None:
    _CACHE[ioc_value] = (finding, datetime.utcnow() + timedelta(seconds=ttl_seconds))

def lookup_osint(ioc: IOC) -> OSINTFinding:
    """
    Replace this with real OSINT provider lookups.
    E.g., AbuseIPDB/VirusTotal/OTX clients with retries + timeouts.
    """
    cached = _get_cached(ioc.value)
    if cached:
        return cached
    finding = _heuristic_lookup(ioc)
    _set_cache(ioc.value, finding)
    return finding

def enrich(iocs: list[IOC]) -> Dict[str, OSINTFinding]:
    """
    Returns a dict keyed by IOC value -> OSINTFinding.
    Deduplicates by IOC value automatically via dict keys.
    """
    return {ioc.value: lookup_osint(ioc) for ioc in iocs}
