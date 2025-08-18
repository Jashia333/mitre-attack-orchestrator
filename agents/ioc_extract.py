# agents/ioc_extract.py
import re
from typing import List
from storage.schema import IOC

IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE  = re.compile(r"https?://[^\s\"'>)\]]+", re.I)  # avoid ) ] ' " >
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b")
MAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
# Use non-capturing groups; match the whole domain; strong word boundaries
DOM_RE  = re.compile(r"\b(?!https?://)(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

TRAILING_PUNCT = ".,;:)]}>\"'"

def _clean(s: str) -> str:
    # strip trailing/leading punctuation commonly stuck to tokens
    return s.strip().strip(TRAILING_PUNCT)

def extract_iocs(text: str) -> List[IOC]:
    found: List[IOC] = []

    # Collect URLs first
    urls = [ _clean(m.group(0)) for m in URL_RE.finditer(text) ]
    for u in urls:
        if u: found.append(IOC(type="url", value=u))

    for m in IP_RE.finditer(text):
        found.append(IOC(type="ip", value=_clean(m.group(0))))
    for m in HASH_RE.finditer(text):
        found.append(IOC(type="hash", value=_clean(m.group(0))))
    for m in MAIL_RE.finditer(text):
        found.append(IOC(type="email", value=_clean(m.group(0))))
    for m in DOM_RE.finditer(text):
        dom = _clean(m.group(0))
        if dom:
            found.append(IOC(type="domain", value=dom))

    # De-dupe (case-insensitive on value + type)
    seen, out = set(), []
    for i in found:
        k = (i.type, i.value.lower())
        if k not in seen:
            seen.add(k); out.append(i)
    return out
