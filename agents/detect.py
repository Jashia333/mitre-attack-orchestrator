# agents/detect.py
from storage.schema import Detection
from langchain_core.prompts import PromptTemplate
import json, re, os
from dotenv import load_dotenv
load_dotenv() 

# Providers (optional imports guarded)
PROVIDER = None
llm = None
try:
    if os.getenv("GROQ_API_KEY"):
        from langchain_groq import ChatGroq
        llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)  # fast + cheap
        PROVIDER = "groq"
    elif os.getenv("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        PROVIDER = "openai"
except Exception:
    llm = None

PROMPT = PromptTemplate.from_template(
    """You are a SOC analyst.
Classify the event as benign, suspicious, or malicious.
Return STRICT JSON: {{"label": "...", "reason": "...", "confidence": 0.0}}.

Event JSON:
{event_json}
""".strip()
)

def _heuristic_detect(event_json: str) -> Detection:
    t = event_json.lower()
    if "failed login" in t or "multiple failed" in t or "brute" in t:
        return Detection(label="malicious",
                         reason="Heuristic: repeated failed logins/brute-force pattern",
                         confidence=0.75)
    if any(k in t for k in ["phish", "suspicious", "malware", "exfil", "c2"]):
        return Detection(label="suspicious",
                         reason="Heuristic: suspicious keywords",
                         confidence=0.6)
    return Detection(label="benign", reason="Heuristic: no suspicious signals", confidence=0.55)

def detect(event_json: str) -> Detection:
    if llm is None:
        return _heuristic_detect(event_json)
    try:
        resp = llm.invoke(PROMPT.format(event_json=event_json)).content
        try:
            data = json.loads(resp)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", resp, re.S)
            data = json.loads(m.group(0)) if m else {}
        if not data:
            return _heuristic_detect(event_json)
        return Detection(
            label=data.get("label", "suspicious"),
            reason=data.get("reason", f"{PROVIDER} parsed with defaults"),
            confidence=float(data.get("confidence", 0.5)),
        )
    except Exception:
        return _heuristic_detect(event_json)
