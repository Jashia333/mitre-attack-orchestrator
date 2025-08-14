# storage/schema.py
from pydantic import BaseModel
from typing import List, Optional, Literal, Dict
from datetime import datetime

class IOC(BaseModel):
    type: Literal["ip", "domain", "url", "hash", "email", "file_path", "registry_key"]
    value: str

class Detection(BaseModel):
    label: Literal["benign", "suspicious", "malicious"]
    reason: str
    confidence: float

class OSINTFinding(BaseModel):
    reputation: Literal["unknown", "suspicious", "malicious"]
    sources: List[str] = []
    last_seen: Optional[datetime] = None
    tags: List[str] = []

class MitreMapping(BaseModel):
    tactic: str
    technique_id: str
    technique: str

class Alert(BaseModel):
    event_id: str
    ts: datetime
    raw: Dict
    detection: Detection
    iocs: List[IOC] = []
    osint: Dict[str, OSINTFinding] = {}
    mitre: List[MitreMapping] = []
    severity: Literal["low", "medium", "high", "critical"] = "low"
