import re
import ipaddress
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from collectors.base_collector import RawObservation

class NormalizedObservation(BaseModel):
    entity_type: str        # 'username', 'email', 'domain', 'phone', 'ip'
    value: str              # Normalized string value
    source: str             # Source identifier
    timestamp: str          # ISO-8601 UTC
    confidence: float       # 0.0 to 1.0
    evidence_text: str      # Readable snippet or description
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

def clean_username(val: str) -> str:
    return val.strip().lstrip("@").lower()

def clean_email(val: str) -> str:
    return val.strip().lower()

def clean_domain(val: str) -> str:
    # Remove http:// or https:// or paths if present
    cleaned = val.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("@")[-1] # if email passed by mistake
    return cleaned

def clean_phone(val: str) -> str:
    # Strip everything except digits and leading '+'
    cleaned = val.strip()
    has_plus = cleaned.startswith("+")
    digits = re.sub(r"\D", "", cleaned)
    return f"+{digits}" if has_plus else digits

def clean_ip(val: str) -> str:
    try:
        # Validate IP format
        ip = ipaddress.ip_address(val.strip())
        return str(ip)
    except ValueError:
        return val.strip()

class ObservationNormalizer:
    @staticmethod
    def normalize(raw: RawObservation) -> Optional[NormalizedObservation]:
        entity_type = raw.entity_type.lower().strip()
        raw_value = raw.value
        
        # Map aliases
        if entity_type in {"user name", "handle", "telegram handle", "telegram"}:
            entity_type = "username"
        elif entity_type in {"phone number", "mobile", "contact"}:
            entity_type = "phone"
        elif entity_type in {"ip address", "ipv4", "ipv6"}:
            entity_type = "ip"
        elif entity_type in {"email address"}:
            entity_type = "email"

        # Apply specific sanitization rules
        if entity_type == "username":
            value = clean_username(raw_value)
            if len(value) < 2: return None
        elif entity_type == "email":
            value = clean_email(raw_value)
            if "@" not in value: return None
        elif entity_type == "domain":
            value = clean_domain(raw_value)
            if "." not in value: return None
        elif entity_type == "phone":
            value = clean_phone(raw_value)
            if len(value) < 5: return None
        elif entity_type == "ip":
            value = clean_ip(raw_value)
            # Ensure it is a valid IP address
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return None
        else:
            # Pass-through for other indicator types (like crypto, upi)
            value = raw_value.strip().lower()
            if not value: return None

        return NormalizedObservation(
            entity_type=entity_type,
            value=value,
            source=raw.source,
            timestamp=raw.timestamp,
            confidence=raw.confidence,
            evidence_text=raw.evidence_text or f"Observed {entity_type} '{value}' via {raw.source}.",
            raw_payload=raw.raw_payload
        )
