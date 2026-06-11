from abc import ABC, abstractmethod
from typing import Any, List, Dict
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class RawObservation(BaseModel):
    entity_type: str
    value: str
    source: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 1.0
    evidence_text: str = ""
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

class BaseCollector(ABC):
    @abstractmethod
    def collect(self, value: str) -> List[RawObservation]:
        """
        Runs the collector on the given input value and returns a list of raw observations.
        """
        pass
