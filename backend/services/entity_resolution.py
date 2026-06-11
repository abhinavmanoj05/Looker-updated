import re
from typing import List, Dict, Set, Tuple
from pydantic import BaseModel, Field

from services.normalizer import NormalizedObservation

class ResolvedEntity(BaseModel):
    entity_type: str
    value: str
    confidence: float
    sources: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    observations: List[NormalizedObservation] = Field(default_factory=list)

class EntityResolver:
    @staticmethod
    def resolve(observations: List[NormalizedObservation]) -> List[ResolvedEntity]:
        """
        Deduplicates observations by merging those with the same (entity_type, value)
        and combining their confidence, sources, and evidence.
        """
        grouped: Dict[Tuple[str, str], List[NormalizedObservation]] = {}
        for obs in observations:
            key = (obs.entity_type, obs.value)
            grouped.setdefault(key, []).append(obs)

        resolved_list: List[ResolvedEntity] = []

        for (etype, val), obs_list in grouped.items():
            # Standard confidence aggregation: max confidence
            max_conf = max(o.confidence for o in obs_list)
            
            # De-duplicate sources and evidence
            unique_sources: Set[str] = set()
            unique_evidence: Set[str] = set()
            
            for o in obs_list:
                unique_sources.add(o.source)
                if o.evidence_text:
                    unique_evidence.add(o.evidence_text)

            resolved_list.append(ResolvedEntity(
                entity_type=etype,
                value=val,
                confidence=round(max_conf, 2),
                sources=sorted(list(unique_sources)),
                evidence=sorted(list(unique_evidence)),
                observations=obs_list
            ))

        return resolved_list

    @staticmethod
    def extract_implicit_relationships(resolved_entities: List[ResolvedEntity]) -> List[Tuple[str, str, str, float]]:
        """
        Scans resolved entities and search snippets to find implicit linkages.
        E.g., if we resolve a username and one of its DDG search snippets contains an email,
        we register an implicit relationship: (username) -[HAS_EMAIL]-> (email).
        
        Returns a list of tuples: (source_value, source_type, target_value, target_type, relation_label, confidence)
        """
        relationships = []
        
        # Build quick lookup of all resolved values to match against
        resolved_lookup = {re.escape(entity.value): entity for entity in resolved_entities}
        if not resolved_lookup:
            return []

        # Find emails and phones in snippets using regex
        email_pattern = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
        phone_pattern = re.compile(r"\+?\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b|\+?\b\d{10,12}\b")

        for entity in resolved_entities:
            # We look for connections in search evidence
            combined_text = " ".join(entity.evidence) + " " + " ".join(
                str(obs.raw_payload) for obs in entity.observations
            )
            
            # 1. Search for emails in this entity's context
            found_emails = set(email_pattern.findall(combined_text))
            for email in found_emails:
                email_clean = email.strip().lower()
                # If we also resolved this email, link them
                matching_entity = next((e for e in resolved_entities if e.entity_type == "email" and e.value == email_clean), None)
                if matching_entity:
                    relationships.append((
                        entity.value, entity.entity_type,
                        matching_entity.value, "email",
                        "MENTIONED_WITH",
                        0.75
                    ))

            # 2. Search for phones in this entity's context
            found_phones = set(phone_pattern.findall(combined_text))
            for phone in found_phones:
                # Clean phone representation
                phone_clean = re.sub(r"\D", "", phone)
                # Link if resolved
                matching_entity = next((e for e in resolved_entities if e.entity_type == "phone" and (phone_clean in e.value or e.value in phone_clean)), None)
                if matching_entity:
                    relationships.append((
                        entity.value, entity.entity_type,
                        matching_entity.value, "phone",
                        "MENTIONED_WITH",
                        0.70
                    ))

        return relationships
