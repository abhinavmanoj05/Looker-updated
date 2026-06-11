import re
import hashlib
import logging
from typing import List, Dict, Any, Tuple

from collectors.base_collector import RawObservation
from collectors.username_collector import UsernameCollector
from collectors.email_collector import EmailCollector
from collectors.domain_collector import DomainCollector
from collectors.phone_collector import PhoneCollector
from collectors.ip_collector import IPCollector

from services.normalizer import ObservationNormalizer, NormalizedObservation
from services.entity_resolution import EntityResolver, ResolvedEntity

logger = logging.getLogger("looker.orchestrator")

class IngestionOrchestrator:
    def __init__(self):
        self.collectors = {
            "username": UsernameCollector(),
            "email": EmailCollector(),
            "domain": DomainCollector(),
            "phone": PhoneCollector(),
            "ip": IPCollector(),
        }

    def _normalize_selector(self, selector: str) -> str:
        s = selector.lower().strip()
        if "user name" in s or "username" in s or "handle" in s or "telegram" in s:
            return "username"
        if "email" in s:
            return "email"
        if "domain" in s or "url" in s or "website" in s:
            return "domain"
        if "phone" in s or "contact" in s or "mobile" in s:
            return "phone"
        if "ip" in s or "address" in s:
            return "ip"
        # Auto-detect from value format
        return s

    def _auto_detect(self, value: str) -> str:
        """Auto-detect indicator type from value format."""
        v = value.strip()
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", v):
            return "ip"
        if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", v):
            return "email"
        if re.match(r"^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$", v) and "@" not in v:
            return "domain"
        if re.match(r"^\+?\d{7,15}$", v):
            return "phone"
        return "username"

    def run(self, selector: str, value: str) -> Dict[str, Any]:
        """
        Runs the full ingestion pipeline:
        1. Selects and executes primary collector (auto-detect if needed).
        2. Normalizes raw observations.
        3. Extracts secondary indicators (e.g., email mentioned in username check).
        4. Resolves entities and extracts implicit relationships.
        5. Computes helper representations for the ledger and ML scoring.
        """
        normalized_selector = self._normalize_selector(selector)
        # Fallback: auto-detect from value
        if normalized_selector not in self.collectors:
            normalized_selector = self._auto_detect(value)

        raw_observations: List[RawObservation] = []

        # 1. Run primary collector
        collector = self.collectors.get(normalized_selector)
        if collector:
            try:
                logger.info(f"Running primary collector for {normalized_selector}: {value}")
                raw_observations.extend(collector.collect(value))
            except Exception as e:
                logger.error(f"Collector for {normalized_selector} failed: {e}")
        else:
            logger.warning(f"No collector found for selector '{selector}' (normalized: '{normalized_selector}')")

        # 2. Extract secondary indicators for single-depth correlation
        secondary_queries: List[Tuple[str, str]] = []
        email_pattern = r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ip_pattern = r"\b(\d{1,3}\.){3}\d{1,3}\b"
        domain_pattern = r"\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b"

        for raw in raw_observations:
            text = f"{raw.evidence_text} {str(raw.raw_payload)}"

            if normalized_selector == "username":
                for email in re.findall(email_pattern, text):
                    secondary_queries.append(("email", email.strip().lower()))
            if normalized_selector in ("username", "email", "domain"):
                for ip in re.findall(ip_pattern, text):
                    if not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("127."):
                        secondary_queries.append(("ip", ip.strip()))

        # Run secondary collectors (limit to 3)
        unique_secondaries = list({(t, v): None for t, v in secondary_queries}.keys())[:3]
        for sec_type, sec_val in unique_secondaries:
            sec_collector = self.collectors.get(sec_type)
            if sec_collector:
                try:
                    logger.info(f"Running secondary collector: {sec_type} -> {sec_val}")
                    raw_observations.extend(sec_collector.collect(sec_val))
                except Exception as e:
                    logger.error(f"Secondary collector for {sec_type} failed: {e}")

        # 3. Normalize all observations
        normalized_obs: List[NormalizedObservation] = []
        for raw in raw_observations:
            norm = ObservationNormalizer.normalize(raw)
            if norm:
                normalized_obs.append(norm)

        # 4. Resolve entities
        resolved_entities = EntityResolver.resolve(normalized_obs)

        # 5. Extract implicit relationships
        implicit_links = EntityResolver.extract_implicit_relationships(resolved_entities)

        # 6. Build compatibility layer for app.py response
        raw_indicators = {
            "username": [], "email": [], "domain": [],
            "phone": [], "ip": [], "upi": [], "crypto": []
        }

        # Collect geolocation from IP entities
        geo_lat = None
        geo_lon = None
        geo_country = None

        for entity in resolved_entities:
            t = entity.entity_type
            if t in raw_indicators:
                raw_indicators[t].append(entity.value)
            # Extract geo from observations
            for obs in entity.observations:
                payload = obs.raw_payload or {}
                if obs.source == "ip_geolocation" and payload.get("latitude"):
                    geo_lat = payload["latitude"]
                    geo_lon = payload["longitude"]
                    geo_country = payload.get("country")

        # Deduplicate
        for k in raw_indicators:
            raw_indicators[k] = sorted(list(set(raw_indicators[k])))

        associated_email = raw_indicators["email"][0] if raw_indicators["email"] else None

        digest = hashlib.sha256(f"{normalized_selector}:{value.strip().lower()}".encode("utf-8")).hexdigest()[:10]
        scammer_alias = f"{normalized_selector}::{digest}"

        source_hits = []
        for entity in resolved_entities:
            for obs in entity.observations:
                if obs.source not in ("phone_parser", "dns_resolver"):
                    source_hits.append({
                        "title": f"[{obs.source.upper()}] {obs.entity_type}: {obs.value}",
                        "snippet": obs.evidence_text,
                        "url": obs.raw_payload.get("url") or obs.raw_payload.get("uri_check") or "",
                        "confidence": obs.confidence,
                        "source": obs.source,
                    })

        result = {
            "scammer_alias": scammer_alias,
            "observation_state": "observed" if resolved_entities else "unresolved",
            "source_reliability": 0.85 if resolved_entities else 0.0,
            "associated_email": associated_email,
            "shared_identifiers": raw_indicators["email"] + raw_indicators["username"],
            "shared_contacts": raw_indicators["phone"],
            "shared_infrastructure": raw_indicators["domain"] + raw_indicators["ip"],
            "raw_indicators": raw_indicators,
            "source_query": value,
            "collection_errors": [],
            "source_hits": source_hits,
            "collector_hits": source_hits if normalized_selector == "username" else [],
            "resolved_entities": resolved_entities,
            "implicit_links": implicit_links,
            "public_sources": {s["source"]: s["url"] for s in source_hits if s.get("url")},
        }

        # Add geo if available
        if geo_lat is not None:
            result["latitude"] = geo_lat
            result["longitude"] = geo_lon
            result["geo_country"] = geo_country

        return result

