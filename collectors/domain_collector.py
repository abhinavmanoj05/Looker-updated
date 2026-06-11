import socket
import requests
import logging
from typing import List
from datetime import datetime, timezone

from collectors.base_collector import BaseCollector, RawObservation

logger = logging.getLogger("looker.domain_collector")

class DomainCollector(BaseCollector):
    def collect(self, domain: str) -> List[RawObservation]:
        domain = domain.strip().lower()
        if not domain or "." not in domain or "/" in domain or "@" in domain:
            return []

        observations = []

        # 1. DNS Resolution (A records)
        try:
            name, aliases, ip_list = socket.gethostbyname_ex(domain)
            for ip in ip_list:
                observations.append(RawObservation(
                    entity_type="domain",
                    value=domain,
                    source="dns_resolver",
                    confidence=1.0,
                    evidence_text=f"Domain '{domain}' resolves to IP: {ip}",
                    raw_payload={"ip": ip, "resolved_name": name, "aliases": aliases}
                ))
        except Exception as e:
            logger.warning(f"DNS resolution for {domain} failed: {e}")

        # 2. RDAP WHOIS Lookup
        # RDAP is an RFC-standardized HTTP-based protocol for WHOIS queries.
        try:
            url = f"https://rdap.org/domain/{domain}"
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 Looker-ThreatIntel/1.0"
            }
            resp = requests.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                
                # Extract registrar
                registrar = "Unknown"
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    registrar = prop[3]
                                    break
                
                # Extract registration events (created, changed, expired)
                events = {}
                for event in data.get("events", []):
                    action = event.get("eventAction", "")
                    date_str = event.get("eventDate", "")
                    if action and date_str:
                        events[action] = date_str

                created = events.get("registration", "Unknown")
                expired = events.get("expiration", "Unknown")

                observations.append(RawObservation(
                    entity_type="domain",
                    value=domain,
                    source="rdap_whois",
                    confidence=0.95,
                    evidence_text=f"WHOIS data retrieved. Registrar: {registrar} (Created: {created}, Expires: {expired})",
                    raw_payload={
                        "registrar": registrar,
                        "created": created,
                        "expired": expired,
                        "status": data.get("status", []),
                        "events": events
                    }
                ))
            else:
                # If RDAP fails (e.g. rate limited or not found), log it
                logger.info(f"RDAP response code for {domain}: {resp.status_code}")
        except Exception as e:
            logger.warning(f"RDAP WHOIS query for {domain} failed: {e}")

        return observations
