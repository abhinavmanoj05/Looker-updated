import os
import re
import logging
import requests
from typing import List
from collectors.base_collector import BaseCollector, RawObservation

logger = logging.getLogger("looker.ip_collector")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

class IPCollector(BaseCollector):
    def collect(self, ip: str) -> List[RawObservation]:
        ip = ip.strip()
        # Basic IPv4/IPv6 validation
        if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$|^[a-fA-F0-9:]+$", ip):
            return []

        observations = []

        # 1. AbuseIPDB reputation check
        if ABUSEIPDB_KEY:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
                headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
                resp = requests.get(url, params=params, headers=headers, timeout=8)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    abuse_score = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)
                    isp = data.get("isp", "Unknown")
                    country = data.get("countryCode", "Unknown")
                    domain = data.get("domain", "")
                    usage_type = data.get("usageType", "Unknown")
                    is_tor = data.get("isTor", False)
                    last_reported = data.get("lastReportedAt", "Never")

                    confidence = min(1.0, abuse_score / 100.0 + 0.1)
                    observations.append(RawObservation(
                        entity_type="ip",
                        value=ip,
                        source="abuseipdb",
                        confidence=confidence,
                        evidence_text=(
                            f"IP {ip} | Abuse Score: {abuse_score}% | Reports: {total_reports} | "
                            f"ISP: {isp} | Country: {country} | Type: {usage_type} | "
                            f"Tor: {'Yes' if is_tor else 'No'} | Last Reported: {last_reported}"
                        ),
                        raw_payload={
                            "ip": ip,
                            "abuse_score": abuse_score,
                            "total_reports": total_reports,
                            "isp": isp,
                            "country": country,
                            "domain": domain,
                            "usage_type": usage_type,
                            "is_tor": is_tor,
                            "last_reported": last_reported,
                        }
                    ))
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup for {ip} failed: {e}")

        # 2. ip-api.com geolocation (free, no key needed)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"
            resp = requests.get(url, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    lat = data.get("lat")
                    lon = data.get("lon")
                    city = data.get("city", "")
                    region = data.get("regionName", "")
                    country = data.get("country", "")
                    isp = data.get("isp", "")
                    org = data.get("org", "")
                    asn = data.get("as", "")

                    observations.append(RawObservation(
                        entity_type="ip",
                        value=ip,
                        source="ip_geolocation",
                        confidence=0.85,
                        evidence_text=(
                            f"IP {ip} geolocated to {city}, {region}, {country} | "
                            f"ISP: {isp} | Org: {org} | ASN: {asn}"
                        ),
                        raw_payload={
                            "ip": ip,
                            "latitude": lat,
                            "longitude": lon,
                            "city": city,
                            "region": region,
                            "country": country,
                            "isp": isp,
                            "org": org,
                            "asn": asn,
                        }
                    ))
        except Exception as e:
            logger.warning(f"Geolocation lookup for {ip} failed: {e}")

        # 3. Shodan InternetDB (free, no key) for port/CVE data
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            headers = {"User-Agent": "Mozilla/5.0 Looker-ThreatIntel/1.0"}
            resp = requests.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                cpes = data.get("cpes", [])
                vulns = data.get("vulns", [])
                tags = data.get("tags", [])
                hostnames = data.get("hostnames", [])

                if ports or vulns:
                    observations.append(RawObservation(
                        entity_type="ip",
                        value=ip,
                        source="shodan_internetdb",
                        confidence=0.9,
                        evidence_text=(
                            f"Shodan scan of {ip}: Open ports: {ports} | "
                            f"Vulnerabilities: {vulns[:5]} | Tags: {tags} | "
                            f"Hostnames: {hostnames[:3]}"
                        ),
                        raw_payload={
                            "ip": ip,
                            "ports": ports,
                            "cpes": cpes,
                            "vulns": vulns,
                            "tags": tags,
                            "hostnames": hostnames,
                        }
                    ))
        except Exception as e:
            logger.warning(f"Shodan InternetDB lookup for {ip} failed: {e}")

        return observations
