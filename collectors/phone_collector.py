import re
import requests
import logging
from html.parser import HTMLParser
from typing import List
from datetime import datetime, timezone

from collectors.base_collector import BaseCollector, RawObservation

logger = logging.getLogger("looker.phone_collector")

# A mapping of common country calling codes to country names
COUNTRY_CODES = {
    "1": "USA/Canada",
    "7": "Russia/Kazakhstan",
    "20": "Egypt",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "36": "Hungary",
    "39": "Italy",
    "40": "Romania",
    "41": "Switzerland",
    "43": "Austria",
    "44": "United Kingdom",
    "45": "Denmark",
    "46": "Sweden",
    "47": "Norway",
    "48": "Poland",
    "49": "Germany",
    "51": "Peru",
    "52": "Mexico",
    "54": "Argentina",
    "55": "Brazil",
    "56": "Chile",
    "57": "Colombia",
    "58": "Venezuela",
    "60": "Malaysia",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "64": "New Zealand",
    "65": "Singapore",
    "66": "Thailand",
    "81": "Japan",
    "82": "South Korea",
    "84": "Vietnam",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "98": "Iran",
    "234": "Nigeria",
    "254": "Kenya",
    "256": "Uganda",
    "351": "Portugal",
    "352": "Luxembourg",
    "353": "Ireland",
    "354": "Iceland",
    "358": "Finland",
    "380": "Ukraine",
    "971": "UAE",
    "972": "Israel",
    "977": "Nepal"
}

class DuckDuckGoPhoneParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.results = []
        self._capture = None
        self._current = {}

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        class_name = attrs_dict.get("class", "")
        if tag == "a" and "result__a" in class_name:
            self._capture = "title"
            self._current = {"title": "", "url": attrs_dict.get("href", "")}
        elif tag in {"a", "div"} and "result__snippet" in class_name:
            self._capture = "snippet"
            self._current.setdefault("snippet", "")

    def handle_data(self, data):
        if self._capture:
            self._current[self._capture] = (self._current.get(self._capture, "") + " " + data).strip()

    def handle_endtag(self, tag):
        if self._capture == "title" and tag == "a":
            if self._current.get("title"):
                self.results.append(self._current)
            self._capture = None
        elif self._capture == "snippet" and tag in {"a", "div"}:
            self._capture = None

class PhoneCollector(BaseCollector):
    def collect(self, phone: str) -> List[RawObservation]:
        # Strip common punctuation
        clean_val = re.sub(r"[^\d+]", "", phone)
        if not clean_val:
            return []

        observations = []

        # 1. Parse Country Code
        country = "Unknown"
        if clean_val.startswith("+"):
            digits = clean_val[1:]
            # Try to match country codes of length 1, 2, 3
            for length in [3, 2, 1]:
                prefix = digits[:length]
                if prefix in COUNTRY_CODES:
                    country = COUNTRY_CODES[prefix]
                    break

            observations.append(RawObservation(
                entity_type="phone",
                value=clean_val,
                source="phone_parser",
                confidence=1.0,
                evidence_text=f"Phone number parsed. Detected Country: {country} (Calling code: {clean_val[:4]})",
                raw_payload={"country": country, "digits": digits}
            ))

        # 2. DuckDuckGo Search Mentions
        try:
            # Search both the raw clean and formatting versions
            quoted = requests.utils.quote(f'"{phone}"')
            url = f"https://html.duckduckgo.com/html/?q={quoted}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
            resp = requests.get(url, headers=headers, timeout=6)
            if resp.status_code == 200:
                parser = DuckDuckGoPhoneParser()
                parser.feed(resp.text)
                for r in parser.results[:6]:
                    title = r.get("title", "").strip()
                    snippet = r.get("snippet", "").strip()
                    href = r.get("url", "").strip()

                    observations.append(RawObservation(
                        entity_type="phone",
                        value=clean_val,
                        source="duckduckgo_search",
                        confidence=0.7,
                        evidence_text=f"Phone number found in search: '{title}' - {snippet} (Source: {href})",
                        raw_payload={"title": title, "snippet": snippet, "url": href}
                    ))
        except Exception as e:
            logger.warning(f"DuckDuckGo search for phone {phone} failed: {e}")

        return observations
