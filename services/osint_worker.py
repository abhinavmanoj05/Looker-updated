import asyncio
import hashlib
import ipaddress
import re
from html.parser import HTMLParser
from typing import Dict, List, Optional

import requests
from celery import shared_task

from collectors.username_collector import collect_username_hits, normalize_username, stable_subject_id


INDICATOR_PATTERNS = {
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "username": re.compile(r"(?<![A-Za-z0-9_])@?[A-Za-z0-9_]{3,32}(?![A-Za-z0-9_])"),
}

SELECTOR_ALIASES = {
    "email": "email",
    "username": "username",
    "user name": "username",
    "handle": "username",
}

SOURCE_METADATA = [
    {"name": "DuckDuckGo HTML", "kind": "search", "reliability": 0.55, "observed": "public_search"},
    {"name": "ip-api.com", "kind": "geolocation", "reliability": 0.7, "observed": "ip_enrichment"},
    {"name": "WhatsMyName-style bundle", "kind": "username_enrichment", "reliability": 0.72, "observed": "username_lookup"},
]


class DuckDuckGoParser(HTMLParser):
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


def _normalize_selector(selector: str) -> str:
    return SELECTOR_ALIASES.get(selector.lower().strip(), selector.lower().strip())


def _stable_alias(selector: str, value: str) -> str:
    digest = hashlib.sha256(f"{selector}:{value}".encode("utf-8")).hexdigest()[:10]
    return f"{selector.lower().replace(' ', '_')}::{digest}"


def _is_public_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
        return not (parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_multicast)
    except ValueError:
        return False


def _clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _dedupe(values: List[str]) -> List[str]:
    return sorted({_clean_text(item) for item in values if _clean_text(item)})


def _extract_indicators(text: str) -> Dict[str, List[str]]:
    matches = {}
    for key, pattern in INDICATOR_PATTERNS.items():
        matches[key] = _dedupe(pattern.findall(text or ""))
    matches["username"] = [item for item in matches.get("username", []) if not item.startswith("http")]
    return matches


def _fetch_text(url: str, timeout: int = 12) -> str:
    response = requests.get(
        url,
        timeout=timeout,
        headers={
            "User-Agent": "Looker-OSINT/1.0 lawful-public-source-research",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    response.raise_for_status()
    return response.text


def _fetch_json(url: str, timeout: int = 12) -> dict:
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "Looker-OSINT/1.0"})
    response.raise_for_status()
    return response.json()


def _parse_search_results(html: str) -> List[dict]:
    parser = DuckDuckGoParser()
    parser.feed(html or "")
    compact = []
    for result in parser.results[:8]:
        title = _clean_text(result.get("title", ""))
        snippet = _clean_text(result.get("snippet", ""))
        url = _clean_text(result.get("url", ""))
        if title or snippet:
            compact.append({"title": title, "snippet": snippet, "url": url})
    return compact


def _classify_observation(selector_key: str, value: str, extracted: Dict[str, List[str]], source_hits: List[dict]) -> str:
    if value in extracted.get(selector_key, []):
        return "observed"
    if source_hits:
        return "observed"
    if any(extracted.values()):
        return "inferred"
    return "unresolved"


def _source_reliability(selector_key: str, source_hits: List[dict], extracted: Dict[str, List[str]]) -> float:
    score = 0.0
    if source_hits:
        score += min(0.35, 0.08 * len(source_hits))
    if any(extracted.values()):
        score += 0.25
    if selector_key == "username" and source_hits:
        score += 0.12
    return min(0.9, round(score, 2))


def _build_graph(selector: str, value: str, alias: str, extracted: Dict[str, List[str]], geo: Optional[dict], source_hits: List[dict]) -> List[dict]:
    root_id = f"subject::{alias}"
    indicator_id = f"indicator::{selector}::{value}"
    elements = [
        {"data": {"id": root_id, "label": alias, "type": "subject"}},
        {"data": {"id": indicator_id, "label": value, "type": _normalize_selector(selector)}},
        {"data": {"source": root_id, "target": indicator_id, "label": "QUERIED_AS"}},
    ]

    for item in extracted.get("email", [])[:12]:
        node_id = f"email::{item}"
        elements.append({"data": {"id": node_id, "label": item, "type": "email"}})
        elements.append({"data": {"source": root_id, "target": node_id, "label": "HAS_EMAIL"}})

    for hit in source_hits[:12]:
        site_label = _clean_text(str(hit.get("site") or hit.get("title") or "source"))
        site_id = f"source::{hashlib.sha256(site_label.encode('utf-8')).hexdigest()[:12]}"
        elements.append({"data": {"id": site_id, "label": site_label, "type": "source"}})
        elements.append({"data": {"source": root_id, "target": site_id, "label": "CHECKED_ON"}})

    return elements


async def ingest_and_analyze(selector: str, value: str):
    selector_key = _normalize_selector(selector)
    normalized_value = _clean_text(value)
    loop = asyncio.get_running_loop()
    collection_errors = []
    source_hits: List[dict] = []

    if selector_key == "username":
        username = normalize_username(normalized_value)
        source_hits = collect_username_hits(username)
        extracted = {"email": [], "username": [username], "domain": [], "phone": [], "crypto": [], "ip": [], "telegram": [], "upi": []}
        evidence_text = " ".join(
            [username]
            + [
                f"{hit.get('site', '')} {hit.get('url', '')} {hit.get('status', '')} {hit.get('evidence', '')}"
                for hit in source_hits
            ]
        )
    else:
        quoted_value = requests.utils.quote(f'"{normalized_value}" email')
        query_url = f"https://html.duckduckgo.com/html/?q={quoted_value}"
        results = await asyncio.gather(loop.run_in_executor(None, _fetch_text, query_url), return_exceptions=True)
        html = ""
        for result in results:
            if isinstance(result, Exception):
                collection_errors.append(str(result))
            elif isinstance(result, str):
                html = result
        source_hits = _parse_search_results(html)
        evidence_text = " ".join([html] + [f"{hit.get('title', '')} {hit.get('snippet', '')}" for hit in source_hits])
        extracted = _extract_indicators(evidence_text)

    email_match = extracted["email"][0] if extracted["email"] else None
    observation_state = _classify_observation(selector_key, normalized_value, extracted, source_hits)
    source_reliability = _source_reliability(selector_key, source_hits, extracted)
    alias = _stable_alias(selector, normalized_value)

    return {
        "selector_hint": selector,
        "normalized_selector": selector_key,
        "observation_state": observation_state,
        "source_reliability": source_reliability,
        "scammer_alias": alias,
        "associated_email": email_match,
        "shared_identifiers": extracted.get("email", []) + extracted.get("username", []),
        "shared_contacts": [],
        "shared_infrastructure": [],
        "raw_indicators": extracted,
        "source_query": normalized_value,
        "collection_errors": collection_errors,
        "source_hits": source_hits,
        "collector_hits": source_hits if selector_key == "username" else [],
        "public_sources": {
            "search": "DuckDuckGo HTML" if selector_key != "username" else None,
            "username_bundle": "whatsmyname_bundle" if selector_key == "username" and source_hits else None,
            "metadata": SOURCE_METADATA,
        },
        "graph_elements": _build_graph(selector, normalized_value, alias, extracted, None, source_hits),
    }


@shared_task(name="services.osint_worker.ingest_and_analyze")
def ingest_and_analyze_task(selector: str, value: str):
    return asyncio.run(ingest_and_analyze(selector, value))
