import os
import json
import time
import logging
import requests
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from collectors.base_collector import BaseCollector, RawObservation

logger = logging.getLogger("looker.username_collector")

# Default fallback sites if we cannot load/download wmn-data.json
FALLBACK_SITES = [
    {
        "name": "GitHub",
        "uri_check": "https://github.com/{account}",
        "e_code": 200,
        "m_code": 404,
        "m_string": "Page not found",
        "category": "coding"
    },
    {
        "name": "Linktree",
        "uri_check": "https://linktr.ee/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "social"
    },
    {
        "name": "GitLab",
        "uri_check": "https://gitlab.com/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "coding"
    },
    {
        "name": "PyPI",
        "uri_check": "https://pypi.org/user/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "coding"
    },
    {
        "name": "DockerHub",
        "uri_check": "https://hub.docker.com/u/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "coding"
    },
    {
        "name": "Medium",
        "uri_check": "https://medium.com/@{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "writing"
    },
    {
        "name": "Dev.to",
        "uri_check": "https://dev.to/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "coding"
    },
    {
        "name": "Pinterest",
        "uri_check": "https://www.pinterest.com/{account}/",
        "e_code": 200,
        "m_code": 404,
        "category": "social"
    },
    {
        "name": "Spotify",
        "uri_check": "https://open.spotify.com/user/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "music"
    },
    {
        "name": "SlideShare",
        "uri_check": "https://www.slideshare.net/{account}",
        "e_code": 200,
        "m_code": 404,
        "category": "corporate"
    }
]

# We limit active checking to a selection of popular, fast, and high-reliability sites
# to prevent checks from taking too long.
TOP_SITES_FILTER = {
    "github", "gitlab", "linktree", "pypi", "dockerhub", "medium", "dev.to", 
    "pinterest", "spotify", "slideshare", "reddit", "twitter", "instagram",
    "behance", "dribbble", "flickr", "patreon", "vimeo", "roblox", "letterboxd",
    "npm", "disqus", "archive.org", "blogger"
}

class UsernameCollector(BaseCollector):
    def __init__(self, cache_dir: str = "collectors"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.schema_path = self.cache_dir / "wmn-data.json"
        self.schema_url = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
        self.sites = self._load_schema()

    def _load_schema(self) -> List[Dict[str, Any]]:
        # Try to download/refresh schema if missing or older than 1 day
        refresh_needed = True
        if self.schema_path.exists():
            age_seconds = time.time() - self.schema_path.stat().st_mtime
            if age_seconds < 86400: # 24 hours
                refresh_needed = False

        if refresh_needed:
            try:
                logger.info(f"Downloading latest WhatsMyName schema from {self.schema_url}...")
                resp = requests.get(self.schema_url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    self.schema_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
                    logger.info("Successfully saved WhatsMyName schema.")
            except Exception as e:
                logger.warning(f"Could not download WhatsMyName schema ({e}). Using local cache or fallback.")

        # Load from path if possible
        if self.schema_path.exists():
            try:
                data = json.loads(self.schema_path.read_text(encoding="utf-8"))
                sites_list = data.get("sites", [])
                if sites_list:
                    return sites_list
            except Exception as e:
                logger.error(f"Error reading local WhatsMyName schema: {e}")

        return FALLBACK_SITES

    def _check_site(self, site: Dict[str, Any], username: str) -> RawObservation | None:
        name = site.get("name", "Unknown")
        uri_check = site.get("uri_check", "")
        if not uri_check or "{account}" not in uri_check:
            return None

        url = uri_check.replace("{account}", username)
        e_code = site.get("e_code")
        m_code = site.get("m_code")
        e_string = site.get("e_string")
        m_string = site.get("m_string")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            # Send GET request with a short timeout to keep it fast
            resp = requests.get(url, headers=headers, timeout=3, allow_redirects=True)
            status = resp.status_code
            content = resp.text

            # Assertion checks:
            # 1. If missing status code matches, it doesn't exist
            if m_code is not None and status == int(m_code):
                return None

            # 2. If expected status code is set, it must match
            if e_code is not None and status != int(e_code):
                return None

            # 3. If missing string is present in body, it does not exist
            if m_string and m_string in content:
                return None

            # 4. If expected string is set, it MUST be in the body
            if e_string and e_string not in content:
                return None

            # If we passed all missing checks and hit success codes:
            return RawObservation(
                entity_type="username",
                value=username,
                source=f"whatsmyname::{name.lower()}",
                confidence=0.9,
                evidence_text=f"Claimed profile found on {name}: {url}",
                raw_payload={
                    "site_name": name,
                    "url": url,
                    "status_code": status,
                    "category": site.get("category", "social"),
                }
            )

        except Exception:
            # Ignore network timeouts/SSL issues to avoid false positives
            return None

    def collect(self, username: str) -> List[RawObservation]:
        # Clean the username
        username = username.strip().lstrip("@")
        if not username:
            return []

        # Scan the entire WhatsMyName database of 500+ websites!
        filtered_sites = self.sites if self.sites else FALLBACK_SITES

        results = []
        # Query all sites concurrently using a large thread pool (80 workers)
        with ThreadPoolExecutor(max_workers=80) as executor:
            future_to_site = {
                executor.submit(self._check_site, site, username): site 
                for site in filtered_sites
            }
            
            for future in as_completed(future_to_site):
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception:
                    pass
                    
        return results

# Keep compatibility with original file exports
def collect_username_hits(username: str, bundle_path: str | None = None) -> list[dict[str, Any]]:
    # Bridge to the new active collector class
    collector = UsernameCollector()
    obs = collector.collect(username)
    return [o.dict() for o in obs]

def normalize_username(value: str) -> str:
    return str(value or "").strip().lstrip("@").lower()

def stable_subject_id(username: str) -> str:
    import hashlib
    digest = hashlib.sha256(normalize_username(username).encode("utf-8")).hexdigest()[:12]
    return f"username::{digest}"
