# Looker Threat Intelligence Platform — Technical Documentation

## 1. Executive Summary

### Overview
The **Looker Threat Intelligence Platform** is a web-based threat investigation and correlation system designed specifically for law enforcement cyber cells (such as police cyber cells). The application allows analysts to enter a single suspect indicator—such as a **username/handle, email address, phone number, web domain, or IP address**—and automatically scrapes open-source intelligence (OSINT) data, normalizes indicators, resolves duplicate entities, and maps connections in an interactive network correlation graph and geospatial map.

### Core Problems Solved
* **Manual Triage**: Automates querying of multiple siloed security feeds, registries, and search engines.
* **Hidden Connections**: Automatically parses scrapers' text blocks to identify and links hidden identifiers (e.g. finding an email mentioned in a username search result).
* **Relationship Visualization**: Replaces textual security logs with a unified, interactive property graph representation.
* **Chain of Custody**: Appends immutable operational event logs for compliance audits and legal integrity.

---

## 2. Monorepo System Architecture

The platform has been consolidated into a clean, modern **Monorepo architecture** that separates frontend and backend logic into self-contained workspaces, managed by a root-level configurations launcher:

![System Architecture Diagram](file:///C:/Users/abhin/Desktop/looker/Looker-threat-intel-platform/architecture_diagram.png)

### Directory Breakdown
* **`/backend` (Python FastAPI)**: Houses the entire Python server, Pydantic schemas, modular scrapers, normalizers, and Neo4j database writing layer.
* **`/frontend` (React + Vite)**: Houses the modular React UI console, stylesheet definitions, and Vite configuration settings.
* **Root Folder**: Contains only container descriptions (`docker-compose.yml`), environmental configurations (`.env`), documentation, and global launch batch files (`START.bat`).

---

## 3. Component Details & Responsibilities

### Backend Modules (`/backend`)
* **`app.py`**: The server's API Gateway. Handles FastAPI endpoints (`/api/investigate`, `/api/graph`, `/api/cases`, `/api/audit`), rate limiting, API key validation, and serves the static production build files from the React frontend.
* **`collectors/`**: Inherits from `BaseCollector` to query live APIs and engines:
  * `username_collector.py`: Concurrently scrapes profile availability across 500+ web platforms (via WhatsMyName check profiles list).
  * `email_collector.py` & `phone_collector.py`: Scrapes web-mentions and profile references from DuckDuckGo HTML search results.
  * `domain_collector.py`: Resolves DNS A-records and queries RDAP WHOIS records from `rdap.org`.
  * `ip_collector.py`: Gathers AbuseIPDB threat ratings, ip-api geolocations, and Shodan InternetDB open ports and CVEs.
* **`services/`**: Processing engine layer:
  * `orchestrator.py`: Orchestrates the ingestion cycle (queries collectors, parses secondary queries, and triggers normalizers).
  * `normalizer.py`: Sanitizes and standardizes indicator string structures.
  * `entity_resolution.py`: Deduplicates observations and regex-extracts implicit relationships from scraped text evidence.
  * `correlation_engine.py`: Converts resolved data into Cytoscape-compliant JSON elements (nodes and edges).
  * `graph_writer.py`: persisted entities directly to Neo4j graph nodes, falling back to a local memory dictionary if Neo4j is offline.
* **`config/database.py`**: Handles connection driver sessions to the Neo4j container database.

### Frontend Components (`/frontend`)
* **`src/main.jsx`**: Initializes the React DOM wrapper.
* **`src/App.jsx`**: Main UI console app coordinating dashboard sub-components:
  * *Investigation Form*: Runs live indicators lookup, logs scanning steps, and displays progress.
  * *Correlation Graph*: Mounts Cytoscape canvas instance to render interactive nodes and edges.
  * *Geospatial Map*: Mounts Leaflet map instance mapping IP coordinates.
  * *Case Ledger*: Displays cards of recent threat investigations.
  * *Source Evidence*: Filters cards of scraped text hits.
  * *Audit Log*: Displays active audit logs.
* **`src/index.css`**: Standardizes glassmorphism CSS designs, scrollbars, background grids, layout grids, and badges.

---

## 4. Technical Stack

* **Programming Languages**: Python 3.10+ (Backend), JavaScript / JSX (Frontend / React).
* **Backend Framework**: FastAPI (ASGI micro-framework), Uvicorn (ASGI web server).
* **Frontend Framework**: React 18.3+ (Component framework), Vite 5+ (Bundler & dev server).
* **Database Engine**: Neo4j 5 (Property graph database).
* **Local Data Stores**: `case_ledger.json` (Structured JSON case backups), `audit_log.jsonl` (Append-only compliance audit trail).
* **Visual Rendering Libraries**: Cytoscape.js (Interactive property graph rendering), Leaflet.js (Geospatial tile-mapping).

---

## 5. Implementation Status

| Component | Status | Path |
| :--- | :--- | :--- |
| **FastAPI Backend Routing** | **Implemented** | `backend/app.py` |
| **Modular OSINT Collectors** | **Implemented** | `backend/collectors/` |
| **Normalizer & Entity Resolution**| **Implemented** | `backend/services/` |
| **Vite / React Dashboard Console**| **Implemented** | `frontend/src/` |
| **Neo4j Graph Database Store** | **Implemented** | `backend/services/graph_writer.py` |
| **Local File Backups & Auditing** | **Implemented** | `backend/case_ledger.json`, `backend/audit_log.jsonl` |
| **Background Thread Scraping** | **Implemented** | Initiated dynamically via FastAPI `BackgroundTasks`. |
| **Automated Testing Suites** | **Missing** | Lacks unit test coverage (e.g. pytest). |
