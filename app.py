import asyncio
import html
import json
import os
import platform
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import joblib
import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from neo4j import GraphDatabase
from pydantic import BaseModel, Field
from sklearn.linear_model import SGDClassifier

from services.orchestrator import IngestionOrchestrator
from services.correlation_engine import CorrelationEngine
from services.graph_writer import GraphWriter

app = FastAPI(title="LE Cyber Threat Intel Platform", version="3.2.0")

allowed_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("LOOKER_API_KEY", "").strip()
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")
MODEL_PATH = os.getenv("MODEL_PATH", "intel_self_trainer.pkl")
CASE_STORE_PATH = os.getenv("CASE_STORE_PATH", "case_ledger.json")


def _open_graph_driver():
    if not NEO4J_PASSWORD:
        return None
    try:
        return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    except Exception:
        return None


graph_db = _open_graph_driver()
GRAPH_STORE_LOCK = threading.Lock()
GRAPH_STORE = {
    "nodes": {},
    "edges": [],
}
CASE_LOCK = threading.Lock()
AUDIT_LOCK = threading.Lock()
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "audit_log.jsonl")
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
RATE_LIMITS = defaultdict(deque)
RATE_LIMIT_LOCK = threading.Lock()


def _load_case_ledger():
    if not os.path.exists(CASE_STORE_PATH):
        return []
    try:
        with open(CASE_STORE_PATH, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _persist_case_ledger():
    try:
        with open(CASE_STORE_PATH, "w", encoding="utf-8") as fh:
            json.dump(CASE_LEDGER, fh, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _append_audit(event_type: str, payload: dict):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "payload": payload,
    }
    try:
        with AUDIT_LOCK, open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


CASE_LEDGER = _load_case_ledger()


def _next_case_id() -> str:
    highest = 0
    for case_item in CASE_LEDGER:
        raw_id = str(case_item.get("id", ""))
        if raw_id.startswith("case-"):
            try:
                highest = max(highest, int(raw_id.split("-", 1)[1]))
            except ValueError:
                continue
    return f"case-{highest + 1:05d}"


class TargetQuery(BaseModel):
    selector: str = Field(..., examples=["Username", "Phone Number", "Crypto Wallet", "Telegram Handle", "IP Address", "UPI ID", "Email", "Domain"])
    value: str = Field(..., min_length=1)





def _record_case(query, extracted_data):
    case_entry = {
        "id": _next_case_id(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "indicator_type": query.selector,
        "indicator_value": query.value,
        "scammer_alias": extracted_data["scammer_alias"],
        "associated_email": extracted_data.get("associated_email"),
        "confidence_score": 1.0,
        "is_linked": False,
        "observation_state": extracted_data.get("observation_state", "inferred"),
        "source_reliability": extracted_data.get("source_reliability", 0.0),
        "public_sources": extracted_data.get("public_sources", {}),
        "source_hits": extracted_data.get("source_hits", []),
        "collector_hits": extracted_data.get("collector_hits", []),
        "raw_indicators": extracted_data.get("raw_indicators", {}),
    }
    with CASE_LOCK:
        CASE_LEDGER.insert(0, case_entry)
        del CASE_LEDGER[200:]
        _persist_case_ledger()
    _append_audit("case_created", case_entry)
    return case_entry


def _require_api_key(request: Request):
    if not API_KEY:
        return
    if request.headers.get("x-api-key", "").strip() != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _enforce_rate_limit(request: Request):
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMITS[client]
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(now)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        try:
            _require_api_key(request)
            _enforce_rate_limit(request)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.post("/api/investigate")
async def investigate_entity(query: TargetQuery, background_tasks: BackgroundTasks, request: Request):
    _require_api_key(request)
    
    # 1. Run modular IngestionOrchestrator
    orchestrator = IngestionOrchestrator()
    extracted_data = orchestrator.run(query.selector, query.value)
    
    # 2. Generate graph nodes and edges via CorrelationEngine
    subject_id = extracted_data["scammer_alias"]
    graph_elements = CorrelationEngine.correlate(
        subject_id=subject_id,
        resolved_entities=extracted_data["resolved_entities"],
        implicit_links=extracted_data["implicit_links"]
    )
    extracted_data["graph_elements"] = graph_elements
    
    # 3. Save to Neo4j database (async) and GRAPH_STORE in-memory fallback (sync)
    background_tasks.add_task(GraphWriter.write_to_neo4j, graph_elements)
    GraphWriter.write_in_memory(graph_elements, GRAPH_STORE, GRAPH_STORE_LOCK)
    
    # 4. Record case ledger entry
    case_entry = _record_case(query, extracted_data)
    
    # 5. Log audit trail
    _append_audit(
        "investigation_completed",
        {
            "case_id": case_entry["id"],
            "selector": query.selector,
            "value": query.value,
            "confidence_score": 1.0,
            "observation_state": extracted_data.get("observation_state", "inferred"),
            "source_reliability": extracted_data.get("source_reliability", 0.0),
        },
    )
    
    # Filter out non-serializable objects (like resolved_entities) from JSON response payload
    serializable_extracted = {k: v for k, v in extracted_data.items() if k not in {"resolved_entities", "implicit_links"}}
    
    return {
        "status": "Success",
        "input": query.value,
        "extracted_intelligence": serializable_extracted,
        "ai_analysis": {
            "is_linked_to_known_syndicates": False,
            "confidence_score": 1.0,
            "feature_vector": [1.0, 1.0, 1.0],
            "selector_hint": query.selector,
            "matched_cases": [],
            "model_note": "Looker OSINT active intelligence graph generation.",
        },
        "case": case_entry,
    }


@app.get("/api/graph")
async def get_graph_data(request: Request):
    _require_api_key(request)
    with GRAPH_STORE_LOCK:
        return list(GRAPH_STORE["nodes"].values()) + list(GRAPH_STORE["edges"])


@app.get("/api/cases")
async def get_cases(request: Request):
    _require_api_key(request)
    with CASE_LOCK:
        return CASE_LEDGER[:100]


@app.get("/api/audit")
async def get_audit_log(request: Request):
    _require_api_key(request)
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8-sig") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    except Exception:
        return []


@app.post("/api/v1/looker/investigate")
async def investigate_entity_v1(payload: TargetQuery, background_tasks: BackgroundTasks, request: Request):
    return await investigate_entity(payload, background_tasks, request)


@app.get("/api/v1/looker/network")
async def get_graph_data_v1(request: Request):
    return await get_graph_data(request)


@app.get("/", response_class=HTMLResponse)
async def serve_single_interface():
    html_path = Path(__file__).with_name("index.html.html")
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<html><body><h1>Interface not found</h1></body></html>")


if __name__ == "__main__":
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

