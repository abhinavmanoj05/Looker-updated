# User Guide

## What This System Does

- Accepts a public indicator such as a phone number, UPI ID, Telegram handle, crypto wallet, or IP address.
- Pulls public web evidence using OSINT-style collection.
- Extracts observed indicators from the collected text.
- Correlates the evidence with previous cases and a lightweight incremental model.
- Stores the result as a case entry and graph record.
- Lets an analyst approve or reject the inferred linkage so the model updates.

## What The Labels Mean

- `observed`: directly seen in a public source.
- `inferred`: pattern-based correlation from public evidence.
- `unresolved`: no useful public-source signal was collected.
- `confirmed`: manually validated by an analyst.

## Operator Protection

- Set `LOOKER_API_KEY` before deployment and enter that key in the interface.
- Keep `CORS_ORIGINS` restricted to trusted internal origins.
- The API applies simple per-client rate limiting to reduce accidental exposure.
- Audit entries are written to `audit_log.jsonl` for investigation traceability.
- Private, loopback, multicast, and reserved IPs are excluded from public geolocation enrichment.

## Start The App

1. Install the Python dependencies listed in `requirements.txt`.
2. Start the service:

```powershell
python app.py
```

3. Open the interface:

```text
http://localhost:8000/
```

## Recommended Environment Variables

- `LOOKER_API_KEY`
- `CORS_ORIGINS`
- `NEO4J_URI`
- `NEO4J_USER`
- `NEO4J_PASSWORD`
- `MODEL_PATH`
- `CASE_STORE_PATH`
- `AUDIT_LOG_PATH`
- `USERNAME_SOURCE_BUNDLE_PATH`

## Username Bundle Format

The username collector expects a JSON array at `USERNAME_SOURCE_BUNDLE_PATH`.
It returns only rows whose `username`, `query`, or `value` field matches the username you submit in the UI/API.

Each item should follow this shape:

```json
[
  {
    "site": "GitHub",
    "url": "https://github.com/example",
    "status": "claimed",
    "evidence": "Profile page exists and matches the username",
    "confidence": 0.93,
    "source": "whatsmyname"
  }
]
```

Field meaning:

- `site`: service or platform name
- `url`: profile or result URL
- `status`: your collector verdict, such as `claimed`, `available`, `taken`, or `unknown`
- `evidence`: short human-readable note
- `confidence`: optional score from `0.0` to `1.0`
- `source`: collector name or upstream tool
- `username` or `query` or `value`: the username this row belongs to

Where raw data goes:

- The collector bundle is read from `USERNAME_SOURCE_BUNDLE_PATH`
- The query you pass is the username string in `indicator_value`
- The normalized result is returned as `collector_hits` and `source_hits`
- The case ledger stores both `source_hits` and `collector_hits`
- Audit logs keep the investigation event, not the full bundle payload

## Typical Workflow

1. Choose an indicator type.
2. Enter the value.
3. Run OSINT correlation.
4. Review evidence, source hits, matched cases, and graph links.
5. Inspect the case ledger for past investigations.
6. Approve or reject the link if the analyst has validated it.

## Notes For Real Use

- This is a triage and correlation console, not proof of identity.
- Public-source evidence still needs analyst review and legal process.
- The graph updates after every investigation. The ML model updates from analyst-labelled feedback to avoid poisoning itself with unverified predictions.
- If Neo4j is unavailable, the system falls back to the local in-memory graph so the interface stays usable.
