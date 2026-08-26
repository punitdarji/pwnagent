# Pwnagent Cloud API — FastAPI Service Implementation

## Context

Build the FastAPI API service that wraps `run_pwnagent_scan()` as a cloud-accessible HTTP + WebSocket API. This is the core piece that lets the client exe connect to a hosted cloud service instead of running scans locally. We're building just the API code now — deployment/infra comes later.

The API service calls the same `run_pwnagent_scan()` function that `cli.py:run_cli()` calls today (at line 180), but exposes it over REST + WebSocket instead of a local CLI.

---

## Architecture Overview

```
CLIENT EXE                              AWS CLOUD
──────────                              ─────────
CLI args + config                       API Gateway (HTTPS + WSS)
     │                                       │
     ├── POST /v1/scans ──────────────► FastAPI Service (ECS Fargate)
     │   (targets, mode, model)              │
     │                                       ├── Validates API key (DynamoDB)
     ├── Upload source ───────────────► S3 (presigned URL)
     │                                       │
     │                                       ├── Enqueues scan (SQS)
     │                                       │
     │                                  Scan Worker (ECS Fargate Task)
     │                                       │
     │                                       ├── run_pwnagent_scan()
     │                                       ├── LLM calls (LiteLLM)
     │                                       ├── Agent coordination
     │                                       │
     │                                  Sandbox (ECS Fargate Task)
     │                                       │ (Kali + nmap + sqlmap + ...)
     │                                       │
     ├── WSS /v1/scans/{id}/stream ◄── Redis Pub/Sub (real-time events)
     │   (findings, agent status)
     │
     └── GET /v1/scans/{id}/report ◄── S3 (results bucket)
```

---

## What Runs Where

### Client Exe (Lightweight)
- CLI argument parsing (`pwnagent/interface/main.py`, `cli.py`)
- Config loading + API key management (`pwnagent/config/`)
- New `PwnagentCloudClient` — HTTP + WebSocket client
- Console rendering of streamed events (Rich)
- Report download and display

### Cloud Service
- `run_pwnagent_scan()` — the entire `pwnagent/core/` package
- Agent building (`pwnagent/agents/`)
- All tools (`pwnagent/tools/`)
- Sandbox lifecycle (`pwnagent/runtime/`)
- Report generation (`pwnagent/report/`)
- LLM provider routing (LiteLLM + OpenAI Agents SDK)

### The Split Boundary
`pwnagent/core/runner.py:101` — `run_pwnagent_scan()`. In cloud mode, the client never calls this function. Instead, it sends a REST request and receives events over WebSocket.

---

## Key Integration Points

| File | Line | What | Role |
|------|------|------|------|
| `pwnagent/runtime/backends.py` | 207 | `register_backend()` | Extension point for cloud sandbox backend |
| `pwnagent/core/runner.py` | 101 | `run_pwnagent_scan()` | The exact client/cloud boundary |
| `pwnagent/interface/cli.py` | 38 | `run_cli()` | Where hybrid mode branching occurs |
| `pwnagent/config/settings.py` | — | `Settings` | Add `CloudSettings` for API URL + key |
| `pwnagent/report/state.py` | — | `ReportState._save_artifacts()` | Adapt for S3 storage in cloud mode |
| `pwnagent/core/execution.py` | 37 | `StreamEventSink` | Event callback → Redis Pub/Sub → WebSocket |

---

## Files to Create

All new files go under `pwnagent/cloud/`.

### 1. `pwnagent/cloud/__init__.py`
Empty init.

### 2. `pwnagent/cloud/models.py`
Pydantic request/response models for the API:
- `ScanRequest` — targets, scan_mode, instruction, max_budget_usd, model
- `ScanResponse` — scan_id, status
- `ScanStatus` — scan_id, status, targets, findings_count, cost_usd, created_at, updated_at
- `FindingResponse` — vulnerability finding fields
- `UploadRequest` / `UploadResponse` — file metadata, presigned URL

### 3. `pwnagent/cloud/scan_manager.py`
In-memory scan lifecycle manager (replaces DynamoDB for now — can swap later):
- `ScanManager` class with a `dict[str, ScanRecord]` store
- `create_scan()` — generates scan_id, stores metadata, returns ScanRecord
- `get_scan()` / `list_scans()` / `update_status()` / `cancel_scan()`
- `ScanRecord` dataclass — scan_id, status, targets, config, asyncio.Task handle, results path, event queue
- Each scan gets an `asyncio.Queue` for event streaming

### 4. `pwnagent/cloud/api.py`
The main FastAPI application:

**REST endpoints:**
- `POST /v1/scans` — validates API key, creates scan, launches `_run_scan_task()` as background asyncio task
- `GET /v1/scans` — list scans (filter by API key/org)
- `GET /v1/scans/{scan_id}` — get scan status + finding count
- `DELETE /v1/scans/{scan_id}` — cancel running scan
- `GET /v1/scans/{scan_id}/findings` — list findings from ReportState
- `GET /v1/scans/{scan_id}/report` — return executive report markdown
- `GET /v1/scans/{scan_id}/sarif` — return SARIF JSON
- `GET /health` — health check

**WebSocket endpoint:**
- `WS /v1/scans/{scan_id}/stream` — authenticates via query param, reads from the scan's event queue, pushes JSON events to client

**Background scan task (`_run_scan_task`):**
- Builds the same `scan_config` dict that `cli.py:85-97` builds
- Creates a `ReportState` (same as `cli.py:99-101`)
- Sets `vulnerability_found_callback` to push `finding.new` events to the queue
- Provides an `event_sink` callback that translates SDK stream events into JSON and pushes to queue
- Calls `run_pwnagent_scan()` with the same parameters as `cli.py:180-187`
- On completion, pushes `scan.completed` event; on error, pushes `scan.failed`

**Auth middleware:**
- Simple API key check via `Authorization: Bearer <key>` header
- Keys stored in a config file or env var (`PWNAGENT_API_KEYS` — comma-separated list for MVP)
- FastAPI dependency that extracts and validates the key

### 5. `pwnagent/cloud/events.py`
Event type definitions and serialization:
- `ScanEvent` base with `type`, `scan_id`, `timestamp`
- Subtypes: `ScanStarted`, `ScanCompleted`, `ScanFailed`, `AgentSpawned`, `AgentStatus`, `ToolCall`, `ToolResult`, `FindingNew`, `UsageUpdate`
- `event_sink_factory(queue)` — returns a `StreamEventSink` callback compatible with `runner.py:113` that translates SDK events into `ScanEvent` objects and puts them on the asyncio.Queue

---

## Files to Modify

### 6. `pwnagent/config/settings.py`
Add `CloudSettings` to the `Settings` model:
```python
class CloudSettings(BaseSettings):
    api_url: str | None = Field(default=None, alias="PWNAGENT_CLOUD_URL")
    api_key: str | None = Field(default=None, alias="PWNAGENT_API_KEY")
```

### 7. `pyproject.toml`
Add console script entry point: `pwnagent-cloud = "pwnagent.cloud.api:main"`
Add optional dependency group `[cloud]`: `fastapi`, `uvicorn`, `websockets`

---

## How It Connects to Existing Code

The API service reuses the existing scan pipeline directly:

```
api.py:_run_scan_task()
  │
  ├── ReportState(scan_id)                    # same as cli.py:99
  ├── report_state.set_scan_config(config)    # same as cli.py:101
  ├── set_global_report_state(report_state)   # same as cli.py:135
  │
  └── run_pwnagent_scan(                      # same as cli.py:180
        scan_config=config,
        scan_id=scan_id,
        image=settings.runtime.image,
        local_sources=sources,
        interactive=False,
        max_budget_usd=request.max_budget_usd,
        model=request.model,
        event_sink=event_sink,                # NEW: pushes to asyncio.Queue
      )
```

The WebSocket endpoint reads from the same `asyncio.Queue` and pushes events to the client.

---

## Client-Cloud Communication Protocol

### REST API (`https://api.pwnagent.ai/v1`)

Auth: `Authorization: Bearer <api_key>` on every request.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/scans` | Start a new scan (targets, mode, instruction, model) |
| `GET` | `/scans` | List org's scans |
| `GET` | `/scans/{id}` | Get scan status + finding count |
| `DELETE` | `/scans/{id}` | Cancel a running scan |
| `GET` | `/scans/{id}/findings` | List findings (filter by severity) |
| `GET` | `/scans/{id}/report` | Download executive report (markdown) |
| `GET` | `/scans/{id}/sarif` | Download SARIF document |
| `POST` | `/scans/{id}/upload` | Get presigned S3 URL for source upload |

### WebSocket (Real-Time Streaming)

`wss://api.pwnagent.ai/v1/scans/{id}/stream?token=<api_key>`

Events pushed server → client:
- `scan.started`, `scan.completed`, `scan.failed`
- `agent.spawned`, `agent.status`
- `tool.call`, `tool.result`
- `finding.new` (real-time vulnerability discovery)
- `usage.update` (cost tracking)

### Source Upload Flow
1. Client calls `POST /scans/{id}/upload` with file metadata
2. Server returns presigned S3 PUT URL (15-min expiry)
3. Client uploads tarball directly to S3
4. Scan worker downloads from S3 into sandbox container

---

## API Key Auth (MVP)

For the initial version, API keys are stored as a simple comma-separated env var:
```
PWNAGENT_API_KEYS="key1,key2,key3"
```

A FastAPI dependency extracts the Bearer token from the Authorization header and checks it against this list. This can be swapped for DynamoDB later without changing the endpoint code.

---

## AWS Infrastructure (Production)

| Service | Role |
|---------|------|
| **API Gateway** | Public HTTPS + WSS endpoint, rate limiting, custom domain |
| **ALB** | Load balancer for API service |
| **ECS Fargate (Service)** | API service — always on, 2+ tasks, auto-scaling |
| **ECS Fargate (Tasks)** | Scan worker — one per scan, 2 vCPU / 4-8 GB RAM |
| **ECS Fargate (Tasks)** | Sandbox container — one per scan, NET_ADMIN + NET_RAW caps |
| **ECR** | Container image registry (API service + sandbox) |
| **S3** | Scan results + source uploads, KMS encrypted |
| **DynamoDB** | `api-keys` table, `scans` table, `orgs` table |
| **ElastiCache (Redis)** | Pub/Sub for real-time event streaming |
| **SQS** | Scan request queue + DLQ |
| **Secrets Manager** | LLM API keys, internal secrets |
| **CloudWatch** | Logging, metrics, cost alarms |
| **Route 53 + ACM** | DNS + TLS for api.pwnagent.ai |

---

## Migration Phases

### Phase 1: Cloud Backend Abstraction (2-3 weeks)
- Add `CloudSettings` to `settings.py`
- Create `pwnagent/cloud/` package skeleton
- Extract `StorageBackend` abstraction in `report/state.py` (Local + S3 implementations)
- Verify local Docker mode is unchanged

### Phase 2: Cloud API Service (3-4 weeks)
- Build FastAPI service with all REST endpoints
- Implement API key auth against DynamoDB
- Set up DynamoDB tables + S3 bucket
- Deploy infrastructure (Terraform/CDK)

### Phase 3: Cloud Scan Worker (3-4 weeks)
- Implement `CloudSandboxBackend` using ECS API
- Build scan worker: SQS consumer → `run_pwnagent_scan()` → results to S3
- Adapt `event_sink` to publish to Redis Pub/Sub

### Phase 4: WebSocket Streaming + Cloud Client (2-3 weeks)
- Add WebSocket endpoint to API service
- Redis Pub/Sub → WebSocket bridge
- Build `PwnagentCloudClient` and `run_cloud_scan()`
- Add hybrid mode detection in `cli.py`
- Create lightweight PyInstaller spec

### Phase 5: Hardening (2-3 weeks)
- Scan timeout watchdog + ECS task cleanup
- Per-org cost tracking + budget enforcement
- CloudWatch dashboards + alarms
- Security hardening (WAF, VPC endpoints, IAM)

---

## Hybrid Mode Logic

```
if PWNAGENT_CLOUD_URL + PWNAGENT_API_KEY are set:
    → Cloud mode: client sends REST request, streams events via WebSocket
else:
    → Local mode: existing behavior unchanged (Docker + run_pwnagent_scan locally)
```

All cloud code is additive. Zero changes to local Docker mode behavior.

---

## Verification

1. Start the API: `pwnagent-cloud` (or `uvicorn pwnagent.cloud.api:app`)
2. Health check: `curl http://localhost:8000/v1/health`
3. Start a scan:
   ```
   curl -X POST http://localhost:8000/v1/scans \
     -H "Authorization: Bearer test-key" \
     -H "Content-Type: application/json" \
     -d '{"targets": [{"original": "https://example.com", "type": "web_application"}], "scan_mode": "quick"}'
   ```
4. Stream events: `wscat -c "ws://localhost:8000/v1/scans/{scan_id}/stream?token=test-key"`
5. Get results: `curl -H "Authorization: Bearer test-key" http://localhost:8000/v1/scans/{scan_id}/report`
