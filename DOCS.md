# EDR-BETA — Developer Documentation

> **Stack**: Rust · Python (FastAPI) · PostgreSQL · Redis · RabbitMQ · Docker · eBPF · YARA · scikit-learn

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Directory Tree](#3-directory-tree)
4. [Flow Diagrams](#4-flow-diagrams)
5. [Setup & Installation](#5-setup--installation)
6. [Configuration Reference](#6-configuration-reference)
7. [Component Reference](#7-component-reference)
8. [API Reference](#8-api-reference)
9. [Database Reference](#9-database-reference)
10. [Deployment & Hardening](#10-deployment--hardening)
11. [Skills Reference](#11-skills-reference)
12. [Known Gaps & TODOs](#12-known-gaps--todos)

---

## 1. Overview

**EDR-BETA** is a hybrid Endpoint Detection & Response (EDR) platform that combines a **Rust daemon** running on each monitored host with a **Python/FastAPI cloud backend** for centralized threat intelligence, ML-based malware scoring, and dynamic sandbox analysis.

When a new file appears in a monitored directory, the Rust agent:
1. Hashes it (SHA-256)
2. Scans it against local YARA signatures (offline, zero-latency detection)
3. Cross-references it against the backend reputation database
4. Uploads unknowns for a full analysis pipeline: **static analysis → ML inference → dynamic sandbox**

The platform is designed for minimal endpoint footprint (the Rust daemon binary is a few MB, statically compiled), maximum auditability (every quarantine action is append-logged), and layered detection (local YARA + cloud ML + Docker sandbox).

---

## 2. Architecture

### High-Level System

```mermaid
graph TD
    subgraph Endpoint["Endpoint Host (Linux)"]
        inotify["inotify / eBPF\nFilesystem Events"]
        daemon["av-daemon\n(Rust / Tokio)"]
        yara["YARA Engine\nsignatures.yar"]
        qsafe["quarantine_safe\nAtomic Isolation"]
        ebpf["eBPF Kernel Sensor\n(optional)"]
    end

    subgraph Cloud["Cloud Backend"]
        api["FastAPI Gateway\n:8000"]
        mq["RabbitMQ\nTask Broker"]
        redis["Redis\nCache + Rate Limit"]
        pg["PostgreSQL\nThreat Intel DB"]

        subgraph Workers["Async Workers"]
            w_static["static_worker\nLIEF + Entropy"]
            w_ml["ml_worker\nRandomForest"]
            w_sandbox["sandbox_worker\nDocker + strace"]
        end

        subgraph Services["Backend Services"]
            s_static["static_analyzer.py"]
            s_ml["ml_inference.py"]
            s_rep["reputation.py"]
        end
    end

    subgraph Storage["Storage"]
        s3["Object Store\n/tmp/object-store"]
        quarantine_fs["/opt/antivirus/quarantine"]
        model["models/\nrf_malware_model.pkl"]
        sigdb["signatures/\nsignatures.yar"]
    end

    subgraph Dashboard["Dashboard"]
        fe["frontend/index.html\nStatic HTML/JS"]
    end

    inotify -->|file path| daemon
    ebpf -.->|kernel events| daemon
    daemon -->|scan| yara
    yara -->|YARA hit| qsafe
    qsafe --> quarantine_fs
    daemon -->|HTTPS| api
    api --> mq
    api --> redis
    api --> pg
    mq --> w_static
    mq --> w_ml
    mq --> w_sandbox
    w_static --> s_static
    w_ml --> s_ml
    w_ml --> s_rep
    w_sandbox --> s3
    s_ml --> model
    yara --> sigdb
    api -->|serve| fe
```

---

## 3. Directory Tree

```
EDR-BETA/
├── .env                          # Runtime secrets (DATABASE_URL, REDIS_URL, etc.)
├── .agents/
│   └── skills/                   # Project-scoped AI agent skills (8 total)
├── docker-compose.yml            # Full stack: postgres, redis, rabbitmq, api, 3 workers
│
├── agent/                        # Rust EDR daemon
│   ├── Cargo.toml                # Workspace manifest + all crate deps
│   ├── config.json               # Agent runtime config (no secrets)
│   └── src/
│       ├── main.rs               # Entrypoint: event loop, YARA scan, policy dispatch
│       ├── config.rs             # Config struct + JSON loader
│       ├── monitor.rs            # inotify filesystem watcher (notify crate)
│       ├── ebpf_monitor.rs       # eBPF kernel sensor (Aya crate, optional)
│       ├── scanner.rs            # SHA-256 hasher + LRU verdict cache
│       ├── scanner/
│       │   ├── mod.rs            # Scanner subsystem public API
│       │   └── yara_engine.rs    # YARA FFI wrapper, spawn_blocking scan
│       ├── quarantine_safe.rs    # Atomic quarantine + metadata sidecar + audit log
│       ├── policy_engine.rs      # Policy dispatcher → quarantine_safe
│       ├── api_client.rs         # HTTP client: hash lookup, file upload, poll verdict
│       └── offline_queue.rs      # JSONL queue for offline resilience
│
├── signatures/
│   ├── signatures.yar            # 7 YARA rules (ClamAV-compatible)
│   └── manifest.json             # Signature version + changelog
│
├── backend/                      # Python FastAPI backend
│   ├── main.py                   # App entrypoint: lifespan pool, routers, SlowAPI
│   ├── requirements.txt          # All Python deps
│   ├── alembic.ini               # Alembic migration config
│   ├── Dockerfile                # Container image for api + workers
│   │
│   ├── core/
│   │   ├── config.py             # Pydantic Settings (all env vars)
│   │   ├── schemas.py            # Shared APIResponse model
│   │   └── cache.py              # Redis client wrapper
│   │
│   ├── auth/
│   │   └── dependencies.py       # bcrypt agent-key + JWT dashboard auth
│   │
│   ├── api/
│   │   ├── routes.py             # Agent API: /upload, /hash/{sha256}, /report/{task_id}
│   │   └── dashboard_routes.py   # Dashboard: /stats, /reports
│   │
│   ├── routers/                  # AV management routers (new)
│   │   ├── scans.py              # /av/scans — trigger + status + close
│   │   ├── quarantine.py         # /av/quarantine — list / restore / delete
│   │   └── signatures.py        # /av/signatures — list + HTTPS update
│   │
│   ├── database/
│   │   ├── schema.sql            # Canonical Postgres schema (6 AV tables)
│   │   └── pool.py               # asyncpg pool (created once at lifespan)
│   │
│   ├── db/
│   │   ├── models.py             # SQLAlchemy ORM models (existing 5 tables)
│   │   └── session.py            # AsyncSessionLocal factory
│   │
│   ├── services/
│   │   ├── static_analyzer.py    # LIEF parser: entropy, imports, file type
│   │   ├── ml_inference.py       # RandomForest scorer (joblib model load)
│   │   └── reputation.py         # classify_risk + compute_confidence
│   │
│   ├── workers/
│   │   ├── static_worker.py      # Consumes static-analysis-queue
│   │   ├── ml_worker.py          # Consumes ml-inference-queue
│   │   └── sandbox_worker.py     # Consumes sandbox-queue
│   │
│   ├── broker/
│   │   └── producer.py           # aio_pika publish helper
│   │
│   └── migrations/
│       ├── env.py                # Alembic env (asyncpg→psycopg2 URL swap)
│       └── versions/
│           └── 0001_av_suite_tables.py   # Initial AV schema migration
│
├── models/
│   └── train.py                  # RandomForest training script
│
├── sandbox/
│   ├── Dockerfile                # deadsec/sandbox image with strace
│   ├── runner.py                 # Docker-based sandbox orchestrator
│   ├── tracer.sh                 # strace wrapper script inside container
│   └── requirements.txt         # docker SDK
│
├── frontend/
│   └── index.html                # Single-page dashboard (served by FastAPI)
│
├── systemd/
│   └── antivirus.service         # Hardened systemd unit
│
└── tests/
    └── signatures/
        ├── generate_corpus.py    # Creates malicious/ + clean/ test samples
        └── test_yara_rules.py    # 16 pytest tests (true-positive + FP per rule)
```

---

## 4. Flow Diagrams

### 4.1 — File Detection Pipeline (Agent)

```mermaid
flowchart TD
    A["inotify / eBPF\nFile Create Event"] --> B["compute_sha256()"]
    B --> C{"In processing\nqueue?"}
    C -- Yes --> SKIP["Skip\n(deduplicate)"]
    C -- No --> D["Add to processing queue"]
    D --> E["YARA scan\nyara_engine::scan_file()"]
    E --> F{"YARA hit?"}
    F -- Yes --> G["policy_engine::\nenforce_quarantine()"]
    G --> H["quarantine_safe::\nquarantine_file()"]
    H --> I["Atomic rename\n+ chmod 0o600\n+ .meta.json sidecar\n+ Audit log"]
    I --> J["Cache verdict\nmalicious/100.0"]
    J --> K["Remove from queue"]
    F -- No --> L{"LRU cache\nhit?"}
    L -- Yes --> M["apply_policy()\n→ verdict from cache"]
    L -- No --> N["api_client::\nlookup_hash()"]
    N --> O{"Backend\nverdict found?"}
    O -- Yes --> P["Cache + apply_policy()"]
    O -- No --> Q["api_client::\nupload_file()"]
    Q --> R["api_client::\npoll_task_status()"]
    R --> S{"Verdict\nreceived?"}
    S -- Yes --> T["Cache + apply_policy()"]
    S -- No/Error --> U["offline_queue::\nenqueue()"]
    M --> K
    P --> K
    T --> K
    U --> K
```

### 4.2 — YARA Engine Internals

```mermaid
sequenceDiagram
    participant Loop as main.rs Event Loop
    participant Engine as YaraEngine (Arc)
    participant Blocking as spawn_blocking thread
    participant LibYARA as libyara (FFI)

    Loop->>Engine: Arc::clone() — zero cost
    Loop->>Blocking: tokio::task::spawn_blocking(scan_file)
    Note over Blocking: CPU-bound work moves off Tokio thread pool
    Blocking->>LibYARA: Compiler::new() → add_rules_file()
    LibYARA-->>Blocking: compiled Rules
    Blocking->>LibYARA: rules.scan_file(path, timeout=30s)
    LibYARA-->>Blocking: Vec<Match>
    Blocking->>Blocking: Extract severity + description from metadata
    Blocking-->>Loop: Ok(Vec<YaraMatch>)
    Loop->>Loop: Hit → quarantine immediately, skip backend
    Loop->>Loop: Miss → fall through to backend lookup
```

### 4.3 — Backend File Analysis Pipeline

```mermaid
flowchart LR
    AGENT["av-daemon\n(Rust)"] -->|POST /api/v1/upload\nX-Agent-Key + X-Agent-ID| API

    subgraph API["FastAPI Gateway :8000"]
        AUTH["verify_agent_key()\nbcrypt check"]
        UPLOAD["upload endpoint\nstream → hash → dedup"]
        PG_WRITE["INSERT FileMetadata\nTaskStatus.PENDING"]
        PUBLISH["publish_task()\nstatic-analysis-queue"]
    end

    AUTH --> UPLOAD --> PG_WRITE --> PUBLISH

    PUBLISH -->|aio_pika| MQ["RabbitMQ"]

    subgraph W1["static_worker"]
        DL["simulate_s3_download()"]
        SA["static_analyzer.analyze_file()\nLIEF: entropy, imports, type"]
        DB1["INSERT StaticFeatures"]
        PUB2["publish ml-inference-queue"]
    end

    subgraph W2["ml_worker"]
        ML["ml_inference.evaluate_risk()\nRandomForest predict_proba"]
        REP["reputation.persist()\nclassify_risk + compute_confidence"]
        CACHE["Redis set_json\nhash:{sha256} TTL=24h"]
        STATUS["FileMetadata.status = COMPLETED"]
        COND{{"risk_score\n40–90?"}}
        PUB3["publish sandbox-queue"]
    end

    subgraph W3["sandbox_worker"]
        DOCKER["SandboxRunner.analyze_file()\nDocker + strace, network=none"]
        PARSE["_parse_results()\nstrace log heuristics"]
        COMBINE["Combined score\nML + sandbox * 10"]
        DB3["UPDATE Reputation"]
    end

    MQ --> W1
    DL --> SA --> DB1 --> PUB2
    PUB2 -->|aio_pika| MQ
    MQ --> W2
    ML --> REP --> CACHE --> STATUS
    STATUS --> COND
    COND -- Yes --> PUB3
    PUB3 -->|aio_pika| MQ
    MQ --> W3
    DOCKER --> PARSE --> COMBINE --> DB3
```

### 4.4 — Reputation Scoring Model

```mermaid
flowchart TD
    A["ML risk_score 0–100\nRF predict_proba * 100"] --> B["classify_risk()"]
    B --> C{"risk_score ≥ dynamic_malicious?\nmax(50, 70 - freq×0.2)"}
    C -- Yes --> D["classification = malicious"]
    C -- No --> E{"risk_score ≥ 40\nSUSPICIOUS_THRESHOLD"}
    E -- Yes --> F["classification = suspicious"]
    E -- No --> G["classification = benign"]

    A --> H["compute_confidence()"]
    H --> I["risk_score × 0.65"]
    H --> J["prev_confidence × 0.20"]
    H --> K["frequency_bonus = min(15, freq×0.5)"]
    H --> L["recency_bonus = max(0, 10 - delta_hours/12)"]
    I & J & K & L --> M["blended = sum, clamp 0–100"]

    D & F & G --> N["Persist Reputation table"]
    M --> N
    N --> O["Redis cache\nhash:{sha256} TTL 24h"]

    subgraph SandboxAdjust["Sandbox Score Adjustment"]
        SA["dyn_score = sandbox_risk × 10"]
        SC["combined = ML_score + dyn_score\nclamped to 100"]
        SB{{"combined > 75?"}}
        SM["→ malicious"]
        SS["→ suspicious (>40)"]
    end

    N -.->|if suspicious route| SandboxAdjust
    SandboxAdjust --> DB["UPDATE Reputation"]
```

### 4.5 — Quarantine Workflow

```mermaid
stateDiagram-v2
    [*] --> Detected: YARA hit or backend verdict=malicious

    Detected --> QuarantineAttempt: enforce_quarantine()

    QuarantineAttempt --> SameFS: fs::rename() succeeds
    QuarantineAttempt --> CrossDevice: EXDEV error

    CrossDevice --> CopyVerify: fs::copy() to quarantine
    CopyVerify --> HashCheck: compute_sha256(dest) == original
    HashCheck --> DeleteSource: match ✓
    HashCheck --> Abort: mismatch — original intact
    DeleteSource --> SameFS

    SameFS --> StripBits: chmod 0o600
    StripBits --> WriteSidecar: .meta.json\n{original_path, sha256,\nsignature_id, severity,\ntimestamp, daemon_version}
    WriteSidecar --> AuditLog: structured JSON log\nfor backend ingestion

    AuditLog --> Quarantined

    Quarantined --> RestoreRequest: Admin action via\nav-cli or dashboard
    Quarantined --> DeleteRequest: Admin action +\nconfirmed=true

    RestoreRequest --> UpdateDB: restored=TRUE\nrestored_by=actor
    UpdateDB --> AuditEntry: av_audit_log\nquarantine_restore
    AuditEntry --> [*]

    DeleteRequest --> UpdateDB2: deleted=TRUE\ndeleted_by=actor
    UpdateDB2 --> AuditEntry2: av_audit_log\nquarantine_delete
    AuditEntry2 --> [*]
```

### 4.6 — API Authentication Flow

```mermaid
sequenceDiagram
    participant Daemon as av-daemon (Rust)
    participant GW as FastAPI Gateway
    participant Auth as auth/dependencies.py
    participant BCrypt as bcrypt
    participant Router as AV Router

    Daemon->>GW: POST /av/scans/trigger\nHeaders: X-Agent-Key: <key>\n         X-Agent-ID: agent-linux-alpha-01

    GW->>Auth: verify_agent_key(request, api_key, agent_id)
    Auth->>BCrypt: checkpw(api_key, AGENT_API_HASH)
    BCrypt-->>Auth: True / False

    alt Key valid
        Auth->>GW: request.state.agent_id = "agent-linux-alpha-01"
        GW->>Router: route handler called
        Router-->>Daemon: 202 Accepted + scan_id
    else Key invalid
        Auth->>GW: HTTP 401 Unauthorized
        Note over Auth: Logs WARNING with agent_id only\nNEVER logs raw api_key
        GW-->>Daemon: 401 {"message":"Unauthorized agent"}
    end
```

### 4.7 — Sandbox Execution Flow

```mermaid
flowchart TD
    TRG["sandbox_worker\nreceives sandbox-queue msg"] --> CHK{"File exists at\n/tmp/sandbox_uploads/{hash}.bin?"}
    CHK -- No --> ERR["Log error, return"]
    CHK -- Yes --> DIRS["Create temp dirs\npayload_dir + output_dir"]
    DIRS --> COPY["shutil.copy2()\nbinary → /sandbox_in/"]
    COPY --> RUN["docker.containers.run()\nimage=deadsec/sandbox:latest\nnetwork_mode=none\nmem_limit=256m\ncpu_quota=50000\ncap_drop=ALL\ncap_add=SYS_PTRACE\npids_limit=50"]
    RUN --> TRACE["tracer.sh runs strace\ninside container"]
    TRACE --> WAIT["container.wait(timeout+10)"]
    WAIT --> PARSE["_parse_results()\nParse strace.log"]
    PARSE --> HEUR["Heuristics:\n• execve → +1\n• socket/connect → +2\n• /etc/shadow → +3\n• network_activity flag"]
    HEUR --> CLEAN["container.remove(force=True)\nCleanup temp dirs"]
    CLEAN --> SCORE["combined_score =\nML_risk + dyn_risk×10\nclamped 0–100"]
    SCORE --> VERDICT{{"combined > 75?"}}
    VERDICT -- Yes --> MAL["classification = malicious\nis_malicious = True"]
    VERDICT -- No --> SUS{{"combined > 40?"}}
    SUS -- Yes --> SUSP["classification = suspicious"]
    SUS -- No --> OK["No change"]
    MAL & SUSP & OK --> DB["UPDATE Reputation + DynamicFeatures"]
```

### 4.8 — Offline Resilience Flow

```mermaid
flowchart TD
    A["Next file event arrives"] --> B["flush_offline_queue()"]
    B --> C{"Queue empty?"}
    C -- Yes --> D["Process new event"]
    C -- No --> E["For each QueuedEvent:"]
    E --> F{"Event file\nstill exists?"}
    F -- No --> G["Discard stale event"]
    F -- Yes --> H["api.lookup_hash(sha256)"]
    H --> I{"Verdict found?"}
    I -- Yes --> J["Cache + apply_policy()"]
    J --> K["Remove from queue"]
    I -- No/Error --> L["Keep in remaining[]"]
    G & K & L --> M["offline_queue::rewrite()\nremaining events"]
    M --> D
    D --> N["Normal detection pipeline"]
```

---

## 5. Setup & Installation

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Rust | 1.75+ | `rustup toolchain install stable` |
| libyara-dev | 4.x | `apt install libyara-dev` / `dnf install yara-devel` |
| Python | 3.11+ | |
| Docker Engine | 24+ | Required for sandbox worker |
| PostgreSQL | 15+ | Via Docker or host install |
| Redis | 7+ | Via Docker or host install |
| RabbitMQ | 3.12+ | Via Docker or host install |

### Quick Start (Docker Compose)

```bash
# 1. Clone and set up environment
git clone https://github.com/noble6/EDR-BETA
cd EDR-BETA
cp .env .env.local     # edit secrets before use

# 2. Start all backend services
docker compose up -d postgres redis rabbitmq

# 3. Run database migrations
cd backend
DATABASE_URL=postgresql+psycopg2://threatuser:threatpass@localhost:5432/threatdb \
  alembic upgrade head

# 4. Start the API and workers
docker compose up -d api worker_static worker_ml worker_sandbox

# 5. Build and run the Rust daemon (on monitored host)
cd ../agent
cargo build --release
# Edit config.json with correct api_url, api_key, signatures_path
./target/release/hybrid-edr-agent
```

### Build the Rust Daemon

```bash
cd agent
# Requires libyara-dev on the build host
cargo build --release
# Binary at: target/release/hybrid-edr-agent
```

### Train the ML Model (first run only)

```bash
cd models
pip install scikit-learn pandas joblib
python train.py
# Outputs: models/saved_models/rf_malware_model.pkl
```

### Generate YARA Test Corpus

```bash
cd tests/signatures
python generate_corpus.py
pytest test_yara_rules.py -v
```

---

## 6. Configuration Reference

### `agent/config.json` (Rust daemon)

| Field | Type | Default | Description |
|---|---|---|---|
| `api_url` | string | `http://127.0.0.1:8000/api/v1` | Backend API base URL |
| `api_key` | string | `prod-agent-key-change-me` | Agent API key — **must be rotated** |
| `agent_id` | string | `agent-linux-alpha-01` | Unique identifier for this endpoint |
| `monitor_dir` | string | `/tmp/monitor` | Directory to watch for new files |
| `quarantine_dir` | string | `/tmp/quarantine` | Quarantine root (must match `ReadWritePaths` in unit file) |
| `cache_capacity` | integer | `2048` | LRU verdict cache size (# SHA-256 entries) |
| `offline_queue_path` | string | `/tmp/edr/offline-queue.jsonl` | JSONL queue for offline resilience |
| `signatures_path` | string? | `/opt/antivirus/signatures/signatures.yar` | Path to YARA `.yar` rule file |

### `.env` (Docker / Backend)

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` | `threatuser` | PostgreSQL username |
| `POSTGRES_PASSWORD` | `threatpass` | PostgreSQL password — **change in production** |
| `POSTGRES_DB` | `threatdb` | Database name |
| `DATABASE_URL` | `postgresql+asyncpg://threatuser:threatpass@postgres:5432/threatdb` | Full async DSN |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `RABBITMQ_URL` | `amqp://guest:guest@rabbitmq:5672/` | RabbitMQ AMQP URL |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `REPORT_POLL_BASE_DELAY_SEC` | `5` | Initial poll delay for task status |

### `backend/core/config.py` (Pydantic Settings)

| Setting | Default | Description |
|---|---|---|
| `PROJECT_NAME` | `Hybrid EDR Platform - API Gateway` | FastAPI title |
| `API_V1_STR` | `/api/v1` | Agent API router prefix |
| `MAX_UPLOAD_SIZE` | `52428800` (50 MB) | Max file upload size |
| `ALLOWED_EXTENSIONS` | `.exe .elf .dll .so .bin .sh .py .pdf .doc .docx` | Accepted file types |
| `AGENT_API_HASH` | `$2b$12$...` | bcrypt hash of the agent API key |
| `SUSPICIOUS_THRESHOLD` | `40.0` | Risk score boundary for suspicious |
| `MALICIOUS_THRESHOLD` | `70.0` | Risk score boundary for malicious |
| `REPORT_POLL_BASE_DELAY_SEC` | `2` | Agent poll base delay |
| `REPORT_POLL_MAX_DELAY_SEC` | `12` | Agent poll max delay |
| `REPORT_POLL_MAX_ATTEMPTS` | `8` | Agent poll max retries |

---

## 7. Component Reference

### 7.1 `av-daemon` (Rust)

**Responsibility**: Filesystem monitoring, YARA scanning, reputation lookup, quarantine enforcement, offline resilience.

**Entry point**: `agent/src/main.rs`

**Startup sequence**:
1. Load `config.json`
2. Compile YARA rules from `signatures_path` (fail-fast if invalid)
3. Mount optional eBPF kernel sensor (Aya); fall back to inotify on error
4. Spawn `monitor::start_monitoring()` on a synchronous thread
5. Enter `while let Some(path) = rx.recv().await` event loop

**Key modules**:

| Module | File | Responsibility |
|---|---|---|
| `scanner::yara_engine` | `src/scanner/yara_engine.rs` | YARA FFI wrapper; `spawn_blocking` scan |
| `quarantine_safe` | `src/quarantine_safe.rs` | Atomic quarantine, sidecar, audit log |
| `policy_engine` | `src/policy_engine.rs` | Routes verdict → quarantine_safe |
| `api_client` | `src/api_client.rs` | Backend HTTP: lookup, upload, poll |
| `offline_queue` | `src/offline_queue.rs` | JSONL persistence for offline events |
| `monitor` | `src/monitor.rs` | inotify watcher via `notify` crate |
| `ebpf_monitor` | `src/ebpf_monitor.rs` | eBPF kernel events via `aya` crate |
| `scanner` | `src/scanner.rs` | SHA-256 hasher, LRU `LocalCache` |

### 7.2 FastAPI Gateway

**Responsibility**: Agent API (upload/hash/report), AV management (scans/quarantine/signatures), dashboard data.

**Entry point**: `backend/main.py`

**Startup (lifespan)**:
1. `create_pool(dsn)` → asyncpg connection pool (min=2, max=20)
2. Attach `SlowAPI` rate limiter
3. Register all routers
4. On shutdown: `close_pool()`

### 7.3 Static Worker

**File**: `backend/workers/static_worker.py`
**Queue**: `static-analysis-queue` (RabbitMQ, durable, prefetch=10)

Reads a file from the object store, runs `static_analyzer.analyze_file()` (LIEF), persists `StaticFeatures`, then publishes to `ml-inference-queue`.

### 7.4 ML Worker

**File**: `backend/workers/ml_worker.py`
**Queue**: `ml-inference-queue` (RabbitMQ, durable, prefetch=10)

Receives static features, runs `ml_inference.evaluate_risk()` (RandomForest via joblib, `asyncio.to_thread`), persists `Reputation`, caches result in Redis (TTL 24h), routes suspicious files (40–90 risk) to `sandbox-queue`.

**Model**: `models/saved_models/rf_malware_model.pkl`  
**Features used**: `entropy`, `imports_count`, `strings_count`

### 7.5 Sandbox Worker

**File**: `backend/workers/sandbox_worker.py`
**Queue**: `sandbox-queue` (RabbitMQ, durable, prefetch=2)

Spawns `deadsec/sandbox:latest` Docker container with:
- `network_mode=none`
- `mem_limit=256m`
- `cpu_quota=50000` (50%)
- `cap_drop=ALL`, `cap_add=SYS_PTRACE`
- `pids_limit=50`

Runs `tracer.sh` inside container (strace wrapper). Parses strace output for `execve`, `socket`/`connect`, `/etc/shadow` access. Combines sandbox score with ML score to update `Reputation`.

### 7.6 Sandbox Image

**File**: `sandbox/runner.py`, `sandbox/tracer.sh`, `sandbox/Dockerfile`

The sandbox container is isolated: no internet, limited memory/CPU, no root capabilities except `SYS_PTRACE`. Output logs are written to `/sandbox_out/strace.log`, then parsed outside the container.

### 7.7 YARA Signatures

**File**: `signatures/signatures.yar`

7 rules — all ClamAV-compatible (≤64 strings, no modules, no global rules):

| Rule ID | Severity | Detects |
|---|---|---|
| `EICAR_Test_File` | low | EICAR standard test string |
| `Trojan_Generic_ObfuscatedPS1_Dropper` | high | IEX + download-cradle + EncodedCommand |
| `Backdoor_Linux_BashReverseShell` | high | /dev/tcp redirect, nc -e, python socket |
| `Dropper_Polyglot_ELF_PE_Embed` | medium | ELF magic at offset 0 + embedded MZ/PE |
| `Loader_Generic_XOR_Shellcode_Stub` | medium | XOR decode loop byte patterns |
| `CoinMiner_XMRig_Config_Strings` | medium | XMRig user-agent and pool JSON |
| `Ransomware_ShadowCopy_Deletion` | high | vssadmin/wmic delete + ransom note strings |

### 7.8 Static Analyzer

**File**: `backend/services/static_analyzer.py`

Pure Python + LIEF. Extracts:
- `file_type`: PE / ELF / UNKNOWN
- `entropy`: Shannon entropy (0.0–8.0)
- `imports`: imported DLL functions (PE) or dynamic symbols (ELF)
- `strings_count`: printable ASCII strings ≥ 5 chars

### 7.9 Dashboard

**File**: `frontend/index.html`

Single-page HTML dashboard served statically by FastAPI (`/dashboard`). Consumes `GET /api/dashboard/stats` and `GET /api/dashboard/reports`.

---

## 8. API Reference

### Agent API (prefix: `/api/v1`)
> Auth: `X-Agent-Key` (bcrypt) + `X-Agent-ID` headers required on all routes.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/upload` | Upload a file for analysis. Returns `task_id`. |
| `GET` | `/api/v1/hash/{sha256}` | Reputation lookup by SHA-256. Redis-cached 24h. |
| `GET` | `/api/v1/report/{task_id}` | Poll scan verdict for a task. Includes sandbox data when available. |

### AV Management API (prefix: `/av`)
> Auth: same `X-Agent-Key` + `X-Agent-ID` headers.

#### Scans

| Method | Path | Rate Limit | Description |
|---|---|---|---|
| `POST` | `/av/scans/trigger` | SlowAPI (configurable) | Trigger a new scan cycle for a host |
| `GET` | `/av/scans/{scan_id}` | — | Get scan status + detection count |
| `PATCH` | `/av/scans/{scan_id}/complete` | — | Daemon closes out a completed scan |

#### Quarantine

| Method | Path | Description |
|---|---|---|
| `GET` | `/av/quarantine/` | List quarantine items. Params: `host_id`, `active_only`, `limit`, `offset` |
| `POST` | `/av/quarantine/{quarantine_id}/restore` | Restore file. Body: `{reason: str}`. Writes audit log. |
| `DELETE` | `/av/quarantine/{quarantine_id}` | Delete file. Body: `{reason: str, confirmed: true}`. Writes audit log. |

#### Signatures

| Method | Path | Rate Limit | Description |
|---|---|---|---|
| `GET` | `/av/signatures/` | — | List signature versions, most recent first |
| `POST` | `/av/signatures/update` | SlowAPI (configurable) | Fetch + register new YARA archive (HTTPS-only URL) |

### Dashboard API (prefix: `/api/dashboard`)
> No auth (served for internal dashboard only — restrict in production).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/dashboard/stats` | Counts: total, malicious, suspicious, benign |
| `GET` | `/api/dashboard/reports` | Paginated reputation list. Params: `skip`, `limit`, `classification`, `search` |

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{"status":"success","data":{"version":"1.0.0"}}` |

---

## 9. Database Reference

### Existing Tables (SQLAlchemy ORM — `db/models.py`)

#### `file_metadata`
| Column | Type | Description |
|---|---|---|
| `id` | Integer PK | Sequential (legacy) |
| `sha256` | String(64) UNIQUE | File hash |
| `size` | Integer | File size in bytes |
| `mime_type` | String(50) | MIME type |
| `first_seen` | DateTime | Upload timestamp |
| `task_id` | String(36) | UUID of analysis task |
| `status` | Enum | PENDING / PROCESSING / COMPLETED / FAILED |
| `agent_id` | String(50) | Reporting agent |

#### `reputation`
| Column | Type | Description |
|---|---|---|
| `sha256` | String(64) UNIQUE | File hash |
| `is_malicious` | Boolean | Binary verdict |
| `classification` | String(16) | benign / suspicious / malicious |
| `risk_score` | Float | 0–100 (ML output) |
| `confidence_score` | Float | 0–100 (blended confidence) |
| `frequency` | Integer | Times seen |
| `first_seen` | DateTime | First detection |
| `last_seen` | DateTime | Most recent detection |
| `tags` | Text | JSON list (e.g. `["Ransomware","Trojan"]`) |

#### `static_features`
| Column | Type | Description |
|---|---|---|
| `task_id` | String(36) UNIQUE | Analysis task UUID |
| `sha256` | String(64) | File hash |
| `file_type` | String(20) | PE / ELF / UNKNOWN |
| `entropy` | Float | Shannon entropy |
| `imports_count` | Integer | Number of imported functions |
| `strings_count` | Integer | Number of extracted strings |
| `raw_data` | Text | JSON: `{imports: [...], metadata: {...}}` |

#### `dynamic_features`
| Column | Type | Description |
|---|---|---|
| `task_id` | String(36) UNIQUE | Analysis task UUID |
| `sha256` | String(64) | File hash |
| `risk_score` | Float | Sandbox risk score |
| `network_activity` | Boolean | True if socket/connect syscalls detected |
| `suspicious_actions` | Text | JSON list of behavioral flags |
| `syscalls` | Text | JSON dict: `{execve: N, open: N, network: N}` |

### AV Suite Tables (asyncpg native — `database/schema.sql`)

| Table | PK Type | Key Foreign Keys | Purpose |
|---|---|---|---|
| `signature_versions` | UUID | — | YARA release tracking |
| `daemon_health_checks` | UUID | → `signature_versions` | Per-host heartbeat |
| `scan_events` | UUID | → `signature_versions` | Scan cycle lifecycle |
| `detections` | UUID | → `scan_events` ON DELETE RESTRICT | Per-file YARA/backend hits |
| `quarantine_records` | UUID | → `detections` ON DELETE RESTRICT | Quarantine state + restore/delete audit |
| `av_audit_log` | UUID | — | Append-only action audit trail |

---

## 10. Deployment & Hardening

### Docker Compose Services

| Service | Image | Port | Role |
|---|---|---|---|
| `postgres` | `postgres:15-alpine` | 5432 | Primary database |
| `redis` | `redis:7-alpine` | 6379 | Cache + rate limit tokens |
| `rabbitmq` | `rabbitmq:3-management-alpine` | 5672, 15672 | Task broker + management UI |
| `api` | `backend/Dockerfile` | 8000 | FastAPI gateway |
| `worker_static` | `backend/Dockerfile` | — | Static analysis consumer |
| `worker_ml` | `backend/Dockerfile` | — | ML inference consumer |
| `worker_sandbox` | `backend/Dockerfile` | — | Sandbox consumer (mounts Docker socket) |

### systemd Unit (`systemd/antivirus.service`)

| Directive | Value | Effect |
|---|---|---|
| `User / Group` | `avd` | Dedicated least-privilege service account |
| `ProtectSystem` | `strict` | Filesystem read-only except `ReadWritePaths` |
| `ReadWritePaths` | `/opt/antivirus/quarantine /opt/antivirus/logs` | Only two paths writable |
| `PrivateTmp` | `true` | Private `/tmp` namespace |
| `NoNewPrivileges` | `true` | Blocks setuid escalation |
| `ProtectHome` | `true` | No home directory access |
| `CapabilityBoundingSet` | `CAP_DAC_READ_SEARCH` | Only required capability for scanning |
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6` | IPC + backend only |
| `SystemCallFilter` | `@system-service ~@privileged ~@resources ~@obsolete` | Syscall allowlist |
| `MemoryDenyWriteExecute` | `true` | Blocks JIT/shellcode injection |
| `ProtectProc` | `invisible` | Hides other processes from daemon |

> **Validate after deploy**: `systemd-analyze security antivirus.service` — target score < 4.0

---

## 11. Skills Reference

All 8 project skills loaded from `.agents/skills/`:

| Skill | Trigger Context |
|---|---|
| `dev-documentation-skill` | Generating developer docs, README, architecture docs |
| `db-schema-skill` | Designing/modifying `schema.sql` or Postgres DB |
| `fastapi-backend-skill` | Building/modifying `av-backend` FastAPI endpoints |
| `quarantine-handling-skill` | Implementing or reviewing quarantine logic |
| `rust-daemon-skill` | Writing/modifying the `av-daemon` Rust binary |
| `systemd-hardening-skill` | Writing/reviewing `antivirus.service` unit files |
| `testing-security-skill` | Writing tests for daemon or backend |
| `yara-signature-skill` | Authoring or validating YARA rules |

---

## 12. Known Gaps & TODOs

> [!WARNING]
> **AES-256 quarantine encryption** is not yet implemented. `quarantine_safe.rs` contains a `// TODO` marker. Until enabled, quarantined files are protected by stripped execute bits + filesystem path only.

> [!WARNING]
> **Sandbox image** (`deadsec/sandbox:latest`) is referenced by name but the image source is in `sandbox/Dockerfile`. The tag must be built locally (`runner.build_image()`) before the sandbox worker can execute. There is no public registry push step.

> [!WARNING]
> **Dashboard CORS** is `allow_origins=["*"]` in `main.py`. This is acceptable for daemon↔backend but must be restricted to the dashboard domain in production.

> [!NOTE]
> **ML model** (`rf_malware_model.pkl`) is not committed to the repository. It must be trained by running `models/train.py` before the ML worker can start. Add this to the CI/CD pipeline or provide a pre-trained artifact download step.

> [!NOTE]
> **S3/object storage** is currently mocked by `simulate_s3_download()` in `static_worker.py`. The boto3 dependency exists but is not wired to real S3/MinIO. File paths use `/tmp/object-store/` on the API host.

> [!NOTE]
> **No CI/CD config** found in the repository (no `.github/workflows/`, no `Makefile`, no `justfile`). Test suite and linting are not automatically enforced.

> [!NOTE]
> **`RABBITMQ_URL` in `ml_worker.py`** references a bare `RABBITMQ_URL` variable at line 127 without importing from settings — this will raise `NameError` at runtime when the sandbox-queue publish path is hit. Fix: replace with `settings.RABBITMQ_URL`.

> [!NOTE]
> **Legacy `enforce_quarantine_legacy()`** in `policy_engine.rs` is marked `#[deprecated]` and will be removed in a future release. Any remaining call-sites must be updated to use `enforce_quarantine()` with full YARA context.

> [!NOTE]
> **No mutual TLS (mTLS)** between av-daemon and the backend. `fastapi-backend-skill` requires HTTPS/mTLS for daemon↔backend communication. Currently only plain HTTPS is assumed in `api_client.rs`.

> [!TIP]
> **Next priority improvements** (suggested order):
> 1. Fix `RABBITMQ_URL` `NameError` in `ml_worker.py`
> 2. Wire real S3/MinIO in `static_worker.py`
> 3. Add CI pipeline (GitHub Actions: `cargo test`, `pytest`, YARA corpus)
> 4. Implement AES-256 quarantine encryption
> 5. Add mTLS between daemon and backend
> 6. Restrict CORS to dashboard domain
