# EDR-BETA — Hybrid Endpoint Detection & Response Platform

**EDR-BETA** is a production-grade, hybrid EDR platform combining a lightweight **Rust daemon** on each monitored host with a scalable **Python/FastAPI cloud backend** for centralized threat intelligence, ML-based malware scoring, YARA signature scanning, and Docker-isolated sandbox detonation.

> 📄 **Full developer documentation with Mermaid flow diagrams**: [`DOCS.md`](./DOCS.md)

---

## ✨ Key Features

### Endpoint Agent (Rust · `agent/`)
- **YARA Scanning** — Offline, zero-latency detection via `libyara` FFI. Rules compiled at startup; scanning offloaded to `spawn_blocking` so the Tokio event loop stays non-blocking.
- **Atomic Quarantine** — `quarantine_safe.rs` performs atomic rename (with cross-device copy-verify fallback), strips execute bits, writes a `.meta.json` sidecar, and appends a structured audit log.
- **eBPF Kernel Monitoring** — Optional `sys_enter_execve` interception via the Aya crate; falls back to inotify if unavailable.
- **Async Event Loop** — Built on Tokio + `notify` for real-time file drop interception.
- **Offline Resilience** — LRU verdict cache + JSONL offline queue keeps the daemon operational when the backend is unreachable.

### Cloud Backend (Python / FastAPI · `backend/`)
- **AV Management API** — Three new routers: `/av/scans`, `/av/quarantine`, `/av/signatures` (see [API Reference](./DOCS.md#8-api-reference)).
- **Microservices Pipeline** — Decoupled analysis via **RabbitMQ**: Static → ML → Sandbox worker chain.
- **ML Static Analysis** — Extracts PE/ELF attributes (entropy, imports, strings) via LIEF; evaluated by a Scikit-Learn `RandomForest` model.
- **Dynamic Sandbox** — Ambiguous files routed to an isolated Docker container (`deadsec/sandbox`, network=none, cap_drop=ALL) with `strace` heuristics.
- **Redis Caching** — 24h SHA-256 → verdict cache; also powers SlowAPI rate limiting.
- **PostgreSQL** — Dual schema: SQLAlchemy ORM tables (reputation, static/dynamic features) + asyncpg native AV suite tables (scan events, quarantine records, audit log).

### Signatures (`signatures/`)
- 7 ClamAV-compatible YARA rules covering EICAR, PowerShell droppers, bash reverse shells, polyglot loaders, XOR shellcode stubs, XMRig coinminers, and ransomware shadow copy deletion.

---

## 🏗 Architecture Overview

```text
[ Endpoint Host (Linux) ]
┌─────────────────────────────────────────────────────────────┐
│  inotify / eBPF  →  av-daemon (Rust/Tokio)                 │
│                        │                                    │
│          ┌─────────────┴──────────────┐                     │
│          ▼                            ▼                     │
│     YARA Engine               LRU Verdict Cache             │
│     signatures.yar            (2048 entries)                │
│          │                            │                     │
│          ▼ hit                        ▼ miss                │
│   quarantine_safe.rs          api_client (HTTPS)            │
│   atomic rename + audit       → backend lookup / upload     │
└─────────────────────────────────────────────────────────────┘
                          │ HTTPS
                          ▼
[ Cloud Backend ]
┌─────────────────────────────────────────────────────────────┐
│  FastAPI Gateway :8000                                      │
│  ├── /api/v1    (Agent API — upload / hash / report)        │
│  ├── /av        (AV Mgmt — scans / quarantine / signatures) │
│  └── /dashboard (Stats + paginated reputation)              │
│                                                             │
│  RabbitMQ Task Broker                                       │
│  ├── static-analysis-queue  → static_worker (LIEF)         │
│  ├── ml-inference-queue     → ml_worker (RandomForest)      │
│  └── sandbox-queue          → sandbox_worker (Docker/strace)│
│                                                             │
│  PostgreSQL :5432  ·  Redis :6379                           │
└─────────────────────────────────────────────────────────────┘
```

> See [`DOCS.md §4`](./DOCS.md#4-flow-diagrams) for full Mermaid flow diagrams of every pipeline stage.

---

## ⚡ Quick Start (Docker Compose)

### Prerequisites

| Tool | Version |
|---|---|
| Docker Engine | 24+ |
| Docker Compose | v2 |
| Rust (stable) | 1.75+ |
| libyara-dev | 4.x |
| Python | 3.11+ |

### 1. Start Backend Services

```bash
git clone https://github.com/noble6/EDR-BETA
cd EDR-BETA

# Build the sandbox image first
cd sandbox && docker build -t deadsec/sandbox:latest . && cd ..

# Launch all services
docker compose --env-file .env up -d --build
```

Access the dashboard at: **http://localhost:8000/dashboard**

### 2. Run Database Migrations

```bash
cd backend
DATABASE_URL=postgresql+psycopg2://threatuser:threatpass@localhost:5432/threatdb \
  alembic upgrade head
```

### 3. Train the ML Model (first run only)

```bash
cd models
pip install scikit-learn pandas joblib
python train.py
# → models/saved_models/rf_malware_model.pkl
```

### 4. Build & Run the Rust Daemon

```bash
cd agent
# Edit config.json: set api_url, api_key, monitor_dir, signatures_path
cargo build --release
./target/release/hybrid-edr-agent
```

Or install as a systemd service:

```bash
sudo cp systemd/antivirus.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now antivirus
```

---

## 📁 Project Structure

```
EDR-BETA/
├── agent/            # Rust EDR daemon (Tokio, YARA, inotify, eBPF)
├── backend/          # FastAPI backend + workers + routers
│   ├── api/          # Agent API routes
│   ├── routers/      # AV management: scans, quarantine, signatures
│   ├── workers/      # RabbitMQ consumers (static, ML, sandbox)
│   ├── services/     # static_analyzer, ml_inference, reputation
│   └── database/     # asyncpg schema (6 AV tables)
├── signatures/       # YARA rules (7 ClamAV-compatible)
├── models/           # RandomForest training script
├── sandbox/          # Docker sandbox image + strace runner
├── frontend/         # Single-page dashboard (HTML/JS)
├── systemd/          # Hardened systemd unit file
├── tests/            # YARA corpus + pytest rules
├── DOCS.md           # Full developer documentation + Mermaid diagrams
└── docker-compose.yml
```

---

## ⚠️ Known Issues & Hardening TODOs

See [`DOCS.md §12`](./DOCS.md#12-known-gaps--todos) for the full list. Top priorities:

1. **AES-256 quarantine encryption** — `quarantine_safe.rs` has a `// TODO` marker; files are currently protected by path + stripped execute bits only.
2. **Real S3/MinIO** — `static_worker.py` mocks object storage via `/tmp/object-store/`.
3. **mTLS** — Daemon↔backend currently uses plain HTTPS. mTLS is required for production.
4. **CORS** — `allow_origins=["*"]` must be restricted to the dashboard domain.
5. **No CI/CD** — No GitHub Actions or Makefile exists yet.

---

## 📝 License

Licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software. Any distribution of modified versions must also be released under GPLv3. See [`LICENSE`](./LICENSE) for full details.
