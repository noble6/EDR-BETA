# Nexus Hybrid EDR & Threat Intelligence System

Nexus is a production-grade, hybrid Endpoint Detection and Response (EDR) and Threat Intelligence platform. It combines a lightweight, kernel-aware Rust endpoint agent with a scalable Python microservices backend to deliver real-time malware detection, Machine Learning (ML) static analysis, and dynamic sandbox detonation.

##  Key Features

### Endpoint Agent (Rust)
* **eBPF Kernel Monitoring:** Direct memory inspection of `sys_enter_execve` for spotting reverse shells and process injection with near-zero overhead.
* **Asynchronous Event Loop:** Built on `tokio` and `notify` to intercept file drops in real time.
* **Offline Resilience:** Uses a local LRU cache and an offline queue to maintain operation even when the cloud backend is unreachable.
* **Automated Mitigation:** Can automatically quarantine identified malicious payloads.

### Cloud Backend (Python / FastAPI)
* **Microservices Architecture:** Decoupled analysis via **RabbitMQ** to prevent API bottlenecks.
* **High-Performance Caching & DB:** **Redis** for fast hash lookups and **PostgreSQL** (via async SQLAlchemy) for persistent reputation storage.
* **Machine Learning Static Analysis:** Extracts PE/ELF attributes (entropy, imports) via `LIEF` and evaluates them using a Scikit-Learn `RandomForest` model.
* **Dynamic Sandbox Detonation:** Automatically routes ambiguous/suspicious files to an isolated Docker container, using `strace` and network monitoring to identify malicious runtime behaviors.
* **Real-Time Dashboard:** A React + Tailwind UI served directly by FastAPI for visualizing threat landscapes and sandbox syscall alerts.

---

## 🏗 Architecture Overview

```text
[ Endpoint ]                          [ Cloud Backend ]
+-------------------+                 +-----------------------------------+
| Rust EDR Agent    | -- HTTPS -->    | FastAPI Gateway (Port 8000)       |
| - eBPF Sensor     |                 | - PostgreSQL (Reputation DB)      |
| - inotify         |                 | - Redis (Hash Cache)              |
| - LRU Cache       |                 +-----------------------------------+
| - Offline Queue   |                               | (RabbitMQ)
+-------------------+                               v
                                      +-----------------------------------+
                                      | Async Workers                     |
                                      | 1. Static Analysis (PE/ELF parse) |
                                      | 2. ML Inference (RandomForest)    |
                                      | 3. Dynamic Sandbox (Docker/strace)|
                                      +-----------------------------------+
```

---

##  Quick Start

### Prerequisites
* Docker & Docker Compose
* Rust toolchain (Nightly recommended for eBPF)
* Python 3.11+ (Local testing)

### 1. Start the Cloud Backend
Deploy the full microservices stack (PostgreSQL, Redis, RabbitMQ, FastAPI, and Workers):
```bash
# Build the internal sandbox image first
cd sandbox && docker build -t deadsec/sandbox:latest .
cd ..

# Launch the data pipeline
docker compose --env-file .env up -d --build
```
*Access the Threat Dashboard at: http://localhost:8000/dashboard*

### 2. Compile and Run the Agent
To utilize eBPF capabilities, run the agent as root.
```bash
cd agent

# Build the eBPF kernel object (Requires bpf-linker & nightly rust)
cd ebpf-code && cargo +nightly build --target=bpfel-unknown-none -Z build-std=core --release
cd ..

# Run the user-space agent
sudo RUST_LOG=info cargo run --release
```

---

## ⚠️ Disclaimer
This system is a structurally complete **Minimum Viable Product (MVP)**. Before deploying into a true enterprise production environment, consider the following hardening steps:
1. **Model Training:** Retrain the ML model on live malware datasets (e.g., VirusShare).
2. **Sandbox Isolation:** Migrate from Docker to Micro-VMs (e.g., AWS Firecracker or QEMU) to prevent container escape exploits.
3. **Transport Security:** Wrap the FastAPI endpoints behind an HTTPS reverse proxy (Nginx/Traefik).

---
## 📝 License
This project is licensed under the **GNU General Public License v3.0 (GPLv3)**. 

What this means for you:
- You have complete freedom to **use**, **modify**, and **distribute** this software.
- If you distribute copies or modified versions of this software, you **must** also release your source code back to the community under this same GPLv3 license.
- It prevents proprietary companies from taking the code, modifying it, and keeping the modifications closed-source.

See the `LICENSE` file for full details.
