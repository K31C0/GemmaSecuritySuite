<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/AI_Model-Gemma_2_2B-8E75B2?style=for-the-badge&logo=google&logoColor=white" />
  <img src="https://img.shields.io/badge/UI-CustomTkinter-1E90FF?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Inference-llama.cpp-FF6B35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Mode-Air--Gapped-FF0040?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<h1 align="center">🛡️ Gemma AI — Security Suite</h1>

<p align="center">
  <strong>An air-gapped, USB-portable AI Security Operations Center for incident response.</strong><br/>
  Runs Google's Gemma 2 2B model locally via <code>llama-cpp-python</code> — zero installation, zero cloud, zero host footprint.
</p>

<p align="center">
  <em>Designed for SOC analysts, incident responders, and cybersecurity professionals<br/>who need fast, private threat analysis on compromised or isolated machines.</em>
</p>

---

## 🎯 Overview

**Gemma AI Security Suite** is being transformed into a **fully portable, enterprise-ready USB incident response toolkit**. It bundles AI-powered cybersecurity tools, offline threat intelligence, and forensic capabilities into a single application that runs directly from a USB drive — leaving **zero traces** on the host machine.

The application runs [Google's Gemma 2 2B](https://huggingface.co/bartowski/gemma-2-2b-it-GGUF) entirely on the target machine's hardware with automatic CUDA/CPU detection. Your data never leaves the device. No installation. No internet. No API keys.

---

## ✨ Features

### 🤖 AI-Powered Tools (Gemma 2 2B — Local Inference)

| Tool | Description |
|------|-------------|
| 💬 **IT Support Co-Pilot** | Interactive chat assistant for real-time IT troubleshooting. Maintains full conversation context with a technical, no-fluff persona. |
| 📊 **Log Analyzer** | Parses Windows Event Log CSVs, extracts Error/Critical events, and uses AI to summarize root causes with suggested remediation steps. |
| 📜 **Script Auditor** | Paste any PowerShell or Bash script — the AI identifies security risks, malicious patterns, and explains each code block. |
| ⚡ **Regex Wizard** | Translates plain English to Regular Expressions, or breaks down complex Regex strings into human-readable explanations. |
| 🎣 **Phishing Analyzer** | Analyzes raw email headers and body text for phishing indicators, SPF/DKIM failures, and social engineering tactics. |

### 🔧 Utility Tools (No AI Required)

| Tool | Description |
|------|-------------|
| 🔐 **File Hash Verifier** | Calculates MD5 and SHA-256 hashes for any file using memory-safe chunked reading. Useful for verifying file integrity. |
| 🌐 **Network Diagnostics** | Runs ICMP ping tests and TCP port scans (HTTP, HTTPS, SSH, RDP, etc.) against any host or IP address. |
| 🌍 **IP Reputation Lookup** | Fully offline IP geolocation and ASN lookup via bundled IP2Location LITE database — no network calls required. |

### 🔒 Portability & Security

| Feature | Description |
|---------|-------------|
| 📁 **Zero-Footprint Runtime** | All paths resolve relative to the toolkit root. No writes to `%APPDATA%`, registry, or host temp directories. |
| ⚡ **Hardware Auto-Profiling** | Automatically detects CUDA GPUs, CPU cores, and available RAM at startup. Configures the LLM for optimal performance without manual tuning. |
| 🌐 **100% Offline Operation** | IP lookups use a local database. The AI model runs locally. No external API calls of any kind. |
| ⚙️ **Portable Configuration** | Optional `config.ini` on the USB root allows overriding data paths for custom deployments. |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          main.py                                 │
│                (Application Orchestrator)                         │
│    config.ensure_dirs() → HW Detect → GUI ↔ Backends → AI       │
├──────────┬────────────────────────────────────┬──────────────────┤
│          │                                    │                  │
│  gui_manager.py                      ai_inference.py             │
│  (CustomTkinter UI)                  (Gemma 2 via llama.cpp)     │
│  • 10 stacked frames                 • Lazy model loading       │
│  • Animated dashboard                 • Auto HW profiling       │
│  • Responsive layout                  • 8192-token context      │
│          │                                    │                  │
│  config.py ──────────────────── hardware_profiler.py             │
│  (Portable path resolver)      (CUDA/CPU/RAM detection)          │
│  • Relative paths only         • nvidia-smi parsing              │
│  • config.ini overrides        • Optimal Llama() kwargs          │
│  • PyInstaller aware           • psutil integration              │
│          │                                    │                  │
├──────────┴────────────┬───────────────────────┘                  │
│                       │                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐      │
│  │ log_parser    │  │ hash_checker │  │ network_scanner   │      │
│  │ (.csv/.evtx)  │  │ (MD5/SHA256) │  │ (ping/port scan)  │      │
│  └──────────────┘  └──────────────┘  └───────────────────┘      │
│  ┌──────────────┐  ┌─────────────────────────────────────┐      │
│  │ ip_lookup     │  │ downloader.py                       │      │
│  │ (IP2Location) │  │ (Threaded HuggingFace download)     │      │
│  │ 100% offline  │  │ Portable model storage              │      │
│  └──────────────┘  └─────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────┘
```

### Design Principles

- **Zero Host Footprint** — All file paths resolve relative to the toolkit root via `config.py`. The suite never writes to `%APPDATA%`, the Windows registry, or any host directory. Designed for forensic use on compromised machines.
- **Clean Separation of Concerns** — The GUI (`gui_manager.py`) contains zero business logic. All AI and tool callbacks are wired in `main.py`, making the codebase testable and modular.
- **Thread Safety** — All file I/O and AI inference operations run on background threads. GUI updates are safely marshalled to the main thread via `app.after()`.
- **Hardware Auto-Profiling** — On first model load, `hardware_profiler.py` detects CUDA GPUs, CPU cores, and available RAM, then auto-configures `llama-cpp-python` for optimal performance (GPU offload, thread count, batch size).
- **Graceful Degradation** — Binary `.evtx` files are detected early with a helpful error. Missing databases show clear download instructions. The suite works on CPU-only machines with reduced performance.

---

## 🚀 Getting Started

### Option A: USB Deployment (Recommended)

> Deploy to a USB drive for portable, zero-installation use on target machines.

1. Clone and install dependencies on your build machine:
   ```bash
   git clone https://github.com/K31C0/GemmaSecuritySuite.git
   cd GemmaSecuritySuite
   pip install -r requirements.txt
   ```
2. Copy the entire project directory to a USB drive.
3. Download the **Gemma 2 2B IT** model (~1.6 GB) and place it in `data/models/`:
   ```
   USB:\GemmaSecuritySuite\data\models\gemma-2-2b-it.gguf
   ```
4. *(Optional)* Download [IP2Location LITE](https://lite.ip2location.com) databases and place in `data/databases/`:
   ```
   USB:\GemmaSecuritySuite\data\databases\IP2LOCATION-LITE-DB11.BIN
   USB:\GemmaSecuritySuite\data\databases\IP2LOCATION-LITE-ASN.BIN
   ```
5. On the target machine, run:
   ```bash
   python main.py
   ```

### Option B: Development Setup

```bash
# Clone the repository
git clone https://github.com/K31C0/GemmaSecuritySuite.git
cd GemmaSecuritySuite

# Install dependencies
pip install customtkinter llama-cpp-python psutil IP2Location

# Launch the application
python main.py
```

On first launch, the app will:
1. Auto-detect your hardware (CUDA GPU, CPU cores, RAM)
2. Download the **Gemma 2 2B IT** model (~1.6 GB) to `data/models/` if not already present
3. Display the dashboard

### Prerequisites

- **Python 3.12+**
- **Windows 10/11** (some utilities use Windows-specific subprocess flags)
- ~2 GB disk space for the Gemma 2 2B GGUF model
- *(Optional)* NVIDIA GPU with CUDA drivers for accelerated inference

---

## 📂 Project Structure

```
GemmaSecuritySuite/
├── main.py                # Entry point — orchestrates all tool wiring
├── config.py              # Portable path resolver (zero host footprint)
├── gui_manager.py         # Full UI: 10 frames, animated dashboard, responsive grid
├── ai_inference.py        # LocalAI wrapper — Gemma 2 via llama-cpp-python
├── hardware_profiler.py   # Auto-detects CUDA/CPU/RAM, configures LLM
├── downloader.py          # Threaded model downloader with progress callbacks
├── log_parser.py          # Windows Event Log CSV parser with .evtx detection
├── hash_checker.py        # MD5/SHA-256 file hashing (chunked, memory-safe)
├── network_scanner.py     # ICMP ping + TCP port scan diagnostics
├── ip_lookup.py           # Offline IP geolocation via IP2Location LITE
├── GemmaSecuritySuite.spec # PyInstaller build configuration
└── data/                  # Portable data directory (on USB drive)
    ├── models/            #   GGUF model files
    ├── databases/         #   IP2Location BIN files
    ├── logs/              #   Chain of custody logs (Phase 2)
    ├── evidence/          #   Encrypted evidence vault (Phase 2)
    ├── exports/           #   PDF/HTML incident reports (Phase 2)
    ├── playbooks/         #   RAG source PDFs (Phase 3)
    └── yara_rules/        #   YARA signature files (Phase 2)
        ├── community/     #     Bundled community rules
        └── custom/        #     Analyst's own rules
```

---

## ⚙️ Portable Configuration

An optional `config.ini` in the toolkit root lets you redirect data paths — useful when evidence or logs should be written to a separate partition:

```ini
[paths]
models_dir    = E:\CustomModels
databases_dir = E:\GeoDBs
logs_dir      = E:\IR_Logs
evidence_dir  = E:\Evidence
exports_dir   = E:\Reports
```

Any key omitted from the file keeps its default (`data/` subdirectory). Relative paths are resolved against the toolkit root.

---

## 🎨 UI Design

The interface features a custom **"Gemma AI"** dark theme with:

- **Color Palette**: Deep navy background (`#070914`), cyan accents (`#00E5FF`), purple highlights (`#B388FF`)
- **Animated Dashboard**: Canvas-rendered horizontal "data stream" lines sweeping across the home screen
- **Responsive Grid**: 4×2 tool card layout with a featured Co-Pilot button spanning the full width
- **Context Guidance**: Every tool includes an info banner explaining its purpose
- **Chat Interface**: Full conversation history with visual separators and formatted message blocks

---

## 🔒 Privacy & Security

- **100% Offline** — The Gemma model runs entirely on local hardware (CPU or CUDA GPU). No data is sent to external AI services.
- **Zero Host Footprint** — All data is stored on the USB drive. No writes to `%APPDATA%`, temp directories, or the Windows registry.
- **No Telemetry** — The application does not collect, store, or transmit any usage data.
- **No External API Calls** — IP geolocation uses a locally-bundled database. No network calls are made by any tool.
- **Open Source** — Every line of code is auditable.

---

## 🛣️ Roadmap

The suite is being transformed into a comprehensive **Air-Gapped USB Incident Response Toolkit** across three phases:

### Phase 1: Portability ✅

- [x] **Zero-Footprint Runtime** — Portable path resolution via `config.py`, `config.ini` overrides
- [x] **Offline Threat Intel** — IP2Location LITE replaces `ip-api.com` for 100% offline IP/ASN lookups
- [x] **Hardware Auto-Profiling** — Auto-detect CUDA/CPU/RAM, configure LLM for optimal performance
- [ ] **Standalone Binary** — PyInstaller `.exe` compilation (deferred to end of project)

### Phase 2: Enterprise Forensics & Incident Response

- [ ] **Immutable Chain of Custody Logging** — Append-only JSONL audit trail with SHA-256 self-integrity
- [ ] **Automated Environment Fingerprinting** — Snapshot host OS, processes, network state on boot
- [ ] **YARA Rule Engine** — Scan files/scripts against malware signatures before AI analysis
- [ ] **Encrypted Evidence Vault** — AES-256-GCM encrypted storage for suspicious files
- [ ] **PCAP Traffic Analysis** — Offline `.pcap` parsing for DNS, HTTP, beaconing, TLS analysis
- [ ] **Automated Incident Reporting** — Export session data as professional PDF/HTML reports

### Phase 3: AI Capabilities & UX

- [ ] **Dynamic Context Window Management** — Auto-summarize old chat history to prevent context overflow
- [ ] **Multi-Model Fallback** — Gracefully swap to smaller models (Phi-3, Qwen2) on low-RAM machines
- [ ] **RAG Playbooks** — Local FAISS vector search over bundled IR playbooks and NIST frameworks
- [ ] **Live Resource Telemetry** — Real-time CPU/RAM/VRAM dashboard widget
- [ ] **Panic Button / Kill Switch** — Instant graceful termination leaving no trace
- [ ] **Process Tree Visualization** — Visual parent-child process mapping for suspicious activity
- [ ] **Colorblind & High-Contrast Modes** — Enterprise accessibility compliance

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Python 3.12+ |
| **GUI Framework** | CustomTkinter (Tkinter wrapper) |
| **AI Runtime** | llama-cpp-python (GGML/GGUF) |
| **AI Model** | Google Gemma 2 2B Instruct (Q4_K_M) |
| **IP Geolocation** | IP2Location LITE (offline BIN database) |
| **Hardware Detection** | psutil + nvidia-smi |
| **Hashing** | Standard library (`hashlib`) |
| **Networking** | Standard library (`socket`, `subprocess`) |
| **Concurrency** | `threading` (daemon workers + `app.after()` marshalling) |

### Dependencies

| Package | Purpose |
|---------|---------|
| `customtkinter` | Modern dark-themed GUI framework |
| `llama-cpp-python` | Local GGUF model inference engine |
| `psutil` | Hardware detection and resource monitoring |
| `IP2Location` | Offline IP geolocation database reader |

All other modules use the **Python standard library**: `threading`, `hashlib`, `subprocess`, `socket`, `csv`, `os`, `sys`, `configparser`, `tkinter`.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

IP geolocation data provided by [IP2Location LITE](https://lite.ip2location.com).

---

<p align="center">
  Built for incident responders. Powered by local AI.<br/>
  <em>No cloud. No APIs. No installation. No trace.</em>
</p>
