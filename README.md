<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/AI_Model-Gemma_2_2B-8E75B2?style=for-the-badge&logo=google&logoColor=white" />
  <img src="https://img.shields.io/badge/UI-CustomTkinter-1E90FF?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Inference-llama.cpp-FF6B35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<h1 align="center">🛡️ Gemma AI — Security Suite</h1>

<p align="center">
  <strong>A fully offline, AI-powered Security Operations Center (SOC) built in Python.</strong><br/>
  Runs Google's Gemma 2 2B model locally via <code>llama-cpp-python</code> — no API keys, no cloud dependencies, no telemetry.
</p>

<p align="center">
  <em>Designed for IT professionals, SOC analysts, and cybersecurity students who need fast, private threat analysis.</em>
</p>

---

## 🎯 Overview

**Gemma AI Security Suite** is a desktop application that bundles **eight specialized cybersecurity tools** into a single interface, all powered by a locally-running large language model. The application downloads and runs [Google's Gemma 2 2B](https://huggingface.co/bartowski/gemma-2-2b-it-GGUF) entirely on your machine — your data never leaves your computer.

Built with a modular architecture that cleanly separates the UI layer from backend logic, enabling easy extension and testing.

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
| 🌍 **IP Reputation Lookup** | Queries geolocation and ASN data for any IP address — returns Country, City, ISP, and Organization. |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py                              │
│              (Application Orchestrator)                      │
│    Wires GUI callbacks → Backend modules → AI Engine         │
├──────────┬──────────────────────────────────┬────────────────┤
│          │                                  │                │
│  gui_manager.py                    ai_inference.py           │
│  (CustomTkinter UI)                (Gemma 2 via llama.cpp)   │
│  • 10 stacked frames               • Lazy model loading     │
│  • Animated dashboard               • Threaded inference     │
│  • Responsive layout                • 8192-token context     │
│          │                                  │                │
├──────────┴──────────┬───────────────────────┘                │
│                     │                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐     │
│  │ log_parser   │  │hash_checker │  │ network_scanner  │     │
│  │ (.csv/.evtx) │  │ (MD5/SHA256)│  │ (ping/port scan) │     │
│  └─────────────┘  └─────────────┘  └──────────────────┘     │
│  ┌─────────────┐  ┌──────────────────────────────────┐      │
│  │ ip_lookup    │  │ downloader.py                    │      │
│  │ (GeoIP/ASN)  │  │ (Threaded HuggingFace download)  │      │
│  └─────────────┘  └──────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

- **Clean Separation of Concerns** — The GUI (`gui_manager.py`) contains zero business logic. All AI and tool callbacks are wired in `main.py`, making the codebase testable and modular.
- **Thread Safety** — All network, file I/O, and AI inference operations run on background threads. GUI updates are safely marshalled to the main thread via `app.after()`.
- **Lazy Model Loading** — The Gemma model is loaded on the first inference request (not at startup), keeping the application responsive during boot.
- **Graceful Degradation** — Binary `.evtx` files are detected early with a helpful error message. Network timeouts and model errors are caught and surfaced cleanly.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.12+**
- **Windows 10/11** (some utilities use Windows-specific subprocess flags)
- ~1.7 GB disk space for the Gemma 2 2B GGUF model

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/gemma-ai-security-suite.git
cd gemma-ai-security-suite

# Install dependencies
pip install customtkinter llama-cpp-python requests

# Launch the application
python main.py
```

On first launch, the app will automatically download the **Gemma 2 2B IT** model (~1.6 GB) from Hugging Face and store it in `%APPDATA%/LogPlatform/models/`.

### Dependencies

| Package | Purpose |
|---------|---------|
| `customtkinter` | Modern dark-themed GUI framework |
| `llama-cpp-python` | Local GGUF model inference engine |
| `requests` | IP geolocation API calls |

All other modules use the **Python standard library**: `threading`, `hashlib`, `subprocess`, `socket`, `csv`, `urllib`, `tkinter`.

---

## 📂 Project Structure

```
gemma-ai-security-suite/
├── main.py              # Entry point — orchestrates all tool wiring
├── gui_manager.py       # Full UI: 10 frames, animated dashboard, responsive grid
├── ai_inference.py      # LocalAI wrapper around Gemma 2 via llama-cpp-python
├── downloader.py        # Threaded model downloader with progress callbacks
├── log_parser.py        # Windows Event Log CSV parser with .evtx detection
├── hash_checker.py      # MD5/SHA-256 file hashing (chunked, memory-safe)
├── network_scanner.py   # ICMP ping + TCP port scan diagnostics
├── ip_lookup.py         # IP geolocation and ASN lookup
└── README.md
```

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

- **100% Offline AI** — The Gemma model runs entirely on your CPU. No data is sent to external AI services.
- **No Telemetry** — The application does not collect, store, or transmit any usage data.
- **Local Storage Only** — The model file is stored in your local `%APPDATA%` directory. Scan results are never persisted to disk.
- **Open Source** — Every line of code is auditable.

> The only external network call is the IP Reputation Lookup tool, which queries the free `ip-api.com` endpoint. This can be disabled or replaced.

---

## 🛣️ Roadmap

- [ ] GPU acceleration via CUDA/Vulkan for faster inference
- [ ] Persistent chat history and scan result export
- [ ] Custom port list configuration for the Network Scanner
- [ ] YARA rule integration for the Script Auditor
- [ ] Multi-model support (switch between Gemma, Phi, Llama)
- [ ] Cross-platform support (Linux/macOS)

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Python 3.12+ |
| **GUI Framework** | CustomTkinter (Tkinter wrapper) |
| **AI Runtime** | llama-cpp-python (GGML/GGUF) |
| **AI Model** | Google Gemma 2 2B Instruct (Q4_K_M) |
| **Networking** | Standard library (`socket`, `subprocess`) |
| **Hashing** | Standard library (`hashlib`) |
| **Concurrency** | `threading` (daemon workers + `app.after()` marshalling) |

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with ❤️ and local AI.<br/>
  <em>No cloud. No APIs. No compromises.</em>
</p>
