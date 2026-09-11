<div align="center">

# 🛡️ KeyOps — AI-Assisted Password Security Center

**Authorized Personal Cybersecurity Application for Intelligent & Safe Password Rotation**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-brightgreen.svg)](https://python.org)
[![Playwright](https://img.shields.io/badge/Playwright-Automated%20Browser-orange.svg)](https://playwright.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-Modern%20Backend-teal.svg)](https://fastapi.tiangolo.com)
[![Privacy: Zero Telemetry](https://img.shields.io/badge/Privacy-Zero%20Telemetry-success.svg)](docs/SECURITY_MODEL.md)

</div>

---

## 📖 Overview

**KeyOps** (Password Security Center) transforms messy lists of compromised/reused passwords (such as exports from **Apple Passwords**, **1Password**, or **Bitwarden**) into a streamlined, human-in-the-loop rotation workflow.

Instead of manually navigating dozens of websites, KeyOps uses an **AI Navigation Agent** paired with an **Authoritative Safety Guardian** and **Controlled Browser Automation** to locate security pages, detect password forms, and prepare rotations while keeping **you** in full control of all credential and security decisions.

---

## 🏛️ Architecture & Security Model

KeyOps adheres to a strict division of responsibility:

```
ACCOUNT METADATA
       │
       ▼
ACCOUNT ANALYZER (Risk Engine)
       │
       ▼
DOMAIN VALIDATOR (tldextract & Registry)
       │
       ▼
BROWSER ENGINE (Playwright Headed Automation)
       │
       ▼
PAGE INSPECTOR ───────────► PAGE SANITIZER (Strips Passwords/OTPs)
                                  │
                                  ▼
                            AI NAVIGATOR (Brain / Gemini / Local)
                                  │
                                  ▼
                           ACTION PLANNER
                                  │
                                  ▼
                        SAFETY POLICY ENGINE (Guardian)
                          ┌───────┴───────┐
                          │               │
                        SAFE           UNSAFE
                          │               │
                          ▼               ▼
                     PLAYWRIGHT         STOP / HUMAN TAKEOVER
                    (Hands / Vault)
```

| Role | Component | Responsibility |
|---|---|---|
| **BRAIN** | AI Reasoning Engine | Reasons over sanitized DOM trees to discover settings paths. |
| **GUARDIAN** | Safety Policy Engine | Authoritative policy engine. Vetoes unsafe/destructive actions and enforces confidence thresholds. |
| **HANDS** | Controlled Playwright | Executes only narrowly scoped, pre-approved browser actions (`click`, `fill_secret`, `scroll`, `navigate`). |
| **VAULT** | Secret Boundary | Absolute isolation barrier. Real passwords and OTPs **never** enter AI prompts. |
| **FINAL AUTHORITY** | The User | Explicit confirmation required before every password submission. |

---

## 🌟 Key Features

- 🛡️ **Zero Telemetry & Local Isolation**: Secrets never leave your machine. Zero telemetry, zero plaintext passwords in SQLite or logs.
- 🤖 **AI-Assisted Navigation**: Integrates Google Gemini with automatic local/offline fallback to handle previously unseen websites.
- 🔒 **Prompt Injection Defense**: Website content is treated strictly as untrusted data, neutralizing adversarial instructions.
- 🎯 **Domain Spoofing Protection**: Validates official registered domains (`tldextract`) to block lookalike domains (`github.com.attacker.com`) and open redirects.
- 🤝 **Mandatory Security Pauses**: Automation instantly yields control upon encountering MFA, 2FA, OTP, CAPTCHA, passkeys, SMS/email verification, or login challenges.
- 🔌 **Universal Platform Support**: Dedicated adapters (Google, Apple, GitHub, Amazon, Microsoft, Discord, Reddit) + Platform detectors (Auth0, Okta, Firebase, Clerk, WordPress, Shopify) + Universal Generic Engine.
- 🍏 **Apple Passwords & macOS Keychain**: Direct credential storage into the secure macOS system Keychain and clean export/import handoffs.
- 📊 **Polished Cybersecurity Dashboard & CLI**: Rich dark-mode UI with live AI activity streaming, Security Score metrics, and a full-featured CLI.

---

## 🚀 Quick Start

### Installation

```bash
# 1. Clone repository
git clone https://github.com/Coderaryanyadav/KeyOps.git
cd KeyOps

# 2. Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies in editable mode
pip install -e .

# 4. Install Playwright browser engine
playwright install chromium
```

### Usage

```bash
# Launch the Interactive macOS Dashboard
password-security dashboard

# Run System Doctor Diagnostics
password-security doctor

# Scan Monitored Accounts & Security Score
password-security scan

# Perform Safe Dry-Run Rotation (Navigates without submitting)
password-security fix github --dry-run
password-security fix --critical --dry-run

# Import Accounts from CSV (Apple Passwords / 1Password / Bitwarden)
password-security import accounts.csv

# View Privacy-Preserving Audit Logs
password-security audit
```

---

## 🧪 Testing & Verification

KeyOps includes an extensive test suite with a 10-scenario mock server simulating real-world security challenges:

```bash
source .venv/bin/activate
pytest
```

**24 Automated Test Suites Passing:**
- `test_secret_boundary.py` (100% credential isolation)
- `test_page_sanitizer.py` (Strips passwords, OTPs, and tokens)
- `test_prompt_injection.py` (Defends against prompt injection attacks)
- `test_safety_engine.py` (Blocks destructive actions & low confidence)
- `test_full_ai_acceptance.py` (10-account end-to-end acceptance challenge)

---

## 📚 Documentation

- [Architecture Deep-Dive](docs/ARCHITECTURE.md)
- [Security Model & Threat Model](docs/SECURITY_MODEL.md)
- [Quickstart Guide](docs/QUICKSTART.md)
- [AI Navigator & Safety Guardian](docs/AI_NAVIGATOR.md)
- [Service Adapters & Extensions Guide](docs/ADAPTERS_GUIDE.md)

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
