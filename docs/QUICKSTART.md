# KeyOps Quickstart Guide

Get up and running with KeyOps in under 2 minutes.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Coderaryanyadav/KeyOps.git
cd KeyOps

# Create & activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package and dependencies in editable mode
pip install -e .

# Install Playwright browser engine
playwright install chromium
```

---

## 🎯 Basic Usage

### 1. Launch Interactive Dashboard
```bash
password-security dashboard
```
Opens the macOS dark-mode cybersecurity dashboard at `http://127.0.0.1:8443`.

### 2. Run System Health Doctor
```bash
password-security doctor
```
Verifies Python runtime, Playwright engine, SQLite database, macOS Keychain access, and AI reasoning guards.

### 3. Scan Accounts & Security Score
```bash
password-security scan
```
Calculates risk metrics and 0–100 Security Score across all monitored accounts.

### 4. Import Accounts from CSV
```bash
password-security import accounts.csv
```
Supports CSV exports from Apple Passwords, 1Password, Bitwarden, or generic CSVs (`service,username,url,status`).

### 5. Safe Password Rotation Dry-Run
```bash
password-security fix github --dry-run
# Or fix all critical risk accounts:
password-security fix --critical --dry-run
```

### 6. View Privacy-Preserving Audit Logs
```bash
password-security audit
```
