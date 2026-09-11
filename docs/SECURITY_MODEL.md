# KeyOps Threat Model & Security Policy

## Core Security Invariants

KeyOps treats user credentials as highest-sensitivity secrets. The system operates under the following hard boundaries:

### 1. Data Invariants
- **Zero Remote Telemetry**: Telemetry is disabled by default. No analytics, tracking scripts, or external telemetry pings.
- **Zero Plaintext Database Storage**: SQLite stores only metadata (service name, username, official domain, risk level, MFA status, rotation timestamp).
- **Zero Plaintext Logs**: `audit_logger.py` redacts passwords, tokens, auth headers, and session cookies from all log outputs.
- **Zero AI Secret Transmission**: `SecretBoundary` ensures raw passwords, master keys, OTP codes, session tokens, and private keys never enter AI prompts.
- **Strict HTTPS / TLS**: Enforced on all non-local browser navigations.

### 2. Domain Security & Anti-Phishing
- **Registered Domain Extraction**: Uses `tldextract` to match domains against trusted official registries.
- **Subdomain Confusion Defense**: Prevents lookalike domains (`github.com.attacker.com` or `github-login.com`).
- **Open Redirect Guard**: Validates destination URLs post-navigation.

### 3. Human-in-the-Loop Safeguards
- **Mandatory Pauses**: Automation instantly halts on MFA, 2FA, OTP, CAPTCHA, passkeys, email/SMS verification, and device approvals.
- **Explicit Confirmation**: Final submission requires user approval. High-value identity providers (Google, Apple, Microsoft, Password Managers, Financial Services) require secondary confirmation.
- **Destructive Action Blocking**: `DangerousActionClassifier` rejects actions targeting account deletion, membership cancellation, 2FA removal, or fund transfers.

### 4. Apple Passwords & Password Manager Reality
- **macOS System Keychain**: Direct local integration via Apple's native `Security.framework` (`keyring`).
- **Sandbox Boundary**: Third-party applications on macOS cannot and must not attempt unauthorized private database extraction or keychain dumping. KeyOps supports direct system Keychain storage and clean CSV import/export handoffs.
