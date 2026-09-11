# Security Policy & Threat Model

## Threat Model & Core Assumptions

Password Security Center treats user passwords as extremely sensitive secrets.
The application is built under the following non-negotiable security
constraints:

### 1. Invariant Rules

- **No Remote Telemetry**: Telemetry is disabled by default. No analytics,
  tracking scripts, or external API pings.
- **No Cloud Secret Storage**: Credentials are never sent to external servers or
  cloud services.
- **No LLM Credential Transmission**: Passwords and session cookies are never
  supplied to AI models or LLMs.
- **No Plaintext Database Storage**: SQLite stores only metadata (service name,
  username, official domain, risk level, mfa status, rotation timestamp).
- **Redacted Exception Tracebacks & Logs**: Secrets are stripped from log
  streams, audit files, and error messages.
- **Strict HTTPS / TLS**: HTTPS verification is enforced on all browser
  navigations; self-signed certificates or bypassed SSL controls are rejected.

### 2. Domain Validation & Phishing Defenses

- Before filling any credential form, the domain is validated against registered
  official domains using registered TLD extraction.
- Prevents subdomain confusion (`service.com.evil.com`), IDN homograph attacks,
  and open redirects.

### 3. Human-in-the-Loop Safeguards

- Automation **must** yield control to the user upon encountering MFA, 2FA,
  CAPTCHA, passkeys, SMS/Email verification, or bot detection.
- Final password submission requires explicit user interaction on a confirmation
  screen. High-value identity accounts require double confirmation.

---

## Reporting Vulnerabilities

If you discover a security vulnerability in Password Security Center, please
report it via encrypted email to `security@example.com` or open a private
advisory. Do not disclose vulnerabilities publicly until patched.
