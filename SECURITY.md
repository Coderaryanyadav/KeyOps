# KeyOps — Security Policy, Threat Model & Invariants

## Objective & Scope

KeyOps is an AI-assisted password rotation tool intended **ONLY** for accounts
owned and authorized by the user.

KeyOps operates on a strict defensive cybersecurity architecture where local
deterministic rules always override AI proposals, human approval remains final
and authoritative, and secrets remain isolated within a strictly bounded
cryptographic container.

---

## What KeyOps CAN Do

- **Automate Authorized Password-Change Workflows**: Navigates account security
  settings on recognized or generic websites using deterministic adapters and AI
  semantic assistance.
- **Generate Strong Passwords Locally**: Produces cryptographically random
  passwords and passphrases using system CSPRNG (`secrets` module) with
  configurable entropy and character sets.
- **Use AI for Semantic Navigation**: Employs AI models (e.g., Google Gemini)
  exclusively for semantic reasoning (identifying navigational links and page
  context) over strictly sanitized DOM trees.
- **Require Explicit Human Approval Before Submission**: Halts execution at the
  submission chokepoint and demands human approval via a single-use,
  time-limited, session-bound cryptographic approval token.
- **Validate Domains Locally**: Deterministically validates target hostnames and
  live URLs against registered eTLD+1 rules with IDNA normalization and
  anti-spoofing checks.
- **Isolate Secrets from AI (`SecretBoundary`)**: Enforces a fail-closed,
  drop-by-default recursive allowlist boundary where raw credentials, session
  tokens, and cookies are never transmitted to AI providers.
- **Store Credentials in macOS Keychain**: Securely stores rotated passwords in
  the native macOS Keychain when explicitly requested by the user, returning
  distinct success/failure status codes.

---

## What KeyOps CANNOT / DOES NOT Do

- **CANNOT Bypass CAPTCHAs, MFA, or Passkeys**: KeyOps intentionally pauses
  automation (`WAITING_FOR_HUMAN`) when CAPTCHA, 2FA/MFA, passkey
  authentication, SMS codes, or security challenges appear.
- **CANNOT Defeat Anti-Bot Systems**: KeyOps does not attempt to circumvent
  Cloudflare, Akamai, reCAPTCHA, or bot-detection mechanisms.
- **CANNOT Bypass Website Account Security Controls**: KeyOps follows standard
  user browser interaction models and respects site rate-limiting, session
  expiration, and authentication requirements.
- **CANNOT Cryptographically Guarantee Remote Password Change on Generic
  Websites**: Generic web applications may return ambiguous post-submission
  confirmation. In such cases, KeyOps fails closed to `UNKNOWN` /
  `HUMAN_VERIFICATION_REQUIRED` rather than falsely asserting success.
- **CANNOT Guarantee Security Against a Compromised Local Operating System**: If
  the host machine is infected with malware, keyloggers, or memory sniffers, no
  user-space tool can ensure secret confidentiality.
- **CANNOT Recover Secrets After Process Restart**: On process termination or
  crash, all in-memory `SecretBoundary` instances, active workflows, and
  approval tokens are wiped. No raw passwords or tokens are persisted.
- **CANNOT Operate Safely on Unauthorized Accounts**: KeyOps is designed
  exclusively for user-owned credentials. Automation against unauthorized
  systems is strictly prohibited.

---

## Core Security Invariants

1. **AI Submission Prohibition**: AI cannot directly trigger submission or
   execute browser actions.
2. **AI Cannot Issue Approval**: Cryptographic approval tokens are generated
   solely by the authoritative server-side `SubmissionApprovalManager`.
3. **Single-Use Bound Approval**: Approval tokens expire, are consumed
   atomically, and are cryptographically bound to `account_id`, `service`,
   `verified_domain`, `browser_session_id`, `workflow_id`, `form_fingerprint`,
   and `process_instance_id`.
4. **Live Domain Verification**: Page URL is verified immediately before
   submission at the action executor chokepoint.
5. **Deterministic Credential Verification**: Password fields must have
   `type='password'`, be visible, enabled, non-readonly, and match expected
   semantic roles (`current_password`, `new_password`, `confirm_password`).
   Generic text fields (`type='text'`) are strictly rejected.
6. **Secret Isolation**: Raw passwords, session secrets, and cookies never enter
   AI prompts, audit logs, API responses, or frontend JavaScript.
7. **No Master Token in WebSocket/Frontend**: WebSocket connections require
   short-lived single-use tickets or HttpOnly session cookies; master API tokens
   never appear in URLs or frontend DOM.
8. **Fail-Closed Verification**: Ambiguous post-change page states produce
   `UNKNOWN`, never `SUCCESS`.

---

## Vulnerability Reporting

If you discover a security vulnerability, please submit a report through a
private GitHub Security Advisory or email the maintainers directly. Do not
disclose vulnerabilities publicly until patched.
