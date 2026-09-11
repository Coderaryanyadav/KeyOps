# KeyOps Architecture Overview

KeyOps (Password Security Center) is designed with a strict division of responsibility across reasoning, security boundaries, and browser automation.

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

---

## 🏛️ Core Architectural Pillars

### 1. The Brain (AI Reasoning Layer)
- **Providers**: `GeminiAIProvider` (remote) and `LocalAIProvider` (deterministic offline).
- **Sanitization**: `PageSanitizer` reduces raw DOM into compact semantic representations (headings, interactive elements, ARIA roles) while stripping raw passwords, tokens, cookies, and personal info.
- **Prompt Injection Defense**: `PromptInjectionGuard` isolates untrusted website text from trusted system instructions.

### 2. The Guardian (Safety Policy Engine)
- **Authoritative Validation**: `ActionSafetyValidator` evaluates every AI action proposal before execution. The AI cannot override the Guardian.
- **Risk Classifier**: `DangerousActionClassifier` automatically identifies and vetoes destructive targets (e.g. "delete account", "disable 2FA", "transfer funds").
- **Confidence Thresholds**: Enforces minimum composite confidence (0.85+ for fields, 0.90+ for submit).

### 3. The Vault (Secret Boundary)
- **Absolute Credential Isolation**: Real passwords never enter AI prompts or application logs.
- **Symbolic Resolution**: The AI emits references like `secret_reference="current_password"`. `SecretBoundary` resolves these strictly within the local browser automation layer.

### 4. The Hands (Controlled Browser Execution)
- **Narrowly Scoped Tools**: `ControlledActionExecutor` executes only safe, validated actions (`click`, `fill_secret`, `scroll`, `navigate`, `wait`).
- **Human Checkpoints**: `HumanInterrupter` automatically halts automation on MFA, 2FA, CAPTCHA, passkeys, SMS/email challenges, and device verification.

### 5. Final Authority (The User)
- **Explicit Confirmation**: Every password change requires explicit user approval on a dedicated confirmation screen displaying the official domain, username, risk, and generated password strength.
