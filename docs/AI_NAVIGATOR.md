# AI Navigator & Safety Guardian

KeyOps includes an AI Navigation Agent designed to discover password management workflows on unknown or redesigned websites.

---

## 🤖 How the AI Navigation Loop Works

1. **DOM Inspection**: `PageInspector` assigns deterministic element IDs (`elem_1`, `elem_2`) to interactive elements.
2. **Privacy Sanitization**: `PageSanitizer` strips all raw passwords, OTP codes, session tokens, and personal details.
3. **Prompt Injection Guard**: `PromptInjectionGuard` neutralizes adversarial webpage instructions.
4. **AI Reasoning**: `GeminiAIProvider` or `LocalAIProvider` evaluates the sanitized semantic tree and proposes a structured action schema:
   ```json
   {
     "action": "click",
     "target_id": "elem_14",
     "reason": "This link leads to account security settings.",
     "confidence": 0.96
   }
   ```
5. **Safety Guardian Validation**: `ActionSafetyValidator` checks the action against safety thresholds, domain policies, and dangerous action classifiers.
6. **Controlled Execution**: `ControlledActionExecutor` executes the approved action in Playwright.

---

## 🔑 Secret Isolation Protocol

The AI reasoning layer operates under fail-closed credential isolation:
- The AI never receives real passwords.
- The AI only emits symbolic references (`secret_reference="current_password"` or `secret_reference="new_password"`).
- `SecretBoundary` maps these references to real values inside the local browser layer only.

---

## ⚙️ AI Configuration

Set your Gemini API key in your environment (optional):
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```
If unset, KeyOps automatically runs in **Local Offline Mode**, using high-precision deterministic heuristics.
