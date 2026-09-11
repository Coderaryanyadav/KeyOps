# Service Adapters & Platform Extensions Guide

KeyOps uses a modular adapter architecture combining known service adapters, platform detection, and a generic discovery engine.

---

## 🔌 Architecture Hierarchy

1. **Dedicated Service Adapters**: `Google`, `Apple`, `Microsoft`, `GitHub`, `Amazon`, `Discord`, `Reddit`.
2. **Platform Detectors**: `Auth0`, `Okta`, `Firebase`, `Supabase`, `Clerk`, `AWS Cognito`, `Keycloak`, `WordPress`, `Shopify`.
3. **Universal Generic Engine**: Discovers navigation paths and form structures on previously unseen websites.
4. **Human-Assisted Mode**: Yields control to user whenever confidence falls below safety thresholds.

---

## 🛠️ Adding a New Service Adapter

To add a new dedicated adapter:
1. Create `app/adapters/<service_name>.py` extending `PasswordAdapter`.
2. Implement required properties and methods:
   - `service_name`
   - `official_domains`
   - `login_url`
   - `password_change_url`
   - `navigate_to_security(page)`
   - `detect_password_fields(page)`
   - `fill_password(page, fields, current_pwd, new_pwd)`
   - `submit_password_change(page, dry_run)`
   - `detect_success(page)`
   - `detect_failure(page)`
3. Register the adapter in `app/adapters/registry.py`.
4. Add unit and integration tests under `tests/unit/` and `tests/integration/`.
