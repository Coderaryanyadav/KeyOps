# Contributing Guidelines

Thank you for contributing to **Password Security Center**!

## Code Architecture & Style

- **Python Version**: 3.10+ (tested up to 3.14).
- **Type Annotations**: All core modules must use strict type hints.
- **Form & Code Verification**: Run tests before submitting changes:
  ```bash
  pytest
  password-security doctor
  ```

## Adding a Service Adapter

To add support for a new online service:
1. Create a new file in `app/adapters/<service_name>.py` extending `PasswordAdapter`.
2. Implement:
   - `service_name`, `official_domains`, `login_url`, `security_url`, `password_change_url`
   - `navigate_to_security()`, `detect_password_fields()`, `fill_password()`, `detect_mfa()`, `detect_captcha()`, `detect_success()`, `detect_failure()`
3. Register your adapter in `app/adapters/registry.py`.
4. Add unit and mock integration tests under `tests/unit/` and `tests/integration/`.
