.PHONY: test security-gate doctor compile

compile:
	uv run python -m compileall app tests

test:
	uv run pytest -v

test-security:
	uv run pytest -v tests/security

test-integration:
	uv run pytest -v tests/integration

test-unit:
	uv run pytest -v tests/unit

doctor:
	uv run python -m app.cli.doctor

security-gate:
	./scripts/security_gate.sh
