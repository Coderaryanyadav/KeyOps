import asyncio
import pytest
import uvicorn
from multiprocessing import Process
from playwright.async_api import async_playwright
from app.adapters.github import GitHubAdapter
from app.browser.engine import BrowserEngine
from app.browser.human_interrupter import HumanInterrupter
from tests.mock_server import mock_app

def run_mock_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=9876, log_level="warning")

@pytest.fixture(scope="module", autouse=True)
def mock_server_process():
    proc = Process(target=run_mock_server, daemon=True)
    proc.start()
    import time
    time.sleep(1.5)  # Wait for mock server startup
    yield
    proc.terminate()

@pytest.mark.asyncio
async def test_mock_server_password_field_detection():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        await page.goto("http://127.0.0.1:9876/settings/security")
        adapter = GitHubAdapter()
        fields = await adapter.detect_password_fields(page)

        assert fields.get("current_password") is not None
        assert fields.get("new_password") is not None
        assert fields.get("confirm_password") is not None

        await browser.close()

@pytest.mark.asyncio
async def test_mfa_detection_interruption():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        await page.goto("http://127.0.0.1:9876/mfa")
        interrupter = HumanInterrupter()
        reason = await interrupter.check_security_checkpoints(page, "TestService")

        assert reason is not None
        assert "MFA" in reason

        await browser.close()
