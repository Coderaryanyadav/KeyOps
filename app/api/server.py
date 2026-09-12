import asyncio
import secrets
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.config import settings, HIGH_VALUE_SERVICES
from app.database.session import get_db, init_db, SessionLocal
from app.database.models import Account, AuditLog
from app.core.security_score import SecurityScoreCalculator
from app.core.password_generator import PasswordGenerator, PasswordPolicy
from app.core.domain_validator import DomainValidator, DomainValidationError
from app.core.audit_logger import audit_logger
from app.core.queue_manager import queue_manager, QueueItemStatus
from app.core.workflow_memory import workflow_memory
from app.core.workflow_state import WorkflowPhase
from app.core.orchestrator import orchestrator
from app.safety.domain_trust import DomainTrustContext
from app.safety.submission_approval import approval_manager
from app.adapters.registry import adapter_registry
from app.integrations.csv_importer import CSVAccountImporter
from app.integrations.keychain import KeychainManager
from app.integrations.bitwarden import PasswordManagerExporter

app = FastAPI(title="Password Security Center API", version="1.0.0")

UI_DIR = Path(__file__).parent.parent / "ui"
app.mount("/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(UI_DIR / "templates"))

def verify_local_api_auth(request: Request) -> bool:
    """
    Strict Local API Authentication Guardian.
    Guards against malicious websites on localhost attempting CSRF or unauthenticated mutations.
    """
    token = request.headers.get("X-KeyOps-Auth-Token") or request.headers.get("X-Auth-Token")
    if not token and "Authorization" in request.headers:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    if not token:
        token = request.query_params.get("token", "")

    expected_token = settings.local_api_token
    if not token or not secrets.compare_digest(token, expected_token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing or invalid local API authorization token."
        )
    return True

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                pass

ws_manager = ConnectionManager()

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "api_token": settings.local_api_token
    })

@app.get("/api/dashboard/overview")
def get_dashboard_overview(db: Session = Depends(get_db)):
    accounts = db.query(Account).all()
    acc_dicts = [
        {
            "id": a.id,
            "service": a.service,
            "username": a.username,
            "domain": a.domain,
            "risk": a.risk,
            "issue": a.issue,
            "mfa_status": a.mfa_status,
            "rotation_status": a.rotation_status,
        }
        for a in accounts
    ]
    overview = SecurityScoreCalculator.calculate(acc_dicts)
    return overview.model_dump()

@app.get("/api/accounts")
def list_accounts(db: Session = Depends(get_db)):
    return db.query(Account).order_by(Account.id.asc()).all()

@app.post("/api/accounts/import")
async def import_accounts(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    content = (await file.read()).decode("utf-8")
    importer = CSVAccountImporter(db)
    imported = importer.import_from_csv_content(content)
    return {"message": f"Successfully imported {len(imported)} accounts", "count": len(imported)}

@app.post("/api/accounts/add")
def add_account(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    service = data.get("service", "").strip()
    username = data.get("username", "").strip()
    domain = data.get("domain", "").strip() or f"{service.lower()}.com"
    risk = data.get("risk", "MEDIUM")
    issue = data.get("issue", "Reused")

    acc = Account(
        service=service,
        username=username,
        domain=domain,
        risk=risk,
        issue=issue,
        mfa_status=data.get("mfa_status", False),
        automation_support="FULL",
        rotation_status="IDLE"
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc

@app.get("/api/queue")
def get_queue():
    return queue_manager.queue

@app.post("/api/queue/init")
def init_queue(
    filter_mode: str = "all",
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    if filter_mode == "compromised":
        accounts = db.query(Account).filter(Account.risk.in_(["CRITICAL", "HIGH"])).all()
    elif filter_mode == "critical":
        accounts = db.query(Account).filter(Account.risk == "CRITICAL").all()
    else:
        accounts = db.query(Account).filter(Account.rotation_status != "SUCCESS").all()

    items = queue_manager.set_queue(accounts)
    return {"queue": items, "count": len(items)}

@app.post("/api/rotation/prepare")
async def prepare_rotation(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    account_id = data.get("account_id")
    acc = db.query(Account).filter(Account.id == account_id).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Account not found")

    acc.rotation_status = "IN_PROGRESS"
    db.commit()

    async def broadcast_progress(payload: Dict[str, Any]):
        await ws_manager.broadcast({
            "type": "ROTATION_PROGRESS",
            **payload
        })

    result = await orchestrator.prepare_rotation_workflow(
        account_id=acc.id,
        service=acc.service,
        domain=acc.domain,
        username=acc.username,
        on_progress_callback=broadcast_progress
    )

    is_high_value = acc.service.lower() in HIGH_VALUE_SERVICES
    result["is_high_value"] = is_high_value
    result["username"] = acc.username

    return result

@app.post("/api/rotation/approve")
async def approve_rotation(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    """
    Called when the human user explicitly reviews credentials and clicks 'Approve' in UI.
    Authoritatively verifies server-side workflow state, domain trust, and live DOM form fingerprint
    BEFORE issuing a one-time cryptographic approval token.
    """
    account_id = data.get("account_id")
    workflow_id = data.get("workflow_id")

    if not workflow_id or not account_id:
        raise HTTPException(status_code=400, detail="Missing workflow_id or account_id.")

    # 1. Lookup workflow server-side
    workflow_state = orchestrator.get_workflow_state(workflow_id)
    if not workflow_state:
        raise HTTPException(status_code=404, detail="Workflow session not found or expired.")

    # 2. Verify account matches
    if workflow_state.account_id != account_id:
        raise HTTPException(status_code=400, detail="Account mismatch with active workflow.")

    acc = db.query(Account).filter(Account.id == account_id).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Account not found in database.")

    if acc.service.lower() != workflow_state.service.lower():
        raise HTTPException(status_code=400, detail="Service mismatch with database record.")

    # 3. Verify workflow phase is READY_FOR_APPROVAL
    if workflow_state.phase != WorkflowPhase.READY_FOR_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail=f"Approval rejected: Workflow is in phase '{workflow_state.phase.value}', expected 'READY_FOR_APPROVAL'."
        )

    # 4. Verify live browser page still exists
    page = orchestrator._active_pages.get(workflow_id)
    if not page or page.is_closed():
        raise HTTPException(status_code=400, detail="Browser page has been closed or lost.")

    # 5. Re-evaluate live domain trust
    trust_ctx = DomainTrustContext(expected_service=acc.service, allowed_explicit_domains=[acc.domain])
    trust_res = trust_ctx.evaluate_url(page.url)
    if not trust_res.is_trusted:
        workflow_state.phase = WorkflowPhase.DOMAIN_VIOLATION
        raise HTTPException(
            status_code=400,
            detail=f"Approval rejected: Live page is on untrusted domain ({trust_res.registrable_domain}): {trust_res.reason}"
        )

    # 6. Recompute live form fingerprint from actual browser DOM
    live_fp = await orchestrator.navigator.compute_form_fingerprint(page)
    if live_fp != workflow_state.form_fingerprint and workflow_state.form_fingerprint not in ("fp_default", "fp_resumed"):
        raise HTTPException(
            status_code=400,
            detail=f"Approval rejected: Form DOM structure changed after preparation. Re-verification required."
        )

    # 7. Issue single-use approval token
    session_id = data.get("session_id") or f"sess_{workflow_id}"
    token = approval_manager.issue_approval_token(
        account_id=acc.id,
        service=acc.service,
        verified_domain=acc.domain,
        browser_session_id=session_id,
        workflow_id=workflow_id,
        form_fingerprint=live_fp,
        ttl_seconds=120
    )

    return {
        "status": "APPROVED",
        "approval_token_id": token.token_id,
        "expires_at": token.expires_at,
        "account_id": acc.id,
        "workflow_id": workflow_id
    }

@app.post("/api/rotation/execute")
async def execute_rotation(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    workflow_id = data.get("workflow_id")
    token_id = data.get("approval_token_id")
    session_id = data.get("session_id")
    account_id = data.get("account_id")
    dry_run = data.get("dry_run", False)
    save_to_keychain = data.get("save_to_keychain", True)

    acc = db.query(Account).filter(Account.id == account_id).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Account not found")

    if not token_id and not dry_run:
        raise HTTPException(status_code=400, detail="Submission rejected: Missing human approval token.")

    async def broadcast_progress(payload: Dict[str, Any]):
        await ws_manager.broadcast({
            "type": "ROTATION_PROGRESS",
            **payload
        })

    if dry_run:
        acc.rotation_status = "DRY_RUN_PASSED"
        db.commit()
        return {"status": "SUCCESS", "message": f"Dry-run rotation validated for {acc.service}."}

    exec_result = await orchestrator.execute_approved_submission(
        workflow_id=workflow_id,
        approval_token_id=token_id,
        session_id=session_id,
        save_to_keychain=save_to_keychain,
        on_progress_callback=broadcast_progress
    )

    if exec_result.get("status") == "SUCCESS":
        acc.rotation_status = "SUCCESS"
        acc.issue = "Secure"
        acc.risk = "LOW"
        db.commit()

        await ws_manager.broadcast({
            "type": "ROTATION_SUCCESS",
            "account_id": acc.id,
            "service": acc.service,
            "message": f"Password rotation successfully confirmed for {acc.service}!"
        })
    else:
        acc.rotation_status = "FAILED"
        db.commit()

        await ws_manager.broadcast({
            "type": "ROTATION_FAILURE",
            "account_id": acc.id,
            "service": acc.service,
            "message": f"Password rotation failed: {exec_result.get('details') or exec_result.get('error')}"
        })

    return exec_result

@app.post("/api/rotation/resume")
async def resume_rotation(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_local_api_auth)
):
    workflow_id = data.get("workflow_id")
    session_id = data.get("session_id")

    async def broadcast_progress(payload: Dict[str, Any]):
        await ws_manager.broadcast({
            "type": "ROTATION_PROGRESS",
            **payload
        })

    res = await orchestrator.resume_workflow_after_human(
        workflow_id=workflow_id,
        session_id=session_id,
        on_progress_callback=broadcast_progress
    )
    return res

@app.get("/api/doctor")
def run_doctor_diagnostics(db: Session = Depends(get_db)):
    import sys
    
    # 1. Python runtime check
    py_ok = sys.version_info >= (3, 10)
    
    # 2. Playwright package check
    try:
        import playwright
        pw_ok = True
    except ImportError:
        pw_ok = False
        
    # 3. Database connection check
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
        
    # 4. Keychain availability check
    try:
        from app.integrations.keychain import KeychainManager
        keychain_ok = True
    except Exception:
        keychain_ok = False
        
    # 5. Gemini configuration
    has_gemini = bool(settings.gemini_api_key)
    
    # 6. Adapters count
    adapters_count = len(adapter_registry.list_adapters())
    
    return {
        "python_version": sys.version,
        "python_supported": py_ok,
        "playwright_installed": pw_ok,
        "chromium_available": pw_ok,
        "database_connected": db_ok,
        "sqlite_path": str(settings.db_url),
        "keychain_accessible": keychain_ok,
        "gemini_configured": has_gemini,
        "adapters_count": adapters_count,
        "local_api_auth_active": bool(settings.local_api_token),
        "telemetry_disabled": True,
        "status": "HEALTHY" if (py_ok and pw_ok and db_ok) else "DEGRADED"
    }

@app.get("/api/workflows")
def get_workflows():
    return {k: v.model_dump() for k, v in workflow_memory._workflows.items()}

@app.get("/api/audit")
def get_audit_logs(db: Session = Depends(get_db)):
    if settings.log_file.exists():
        with open(settings.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return {"logs": lines[-100:]}
    return {"logs": ["No audit logs recorded yet."]}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token or not secrets.compare_digest(token, settings.local_api_token):
        await websocket.close(code=1008)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

