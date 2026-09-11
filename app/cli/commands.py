import sys
import webbrowser
import uvicorn
import typer
from typing import Optional
from rich.console import Console
from rich.table import Table

from app.config import settings
from app.database.session import SessionLocal, init_db
from app.database.models import Account
from app.core.security_score import SecurityScoreCalculator
from app.core.audit_logger import audit_logger
from app.adapters.registry import adapter_registry
from app.integrations.csv_importer import CSVAccountImporter
from app.cli.doctor import run_doctor_diagnostics

app = typer.Typer(help="Password Security Center CLI — Personal Cybersecurity Manager")
console = Console()

@app.command("dashboard")
def start_dashboard(
    port: int = typer.Option(8443, help="Port to run dashboard server"),
    open_browser: bool = typer.Option(True, help="Automatically open default browser")
):
    """Launch the interactive Password Security Center dashboard."""
    init_db()
    url = f"http://127.0.0.1:{port}"
    console.print(f"\n[bold green]🚀 Launching Password Security Center Dashboard at {url}[/bold green]\n")
    
    if open_browser:
        webbrowser.open(url)
        
    uvicorn.run("app.api.server:app", host="127.0.0.1", port=port, log_level="warning")

@app.command("doctor")
def doctor_cmd():
    """Run comprehensive system diagnostics."""
    run_doctor_diagnostics()

@app.command("scan")
def scan_cmd():
    """Run security scan across all monitored accounts."""
    init_db()
    db = SessionLocal()
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

    console.print(f"\n[bold cyan]SECURITY OVERVIEW SCORE: {overview.score} / 100[/bold cyan]")
    console.print(f"Critical: [red]{overview.critical_count}[/red] | High: [amber]{overview.high_count}[/amber] | Medium: [blue]{overview.medium_count}[/blue] | Low: [green]{overview.low_count}[/green]\n")

    table = Table(title="Account Risk Status")
    table.add_column("Service", style="cyan")
    table.add_column("Username", style="white")
    table.add_column("Domain", style="blue")
    table.add_column("Risk", style="bold red")
    table.add_column("Issue", style="yellow")

    for a in accounts:
        table.add_row(a.service, a.username, a.domain, a.risk, a.issue)

    console.print(table)
    db.close()

@app.command("import")
def import_cmd(csv_path: str = typer.Argument(..., help="Path to accounts CSV file")):
    """Import accounts from CSV file."""
    init_db()
    db = SessionLocal()
    with open(csv_path, "r", encoding="utf-8") as f:
        content = f.read()
    importer = CSVAccountImporter(db)
    imported = importer.import_from_csv_content(content)
    console.print(f"[bold green]✓ Successfully imported {len(imported)} accounts from {csv_path}[/bold green]")
    db.close()

@app.command("adapters")
def adapters_cmd():
    """List all registered service adapters."""
    adapters = adapter_registry.list_adapters()
    table = Table(title="Registered Service Adapters")
    table.add_column("Service", style="cyan")
    table.add_column("Official Domains", style="green")
    table.add_column("Login URL", style="blue")

    for a in adapters:
        table.add_row(a.service_name, ", ".join(a.official_domains), a.login_url)

    console.print(table)

@app.command("audit")
def audit_cmd():
    """View privacy-preserving audit logs."""
    if settings.log_file.exists():
        with open(settings.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-50:]:
            console.print(line.strip())
    else:
        console.print("[yellow]No audit logs found.[/yellow]")

@app.command("fix")
def fix_cmd(
    service: Optional[str] = typer.Argument(None, help="Service name to fix"),
    critical: bool = typer.Option(False, "--critical", help="Fix all critical risk accounts"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Perform navigation dry-run without submitting password changes"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm prompt (still verifies approval token)")
):
    """Initiate genuine AI-assisted password rotation for specified account or risk category."""
    import asyncio
    from app.core.orchestrator import orchestrator
    from app.safety.submission_approval import approval_manager

    init_db()
    db = SessionLocal()
    
    if service:
        accs = db.query(Account).filter(Account.service.ilike(f"%{service}%")).all()
    elif critical:
        accs = db.query(Account).filter(Account.risk == "CRITICAL").all()
    else:
        accs = db.query(Account).filter(Account.risk.in_(["CRITICAL", "HIGH"])).all()

    if not accs:
        console.print("[yellow]No matching accounts found for rotation.[/yellow]")
        db.close()
        return

    async def _process_cli_rotations():
        for a in accs:
            console.print(f"\n[bold cyan]═══ Processing Account #{a.id}: {a.service} ({a.username}) ═══[/bold cyan]")
            
            # Progress callback for terminal
            async def print_progress(payload):
                phase = payload.get("phase", "PROGRESS")
                msg = payload.get("message", "")
                console.print(f"  [dim]{phase}:[/dim] {msg}")

            prep_res = await orchestrator.prepare_rotation_workflow(
                account_id=a.id,
                service=a.service,
                domain=a.domain,
                username=a.username,
                on_progress_callback=print_progress
            )

            status = prep_res.get("status")
            if status != "READY_FOR_APPROVAL":
                console.print(f"[bold red]✗ Preparation stopped with status '{status}': {prep_res.get('reason') or prep_res.get('message')}[/bold red]")
                a.rotation_status = "FAILED"
                db.commit()
                continue

            if dry_run:
                console.print("[bold yellow]✓ [DRY-RUN] Form located and CSPRNG secret prepared successfully. Submission skipped.[/bold yellow]")
                a.rotation_status = "DRY_RUN_PASSED"
                db.commit()
                continue

            # Human Approval Gate
            approved = yes
            if not approved:
                approved = typer.confirm(f"\nAuthorize final password submission for {a.service} ({a.username}) on domain {a.domain}?", default=False)

            if not approved:
                console.print("[yellow]Submission cancelled by user.[/yellow]")
                a.rotation_status = "CANCELLED"
                db.commit()
                continue

            # Issue cryptographic approval token
            token = approval_manager.issue_approval_token(
                account_id=a.id,
                service=a.service,
                verified_domain=a.domain,
                browser_session_id=prep_res["session_id"],
                workflow_id=prep_res["workflow_id"],
                form_fingerprint=prep_res["form_fingerprint"]
            )

            # Execute submission through secure ControlledActionExecutor
            exec_res = await orchestrator.execute_approved_submission(
                workflow_id=prep_res["workflow_id"],
                approval_token_id=token.token_id,
                session_id=prep_res["session_id"],
                save_to_keychain=True,
                on_progress_callback=print_progress
            )

            if exec_res.get("status") == "SUCCESS":
                console.print(f"[bold green]✓ Password rotation successfully verified and stored for {a.service}![/bold green]")
                a.rotation_status = "SUCCESS"
                a.issue = "Secure"
                a.risk = "LOW"
                db.commit()
            else:
                console.print(f"[bold red]✗ Rotation failed: {exec_res.get('details') or exec_res.get('error')}[/bold red]")
                a.rotation_status = "FAILED"
                db.commit()

    asyncio.run(_process_cli_rotations())
    db.close()
    console.print("\n[bold green]✓ Batch CLI rotation process complete.[/bold green]\n")

if __name__ == "__main__":
    app()

