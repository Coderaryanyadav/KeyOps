import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any
from pydantic import BaseModel, Field
from app.config import APP_DIR
from app.core.audit_logger import audit_logger

WORKFLOW_DB_FILE = APP_DIR / "workflow_memory.json"

class WebsiteWorkflow(BaseModel):
    domain: str
    service_name: str
    security_url: str
    password_change_url: str
    form_selectors: Dict[str, str] = Field(default_factory=dict)
    password_requirements: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.90
    adapter_version: str = "1.0.0"
    last_validated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class WorkflowMemory:
    """
    Non-sensitive website workflow knowledge base.
    Persists discovered navigation routes, form structures, and policy heuristics.
    CRITICAL SECURITY INVARIANT: NEVER stores secrets, passwords, cookies, or auth tokens.
    """

    def __init__(self, memory_file: Optional[Path] = None):
        self.file_path = memory_file or WORKFLOW_DB_FILE
        self._workflows: Dict[str, WebsiteWorkflow] = {}
        self._load()

    def _load(self) -> None:
        if self.file_path.exists():
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self._workflows[k] = WebsiteWorkflow(**v)
            except Exception as e:
                audit_logger.log_event("WORKFLOW_MEMORY", f"Failed to load workflow memory: {str(e)}", level="WARNING")

    def _save(self) -> None:
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                data = {k: v.model_dump() for k, v in self._workflows.items()}
                json.dump(data, f, indent=2)
        except Exception as e:
            audit_logger.log_event("WORKFLOW_MEMORY", f"Failed to save workflow memory: {str(e)}", level="ERROR")

    def get_workflow(self, domain: str) -> Optional[WebsiteWorkflow]:
        return self._workflows.get(domain.lower())

    def record_workflow(self, workflow: WebsiteWorkflow) -> None:
        key = workflow.domain.lower()
        self._workflows[key] = workflow
        self._save()
        audit_logger.log_event("WORKFLOW_MEMORY", f"Recorded validated workflow for domain '{key}' (confidence={workflow.confidence:.2f}).")

    def invalidate_workflow(self, domain: str, reason: str) -> None:
        key = domain.lower()
        if key in self._workflows:
            del self._workflows[key]
            self._save()
            audit_logger.log_event("WORKFLOW_MEMORY", f"Invalidated workflow for domain '{key}' due to: {reason}.")

workflow_memory = WorkflowMemory()
