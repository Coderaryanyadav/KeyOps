from enum import Enum
from typing import List, Dict, Optional, Callable, Awaitable
from pydantic import BaseModel, Field
from app.database.models import Account
from app.core.audit_logger import audit_logger

class QueueItemStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    READY_FOR_CONFIRMATION = "READY_FOR_CONFIRMATION"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"

class QueueItem(BaseModel):
    account_id: int
    service: str
    username: str
    domain: str
    risk: str
    status: QueueItemStatus = QueueItemStatus.PENDING
    current_step: str = "Queued"
    confidence: float = 1.0
    challenge_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    generated_password: Optional[str] = None
    is_high_value: bool = False

class QueueManager:
    """
    Manages the batch password rotation queue and state machine.
    Enforces automatic pausing at security boundaries and human checkpoints.
    """

    def __init__(self):
        self._queue: List[QueueItem] = []
        self._active_index: int = 0
        self._is_running: bool = False
        self._is_paused: bool = False

    @property
    def queue(self) -> List[QueueItem]:
        return list(self._queue)

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def is_paused(self) -> bool:
        return self._is_paused

    def set_queue(self, accounts: List[Account]) -> List[QueueItem]:
        self._queue = []
        self._active_index = 0
        self._is_running = False
        self._is_paused = False

        # Sort accounts: CRITICAL first, then HIGH, then MEDIUM, then LOW
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_accounts = sorted(accounts, key=lambda a: priority_order.get(a.risk.upper(), 4))

        for acc in sorted_accounts:
            item = QueueItem(
                account_id=acc.id,
                service=acc.service,
                username=acc.username,
                domain=acc.domain,
                risk=acc.risk,
                status=QueueItemStatus.PENDING,
                is_high_value=acc.risk.upper() == "CRITICAL"
            )
            self._queue.append(item)

        audit_logger.log_event("QUEUE", f"Initialized rotation queue with {len(self._queue)} accounts.")
        return list(self._queue)

    def get_current_item(self) -> Optional[QueueItem]:
        if 0 <= self._active_index < len(self._queue):
            return self._queue[self._active_index]
        return None

    def update_item_status(self, account_id: int, status: QueueItemStatus, step: str, confidence: float = 1.0, reason: Optional[str] = None):
        for item in self._queue:
            if item.account_id == account_id:
                item.status = status
                item.current_step = step
                item.confidence = confidence
                if status == QueueItemStatus.VERIFICATION_REQUIRED:
                    item.challenge_reason = reason
                    self._is_paused = True
                elif status == QueueItemStatus.FAILED:
                    item.failure_reason = reason
                break

    def advance_to_next(self) -> Optional[QueueItem]:
        self._active_index += 1
        self._is_paused = False
        if self._active_index < len(self._queue):
            item = self._queue[self._active_index]
            item.status = QueueItemStatus.IN_PROGRESS
            return item
        self._is_running = False
        return None

queue_manager = QueueManager()
