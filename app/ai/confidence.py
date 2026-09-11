from typing import Tuple
from pydantic import BaseModel, Field

class ConfidenceBreakdown(BaseModel):
    ai_confidence: float = 0.90
    dom_confidence: float = 0.90
    semantic_confidence: float = 0.90
    domain_confidence: float = 1.0
    overall_confidence: float = 0.90
    decision: str = "SAFE_TO_PROCEED"  # SAFE_TO_PROCEED, REQUIRES_HUMAN_CONFIRMATION, REJECT_LOW_CONFIDENCE

class MultiDimensionalConfidenceEngine:
    """
    Combines AI reasoning confidence, DOM signal confidence, semantic confidence,
    and domain safety into an authoritative composite confidence metric.
    """

    def calculate_confidence(
        self,
        ai_conf: float,
        dom_conf: float,
        semantic_conf: float,
        is_verified_domain: bool = True,
        is_credential_action: bool = False
    ) -> ConfidenceBreakdown:
        domain_conf = 1.0 if is_verified_domain else 0.0

        # Weighted composition
        if not is_verified_domain:
            return ConfidenceBreakdown(
                ai_confidence=ai_conf,
                dom_confidence=dom_conf,
                semantic_confidence=semantic_conf,
                domain_confidence=0.0,
                overall_confidence=0.0,
                decision="REJECT_LOW_CONFIDENCE"
            )

        composite = (ai_conf * 0.40) + (dom_conf * 0.30) + (semantic_conf * 0.30)
        
        # Stricter threshold for credential actions
        min_threshold = 0.88 if is_credential_action else 0.75

        if composite >= min_threshold:
            decision = "SAFE_TO_PROCEED"
        elif composite >= 0.60:
            decision = "REQUIRES_HUMAN_CONFIRMATION"
        else:
            decision = "REJECT_LOW_CONFIDENCE"

        return ConfidenceBreakdown(
            ai_confidence=ai_conf,
            dom_confidence=dom_conf,
            semantic_confidence=semantic_conf,
            domain_confidence=domain_conf,
            overall_confidence=round(composite, 2),
            decision=decision
        )
