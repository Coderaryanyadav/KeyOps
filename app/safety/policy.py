from pydantic import BaseModel

class SafetyPolicyConfig(BaseModel):
    min_navigation_confidence: float = 0.80
    min_field_confidence: float = 0.85
    min_submission_confidence: float = 0.90
    block_dangerous_actions: bool = True
    require_explicit_submission_approval: bool = True
    allow_arbitrary_js: bool = False  # NEVER allowed
    allow_shell_execution: bool = False  # NEVER allowed
    allow_raw_passwords_to_ai: bool = False  # NEVER allowed

default_safety_policy = SafetyPolicyConfig()
