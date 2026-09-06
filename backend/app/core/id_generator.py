"""
Unique Identifier Generator for Q-SHIELD Security Platform.
Generates human-readable, unique Signature and Analysis IDs.
"""

import uuid

def generate_signature_id() -> str:
    """Generates a unique Signature ID following format: QSHIELD-SIGN-XXXXXXXX."""
    return f"QSHIELD-SIGN-{uuid.uuid4().hex[:8].upper()}"

def generate_analysis_id() -> str:
    """Generates a unique Analysis ID following format: QSHIELD-ANALYSIS-XXXXXXXX."""
    return f"QSHIELD-ANALYSIS-{uuid.uuid4().hex[:8].upper()}"
