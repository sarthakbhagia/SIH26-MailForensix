"""ML Schemas Package."""
from ml.src.schemas.canonical_email import CanonicalEmail, compute_deterministic_email_id

__all__ = ["CanonicalEmail", "compute_deterministic_email_id"]
