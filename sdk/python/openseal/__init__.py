"""OpenSeal API client (slice 8, VS-08E): one method per operation of the OpenSeal API,
OAuth helpers, and webhook verification. Standard library only."""

from ._operations import OPERATIONS
from .client import JWT_BEARER, OpenSeal, OpenSealError, Response, verify_webhook

__all__ = ["JWT_BEARER", "OPERATIONS", "OpenSeal", "OpenSealError", "Response", "verify_webhook"]
__version__ = "0.1.0b0"
