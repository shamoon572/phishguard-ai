"""
Rate limiting setup, isolated so app.py stays readable.
Uses flask-limiter with an in-memory store by default; point it at Redis
in production by setting storage_uri on the Limiter for multi-worker deployments.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)
