import secrets
from fastapi import Header, HTTPException, status
from .config import settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Protect state-changing/operator endpoints in non-development deployments."""
    if settings.environment == "development" and not settings.api_key:
        return
    if not settings.api_key or not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="operator API key required")
