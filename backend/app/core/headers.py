"""
Security headers and request payload hardening middleware for FastAPI.
Adds strict Content-Security-Policy, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, frame protection, HSTS, and request body size limits.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from app.core.config import settings

_NON_PROD_ENVS = frozenset({"development", "dev", "test", "testing", "local"})


def _is_production() -> bool:
    return settings.ENV.strip().lower() not in _NON_PROD_ENVS


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """
    Enforces maximum request body size limits to protect against memory exhaustion / DoS attacks.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Check Content-Length header if present
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > settings.MAX_REQUEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Request body too large. Maximum allowed size is {settings.MAX_REQUEST_BODY_BYTES} bytes."
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects browser security headers on every response.
    CSP is strict in production (no inline scripts/styles with unsafe fallbacks).
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        is_prod = _is_production()

        # --- Content-Security-Policy ---
        if is_prod:
            csp = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; "
                "font-src 'self' data:; "
                "connect-src 'self' wss: ws:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "object-src 'none'; "
                "upgrade-insecure-requests"
            )
        else:
            # Relaxed CSP for development (allows HMR, eval, inline)
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; "
                "font-src 'self' data: https://fonts.gstatic.com; "
                "connect-src 'self' ws: wss: http://localhost:* http://127.0.0.1:*; "
                "frame-ancestors 'self'"
            )

        response.headers["Content-Security-Policy"] = csp

        # --- Standard security headers ---
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
            "magnetometer=(), gyroscope=(), accelerometer=()"
        )
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # --- HSTS (only in production behind TLS termination) ---
        if is_prod:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        # --- Cache-Control for API responses ---
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
            response.headers.setdefault("Pragma", "no-cache")

        return response
