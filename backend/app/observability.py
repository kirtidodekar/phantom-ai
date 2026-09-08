"""
Structured logging and centralized error handling for the Sentinel AI API.

Keeps observability concerns in one module so route handlers stay focused on
domain logic. Log records are emitted as single-line JSON so they can be
shipped to a SIEM/log pipeline without additional parsing rules.

Security note: this module deliberately never logs request bodies, database
URLs, or credentials. Only non-sensitive metadata is recorded.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

LOGGER_NAME = "sentinel"
_REDACTED_KEYS = {"database_url", "password", "secret", "token", "authorization", "api_key"}


class JsonLogFormatter(logging.Formatter):
    """Renders log records as compact single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach structured extras set via logger.info(..., extra={...}).
        for key, value in getattr(record, "context", {}).items():
            if key.lower() in _REDACTED_KEYS:
                continue
            payload[key] = value

        if record.exc_info:
            payload["error_type"] = record.exc_info[0].__name__ if record.exc_info[0] else "Unknown"

        return json.dumps(payload, default=str)


def get_logger() -> logging.Logger:
    """Returns the configured application logger."""
    return logging.getLogger(LOGGER_NAME)


def configure_logging() -> logging.Logger:
    """Installs the JSON handler once, honouring the LOG_LEVEL environment variable."""
    logger = logging.getLogger(LOGGER_NAME)
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


def log_event(level: str, message: str, **context: Any) -> None:
    """Emits a structured log record with arbitrary non-sensitive context."""
    logger = get_logger()
    safe_context = {k: v for k, v in context.items() if k.lower() not in _REDACTED_KEYS}
    logger.log(
        getattr(logging, level.upper(), logging.INFO),
        message,
        extra={"context": safe_context},
    )


def install_observability(app: FastAPI) -> None:
    """
    Registers request logging middleware and centralized exception handlers.

    Every response carries an `X-Request-ID` so a UI error can be traced back
    to a specific server-side log record.
    """
    configure_logging()

    @app.middleware("http")
    async def request_logger(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        started = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            log_event(
                "error",
                "request_failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
            )
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Request-ID"] = request_id

        # Health polling is high frequency; keep it at debug to avoid log noise.
        level = "debug" if request.url.path == "/api/health" else "info"
        if response.status_code >= 500:
            level = "error"
        elif response.status_code >= 400:
            level = "warning"

        log_event(
            level,
            "request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """Returns a consistent error envelope for expected HTTP errors."""
        log_event(
            "warning",
            "http_error",
            method=request.method,
            path=request.url.path,
            status=exc.status_code,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "type": "http_error",
                    "status": exc.status_code,
                    "message": str(exc.detail),
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Surfaces schema validation problems without echoing the raw payload."""
        fields = []
        for err in exc.errors():
            location = ".".join(str(part) for part in err.get("loc", []) if part != "body")
            fields.append({"field": location or "body", "issue": err.get("msg", "invalid")})

        log_event(
            "warning",
            "validation_error",
            method=request.method,
            path=request.url.path,
            field_count=len(fields),
        )
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "type": "validation_error",
                    "status": 422,
                    "message": "Request payload failed validation.",
                    "fields": fields,
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """
        Catches anything unexpected. The client receives a generic message so
        internal details and connection strings can never leak through the API.
        """
        get_logger().exception(
            "unhandled_exception",
            extra={"context": {"method": request.method, "path": request.url.path}},
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "type": "internal_error",
                    "status": 500,
                    "message": "An internal error occurred while processing the request.",
                }
            },
        )
