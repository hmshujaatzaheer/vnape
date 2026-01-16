"""
V-NAPE Logging Utilities

Provides structured logging with support for trace events, enforcement decisions,
and verification results. Supports multiple output formats (JSON, text, structured).
"""

import json
import logging
import sys
import threading
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class LogLevel(Enum):
    """Log levels for V-NAPE logging."""

    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

    # Custom levels for V-NAPE
    TRACE = 5  # Below DEBUG, for detailed trace logging
    SECURITY = 25  # Between INFO and WARNING, for security events
    ENFORCEMENT = 26  # For enforcement decisions
    VERIFICATION = 27  # For verification results


# Register custom log levels
logging.addLevelName(LogLevel.TRACE.value, "TRACE")
logging.addLevelName(LogLevel.SECURITY.value, "SECURITY")
logging.addLevelName(LogLevel.ENFORCEMENT.value, "ENFORCEMENT")
logging.addLevelName(LogLevel.VERIFICATION.value, "VERIFICATION")


@dataclass
class LogContext:
    """Context information for structured logging."""

    session_id: str | None = None
    protocol_name: str | None = None
    component: str | None = None
    trace_id: str | None = None
    enforcement_mode: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceEventLog:
    """Structured log entry for trace events."""

    timestamp: datetime
    event_name: str
    event_args: dict[str, Any]
    protocol: str
    session_id: str
    sequence_number: int
    context: LogContext | None = None


@dataclass
class EnforcementDecisionLog:
    """Structured log entry for enforcement decisions."""

    timestamp: datetime
    action: str
    policy_violated: str | None
    confidence: float
    quantum_adjusted: bool
    quantum_risk_score: float | None
    reason: str
    context: LogContext | None = None


@dataclass
class VerificationResultLog:
    """Structured log entry for verification results."""

    timestamp: datetime
    property_verified: str
    result: str  # SAT, UNSAT, UNKNOWN, TIMEOUT
    verification_time_ms: float
    counterexample: str | None
    certificate_generated: bool
    context: LogContext | None = None


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def __init__(self, include_timestamp: bool = True, include_level: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_level = include_level

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "message": record.getMessage(),
            "logger": record.name,
        }

        if self.include_timestamp:
            log_data["timestamp"] = datetime.fromtimestamp(record.created).isoformat()

        if self.include_level:
            log_data["level"] = record.levelname

        # Include exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Include extra fields
        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "exc_info",
                "exc_text",
                "thread",
                "threadName",
                "message",
                "asctime",
            ):
                try:
                    json.dumps(value)  # Test JSON serializable
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "TRACE": "\033[90m",  # Dark gray
        "SECURITY": "\033[93m",  # Light yellow
        "ENFORCEMENT": "\033[94m",  # Light blue
        "VERIFICATION": "\033[95m",  # Light magenta
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str | None = None, datefmt: str | None = None):
        if fmt is None:
            fmt = "%(asctime)s | %(levelname)-12s | %(name)s | %(message)s"
        if datefmt is None:
            datefmt = "%Y-%m-%d %H:%M:%S"
        super().__init__(fmt, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        # Apply color to level name
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class VNAPELogger:
    """
    Centralized logger for V-NAPE framework.

    Provides structured logging with support for:
    - Multiple output formats (JSON, text, colored)
    - Multiple output destinations (console, file, remote)
    - Context-aware logging
    - Specialized methods for trace events, enforcement, and verification
    """

    _instance: Optional["VNAPELogger"] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern for global logger access."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        name: str = "vnape",
        level: LogLevel | int = LogLevel.INFO,
        json_output: bool = False,
        colored_output: bool = True,
        log_file: Path | None = None,
    ):
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._initialized = True
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level.value if isinstance(level, LogLevel) else level)
        self.logger.handlers = []  # Clear existing handlers

        self.context = LogContext()
        self._json_output = json_output
        self._colored_output = colored_output

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        if json_output:
            console_handler.setFormatter(JSONFormatter())
        elif colored_output:
            console_handler.setFormatter(ColoredFormatter())
        else:
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s | %(levelname)-12s | %(name)s | %(message)s")
            )
        self.logger.addHandler(console_handler)

        # File handler (always JSON for structured analysis)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(JSONFormatter())
            self.logger.addHandler(file_handler)

    def set_context(self, context: LogContext) -> None:
        """Set the logging context."""
        self.context = context

    def update_context(self, **kwargs) -> None:
        """Update specific context fields."""
        for key, value in kwargs.items():
            if hasattr(self.context, key):
                setattr(self.context, key, value)
            else:
                self.context.extra[key] = value

    def _add_context(self, extra: dict[str, Any]) -> dict[str, Any]:
        """Add context to log extra fields."""
        context_dict = asdict(self.context)
        context_dict.update(extra)
        return context_dict

    def trace(self, msg: str, **kwargs) -> None:
        """Log at TRACE level."""
        self.logger.log(LogLevel.TRACE.value, msg, extra=self._add_context(kwargs))

    def debug(self, msg: str, **kwargs) -> None:
        """Log at DEBUG level."""
        self.logger.debug(msg, extra=self._add_context(kwargs))

    def info(self, msg: str, **kwargs) -> None:
        """Log at INFO level."""
        self.logger.info(msg, extra=self._add_context(kwargs))

    def warning(self, msg: str, **kwargs) -> None:
        """Log at WARNING level."""
        self.logger.warning(msg, extra=self._add_context(kwargs))

    def error(self, msg: str, **kwargs) -> None:
        """Log at ERROR level."""
        self.logger.error(msg, extra=self._add_context(kwargs))

    def critical(self, msg: str, **kwargs) -> None:
        """Log at CRITICAL level."""
        self.logger.critical(msg, extra=self._add_context(kwargs))

    def security(self, msg: str, **kwargs) -> None:
        """Log security-related events."""
        self.logger.log(LogLevel.SECURITY.value, msg, extra=self._add_context(kwargs))

    def enforcement(self, msg: str, **kwargs) -> None:
        """Log enforcement decisions."""
        self.logger.log(LogLevel.ENFORCEMENT.value, msg, extra=self._add_context(kwargs))

    def verification(self, msg: str, **kwargs) -> None:
        """Log verification results."""
        self.logger.log(LogLevel.VERIFICATION.value, msg, extra=self._add_context(kwargs))

    def log_trace_event(
        self,
        event_name: str,
        event_args: dict[str, Any],
        protocol: str,
        session_id: str,
        sequence_number: int,
    ) -> None:
        """Log a protocol trace event."""
        log_entry = TraceEventLog(
            timestamp=datetime.now(),
            event_name=event_name,
            event_args=event_args,
            protocol=protocol,
            session_id=session_id,
            sequence_number=sequence_number,
            context=self.context,
        )
        self.trace(
            f"Trace event: {event_name}",
            trace_event=asdict(log_entry),
        )

    def log_enforcement_decision(
        self,
        action: str,
        policy_violated: str | None,
        confidence: float,
        quantum_adjusted: bool,
        quantum_risk_score: float | None,
        reason: str,
    ) -> None:
        """Log an enforcement decision."""
        log_entry = EnforcementDecisionLog(
            timestamp=datetime.now(),
            action=action,
            policy_violated=policy_violated,
            confidence=confidence,
            quantum_adjusted=quantum_adjusted,
            quantum_risk_score=quantum_risk_score,
            reason=reason,
            context=self.context,
        )
        self.enforcement(
            f"Enforcement decision: {action} (confidence={confidence:.2f})",
            enforcement_decision=asdict(log_entry),
        )

    def log_verification_result(
        self,
        property_verified: str,
        result: str,
        verification_time_ms: float,
        counterexample: str | None = None,
        certificate_generated: bool = False,
    ) -> None:
        """Log a verification result."""
        log_entry = VerificationResultLog(
            timestamp=datetime.now(),
            property_verified=property_verified,
            result=result,
            verification_time_ms=verification_time_ms,
            counterexample=counterexample,
            certificate_generated=certificate_generated,
            context=self.context,
        )
        self.verification(
            f"Verification result: {result} for {property_verified} ({verification_time_ms:.2f}ms)",
            verification_result=asdict(log_entry),
        )

    def exception(self, msg: str, exc: Exception | None = None, **kwargs) -> None:
        """Log an exception with stack trace."""
        if exc:
            kwargs["exception_type"] = type(exc).__name__
            kwargs["exception_message"] = str(exc)
            kwargs["stack_trace"] = traceback.format_exc()
        self.logger.exception(msg, extra=self._add_context(kwargs))


# Global logger instance
_global_logger: VNAPELogger | None = None


def get_logger(name: str | None = None) -> VNAPELogger:
    """Get the global logger or create a named logger."""
    global _global_logger
    if _global_logger is None:
        _global_logger = VNAPELogger()
    if name:
        child_logger = VNAPELogger.__new__(VNAPELogger)
        child_logger.logger = _global_logger.logger.getChild(name)
        child_logger.context = _global_logger.context
        child_logger._initialized = True
        return child_logger
    return _global_logger


def configure_logging(
    level: LogLevel | int = LogLevel.INFO,
    json_output: bool = False,
    colored_output: bool = True,
    log_file: Path | None = None,
) -> VNAPELogger:
    """Configure the global logger."""
    global _global_logger
    _global_logger = VNAPELogger(
        level=level,
        json_output=json_output,
        colored_output=colored_output,
        log_file=log_file,
    )
    return _global_logger


# Convenience functions
def log_trace_event(
    event_name: str,
    event_args: dict[str, Any],
    protocol: str,
    session_id: str,
    sequence_number: int,
) -> None:
    """Log a trace event using the global logger."""
    get_logger().log_trace_event(event_name, event_args, protocol, session_id, sequence_number)


def log_enforcement_decision(
    action: str,
    policy_violated: str | None,
    confidence: float,
    quantum_adjusted: bool = False,
    quantum_risk_score: float | None = None,
    reason: str = "",
) -> None:
    """Log an enforcement decision using the global logger."""
    get_logger().log_enforcement_decision(
        action, policy_violated, confidence, quantum_adjusted, quantum_risk_score, reason
    )


def log_verification_result(
    property_verified: str,
    result: str,
    verification_time_ms: float,
    counterexample: str | None = None,
    certificate_generated: bool = False,
) -> None:
    """Log a verification result using the global logger."""
    get_logger().log_verification_result(
        property_verified, result, verification_time_ms, counterexample, certificate_generated
    )
