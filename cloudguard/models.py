"""Shared data models for CloudGuard."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class ControlDefinition:
    id: str
    title: str
    article: str
    gdpr_clause: str
    csp: str
    service: str
    check: str
    description: str
    remediation: str


@dataclass
class CheckResult:
    control_id: str
    title: str
    article: str
    gdpr_clause: str
    csp: str
    service: str
    status: Status
    detail: str
    remediation: str
    raw: Optional[Any] = field(default=None, repr=False)
