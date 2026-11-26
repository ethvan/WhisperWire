from dataclasses import dataclass, field
from typing import Literal


@dataclass
class InspectionContext:
    """
    Describes the context in which a message is inspected.
    """

    direction: Literal["inbound", "outbound"]
    protocol: str
    session_id: str | None = None
    request_id: str | None = None


@dataclass
class Finding:
    """
    Represents an individual security observation.
    """

    rule_id: str
    severity: Literal[
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    ]
    category: str
    description: str
    evidence: str | None = None


@dataclass
class InspectionReport:
    """
    Contains the results of an individual module's inspection.
    """

    module_id: str
    findings: list[Finding] = field(default_factory=list)
    success: bool = True
    error: str | None = None
