from dataclasses import dataclass, field
from typing import Literal

from proxy.models import Finding, InspectionReport


@dataclass
class PolicyDecision:
    """
    Represents the security disposition determined by PolicyEngine.
    """

    action: Literal["allow", "block", "ask"]
    reason: str
    findings: list[Finding] = field(default_factory=list)
    inspection_errors: list[str] = field(default_factory=list)


class PolicyEngine:
    """
    Evaluates inspection reports and determines the appropriate
    security disposition for the current operating mode.
    """

    VALID_MODES = {"observe", "alert", "ask"}

    def evaluate(
        self,
        reports: list[InspectionReport],
        mode: str,
    ) -> PolicyDecision:
        """
        Evaluate inspection reports and return a policy decision.

        The policy engine is transport-agnostic. It determines
        what should happen, but does not enforce the decision.
        """

        if mode not in self.VALID_MODES:
            raise ValueError(f"Unsupported policy mode: {mode}")

        findings = []
        inspection_errors = []

        for report in reports:
            findings.extend(report.findings)

            if not report.success:
                error = report.error or "Unknown inspection error"
                inspection_errors.append(
                    f"{report.module_id}: {error}"
                )

        # Observe mode records findings and failures but never
        # intervenes in the operation.
        if mode == "observe":
            return PolicyDecision(
                action="allow",
                reason="Observe mode does not enforce security decisions.",
                findings=findings,
                inspection_errors=inspection_errors,
            )

        severities = {finding.severity for finding in findings}

        # Critical findings always block in enforcement-capable modes.
        if "critical" in severities:
            return PolicyDecision(
                action="block",
                reason="A critical security finding was detected.",
                findings=findings,
                inspection_errors=inspection_errors,
            )

        # High-severity findings block in alert mode.
        if mode == "alert" and "high" in severities:
            return PolicyDecision(
                action="block",
                reason="A high-severity security finding was detected.",
                findings=findings,
                inspection_errors=inspection_errors,
            )

        # High-severity findings require agent consideration in ask mode.
        if mode == "ask" and "high" in severities:
            return PolicyDecision(
                action="ask",
                reason="A high-severity security finding requires agent consideration.",
                findings=findings,
                inspection_errors=inspection_errors,
            )

        # Inspection failures must not silently become clean results.
        # In ask mode, the operation must pause for agent consideration.
        if mode == "ask" and inspection_errors:
            return PolicyDecision(
                action="ask",
                reason="One or more inspection modules failed.",
                findings=findings,
                inspection_errors=inspection_errors,
            )

        # Alert mode communicates inspection failures separately,
        # but does not block the operation solely because of them.
        return PolicyDecision(
            action="allow",
            reason="No blocking security conditions were detected.",
            findings=findings,
            inspection_errors=inspection_errors,
        )

