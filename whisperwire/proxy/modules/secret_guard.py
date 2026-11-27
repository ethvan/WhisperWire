import base64
import binascii
import re

from proxy.models import (
    Finding,
    InspectionContext,
    InspectionReport,
)
from proxy.modules.secret_rules import SECRET_RULES


class SecretGuard:
    """
    Detects recognizable credentials and explicitly known secrets.

    Known secrets receive higher severity than format-based matches.
    SecretGuard reports findings but does not enforce policy.
    """

    id = "secret_guard"
    name = "SecretGuard"
    version = "0.2.0"

    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    )

    def __init__(
        self,
        known_secrets: set[str] | None = None,
    ):
        self.known_secrets = frozenset(
            secret for secret in (known_secrets or set()) if secret
        )

    async def inspect(
        self,
        message: dict,
        context: InspectionContext,
    ) -> InspectionReport:

        findings: list[Finding] = []

        try:
            self._inspect_value(message, findings)

            return InspectionReport(
                module_id=self.id,
                findings=findings,
                success=True,
            )

        except Exception as exc:
            return InspectionReport(
                module_id=self.id,
                findings=[],
                success=False,
                error=type(exc).__name__,
            )

    def _inspect_string(
        self,
        value: str,
        findings: list[Finding],
    ) -> None:

        # Known canaries take precedence over format-based matches.
        known_canary_detected = False

        for secret in self.known_secrets:
            if secret in value:
                known_canary_detected = True

                self._add_finding(
                    findings=findings,
                    rule_id="secret.known_canary",
                    category="credential",
                    severity="critical",
                    description="Known sensitive value detected.",
                )

        if known_canary_detected:
            return

        for rule in SECRET_RULES:
            if rule.pattern.search(value):
                self._add_finding(
                    findings=findings,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                )

        if self.PRIVATE_KEY_PATTERN.search(value):
            self._add_finding(
                findings=findings,
                rule_id="secret.private_key",
                category="credential",
                severity="high",
                description="Private key structure detected.",
            )

        decoded = self._decode_base64(value)

        if decoded is not None and decoded != value:
            self._inspect_string(decoded, findings)

    def _inspect_value(
        self,
        value,
        findings: list[Finding],
    ) -> None:

        if isinstance(value, dict):
            for child in value.values():
                self._inspect_value(child, findings)

        elif isinstance(value, list):
            for child in value:
                self._inspect_value(child, findings)

        elif isinstance(value, str):
            self._inspect_string(value, findings)

    def _decode_base64(self, value: str) -> str | None:

        if len(value) < 16:
            return None

        try:
            decoded = base64.b64decode(
                value,
                validate=True,
            )

            return decoded.decode("utf-8")

        except (
            binascii.Error,
            UnicodeDecodeError,
            ValueError,
        ):
            return None

    def _add_finding(
        self,
        findings: list[Finding],
        rule_id: str,
        category: str,
        severity: str,
        description: str,
    ) -> None:

        # Avoid duplicate findings for the same rule.
        if rule_id != "secret.known_canary":
            if any(finding.rule_id == rule_id for finding in findings):
                return

        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                category=category,
                description=description,
                evidence=None,
            )
        )
