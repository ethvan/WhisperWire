import re
from typing import Any

from proxy.models import (
    Finding,
    InspectionContext,
    InspectionReport,
)


class PromptShield:
    """Deterministic prompt-injection indicator detector."""

    def __init__(self) -> None:
        self._rules = [
            (
                "prompt.instruction_override",
                "instruction_override",
                re.compile(
                    r"\b(ignore|disregard|override)\b"
                    r".{0,60}\b(previous|prior|above|all)\b"
                    r".{0,40}\b(instructions?|prompts?|rules?)\b",
                    re.IGNORECASE,
                ),
                "Potential instruction override detected.",
            ),
            (
                "prompt.system_extraction",
                "system_prompt_extraction",
                re.compile(
                    r"\b(reveal|show|print|repeat|disclose)\b"
                    r".{0,50}\b(system|developer)\b"
                    r".{0,30}\b(prompt|instructions?)\b",
                    re.IGNORECASE,
                ),
                "Potential system prompt extraction detected.",
            ),
            (
                "prompt.safety_bypass",
                "safety_bypass",
                re.compile(
                    r"\b(bypass|disable|ignore|circumvent)\b"
                    r".{0,50}\b(safety|security)\b"
                    r".{0,30}\b(restrictions?|filters?|guardrails?|rules?)\b",
                    re.IGNORECASE,
                ),
                "Potential safety control bypass detected.",
            ),
            (
                "prompt.data_exfiltration",
                "data_exfiltration",
                re.compile(
                    r"\b(?:"
                    r"(?:send|transmit|exfiltrate|forward|upload)"
                    r".{0,80}"
                    r"(?:secrets?|credentials?|tokens?|private data)"
                    r"|"
                    r"(?:secrets?|credentials?|tokens?|private data)"
                    r".{0,80}"
                    r"(?:send|transmit|exfiltrate|forward|upload)"
                    r")\b",
                    re.IGNORECASE,
                ),
                "Potential sensitive data exfiltration instruction detected.",
            ),
        ]

    async def inspect(
        self,
        message: dict[str, Any],
        context: InspectionContext,
    ) -> InspectionReport:
        findings: list[Finding] = []

        try:
            for value in self._walk_values(message):
                if not isinstance(value, str):
                    continue

                for rule_id, category, pattern, description in self._rules:
                    if pattern.search(value):
                        finding = Finding(
                            rule_id=rule_id,
                            severity="high",
                            category=category,
                            description=description,
                            evidence=f"Matched indicator: {rule_id}",
                        )

                        if finding not in findings:
                            findings.append(finding)

            return InspectionReport(
                module_id=self.id,
                findings=findings,
            )

        except Exception as exc:
            return InspectionReport(
                module_id=self.id,
                success=False,
                error=type(exc).__name__,
            )

    @property
    def id(self) -> str:
        return "prompt_shield"

    @property
    def name(self) -> str:
        return "PromptShield"

    @property
    def version(self) -> str:
        return "0.1.0"

    @staticmethod
    def _walk_values(value: Any):
        """Yield every value nested inside dictionaries and lists."""
        if isinstance(value, dict):
            for nested_value in value.values():
                yield from PromptShield._walk_values(nested_value)
        elif isinstance(value, list):
            for nested_value in value:
                yield from PromptShield._walk_values(nested_value)
        else:
            yield value
