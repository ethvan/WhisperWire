from proxy.models import InspectionContext, InspectionReport, Finding

class TestModule:
    @property
    def id(self) -> str:
        return "test_module"

    @property
    def name(self) -> str:
        return "Test Security Module"

    @property
    def version(self) -> str:
        return "0.1.0"

    async def inspect(
        self,
        message: dict,
        context: InspectionContext,
    ) -> InspectionReport:
        """
        Detect a predictable test string in an inbound MCP message.
        """

        serialized_message = str(message)

        findings = []

        if "whisperwire-test-trigger" in serialized_message:
            findings.append(
                Finding(
                    rule_id="TEST-001",
                    severity="high",
                    category="test_detection",
                    description="Test trigger detected in MCP message",
                    evidence="whisperwire-test-trigger",
                )
            )

        return InspectionReport(
            module_id=self.id,
            findings=findings,
        )
