from proxy.models import InspectionContext, InspectionReport
from proxy.modules.registry import ModuleRegistry


class InspectionEngine:
    """
    Coordinates security module inspections and aggregates their reports.
    """

    def __init__(self, registry: ModuleRegistry):
        self.registry = registry

    async def inspect(
        self,
        message: dict,
        context: InspectionContext,
    ) -> list[InspectionReport]:
        """
        Run all registered security modules against a message.

        Returns one InspectionReport per registered module.
        """
        reports = []

        for module in self.registry.get_all():
            try:
                report = await module.inspect(message, context)
                reports.append(report)

            except Exception as exc:
                reports.append(
                    InspectionReport(
                        module_id=module.id,
                        findings=[],
                        success=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )

        return reports
