from typing import Protocol

from proxy.models import InspectionContext, InspectionReport


class SecurityModule(Protocol):
    """
    Interface that all whisperWire security modules must implement.
    """

    @property
    def id(self) -> str:
        """Unique, stable identifier for this module."""
        ...

    @property
    def name(self) -> str:
        """Human-readable module name."""
        ...

    @property
    def version(self) -> str:
        """Version of this module."""
        ...

    async def inspect(
        self,
        message: dict,
        context: InspectionContext,
    ) -> InspectionReport:
        """
        Inspect a message and return any security findings.

        Modules must not enforce policy or modify traffic.
        """
        ...
