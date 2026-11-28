import hashlib
import json
import os
import re
import tempfile

from pathlib import Path

from proxy.models import (
    Finding,
    InspectionContext,
    InspectionReport,
)


class ToolIntegrity:
    """
    Maintains trusted MCP tool fingerprints and detects modifications.

    Enrollment is explicit. Inspection never creates or modifies pins.
    """

    PIN_VERSION = 1
    FINGERPRINT_PATTERN = re.compile(r"^[a-f0-9]{64}$")

    def __init__(self, pins_file: Path):
        self.pins_file = Path(pins_file)

    @property
    def id(self) -> str:
        return "tool_integrity"

    @property
    def name(self) -> str:
        return "Tool Integrity"

    @property
    def version(self) -> str:
        return "0.1.0"

    # -----------------------------------------------------
    # Fingerprinting
    # -----------------------------------------------------

    @staticmethod
    def _fingerprint(tool: dict) -> str:
        """
        Generate a deterministic SHA-256 fingerprint.

        Dictionary ordering does not affect the result.
        """

        if not isinstance(tool, dict):
            raise ValueError("Tool definition must be a dictionary.")

        if not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ValueError("Tool definition requires a valid name.")

        try:
            canonical = json.dumps(
                tool,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Tool definition is not valid JSON data.") from exc

        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # -----------------------------------------------------
    # Identity
    # -----------------------------------------------------

    @staticmethod
    def _validate_identity(server_id: str, tool: dict) -> tuple[str, str]:
        if not isinstance(server_id, str) or not server_id.strip():
            raise ValueError("A valid server identity is required.")

        if not isinstance(tool, dict):
            raise ValueError("Tool definition must be a dictionary.")

        tool_name = tool.get("name")

        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("Tool definition requires a valid name.")

        return server_id, tool_name

    # -----------------------------------------------------
    # Persistent pin storage
    # -----------------------------------------------------

    def _load_pins(self) -> dict[str, dict[str, str]]:
        """
        Load and validate the persistent trust store.

        A missing file represents an initially empty trust store.
        Existing malformed storage is treated as an error.
        """

        if not self.pins_file.exists():
            return {}

        with self.pins_file.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid pin store structure.")

        if data.get("version") != self.PIN_VERSION:
            raise ValueError("Unsupported pin store version.")

        pins = data.get("pins")

        if not isinstance(pins, dict):
            raise ValueError("Invalid pin records.")

        for server_id, tools in pins.items():
            if not isinstance(server_id, str) or not server_id.strip():
                raise ValueError("Invalid server identity in pin store.")

            if not isinstance(tools, dict):
                raise ValueError("Invalid tool records in pin store.")

            for tool_name, fingerprint in tools.items():
                if not isinstance(tool_name, str) or not tool_name.strip():
                    raise ValueError("Invalid tool identity in pin store.")

                if not isinstance(
                    fingerprint, str
                ) or not self.FINGERPRINT_PATTERN.fullmatch(fingerprint):
                    raise ValueError("Invalid fingerprint in pin store.")

        return pins

    def _save_pins(self, pins: dict[str, dict[str, str]]) -> None:
        """
        Persist pins using an atomic file replacement.
        """

        self.pins_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": self.PIN_VERSION,
            "pins": pins,
        }

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.pins_file.parent,
                prefix=f".{self.pins_file.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)

                json.dump(
                    data,
                    file,
                    indent=2,
                    ensure_ascii=False,
                )

                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self.pins_file)
            temporary_path = None

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    # -----------------------------------------------------
    # Explicit enrollment
    # -----------------------------------------------------

    def enroll(self, server_id: str, tool: dict) -> None:
        """
        Explicitly enroll a tool by storing its fingerprint.

        Existing enrollments cannot be overwritten.
        """

        server_id, tool_name = self._validate_identity(
            server_id,
            tool,
        )

        fingerprint = self._fingerprint(tool)
        pins = self._load_pins()

        server_pins = pins.setdefault(server_id, {})

        if tool_name in server_pins:
            raise FileExistsError(
                f"Tool '{tool_name}' is already enrolled on this server."
            )

        server_pins[tool_name] = fingerprint

        self._save_pins(pins)

    # -----------------------------------------------------
    # Inspection
    # -----------------------------------------------------

    async def inspect(
        self,
        message: dict,
        context: InspectionContext,
    ) -> InspectionReport:
        """
        Verify a discovered tool against its approved fingerprint.

        This method never enrolls or modifies trusted fingerprints.
        """

        if context.direction != "outbound":
            return InspectionReport(module_id=self.id)

        try:
            if not isinstance(message, dict):
                raise ValueError("Invalid inspection message.")

            server_id, tool_name = self._validate_identity(
                message.get("server_id"),
                message.get("tool"),
            )

            fingerprint = self._fingerprint(message["tool"])
            pins = self._load_pins()

            approved_fingerprint = pins.get(server_id, {}).get(tool_name)

        except Exception as exc:
            return InspectionReport(
                module_id=self.id,
                success=False,
                error=type(exc).__name__,
            )

        if approved_fingerprint is None:
            return InspectionReport(
                module_id=self.id,
                findings=[
                    Finding(
                        rule_id="tool.unpinned",
                        severity="medium",
                        category="tool_integrity",
                        description=(
                            f"Tool '{tool_name}' has not been explicitly enrolled."
                        ),
                    )
                ],
            )

        if fingerprint != approved_fingerprint:
            return InspectionReport(
                module_id=self.id,
                findings=[
                    Finding(
                        rule_id="tool.integrity_changed",
                        severity="critical",
                        category="tool_integrity",
                        description=(
                            f"Tool '{tool_name}' differs from its approved fingerprint."
                        ),
                    )
                ],
            )

        return InspectionReport(module_id=self.id)
