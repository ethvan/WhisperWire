import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from proxy.config import ProxyConfig
from proxy.models import Finding, InspectionContext


class AuditLogger:
    def __init__(self, config: ProxyConfig):
        self.log_dir = config.log_dir
        self.log_bodies = config.log_bodies

        self.traffic_path = self.log_dir / "traffic.jsonl"
        self.alerts_path = self.log_dir / "alerts.jsonl"

        self._lock = asyncio.Lock()

        self.log_dir.mkdir(parents=True, exist_ok=True)

    async def log_traffic(
        self,
        context: InspectionContext,
        message: dict | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "timestamp": self._timestamp(),
            "event_type": "traffic",
            "direction": context.direction,
            "protocol": context.protocol,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "metadata": metadata or {},
        }

        if self.log_bodies and message is not None:
            record["message"] = message

        await self._write(self.traffic_path, record)

    async def log_alert(
        self,
        context: InspectionContext,
        module_id: str,
        finding: Finding,
    ) -> None:
        record = {
            "timestamp": self._timestamp(),
            "event_type": "security_alert",
            "direction": context.direction,
            "protocol": context.protocol,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "module_id": module_id,
            "finding": {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "category": finding.category,
                "description": finding.description,
                # Evidence may contain sensitive information.
                # Only log if explicitly requested.
                "evidence": finding.evidence if self.log_bodies else None,
            },
        }

        await self._write(self.alerts_path, record)

    async def _write(
        self,
        path,
        record: dict[str, Any],
    ) -> None:
        line = json.dumps(record, ensure_ascii=False) + "\n"

        async with self._lock:
            await asyncio.to_thread(
                self._append_line,
                path,
                line,
            )

    @staticmethod
    def _append_line(path, line: str) -> None:
        with path.open("a", encoding="utf-8") as file:
            file.write(line)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()
