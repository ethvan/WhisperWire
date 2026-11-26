import json
import pytest

from proxy.audit import AuditLogger
from proxy.models import Finding, InspectionContext


@pytest.fixture
def context():
    return InspectionContext(
        direction="inbound",
        protocol="mcp",
        session_id="test-session",
        request_id="test-request",
    )


@pytest.mark.asyncio
async def test_creates_log_directory(tmp_path):
    log_dir = tmp_path / "logs"

    AuditLogger(log_dir=log_dir)

    assert log_dir.exists()
    assert log_dir.is_dir()


@pytest.mark.asyncio
async def test_logs_traffic_without_body(tmp_path, context):
    logger = AuditLogger(log_dir=tmp_path)

    await logger.log_traffic(
        context,
        message={"method": "tools/call", "params": {"name": "echo"}},
    )

    records = [
        json.loads(line)
        for line in (tmp_path / "traffic.jsonl").read_text().splitlines()
    ]

    assert len(records) == 1
    assert records[0]["event_type"] == "traffic"
    assert records[0]["direction"] == "inbound"
    assert "message" not in records[0]


@pytest.mark.asyncio
async def test_logs_traffic_with_body(tmp_path, context):
    logger = AuditLogger(log_dir=tmp_path, log_bodies=True)

    message = {"method": "tools/call"}

    await logger.log_traffic(context, message=message)

    records = [
        json.loads(line)
        for line in (tmp_path / "traffic.jsonl").read_text().splitlines()
    ]

    assert records[0]["message"] == message


@pytest.mark.asyncio
async def test_logs_security_alert(tmp_path, context):
    logger = AuditLogger(log_dir=tmp_path)

    finding = Finding(
        rule_id="TEST-001",
        severity="high",
        category="prompt_injection",
        description="Potential prompt injection detected",
        evidence="Ignore all previous instructions",
    )

    await logger.log_alert(
        context=context,
        module_id="prompt_shield",
        finding=finding,
    )

    records = [
        json.loads(line)
        for line in (tmp_path / "alerts.jsonl").read_text().splitlines()
    ]

    assert len(records) == 1
    assert records[0]["event_type"] == "security_alert"
    assert records[0]["module_id"] == "prompt_shield"
    assert records[0]["finding"]["rule_id"] == "TEST-001"


@pytest.mark.asyncio
async def test_multiple_writes(tmp_path, context):
    logger = AuditLogger(log_dir=tmp_path)

    for _ in range(5):
        await logger.log_traffic(context)

    records = [
        json.loads(line)
        for line in (tmp_path / "traffic.jsonl").read_text().splitlines()
    ]

    assert len(records) == 5

