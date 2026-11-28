import json

import pytest

from proxy.models import InspectionContext
from proxy.modules.tool_integrity import ToolIntegrity


@pytest.fixture
def pins_file(tmp_path):
    return tmp_path / "tool_pins.json"


@pytest.fixture
def integrity(pins_file):
    return ToolIntegrity(pins_file=pins_file)


def make_tool(
    name="read_file",
    description="Read a file from the filesystem.",
):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        },
    }


def make_context(direction="outbound"):
    return InspectionContext(
        direction=direction,
        protocol="mcp",
        session_id="test-session",
        request_id="test-request",
    )


async def inspect_tool(integrity, tool, server_id: str):
    return await integrity.inspect(
        message={
            "server_id": server_id,
            "tool": tool,
        },
        context=make_context(),
    )


def finding_ids(report):
    return {finding.rule_id for finding in report.findings}


# ---------------------------------------------------------
# Fingerprinting and verification
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_identical_tool_definitions_have_stable_fingerprints(
    integrity,
):
    tool = make_tool()

    integrity.enroll("server-a", tool)

    reordered_tool = {
        "inputSchema": {
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
            },
            "type": "object",
        },
        "description": "Read a file from the filesystem.",
        "name": "read_file",
    }

    report = await inspect_tool(integrity, reordered_tool, "server-a")

    assert report.success is True
    assert report.findings == []


@pytest.mark.asyncio
async def test_modified_tool_definition_changes_fingerprint(integrity):
    integrity.enroll("server-a", make_tool())

    modified_tool = make_tool(description="Read and modify files on the filesystem.")

    report = await inspect_tool(integrity, modified_tool, "server-a")

    assert report.success is True
    assert "tool.integrity_changed" in finding_ids(report)


@pytest.mark.asyncio
async def test_unpinned_tool_produces_finding(integrity):
    report = await inspect_tool(integrity, make_tool(), "test-server")

    assert report.success is True
    assert "tool.unpinned" in finding_ids(report)


@pytest.mark.asyncio
async def test_matching_fingerprint_produces_no_findings(integrity):
    tool = make_tool()

    integrity.enroll("server-a", tool)

    report = await inspect_tool(integrity, tool, "server-a")

    assert report.success is True
    assert report.findings == []


# ---------------------------------------------------------
# Enrollment behavior
# ---------------------------------------------------------


def test_enrollment_creates_persistent_pin(integrity, pins_file):
    tool = make_tool()

    integrity.enroll("server-a", tool)

    assert pins_file.exists()
    assert pins_file.is_file()

    data = json.loads(pins_file.read_text())

    assert data["version"] == ToolIntegrity.PIN_VERSION
    assert "server-a" in data["pins"]
    assert "read_file" in data["pins"]["server-a"]

    fingerprint = data["pins"]["server-a"]["read_file"]

    assert len(fingerprint) == 64
    assert all(character in "0123456789abcdef" for character in fingerprint)


def test_duplicate_enrollment_is_rejected(integrity):
    tool = make_tool()

    integrity.enroll("server-a", tool)

    with pytest.raises(FileExistsError):
        integrity.enroll("server-a", tool)


def test_conflicting_enrollment_is_rejected(integrity):
    integrity.enroll("server-a", make_tool())

    modified_tool = make_tool(description="A different tool definition.")

    with pytest.raises(FileExistsError):
        integrity.enroll("server-a", modified_tool)


def test_invalid_tool_cannot_be_enrolled(integrity):
    invalid_tool = {
        "description": "Missing required tool name.",
    }

    with pytest.raises(ValueError):
        integrity.enroll("server-a", invalid_tool)


@pytest.mark.asyncio
async def test_invalid_tool_definition_causes_failed_inspection(integrity):
    invalid_tool = {"description": "Missing tool name."}

    report = await inspect_tool(integrity, invalid_tool, "server-a")

    assert report.success is False
    assert report.error == "ValueError"
    assert report.findings == []


def test_empty_server_identity_cannot_be_enrolled(integrity):
    with pytest.raises(ValueError):
        integrity.enroll("", make_tool())


@pytest.mark.asyncio
async def test_missing_server_identity_causes_failed_inspection(integrity):
    report = await integrity.inspect(
        message={"tool": make_tool()},
        context=make_context(),
    )

    assert report.success is False
    assert report.error == "ValueError"
    assert report.findings == []


# ---------------------------------------------------------
# Trust isolation
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_pin_is_not_shared_across_servers(
    integrity,
):
    integrity.enroll("server-a", make_tool())

    report = await inspect_tool(
        integrity,
        make_tool(),
        server_id="server-b",
    )

    assert report.success is True
    assert "tool.unpinned" in finding_ids(report)


@pytest.mark.asyncio
async def test_inspection_does_not_automatically_enroll_tools(
    integrity,
    pins_file,
):
    report = await inspect_tool(integrity, make_tool(), "test-server")

    assert "tool.unpinned" in finding_ids(report)
    assert not pins_file.exists()


@pytest.mark.asyncio
async def test_modified_tool_does_not_overwrite_existing_pin(
    integrity,
):
    original_tool = make_tool()

    integrity.enroll("server-a", original_tool)

    modified_tool = make_tool(description="Modified definition.")

    first_report = await inspect_tool(integrity, modified_tool, "server-a")
    second_report = await inspect_tool(integrity, original_tool, "server-a")

    assert "tool.integrity_changed" in finding_ids(first_report)
    assert second_report.success is True
    assert second_report.findings == []


# ---------------------------------------------------------
# Persistence
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_enrollment_survives_module_restart(
    pins_file,
):
    first_instance = ToolIntegrity(pins_file=pins_file)

    tool = make_tool()

    first_instance.enroll("server-a", tool)

    second_instance = ToolIntegrity(pins_file=pins_file)

    report = await inspect_tool(second_instance, tool, "server-a")

    assert report.success is True
    assert report.findings == []


@pytest.mark.asyncio
async def test_missing_pin_file_starts_with_empty_trust_store(
    integrity,
    pins_file,
):
    assert not pins_file.exists()

    report = await inspect_tool(integrity, make_tool(), "test-server")

    assert report.success is True
    assert "tool.unpinned" in finding_ids(report)


# ---------------------------------------------------------
# Storage failure handling
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_pin_file_causes_failed_inspection(
    pins_file,
):
    pins_file.write_text("{ invalid json")

    integrity = ToolIntegrity(pins_file=pins_file)

    report = await inspect_tool(integrity, make_tool(), "test-server")

    assert report.success is False
    assert report.error is not None


@pytest.mark.asyncio
async def test_unreadable_pin_storage_causes_failed_inspection(
    tmp_path,
):
    # A directory at the expected file path causes a read failure.
    pins_file = tmp_path / "tool_pins.json"
    pins_file.mkdir()

    integrity = ToolIntegrity(pins_file=pins_file)

    report = await inspect_tool(integrity, make_tool(), "test-server")

    assert report.success is False
    assert report.error is not None


# ---------------------------------------------------------
# Inspection context
# ---------------------------------------------------------


@pytest.mark.asyncio
async def test_inbound_inspection_does_not_evaluate_tool_integrity(
    integrity,
):
    report = await integrity.inspect(
        message={
            "server_id": "server-a",
            "tool": make_tool(),
        },
        context=make_context(direction="inbound"),
    )

    assert report.success is True
    assert report.findings == []
