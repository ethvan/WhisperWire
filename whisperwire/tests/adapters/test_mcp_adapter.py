import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from proxy.adapters.mcp_adapter import MCPAdapter
from proxy.config import ProxyConfig


# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------


class MockInspectionEngine:
    def __init__(self):
        self.calls = []

    async def inspect(self, message, context):
        self.calls.append(
            {
                "message": message,
                "context": context,
            }
        )
        return []


class MockAuditor:
    def __init__(self):
        self.traffic = []
        self.alerts = []

    async def log_traffic(self, **kwargs):
        self.traffic.append(kwargs)

    async def log_alert(self, **kwargs):
        self.alerts.append(kwargs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter():
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_url="http://127.0.0.1:9000/mcp",
        mode="observe",
        log_dir=None,
        rules_file=None,
        pins_file=None,
        log_bodies=False,
    )

    engine = MockInspectionEngine()
    auditor = MockAuditor()

    return MCPAdapter(
        config=config,
        auditor=auditor,
        inspection_engine=engine,
    )


# ---------------------------------------------------------------------------
# Request and response helpers
# ---------------------------------------------------------------------------


def make_request(headers=None):
    headers = headers or {}

    raw_headers = [
        (key.lower().encode(), value.encode()) for key, value in headers.items()
    ]

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "query_string": b"",
            "headers": raw_headers,
            "server": ("127.0.0.1", 8080),
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
        }
    )


def make_tools_request(request_id=1):
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/list",
        }
    ).encode()


def make_tools_response(tools, request_id=1):
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": tools,
            },
        }
    ).encode()


class MockAsyncStream(httpx.AsyncByteStream):
    def __init__(self, body):
        self.body = body
        self.closed = False

    async def __aiter__(self):
        yield self.body

    async def aclose(self):
        self.closed = True


def make_upstream_response(
    body: bytes,
    status_code=200,
    headers=None,
):
    return httpx.Response(
        status_code=status_code,
        headers=headers or {"content-type": "application/json"},
        stream=MockAsyncStream(body),
        request=httpx.Request("POST", "http://upstream.test/mcp"),
    )


# ---------------------------------------------------------------------------
# Forwarding integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_forward_request_inspects_tools_list_response(adapter):
    tools = [
        {
            "name": "read_file",
            "description": "Read files.",
        }
    ]

    request_body = make_tools_request()
    response_body = make_tools_response(tools)

    upstream_response = make_upstream_response(response_body)

    adapter.client.build_request = MagicMock()
    adapter.client.send = AsyncMock(return_value=upstream_response)

    request = make_request(
        {
            "content-type": "application/json",
            "mcp-session-id": "session-123",
        }
    )
    request._body = request_body

    response = await adapter._forward_request(request)

    assert len(adapter.inspection_engine.calls) == 2

    directions = [call["context"].direction for call in adapter.inspection_engine.calls]

    assert directions == ["inbound", "outbound"]

    assert isinstance(response, Response)
    assert response.body == response_body
    assert upstream_response.is_closed


@pytest.mark.asyncio
async def test_forward_request_preserves_original_response_body(adapter):
    tools = [
        {
            "name": "read_file",
            "description": "Read files.",
        }
    ]

    request_body = make_tools_request()
    response_body = make_tools_response(tools)

    upstream_response = make_upstream_response(response_body)

    adapter.client.build_request = MagicMock()
    adapter.client.send = AsyncMock(return_value=upstream_response)

    request = make_request(
        {
            "content-type": "application/json",
        }
    )
    request._body = request_body

    response = await adapter._forward_request(request)

    assert response.body == response_body
    assert upstream_response.is_closed


@pytest.mark.asyncio
async def test_forward_request_does_not_inspect_unrelated_response(adapter):
    request_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping",
        }
    ).encode()

    response_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {},
        }
    ).encode()

    upstream_response = make_upstream_response(response_body)

    adapter.client.build_request = MagicMock()
    adapter.client.send = AsyncMock(return_value=upstream_response)

    request = make_request(
        {
            "content-type": "application/json",
        }
    )
    request._body = request_body

    await adapter._forward_request(request)

    outbound_calls = [
        call
        for call in adapter.inspection_engine.calls
        if call["context"].direction == "outbound"
    ]

    assert outbound_calls == []


@pytest.mark.asyncio
async def test_forward_request_preserves_sse_streaming(adapter):
    sse_body = b'event: message\ndata: {"jsonrpc":"2.0"}\n\n'

    upstream_response = make_upstream_response(
        sse_body,
        headers={"content-type": "text/event-stream"},
    )

    adapter.client.build_request = MagicMock()
    adapter.client.send = AsyncMock(return_value=upstream_response)

    request = make_request(
        {
            "content-type": "application/json",
        }
    )
    request._body = make_tools_request()

    response = await adapter._forward_request(request)

    assert isinstance(response, StreamingResponse)

    received_body = b"".join([chunk async for chunk in response.body_iterator])

    assert received_body == sse_body

    outbound_calls = [
        call
        for call in adapter.inspection_engine.calls
        if call["context"].direction == "outbound"
    ]

    assert outbound_calls == []


@pytest.mark.asyncio
async def test_forward_request_preserves_upstream_status(adapter):
    upstream_response = make_upstream_response(
        b'{"error":"not found"}',
        status_code=404,
    )

    adapter.client.build_request = MagicMock()
    adapter.client.send = AsyncMock(return_value=upstream_response)

    request = make_request()
    request._body = b"{}"

    response = await adapter._forward_request(request)

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_forward_request_closes_upstream_response_after_streaming(adapter):
    response_body = b'{"jsonrpc":"2.0","result":{}}'

    upstream_response = make_upstream_response(response_body)

    adapter.client.build_request = MagicMock()
    adapter.client.send = AsyncMock(return_value=upstream_response)

    request = make_request()
    request._body = b"{}"

    response = await adapter._forward_request(request)

    assert isinstance(response, StreamingResponse)
    assert not upstream_response.is_closed

    async for _ in response.body_iterator:
        pass

    assert upstream_response.is_closed


# ---------------------------------------------------------------------------
# Outbound inspection unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inspects_tools_list_response(adapter):
    tools = [
        {
            "name": "read_file",
            "description": "Read a file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
            },
        }
    ]

    request = make_request(
        {
            "mcp-session-id": "session-123",
        }
    )

    await adapter._inspect_outbound(
        request,
        make_tools_request(),
        make_tools_response(tools),
        "application/json",
    )

    assert len(adapter.inspection_engine.calls) == 1

    call = adapter.inspection_engine.calls[0]

    assert call["message"]["tool"] == tools[0]
    assert call["message"]["server_id"] == adapter.config.upstream_url

    assert call["context"].direction == "outbound"
    assert call["context"].protocol == "mcp"
    assert call["context"].session_id == "session-123"


@pytest.mark.asyncio
async def test_inspects_each_advertised_tool(adapter):
    tools = [
        {"name": "read_file", "description": "Read files."},
        {"name": "write_file", "description": "Write files."},
        {"name": "delete_file", "description": "Delete files."},
    ]

    request = make_request()

    await adapter._inspect_outbound(
        request,
        make_tools_request(),
        make_tools_response(tools),
        "application/json",
    )

    calls = adapter.inspection_engine.calls

    assert len(calls) == 3

    inspected_names = [call["message"]["tool"]["name"] for call in calls]

    assert inspected_names == [
        "read_file",
        "write_file",
        "delete_file",
    ]


@pytest.mark.asyncio
async def test_ignores_non_tools_list_response(adapter):
    request = make_request()

    ordinary_request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping",
        }
    ).encode()

    ordinary_response = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {},
        }
    ).encode()

    await adapter._inspect_outbound(
        request,
        ordinary_request,
        ordinary_response,
        "application/json",
    )

    assert adapter.inspection_engine.calls == []


@pytest.mark.asyncio
async def test_ignores_non_json_response(adapter):
    request = make_request()

    await adapter._inspect_outbound(
        request,
        make_tools_request(),
        b"event: message\ndata: {}\n\n",
        "text/event-stream",
    )

    assert adapter.inspection_engine.calls == []


@pytest.mark.asyncio
async def test_handles_malformed_response_json(adapter):
    request = make_request()

    await adapter._inspect_outbound(
        request,
        make_tools_request(),
        b"{invalid json",
        "application/json",
    )

    assert adapter.inspection_engine.calls == []


@pytest.mark.asyncio
async def test_handles_empty_tool_list(adapter):
    request = make_request()

    await adapter._inspect_outbound(
        request,
        make_tools_request(),
        make_tools_response([]),
        "application/json",
    )

    assert adapter.inspection_engine.calls == []


@pytest.mark.asyncio
async def test_ignores_response_with_unrelated_request_id(adapter):
    request = make_request()

    response = make_tools_response(
        [{"name": "read_file"}],
        request_id=999,
    )

    await adapter._inspect_outbound(
        request,
        make_tools_request(request_id=1),
        response,
        "application/json",
    )

    assert adapter.inspection_engine.calls == []


@pytest.mark.asyncio
async def test_malformed_request_does_not_trigger_inspection(adapter):
    request = make_request()

    await adapter._inspect_outbound(
        request,
        b"{invalid request",
        make_tools_response([{"name": "read_file"}]),
        "application/json",
    )

    assert adapter.inspection_engine.calls == []
