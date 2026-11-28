import json
import logging
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, Response

from proxy.config import ProxyConfig
from proxy.audit import AuditLogger
from proxy.inspection import InspectionEngine
from proxy.models import InspectionContext

logger = logging.getLogger("whisperwire.adapter")

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class MCPAdapter:
    def __init__(
        self,
        config: ProxyConfig,
        auditor: AuditLogger,
        inspection_engine: InspectionEngine,
    ):

        self.config = config
        self.auditor = auditor
        self.inspection_engine = inspection_engine

        self.client = httpx.AsyncClient(timeout=None)

        self.app = FastAPI(lifespan=self._lifespan)
        self._register_routes()

    @asynccontextmanager
    async def _lifespan(self, app: FastAPI):
        yield
        await self.client.aclose()

    def _register_routes(self):
        @self.app.api_route(
            "/mcp",
            methods=["GET", "POST", "DELETE"],
        )
        async def proxy_request(request: Request):
            return await self._forward_request(request)

    async def _inspect_inbound(self, request: Request, body: bytes) -> None:
        """
        Inspect and audit inbound MCP messages.

        The original request body is never modified.
        """
        if not body:
            return

        # Only inspect JSON request bodies.
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type.lower():
            logger.debug(
                "Skipping inbound inspection for content type: %s",
                content_type,
            )
            return

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Unable to parse inbound MCP request as JSON")
            return

        # MCP supports individual JSON-RPC messages and batches.
        messages = payload if isinstance(payload, list) else [payload]

        session_id = request.headers.get("mcp-session-id")

        for message in messages:
            if not isinstance(message, dict):
                logger.warning("Skipping non-object JSON-RPC message in request")
                continue

            request_id = message.get("id")

            context = InspectionContext(
                direction="inbound",
                protocol="mcp",
                session_id=session_id,
                request_id=(str(request_id) if request_id is not None else None),
            )

            # Record the inbound traffic.
            await self.auditor.log_traffic(
                context=context,
                message=message,
                metadata={
                    "http_method": request.method,
                    "mcp_method": message.get("method"),
                    "content_type": content_type,
                },
            )

            # Run all registered security modules.
            reports = await self.inspection_engine.inspect(
                message=message,
                context=context,
            )

            # Record any findings.
            for report in reports:
                if not report.success:
                    logger.error(
                        "Inspection module '%s' failed: %s",
                        report.module_id,
                        report.error,
                    )
                    continue

                for finding in report.findings:
                    await self.auditor.log_alert(
                        context=context,
                        module_id=report.module_id,
                        finding=finding,
                    )

    async def _inspect_outbound(
        self,
        request: Request,
        request_body: bytes,
        response_body: bytes,
        response_content_type: str,
    ) -> None:
        """
        Inspect tool definitions returned by an MCP tools/list request.

        The original upstream response is never modified.
        """
        if not response_body:
            return

        if "application/json" not in response_content_type.lower():
            return

        try:
            request_payload = json.loads(request_body)
            response_payload = json.loads(response_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Unable to parse outbound MCP response as JSON")
            return

        # This initial implementation handles individual JSON-RPC messages.
        if not isinstance(request_payload, dict):
            return

        if not isinstance(response_payload, dict):
            return

        if request_payload.get("method") != "tools/list":
            return

        request_id = request_payload.get("id")
        response_id = response_payload.get("id")

        if request_id is None or request_id != response_id:
            return

        result = response_payload.get("result")

        if not isinstance(result, dict):
            return

        tools = result.get("tools")

        if not isinstance(tools, list):
            return

        session_id = request.headers.get("mcp-session-id")

        for tool in tools:
            if not isinstance(tool, dict):
                continue

            message = {
                "server_id": self.config.upstream_url,
                "tool": tool,
            }

            context = InspectionContext(
                direction="outbound",
                protocol="mcp",
                session_id=session_id,
                request_id=str(request_id),
            )

            await self.auditor.log_traffic(
                context=context,
                message=message,
                metadata={
                    "http_method": request.method,
                    "mcp_method": "tools/list",
                    "tool_name": tool.get("name"),
                },
            )

            reports = await self.inspection_engine.inspect(
                message=message,
                context=context,
            )

            for report in reports:
                if not report.success:
                    logger.error(
                        "Inspection module '%s' failed: %s",
                        report.module_id,
                        report.error,
                    )
                    continue

                for finding in report.findings:
                    await self.auditor.log_alert(
                        context=context,
                        module_id=report.module_id,
                        finding=finding,
                    )

    def _is_outbound_inspection_candidate(
        self,
        request: Request,
        request_body: bytes,
        response_content_type: str,
    ) -> bool:
        if request.method != "POST":
            return False

        if "application/json" not in response_content_type.lower():
            return False

        try:
            payload = json.loads(request_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

        return isinstance(payload, dict) and payload.get("method") == "tools/list"

    async def _forward_request(self, request: Request):
        upstream_url = self.config.upstream_url

        if request.url.query:
            upstream_url += f"?{request.url.query}"

        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
            and key.lower() not in {"host", "content-length"}
        }

        body = await request.body()

        try:
            await self._inspect_inbound(request, body)
        except Exception:
            logger.exception(
                "Inbound inspection or auditing failed; continuing in observe mode."
            )

        upstream_request = self.client.build_request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )

        logger.info(
            "Forwarding %s request to %s",
            request.method,
            upstream_url,
        )

        upstream_response = await self.client.send(
            upstream_request,
            stream=True,
        )

        response_headers = {
            key: value
            for key, value in upstream_response.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "content-length"
        }

        if request.method == "HEAD" or upstream_response.status_code in {204, 304}:
            await upstream_response.aclose()
            return Response(
                status_code=upstream_response.status_code,
                headers=response_headers,
            )

        response_content_type = upstream_response.headers.get("content-type", "")

        if self._is_outbound_inspection_candidate(
            request,
            body,
            response_content_type,
        ):
            response_body = await upstream_response.aread()

            try:
                await self._inspect_outbound(
                    request=request,
                    request_body=body,
                    response_body=response_body,
                    response_content_type=response_content_type,
                )
            except Exception:
                logger.exception(
                    "Outbound inspection or auditing failed; continuing in observe mode."
                )
            finally:
                await upstream_response.aclose()

            return Response(
                content=response_body,
                status_code=upstream_response.status_code,
                headers=response_headers,
            )

        async def stream_response():
            try:
                async for chunk in upstream_response.aiter_raw():
                    yield chunk
            finally:
                await upstream_response.aclose()

        return StreamingResponse(
            stream_response(),
            status_code=upstream_response.status_code,
            headers=response_headers,
        )

    async def run(self):
        config = uvicorn.Config(
            self.app,
            host=self.config.listen_host,
            port=self.config.listen_port,
            log_level="info",
        )

        server = uvicorn.Server(config)
        await server.serve()
