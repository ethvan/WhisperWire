
import logging
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, Response

from proxy.config import ProxyConfig
from proxy.audit import AuditLogger
from proxy.inspection import InspectionEngine

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
    def __init__(self,
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
            if key.lower() not in HOP_BY_HOP_HEADERS
            and key.lower() != "content-length"
        }

        if request.method == "HEAD" or upstream_response.status_code in {
            204, 304
        }:
            await upstream_response.aclose()
            return Response(
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

