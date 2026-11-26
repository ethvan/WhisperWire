import logging

from proxy.config import ProxyConfig
from proxy.adapters.mcp_adapter import MCPAdapter


logger = logging.getLogger("whisperwire")


async def run_proxy(config: ProxyConfig):
    """
    Assemble and start the whisperWire application.
    """

    logger.info("Initializing whisperWire...")

    adapter = MCPAdapter(config=config)

    logger.info("Starting MCP adapter...")

    await adapter.run()
