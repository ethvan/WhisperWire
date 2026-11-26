import logging

# == whisperWire libs == #
from proxy.config import ProxyConfig
from proxy.adapters.mcp_adapter import MCPAdapter
from proxy.audit import AuditLogger
from proxy.modules.registry import ModuleRegistry
from proxy.inspection import InspectionEngine

logger = logging.getLogger("whisperwire")

async def run_proxy(config: ProxyConfig):
    """
    Assemble and start the whisperWire application.
    """

    logger.info("Initializing whisperWire...")

    # Initialize shared components
    auditor = AuditLogger(config)

    registry = ModuleRegistry()
    inspection_engine = InspectionEngine(registry)

    # Initialize MCP adapter with shared dependencies
    adapter = MCPAdapter(
        config=config,
        auditor=auditor,
        inspection_engine=inspection_engine,
    )

    logger.info("Starting MCP adapter...")

    await adapter.run()
