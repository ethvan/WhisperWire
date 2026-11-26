import argparse
import os

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProxyConfig:
    """
    Proxy configuration dataclass
    Instead of handling individual arguments, pass config where needed and
    allow reading.
    """

    # Network configuration
    listen_host: str
    listen_port: int
    upstream_url: str

    # Operating configuration
    mode: str
    log_dir: Path

    # Optional configuration files
    rules_file: Path | None
    pins_file: Path | None

    # Logging options
    log_bodies: bool


def parse_config() -> ProxyConfig:
    """
    Parse command-line arguments and environment variables.
    Return a validated ProxyConfig object.
    """

    parser = argparse.ArgumentParser(description="whisperWire - Agent Security Gateway")

    # Network settings
    parser.add_argument(
        "--listen-host",
        default=os.getenv("WHISPERWIRE_HOST", "0.0.0.0"),
        help="Host interface to listen on.",
    )

    parser.add_argument(
        "--listen-port",
        type=int,
        default=int(os.getenv("WHISPERWIRE_PORT", "8080")),
        help="Port whisperWire listens on.",
    )

    parser.add_argument(
        "--upstream",
        default=os.getenv("WHISPERWIRE_UPSTREAM", "http://127.0.0.1:9000/mcp"),
        help="Upstream MCP server URL.",
    )

    # Operating mode
    parser.add_argument(
        "--mode",
        choices=["observe", "alert", "ask"],
        default="observe",
        help="Proxy operating mode.",
    )

    # Logging
    parser.add_argument(
        "--log-dir", type=Path, default=Path("./logs"), help="Directory for proxy logs."
    )

    parser.add_argument(
        "--log-bodies", action="store_true", help="Enable full message-body logging."
    )

    # Future configuration
    parser.add_argument(
        "--rules", type=Path, default=None, help="Path to security rules configuration."
    )

    parser.add_argument(
        "--pins", type=Path, default=None, help="Path to tool integrity pins."
    )

    args = parser.parse_args()

    # Only observe mode is implemented in the current MVP.
    if args.mode != "observe":
        parser.error(f"Mode '{args.mode}' is not implemented yet. Use --mode observe.")

    # Basic validation
    # TCP Ports can only be between these values
    if not 1 <= args.listen_port <= 65535:
        parser.error("Listen port must be between 1 and 65535.")

    # MCP is over streamable HTTP/HTTPS, and ofc HTTP/HTTPS endpoints use them too :)
    if not args.upstream.startswith(("http://", "https://")):
        parser.error("Upstream must be an HTTP or HTTPS URL.")

    return ProxyConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_url=args.upstream,
        mode=args.mode,
        log_dir=args.log_dir,
        rules_file=args.rules,
        pins_file=args.pins,
        log_bodies=args.log_bodies,
    )
