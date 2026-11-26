import asyncio
import logging

from proxy.config import parse_config
from proxy.app import run_proxy


def main():
    config = parse_config()

    # 2. Set up application logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    logger = logging.getLogger("whisperwire")

    logger.info("Starting whisperWire")
    logger.info("Listening on %s:%s", config.listen_host, config.listen_port)
    logger.info("Upstream: %s", config.upstream_url)
    logger.info("Mode: %s", config.mode)

    # Create log directory
    config.log_dir.mkdir(parents=True, exist_ok=True)

    # Start proxy
    try:
        asyncio.run(run_proxy(config))

    except KeyboardInterrupt:
        logger.info("Shutting down whisperWire")


if __name__ == "__main__":
    main()
