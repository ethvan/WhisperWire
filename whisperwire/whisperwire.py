# Agent Security Gateway Entry Point
# Loads required configuration via YAML and cmdline args.
# NOTE: YAML config not yet implemented.

# Parse Arguments
import argparse
from pathlib import Path

import mcp


def parse_args():
    # TODO: Potential epilog here
    parser = argparse.ArgumentParser(
        description="entrypoint for WhisperWire, an Agent Security Gateway."
    )

    parser.add_argument(
        "--mode",
        type=str,
        choices=["observe", "alert", "ask"],
        required=True,
        help="Execution modes: observe, alert, or ask.",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        required=True,
        help="Directory path to store logs",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        required=True,
        help="Path to the rules YAML file",
    )
    parser.add_argument(
        "--pins",
        type=Path,
        required=True,
        help="Path to the MCP function pinning file",
    )
    parser.add_argument(
        "--log-bodies",
        type=Path,
        default=None,
        help="Optional file path to log request/response bodies",
    )

    return parser.parse_args()


def main():
    """
    Entrypoint via `uv run whisperwire`.

    Should also serve as general entrypoint for project
    """
    
    args = parse_args()
    print(f"Running WhisperWire in {args.mode} mode...")

if __name__ == "__main__":
    main()
