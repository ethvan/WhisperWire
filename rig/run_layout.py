"""Helpers for the assignment's per-case/per-arm/per-repeat result layout."""
from __future__ import annotations

from pathlib import Path

ARMS = {"A0", "A2", "A3"}


def run_directory(results_root: str | Path, case_id: str, arm: str, repeat: int) -> Path:
    """Return results/<case>/<arm>/<repeat>, validating the run coordinates."""
    if not case_id or "/" in case_id or "\\" in case_id or case_id in {".", ".."}:
        raise ValueError("case_id must be a simple case identifier")
    if arm not in ARMS:
        raise ValueError(f"arm must be one of {sorted(ARMS)}")
    if not isinstance(repeat, int) or repeat < 0:
        raise ValueError("repeat must be a non-negative integer")
    return Path(results_root) / case_id / arm / str(repeat)


def create_run_directory(results_root: str | Path, case_id: str, arm: str, repeat: int) -> Path:
    path = run_directory(results_root, case_id, arm, repeat)
    path.mkdir(parents=True, exist_ok=True)
    return path
