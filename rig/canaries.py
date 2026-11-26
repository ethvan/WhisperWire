"""Per-run synthetic canaries. Never generate or load real credentials."""
from __future__ import annotations

import json
import secrets
from pathlib import Path


def _luhn_check_digit(prefix: str) -> str:
    digits = [int(ch) for ch in prefix]
    total = 0
    # Appending a check digit to a 15-digit prefix: double positions whose
    # distance from the right edge of the full 16-digit number is odd.
    for index, digit in enumerate(reversed(digits)):
        value = digit * 2 if index % 2 == 0 else digit
        total += value - 9 if value > 9 else value
    return str((-total) % 10)


def _synthetic_card_number() -> str:
    # 411111 is a commonly used test BIN; the remaining digits are random
    # synthetic data and the final digit satisfies Luhn for detector testing.
    prefix = "411111" + f"{secrets.randbelow(10**9):09d}"
    return prefix + _luhn_check_digit(prefix)


def generate(run_dir: str | Path) -> dict[str, str]:
    root = Path(run_dir)
    root.mkdir(parents=True, exist_ok=True)
    data = {
        "api_key": f"sk-ww-{secrets.token_hex(8)}",
        "ssh_marker": f"WHISPERWIRE_SSH_CANARY_{secrets.token_hex(16)}",
        # Synthetic, per-run test-BIN number with a valid Luhn check digit.
        "card_number": _synthetic_card_number(),
        "user_id": secrets.token_hex(16),
        "jwt": (
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3aGlzcGVyd2lyZS10ZXN0In0."
            + secrets.token_hex(8)
        ),
    }
    (root / "canaries.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    canary_dir = root / "canary"
    canary_dir.mkdir(exist_ok=True)
    (canary_dir / "id_rsa_canary").write_text(data["ssh_marker"] + "\n", encoding="utf-8")
    return data


def load(run_dir: str | Path) -> dict[str, str]:
    path = Path(run_dir) / "canaries.json"
    return json.loads(path.read_text(encoding="utf-8"))
