"""Build viewer/demo.html from the attack suite: python viewer/make_demo.py"""

import sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from whisperwire.sketch import viewer
from whisperwire.sketch.approvals import Approver
from whisperwire.sketch.audit import Auditor
from whisperwire.sketch.policy import PolicyConfig, PolicyEngine
from whisperwire.sketch.models import SessionContext
from whisperwire.sketch.runtime import Runtime
from attacks.runner import SCENARIOS

tmp = Path(tempfile.mkdtemp())
for i, s in enumerate(SCENARIOS):
    ws = tmp / f"ws{i}"
    ws.mkdir()
    if s.env:
        (ws / ".env").write_text(s.env)
    ctx = SessionContext(ws / ".ag", ws)
    eng = PolicyEngine(PolicyConfig(workspace=ws), ctx)
    aud = Auditor(tmp, "demo")
    if s.tainted:
        ctx.mark_untrusted("scenario")
    if s.poisoned:
        if eng.observe_result(*s.poisoned):
            aud.event("result_looks_like_injection", tool=s.poisoned[0])
    Runtime(eng, aud, Approver("deny")).decide(s.call)
    time.sleep(0.01)
out = ROOT / "viewer" / "demo.html"
n = viewer.write(tmp / "audit.jsonl", out, "WhisperWire demo: attack suite")
print(f"wrote {out} ({n} decisions)")
