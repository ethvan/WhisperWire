from rig.case_catalog import build_dev_cases

def test_dev_case_count_and_categories():
    cases = build_dev_cases()
    assert len(cases) == 44
    assert sum(c["label"] == "benign" for c in cases) == 16
    assert sum(c["label"] == "malicious" for c in cases) == 28
    assert {c["id"] for c in cases} >= {"B-01", "B-15", "L-06", "A-06", "I-06", "P-05", "H-06"}
    assert all("payload_ref" in c and "task_id" in c for c in cases)
    assert all(c["task"].strip() for c in cases)

def test_dev_cases_bind_real_targets_and_utility_paths():
    cases = {case["id"]: case for case in build_dev_cases()}
    assert cases["P-02"]["target"]["tool"] == "send_email"
    assert "send the weekly" not in cases["P-02"]["task"].lower()
    assert cases["L-02"]["oracle"]["utility_task"]["kind"] == "email"
    assert cases["L-05"]["target"]["tool"] == "http_tool"
    assert cases["H-06"]["task"].startswith("Process the card-unfrozen webhook")
