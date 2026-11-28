import pytest

from proxy.models import Finding, InspectionReport
from proxy.policy import PolicyEngine


@pytest.fixture
def policy():
    return PolicyEngine()


def make_finding(
    rule_id="test.rule",
    severity="medium",
    category="test",
):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        description="Test finding",
        evidence=None,
    )


def make_report(
    module_id="test_module",
    findings=None,
    success=True,
    error=None,
):
    return InspectionReport(
        module_id=module_id,
        findings=findings or [],
        success=success,
        error=error,
    )


# ---------------------------------------------------------
# Clean inspections
# ---------------------------------------------------------


@pytest.mark.parametrize("mode", ["observe", "alert", "ask"])
def test_clean_inspection_is_allowed(policy, mode):
    decision = policy.evaluate(
        reports=[make_report()],
        mode=mode,
    )

    assert decision.action == "allow"
    assert decision.findings == []
    assert decision.inspection_errors == []


# ---------------------------------------------------------
# Low and medium severity findings
# ---------------------------------------------------------


@pytest.mark.parametrize("mode", ["observe", "alert", "ask"])
@pytest.mark.parametrize("severity", ["informational", "low", "medium"])
def test_low_and_medium_findings_are_allowed(policy, mode, severity):
    finding = make_finding(severity=severity)

    decision = policy.evaluate(
        reports=[make_report(findings=[finding])],
        mode=mode,
    )

    assert decision.action == "allow"
    assert finding in decision.findings


# ---------------------------------------------------------
# High severity findings
# ---------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected_action"),
    [
        ("observe", "allow"),
        ("alert", "block"),
        ("ask", "ask"),
    ],
)
def test_high_severity_finding_respects_operating_mode(
    policy,
    mode,
    expected_action,
):
    finding = make_finding(severity="high")

    decision = policy.evaluate(
        reports=[make_report(findings=[finding])],
        mode=mode,
    )

    assert decision.action == expected_action
    assert finding in decision.findings


# ---------------------------------------------------------
# Critical severity findings
# ---------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected_action"),
    [
        ("observe", "allow"),
        ("alert", "block"),
        ("ask", "block"),
    ],
)
def test_critical_finding_respects_operating_mode(
    policy,
    mode,
    expected_action,
):
    finding = make_finding(severity="critical")

    decision = policy.evaluate(
        reports=[make_report(findings=[finding])],
        mode=mode,
    )

    assert decision.action == expected_action
    assert finding in decision.findings


# ---------------------------------------------------------
# Inspection failures
# ---------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected_action"),
    [
        ("observe", "allow"),
        ("alert", "allow"),
        ("ask", "ask"),
    ],
)
def test_inspection_failure_respects_operating_mode(
    policy,
    mode,
    expected_action,
):
    report = make_report(
        module_id="secret_guard",
        success=False,
        error="RuntimeError",
    )

    decision = policy.evaluate(
        reports=[report],
        mode=mode,
    )

    assert decision.action == expected_action
    assert len(decision.inspection_errors) == 1
    assert "secret_guard" in decision.inspection_errors[0]
    assert "RuntimeError" in decision.inspection_errors[0]


def test_multiple_inspection_failures_are_preserved(policy):
    reports = [
        make_report(
            module_id="secret_guard",
            success=False,
            error="RuntimeError",
        ),
        make_report(
            module_id="prompt_shield",
            success=False,
            error="ValueError",
        ),
    ]

    decision = policy.evaluate(
        reports=reports,
        mode="ask",
    )

    assert decision.action == "ask"
    assert len(decision.inspection_errors) == 2

    assert any("secret_guard" in error for error in decision.inspection_errors)
    assert any("prompt_shield" in error for error in decision.inspection_errors)


# ---------------------------------------------------------
# Decision precedence
# ---------------------------------------------------------


def test_most_restrictive_finding_determines_decision(policy):
    findings = [
        make_finding(rule_id="test.low", severity="low"),
        make_finding(rule_id="test.high", severity="high"),
        make_finding(rule_id="test.critical", severity="critical"),
    ]

    decision = policy.evaluate(
        reports=[make_report(findings=findings)],
        mode="ask",
    )

    assert decision.action == "block"
    assert len(decision.findings) == 3


def test_critical_finding_overrides_inspection_failure(policy):
    reports = [
        make_report(
            findings=[
                make_finding(severity="critical"),
            ],
        ),
        make_report(
            module_id="secret_guard",
            success=False,
            error="RuntimeError",
        ),
    ]

    decision = policy.evaluate(
        reports=reports,
        mode="ask",
    )

    assert decision.action == "block"
    assert len(decision.findings) == 1
    assert len(decision.inspection_errors) == 1


def test_all_findings_are_preserved_when_blocking(policy):
    findings = [
        make_finding(rule_id="test.high", severity="high"),
        make_finding(rule_id="test.critical", severity="critical"),
    ]

    decision = policy.evaluate(
        reports=[
            make_report(findings=findings),
        ],
        mode="alert",
    )

    assert decision.action == "block"
    assert decision.findings == findings


# ---------------------------------------------------------
# Input validation
# ---------------------------------------------------------


def test_unsupported_mode_is_rejected(policy):
    with pytest.raises(ValueError):
        policy.evaluate(
            reports=[make_report()],
            mode="invalid",
        )
