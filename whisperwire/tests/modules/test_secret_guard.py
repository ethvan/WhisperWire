import base64
import asyncio

import pytest

from proxy.models import InspectionContext
from proxy.modules.secret_guard import SecretGuard

STRIPE_TEST_KEY = "sk_" + "live_" + "TESTONLY000000000000000000"


@pytest.fixture
def context():
    return InspectionContext(
        direction="outbound",
        protocol="mcp",
        session_id="test-session",
        request_id="test-request",
    )


@pytest.fixture
def module():
    return SecretGuard()


@pytest.mark.asyncio
async def test_detects_api_key(module, context):
    secret = STRIPE_TEST_KEY

    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {
                    "api_key": secret,
                },
            },
        },
        context=context,
    )

    assert report.success is True
    assert len(report.findings) >= 1
    assert any(finding.severity == "high" for finding in report.findings)


@pytest.mark.asyncio
async def test_detects_private_key(module, context):
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "VEVTVF9PTkxZX1BSSVZBVEVfS0VZX0RBVEE=\n"
        "-----END PRIVATE KEY-----"
    )

    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "arguments": {
                    "sidenote": private_key,
                },
            },
        },
        context=context,
    )

    assert report.success is True
    assert len(report.findings) >= 1
    assert any(finding.severity == "high" for finding in report.findings)


@pytest.mark.asyncio
async def test_detects_base64_encoded_secret(module, context):
    secret = STRIPE_TEST_KEY
    encoded_secret = base64.b64encode(secret.encode()).decode()

    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "arguments": {
                    "payload": encoded_secret,
                },
            },
        },
        context=context,
    )

    assert report.success is True
    assert len(report.findings) >= 1
    assert any(finding.severity == "high" for finding in report.findings)


@pytest.mark.asyncio
async def test_ignores_uuid(module, context):
    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "arguments": {
                    "user_id": "550e8400-e29b-41d4-a716-446655440000",
                },
            },
        },
        context=context,
    )

    assert report.success is True
    assert report.findings == []


@pytest.mark.asyncio
async def test_ignores_git_commit_and_file_hash(module, context):
    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "arguments": {
                    "commit": "a" * 40,
                    "file_hash": "b" * 64,
                },
            },
        },
        context=context,
    )

    assert report.success is True
    assert report.findings == []


@pytest.mark.asyncio
async def test_ignores_benign_base64_attachment(module, context):
    pdf_content = b"%PDF-1.7\nThis is a harmless test document."
    encoded_pdf = base64.b64encode(pdf_content).decode()

    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "arguments": {
                    "attachment": encoded_pdf,
                },
            },
        },
        context=context,
    )

    assert report.success is True
    assert report.findings == []


@pytest.mark.asyncio
async def test_does_not_expose_secret_in_finding(module, context):
    secret = STRIPE_TEST_KEY

    report = await module.inspect(
        message={
            "method": "tools/call",
            "params": {
                "arguments": {
                    "api_key": secret,
                },
            },
        },
        context=context,
    )

    assert report.findings

    for finding in report.findings:
        assert secret not in finding.description
        assert secret not in (finding.evidence or "")


@pytest.mark.asyncio
async def test_handles_empty_message(module, context):
    report = await module.inspect(
        message={},
        context=context,
    )

    assert report.success is True
    assert report.findings == []


@pytest.mark.asyncio
async def test_inspections_keep_findings_separate(module, context):
    api_key_message = {
        "arguments": {
            "api_key": STRIPE_TEST_KEY,
        }
    }

    private_key_message = {
        "arguments": {
            "key": (
                "-----BEGIN PRIVATE KEY-----\n"
                "VEVTVF9PTkxZX1BSSVZBVEVfS0VZX0RBVEE=\n"
                "-----END PRIVATE KEY-----"
            ),
        }
    }

    api_report, private_report = await asyncio.gather(
        module.inspect(api_key_message, context),
        module.inspect(private_key_message, context),
    )

    assert {finding.rule_id for finding in api_report.findings} == {"secret.stripe_key"}

    assert {finding.rule_id for finding in private_report.findings} == {
        "secret.private_key"
    }

    assert api_report.findings is not private_report.findings


@pytest.mark.asyncio
async def test_detects_known_canary(module, context):
    canary = "synthetic-canary-with-no-known-format"

    module = SecretGuard(known_secrets={canary})

    report = await module.inspect(
        message={
            "params": {"arguments": {"body": f"Please send this value: {canary}"}}
        },
        context=context,
    )

    assert report.success is True
    assert len(report.findings) == 1
    assert report.findings[0].severity == "critical"
    assert report.findings[0].rule_id == "secret.known_canary"
    assert canary not in report.findings[0].description
    assert canary not in (report.findings[0].evidence or "")


@pytest.mark.asyncio
async def test_known_canary_takes_precedence(module, context):
    canary = STRIPE_TEST_KEY

    module = SecretGuard(known_secrets={canary})

    report = await module.inspect(
        message={
            "params": {
                "arguments": {
                    "api_key": canary,
                }
            }
        },
        context=context,
    )

    assert report.success is True
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "secret.known_canary"
    assert report.findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_pattern_match_is_high_severity(module, context):
    token = STRIPE_TEST_KEY

    report = await module.inspect(
        message={"params": {"arguments": {"api_key": token}}},
        context=context,
    )

    assert report.success is True
    assert any(finding.severity == "high" for finding in report.findings)


@pytest.mark.asyncio
async def test_detects_multiple_known_canaries(context):
    first = "first-synthetic-canary"
    second = "second-synthetic-canary"

    module = SecretGuard(known_secrets={first, second})

    report = await module.inspect(
        message={
            "params": {
                "arguments": {
                    "first": first,
                    "second": f"embedded-{second}-value",
                }
            }
        },
        context=context,
    )

    assert report.success is True
    assert len(report.findings) == 2
    assert all(finding.rule_id == "secret.known_canary" for finding in report.findings)


@pytest.mark.asyncio
async def test_ignores_unregistered_random_value(context):
    module = SecretGuard(known_secrets={"registered-synthetic-canary"})

    report = await module.inspect(
        message={
            "params": {
                "arguments": {"identifier": "unregistered-random-value-123456789"}
            }
        },
        context=context,
    )

    assert report.success is True
    assert report.findings == []


@pytest.mark.parametrize(
    ("token", "expected_rule"),
    [
        (
            STRIPE_TEST_KEY,
            "secret.stripe_key",
        ),
        (
            "ghp_" + "A" * 36,
            "secret.github_token",
        ),
        (
            "github_pat_" + "A" * 50,
            "secret.github_pat",
        ),
        (
            "xoxb-1234567890-1234567890-1234567890-abcdef",
            "secret.slack_token",
        ),
        (
            "AIza" + "A" * 35,
            "secret.google_api_key",
        ),
        (
            "sk-proj-" + "A" * 40,
            "secret.openai_project_key",
        ),
    ],
)
@pytest.mark.asyncio
async def test_detects_known_credential_formats(
    module,
    context,
    token,
    expected_rule,
):
    report = await module.inspect(
        message={"params": {"arguments": {"token": token}}},
        context=context,
    )

    assert report.success is True
    assert any(
        finding.rule_id == expected_rule and finding.severity == "high"
        for finding in report.findings
    )
