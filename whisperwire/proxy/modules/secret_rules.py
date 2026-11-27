from dataclasses import dataclass
import re


@dataclass(frozen=True)
class SecretRule:
    """Defines a recognizable credential format."""

    rule_id: str
    category: str
    pattern: re.Pattern[str]
    severity: str
    description: str


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        rule_id="secret.stripe_key",
        category="credential",
        pattern=re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
        severity="high",
        description="Potential Stripe secret key detected.",
    ),
    SecretRule(
        rule_id="secret.github_token",
        category="credential",
        pattern=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        severity="high",
        description="Potential GitHub personal access token detected.",
    ),
    SecretRule(
        rule_id="secret.github_pat",
        category="credential",
        pattern=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        severity="high",
        description="Potential GitHub fine-grained token detected.",
    ),
    SecretRule(
        rule_id="secret.slack_token",
        category="credential",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        severity="high",
        description="Potential Slack token detected.",
    ),
    SecretRule(
        rule_id="secret.google_api_key",
        category="credential",
        pattern=re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
        severity="high",
        description="Potential Google API key detected.",
    ),
    SecretRule(
        rule_id="secret.openai_project_key",
        category="credential",
        pattern=re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
        severity="high",
        description="Potential OpenAI project key detected.",
    ),
)
