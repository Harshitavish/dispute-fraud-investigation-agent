"""Policy engine unit tests.

These cover the two properties that keep a model error from becoming a payout.
"""

from __future__ import annotations

import pytest

from app.agents.policy import band_for, decide
from app.config import get_settings

SETTINGS = get_settings()


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.0, "LOW"), (29.9, "LOW"), (30.0, "MEDIUM"), (55.0, "MEDIUM"), (70.0, "MEDIUM"), (70.1, "HIGH"), (100.0, "HIGH")],
)
def test_band_boundaries(score: float, expected: str) -> None:
    assert band_for(score) == expected


def test_model_may_escalate() -> None:
    action, rules_action, reasons = decide(
        risk_score=5.0, amount_paise=10_000, llm_recommendation="reject_and_flag"
    )
    assert rules_action == "auto_refund"
    assert action == "reject_and_flag"
    assert any("escalated" in r for r in reasons)


def test_model_may_not_de_escalate() -> None:
    """The ratchet. A persuasive model -- or a prompt-injected dispute
    description -- must never be able to turn a review into a payout."""
    action, rules_action, reasons = decide(
        risk_score=95.0, amount_paise=10_000, llm_recommendation="auto_refund"
    )
    assert rules_action == "reject_and_flag"
    assert action == "reject_and_flag"
    assert any("does not permit de-escalation" in r for r in reasons)


def test_high_value_guardrail_overrides_clean_score() -> None:
    """Clean signals are not authority to release a large sum unattended."""
    amount = SETTINGS.manual_review_amount_paise + 1
    action, rules_action, reasons = decide(
        risk_score=0.0, amount_paise=amount, llm_recommendation="auto_refund"
    )
    assert rules_action == "auto_refund"
    assert action == "manual_review"
    assert any("High-value guardrail" in r for r in reasons)


def test_guardrail_does_not_downgrade_a_rejection() -> None:
    amount = SETTINGS.manual_review_amount_paise + 1
    action, _, _ = decide(
        risk_score=99.0, amount_paise=amount, llm_recommendation="reject_and_flag"
    )
    assert action == "reject_and_flag"


def test_missing_llm_recommendation_is_tolerated() -> None:
    action, _, _ = decide(risk_score=10.0, amount_paise=1_000, llm_recommendation=None)
    assert action == "auto_refund"
