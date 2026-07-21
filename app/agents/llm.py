"""LLM layer (Anthropic Claude).

Two responsibilities only:
  1. Adjudication -- reason over the computed signals and produce a structured
     recommendation with a written justification.
  2. Communication -- draft the customer/merchant notification.

Both have deterministic fallbacks. If ANTHROPIC_API_KEY is unset the pipeline
still completes end-to-end using rule-based text; you lose the prose quality,
not the decision. That property matters: a payments workflow should degrade,
not halt, when an upstream dependency is unavailable.
"""

from __future__ import annotations

import json
from typing import Any

from app.config import get_settings

_ADJUDICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "assessment": {
            "type": "string",
            "description": "2-4 sentence analyst narrative explaining what the evidence shows.",
        },
        "fraud_typology": {
            "type": "string",
            "enum": [
                "none",
                "account_takeover",
                "friendly_fraud",
                "card_testing",
                "merchant_error",
                "service_failure",
                "unclear",
            ],
        },
        "key_findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific facts driving the conclusion, most important first.",
        },
        "recommended_action": {
            "type": "string",
            "enum": ["auto_refund", "manual_review", "reject_and_flag"],
        },
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "dissent": {
            "type": "string",
            "description": "The strongest argument against the recommendation. Empty string if none.",
        },
    },
    "required": [
        "assessment",
        "fraud_typology",
        "key_findings",
        "recommended_action",
        "confidence",
        "dissent",
    ],
    "additionalProperties": False,
}

_NOTIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "required": ["subject", "body"],
    "additionalProperties": False,
}

ANALYST_SYSTEM = """You are a senior payments fraud analyst at a payment gateway, reviewing a \
disputed transaction.

A deterministic rules engine has already computed a risk score and a set of triggered signals. \
Do not recompute the score. Your job is to interpret the evidence: identify the fraud typology \
if there is one, name the specific facts that drive the conclusion, and state the strongest \
argument against your own recommendation.

Ground every finding in the supplied evidence. Do not invent transaction details, customer \
history, or external context that is not in the payload. If the evidence is genuinely \
ambiguous, recommend manual_review and say why.

Weigh the cost of both errors. Wrongly refunding fraud loses money; wrongly rejecting a \
legitimate customer loses the customer and invites a regulatory complaint. Neither is free."""

WRITER_SYSTEM = """You write customer and merchant notifications for a payment gateway's \
dispute team.

Be clear, warm, and specific. State the outcome in the first sentence. Reference the concrete \
details of the case (amount, merchant, date) so the message does not read as a form letter.

Never disclose internal fraud signals, risk scores, IP addresses, device fingerprints, or \
detection logic -- that information helps attackers calibrate. Never accuse the recipient of \
fraud. If a case is under review, set an expectation for next steps and timing.

Plain text only, no markdown. Sign off as 'Disputes Team'."""


class LLMClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None
        self.available = False

        if not self.settings.llm_enabled or not self.settings.anthropic_api_key:
            return
        try:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.settings.anthropic_api_key)
            self.available = True
        except Exception:  # noqa: BLE001 - missing package or bad key: fall back quietly
            self.available = False

    # -- internals ---------------------------------------------------------

    def _structured(self, *, system: str, prompt: str, schema: dict) -> dict[str, Any] | None:
        if not self.available:
            return None
        try:
            response = self._client.messages.create(
                model=self.settings.llm_model,
                max_tokens=self.settings.llm_max_tokens,
                thinking={"type": "adaptive"},
                output_config={
                    "effort": self.settings.llm_effort,
                    "format": {"type": "json_schema", "schema": schema},
                },
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            if response.stop_reason == "refusal":
                return None
            text = next((b.text for b in response.content if b.type == "text"), None)
            return json.loads(text) if text else None
        except Exception:  # noqa: BLE001 - any LLM failure degrades to the rule path
            return None

    # -- public API --------------------------------------------------------

    def adjudicate(
        self,
        *,
        context: dict[str, Any],
        signals: list[dict[str, Any]],
        risk_score: float,
        risk_band: str,
        policy_action: str,
    ) -> dict[str, Any]:
        triggered = [s for s in signals if s["triggered"]]
        prompt = f"""Review this payment dispute.

## Dispute
{json.dumps(context["dispute"], indent=2)}

## Transaction
{json.dumps(context["transaction"], indent=2)}

## Merchant
{json.dumps(context["merchant"], indent=2)}

## Customer behavioural baseline
{json.dumps(context["profile"], indent=2)}

## Transaction velocity around the disputed charge
{json.dumps(context["velocity"], indent=2)}

## Recent transaction timeline
{json.dumps(context["recent_transactions"], indent=2)}

## Threat intelligence on the source IP
{json.dumps(context["ip_reputation"], indent=2)}

## Rules-engine output
Risk score: {risk_score}/100 (band: {risk_band})
Policy engine's action before your review: {policy_action}
Triggered signals:
{json.dumps(triggered, indent=2)}

Produce your structured assessment."""

        result = self._structured(system=ANALYST_SYSTEM, prompt=prompt, schema=_ADJUDICATION_SCHEMA)
        if result is not None:
            result["source"] = "llm"
            return result
        return self._fallback_adjudication(signals, risk_score, risk_band, policy_action)

    def draft_notification(
        self,
        *,
        audience: str,
        decision: str,
        context: dict[str, Any],
        assessment: str,
    ) -> dict[str, Any]:
        dispute = context["dispute"]
        txn = context["transaction"]
        merchant = context["merchant"]
        recipient = context["customer"]["name"] if audience == "customer" else merchant["name"]

        prompt = f"""Write a notification email.

Audience: {audience}
Recipient name: {recipient}
Outcome: {decision}

Case facts you may reference:
- Dispute ID: {dispute['id']}
- Amount: {dispute['amount_display']}
- Merchant: {merchant['name']}
- Transaction date: {txn['created_at'][:10]}
- Reason the customer gave: {dispute['reason_code'].replace('_', ' ').lower()}

Internal analyst summary (for your understanding only -- do NOT quote internal
detection logic, scores, or signals to the recipient):
{assessment}

Outcome wording guidance:
- auto_refund: refund approved and processing; 5-7 working days to land.
- manual_review: under review by a specialist; response within 2 working days.
- reject_and_flag: we could not approve the claim; explain the appeal route
  without accusing them of anything.

Write the subject and body."""

        result = self._structured(
            system=WRITER_SYSTEM, prompt=prompt, schema=_NOTIFICATION_SCHEMA
        )
        if result is not None:
            result["source"] = "llm"
            return result
        return self._fallback_notification(audience, decision, context)

    # -- deterministic fallbacks ------------------------------------------

    @staticmethod
    def _fallback_adjudication(
        signals: list[dict[str, Any]], risk_score: float, risk_band: str, policy_action: str
    ) -> dict[str, Any]:
        triggered = [s for s in signals if s["triggered"]]
        names = {s["name"] for s in triggered}

        if {"anonymised_network", "geo_mismatch"} & names and "unrecognised_device" in names:
            typology = "account_takeover"
        elif "serial_refund_claimant" in names:
            typology = "friendly_fraud"
        elif "velocity_spike" in names and "amount_anomaly" not in names:
            typology = "card_testing"
        elif not triggered:
            typology = "service_failure"
        else:
            typology = "unclear"

        return {
            "assessment": (
                f"Rules-engine adjudication (LLM unavailable). Risk scored {risk_score}/100 "
                f"in the {risk_band} band from {len(triggered)} triggered signal(s). "
                f"Policy action: {policy_action}."
            ),
            "fraud_typology": typology,
            "key_findings": [f"{s['name']}: {s['rationale']}" for s in triggered] or [
                "No risk signals triggered; the claim is consistent with a genuine service failure."
            ],
            "recommended_action": policy_action,
            "confidence": 0.55,
            "dissent": "Generated without model review; treat borderline cases as manual_review.",
            "source": "rules_fallback",
        }

    @staticmethod
    def _fallback_notification(
        audience: str, decision: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        dispute = context["dispute"]
        merchant = context["merchant"]["name"]
        name = context["customer"]["name"] if audience == "customer" else merchant
        amount = dispute["amount_display"]

        bodies = {
            "auto_refund": (
                f"Hello {name},\n\n"
                f"Your dispute {dispute['id']} for {amount} at {merchant} has been approved. "
                f"The refund is processing now and should reach your original payment method "
                f"within 5-7 working days.\n\n"
                f"No further action is needed from you.\n\nDisputes Team\n"
            ),
            "manual_review": (
                f"Hello {name},\n\n"
                f"We have received your dispute {dispute['id']} for {amount} at {merchant}. "
                f"A specialist is reviewing it and we will write to you with an outcome within "
                f"2 working days.\n\n"
                f"You do not need to do anything in the meantime.\n\nDisputes Team\n"
            ),
            "reject_and_flag": (
                f"Hello {name},\n\n"
                f"We have completed our review of dispute {dispute['id']} for {amount} at "
                f"{merchant} and were not able to approve the claim on the evidence available.\n\n"
                f"If you have additional documentation, reply to this message within 15 days "
                f"and we will reopen the case.\n\nDisputes Team\n"
            ),
        }

        subjects = {
            "auto_refund": f"Refund approved - {dispute['id']}",
            "manual_review": f"Your dispute is under review - {dispute['id']}",
            "reject_and_flag": f"Outcome of your dispute - {dispute['id']}",
        }

        return {
            "subject": subjects.get(decision, f"Update on dispute {dispute['id']}"),
            "body": bodies.get(decision, bodies["manual_review"]),
            "source": "template_fallback",
        }
