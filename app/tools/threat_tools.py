"""Deterministic risk-scoring engine.

Design note: the LLM does *not* compute the risk score. Scoring is explicit,
weighted and reproducible here in Python; the model's job is to reason over the
signals, spot combinations the rules miss, and write the justification. A number
that decides whether money moves has to be auditable and testable -- you cannot
regression-test a vibe.

Each signal returns evidence alongside its weight, so the audit log records not
just "score 82" but "score 82 because of these seven facts".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Signal:
    name: str
    triggered: bool
    weight: float
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def contribution(self) -> float:
        return self.weight if self.triggered else 0.0


# Weights are expressed on a 0-100 scale. The total of all weights exceeds 100
# on purpose -- a transaction that trips everything should saturate, not be
# averaged down into the middle of the range.
WEIGHTS = {
    "anonymised_network": 25.0,
    "ip_abuse_reputation": 15.0,
    "geo_mismatch": 15.0,
    "unrecognised_device": 10.0,
    "velocity_spike": 12.0,
    "amount_anomaly": 12.0,
    "card_country_mismatch": 8.0,
    "shared_ip_cluster": 6.0,
    "serial_refund_claimant": 22.0,
    "elevated_dispute_rate": 8.0,
    "high_risk_merchant": 5.0,
    "immediate_dispute": 5.0,
}


def evaluate_signals(
    *,
    transaction: dict[str, Any],
    customer: dict[str, Any],
    profile: dict[str, Any],
    velocity: dict[str, Any],
    ip_reputation: dict[str, Any],
    ip_cluster: dict[str, Any],
    merchant: dict[str, Any],
    dispute: dict[str, Any],
) -> list[Signal]:
    signals: list[Signal] = []

    # 1. Anonymising infrastructure. Tor/proxy/datacenter for a consumer
    #    retail payment is close to a standalone red flag.
    anon = ip_reputation["is_tor"] or ip_reputation["is_proxy"] or ip_reputation["is_datacenter"]
    signals.append(
        Signal(
            "anonymised_network",
            anon,
            WEIGHTS["anonymised_network"],
            "Payment originated from Tor, a proxy, or datacenter infrastructure.",
            {
                "is_tor": ip_reputation["is_tor"],
                "is_proxy": ip_reputation["is_proxy"],
                "is_datacenter": ip_reputation["is_datacenter"],
                "asn_org": ip_reputation["asn_org"],
            },
        )
    )

    # 2. Reputation feed score.
    signals.append(
        Signal(
            "ip_abuse_reputation",
            ip_reputation["abuse_score"] >= 60,
            WEIGHTS["ip_abuse_reputation"],
            "Source IP carries a high abuse score in the threat feed.",
            {"abuse_score": ip_reputation["abuse_score"], "known_to_feed": ip_reputation["known"]},
        )
    )

    # 3. Geography. Compared against where this customer has actually been
    #    seen before, not against a global allowlist.
    txn_country = transaction["country"]
    seen_before = txn_country in profile["known_countries"]
    geo_mismatch = txn_country != customer["home_country"] and not seen_before
    signals.append(
        Signal(
            "geo_mismatch",
            geo_mismatch,
            WEIGHTS["geo_mismatch"],
            "Transaction country differs from the customer's home and historical countries.",
            {
                "transaction_country": txn_country,
                "home_country": customer["home_country"],
                "known_countries": profile["known_countries"],
            },
        )
    )

    # 4. Device.
    new_device = transaction["device_fingerprint"] not in profile["known_devices"]
    signals.append(
        Signal(
            "unrecognised_device",
            new_device,
            WEIGHTS["unrecognised_device"],
            "Device fingerprint has never been seen on this account.",
            {"device": transaction["device_fingerprint"], "known_devices": profile["known_devices"]},
        )
    )

    # 5. Velocity -- card testing and takeover bursts look like this.
    burst = velocity["last_1h"]["count"] >= 3
    signals.append(
        Signal(
            "velocity_spike",
            burst,
            WEIGHTS["velocity_spike"],
            "Unusual number of transactions in the hour around the disputed charge.",
            {"last_1h": velocity["last_1h"], "last_24h": velocity["last_24h"]},
        )
    )

    # 6. Amount anomaly relative to this customer's own baseline.
    avg = profile["avg_amount_paise"] or 1
    mx = profile["max_amount_paise"] or 1
    amount = transaction["amount_paise"]
    anomalous = amount > max(3 * mx, 5 * avg)
    signals.append(
        Signal(
            "amount_anomaly",
            anomalous,
            WEIGHTS["amount_anomaly"],
            "Charge is far outside the customer's historical spending range.",
            {
                "amount_paise": amount,
                "customer_avg_paise": avg,
                "customer_max_paise": mx,
                "multiple_of_max": round(amount / mx, 2) if mx else None,
            },
        )
    )

    # 7. Card issued in one country, used from another.
    issuer = transaction.get("card_issuer_country")
    mismatch = bool(issuer) and issuer != txn_country
    signals.append(
        Signal(
            "card_country_mismatch",
            mismatch,
            WEIGHTS["card_country_mismatch"],
            "Card issuing country does not match the transaction country.",
            {"issuer_country": issuer, "transaction_country": txn_country},
        )
    )

    # 8. One IP serving many accounts. Often carrier NAT (benign) but also
    #    account-farming (not benign) -- hence the deliberately low weight.
    shared = ip_cluster["distinct_customers"] >= 4
    signals.append(
        Signal(
            "shared_ip_cluster",
            shared,
            WEIGHTS["shared_ip_cluster"],
            "Multiple distinct accounts have transacted from this IP.",
            {"distinct_customers": ip_cluster["distinct_customers"]},
        )
    )

    # 9 & 10. Friendly fraud: the customer is real, the card is real, the
    #    goods were delivered -- and they dispute anyway, repeatedly.
    serial = profile["prior_refunded_disputes"] >= 3
    signals.append(
        Signal(
            "serial_refund_claimant",
            serial,
            WEIGHTS["serial_refund_claimant"],
            "Customer has a history of disputes previously resolved in their favour.",
            {
                "prior_refunded_disputes": profile["prior_refunded_disputes"],
                "prior_disputes": profile["prior_disputes"],
            },
        )
    )
    signals.append(
        Signal(
            "elevated_dispute_rate",
            profile["dispute_rate"] > 0.15,
            WEIGHTS["elevated_dispute_rate"],
            "Share of this customer's transactions ending in dispute is abnormally high.",
            {"dispute_rate": profile["dispute_rate"]},
        )
    )

    # 11. Merchant-side risk. Card networks start monitoring around 0.9%.
    signals.append(
        Signal(
            "high_risk_merchant",
            merchant["chargeback_rate"] > 0.009,
            WEIGHTS["high_risk_merchant"],
            "Merchant's chargeback rate is above the network monitoring threshold.",
            {"chargeback_rate": merchant["chargeback_rate"], "category": merchant["category"]},
        )
    )

    # 12. Dispute filed almost immediately -- consistent with a takeover victim
    #     reacting to an alert, or with an attacker covering tracks.
    signals.append(
        Signal(
            "immediate_dispute",
            dispute["hours_since_transaction"] < 1.0,
            WEIGHTS["immediate_dispute"],
            "Dispute was raised within an hour of the transaction.",
            {"hours_since_transaction": dispute["hours_since_transaction"]},
        )
    )

    return signals


def score(signals: list[Signal]) -> float:
    """Sum contributions and clamp to 0-100."""
    return round(min(100.0, sum(s.contribution for s in signals)), 2)


def serialise(signals: list[Signal]) -> list[dict[str, Any]]:
    out = []
    for s in signals:
        d = asdict(s)
        d["contribution"] = s.contribution
        out.append(d)
    return out


def triggered_names(signals: list[Signal]) -> list[str]:
    return [s.name for s in signals if s.triggered]
