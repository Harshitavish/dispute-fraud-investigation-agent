"""Seed a realistic dataset with four hand-built dispute scenarios.

The scenarios are designed so each one exercises a different branch of the
agent graph: auto-refund, hard reject, behavioural (friendly-fraud) review,
and the high-value guardrail.
"""

from __future__ import annotations

import random
from datetime import timedelta

from sqlalchemy.orm import Session

from app.db.models import (
    Customer,
    Dispute,
    DisputeStatus,
    IPReputation,
    Merchant,
    Transaction,
    TransactionStatus,
    utcnow,
)
from app.db.session import init_db, session_scope

RNG = random.Random(20260720)  # deterministic seed -> reproducible demos

MERCHANTS = [
    ("mrc_kirana", "Kirana Fresh Pvt Ltd", "ops@kiranafresh.example", "grocery", 0.004),
    ("mrc_travel", "SkyRoute Travel", "support@skyroute.example", "travel", 0.021),
    ("mrc_gaming", "PixelForge Games", "billing@pixelforge.example", "gaming", 0.014),
]

CUSTOMERS = [
    ("cst_aarav", "Aarav Sharma", "aarav.sharma@example.com", "+91-98200-11223", "IN"),
    ("cst_meera", "Meera Iyer", "meera.iyer@example.com", "+91-99400-55667", "IN"),
    ("cst_rohan", "Rohan Gupta", "rohan.gupta@example.com", "+91-97300-88991", "IN"),
    ("cst_diya", "Diya Nair", "diya.nair@example.com", "+91-96500-33445", "IN"),
]

IP_FEED = [
    # ip, tor, proxy, datacenter, abuse, country, asn
    ("49.36.180.22", False, False, False, 2, "IN", "Reliance Jio Infocomm"),
    ("103.21.244.10", False, False, False, 5, "IN", "Bharti Airtel"),
    ("117.230.14.88", False, False, False, 1, "IN", "BSNL"),
    ("185.220.101.44", True, True, True, 96, "RU", "Tor Exit Relay / Foundation"),
    ("45.155.205.233", False, True, True, 78, "NL", "Bulletproof Hosting BV"),
    ("152.58.90.17", False, False, False, 3, "IN", "Reliance Jio Infocomm"),
]

CLEAN_IPS = ["49.36.180.22", "103.21.244.10", "117.230.14.88", "152.58.90.17"]


def _history(session: Session, customer_id: str, merchant_id: str, device: str, count: int) -> None:
    """Backfill routine transactions so velocity/amount baselines are meaningful."""
    now = utcnow()
    for i in range(count):
        session.add(
            Transaction(
                id=f"txn_h_{customer_id[-5:]}_{i:03d}",
                merchant_id=merchant_id,
                customer_id=customer_id,
                amount_paise=RNG.randint(30_000, 250_000),  # Rs. 300 - 2,500
                status=TransactionStatus.CAPTURED,
                method="card",
                card_bin="411111",
                card_last4=f"{RNG.randint(1000, 9999)}",
                card_issuer_country="IN",
                ip_address=RNG.choice(CLEAN_IPS),
                device_fingerprint=device,
                country="IN",
                city=RNG.choice(["Mumbai", "Pune", "Bengaluru", "Chennai"]),
                created_at=now - timedelta(days=RNG.randint(5, 180), hours=RNG.randint(0, 23)),
            )
        )


def seed(reset: bool = True) -> None:
    init_db()

    with session_scope() as session:
        if reset:
            for model in (Dispute, Transaction, IPReputation, Customer, Merchant):
                session.query(model).delete()
            session.flush()

        for mid, name, email, cat, cb in MERCHANTS:
            session.add(
                Merchant(id=mid, name=name, email=email, category=cat, chargeback_rate=cb)
            )

        for cid, name, email, phone, country in CUSTOMERS:
            session.add(
                Customer(id=cid, name=name, email=email, phone=phone, home_country=country)
            )

        for ip, tor, proxy, dc, abuse, country, asn in IP_FEED:
            session.add(
                IPReputation(
                    ip_address=ip,
                    is_tor=tor,
                    is_proxy=proxy,
                    is_datacenter=dc,
                    abuse_score=abuse,
                    country=country,
                    asn_org=asn,
                )
            )
        session.flush()

        _history(session, "cst_aarav", "mrc_kirana", "dev_aarav_pixel7", 24)
        _history(session, "cst_meera", "mrc_travel", "dev_meera_iphone14", 18)
        _history(session, "cst_rohan", "mrc_gaming", "dev_rohan_win11", 31)
        _history(session, "cst_diya", "mrc_travel", "dev_diya_macbook", 12)

        now = utcnow()

        # --- Scenario 1: clean, low-value, service not rendered -> auto refund
        session.add(
            Transaction(
                id="txn_clean_001",
                merchant_id="mrc_kirana",
                customer_id="cst_aarav",
                amount_paise=149_900,  # Rs. 1,499
                status=TransactionStatus.CAPTURED,
                method="card",
                card_bin="411111",
                card_last4="4242",
                card_issuer_country="IN",
                ip_address="49.36.180.22",
                device_fingerprint="dev_aarav_pixel7",
                country="IN",
                city="Mumbai",
                created_at=now - timedelta(days=6),
            )
        )
        session.add(
            Dispute(
                id="dsp_001",
                transaction_id="txn_clean_001",
                reason_code="SERVICE_NOT_RENDERED",
                description=(
                    "Order was marked delivered but nothing arrived. I waited four days "
                    "and the merchant's support line does not connect. Please refund."
                ),
                amount_paise=149_900,
                status=DisputeStatus.OPEN,
                raised_at=now - timedelta(hours=8),
            )
        )

        # --- Scenario 2: account takeover -> reject + flag
        for i in range(4):  # burst of card testing from the same bad IP
            session.add(
                Transaction(
                    id=f"txn_ato_burst_{i}",
                    merchant_id="mrc_gaming",
                    customer_id="cst_rohan",
                    amount_paise=RNG.randint(80_000, 400_000),
                    status=TransactionStatus.CAPTURED,
                    method="card",
                    card_bin="521234",
                    card_last4="9911",
                    card_issuer_country="IN",
                    ip_address="185.220.101.44",
                    device_fingerprint="dev_unknown_headless",
                    country="RU",
                    city="Saint Petersburg",
                    created_at=now - timedelta(minutes=40 - i * 7),
                )
            )
        session.add(
            Transaction(
                id="txn_ato_002",
                merchant_id="mrc_gaming",
                customer_id="cst_rohan",
                amount_paise=1_899_900,  # Rs. 18,999
                status=TransactionStatus.CAPTURED,
                method="card",
                card_bin="521234",
                card_last4="9911",
                card_issuer_country="IN",
                ip_address="185.220.101.44",
                device_fingerprint="dev_unknown_headless",
                country="RU",
                city="Saint Petersburg",
                created_at=now - timedelta(minutes=12),
            )
        )
        session.add(
            Dispute(
                id="dsp_002",
                transaction_id="txn_ato_002",
                reason_code="FRAUDULENT_TRANSACTION",
                description=(
                    "I did not authorise this purchase. I was asleep and my card is with me. "
                    "There are several other charges I don't recognise from tonight."
                ),
                amount_paise=1_899_900,
                status=DisputeStatus.OPEN,
                raised_at=now - timedelta(minutes=5),
            )
        )

        # --- Scenario 3: friendly fraud pattern -> human review
        session.add(
            Transaction(
                id="txn_friendly_003",
                merchant_id="mrc_gaming",
                customer_id="cst_diya",
                amount_paise=299_900,  # Rs. 2,999
                status=TransactionStatus.CAPTURED,
                method="card",
                card_bin="411111",
                card_last4="7788",
                card_issuer_country="IN",
                ip_address="103.21.244.10",
                device_fingerprint="dev_diya_macbook",
                country="IN",
                city="Kochi",
                created_at=now - timedelta(days=11),
            )
        )
        # A trail of previously-refunded disputes: the tell for friendly fraud.
        for i in range(4):
            session.add(
                Transaction(
                    id=f"txn_diya_prior_{i}",
                    merchant_id="mrc_gaming",
                    customer_id="cst_diya",
                    amount_paise=RNG.randint(150_000, 350_000),
                    status=TransactionStatus.REFUNDED,
                    method="card",
                    card_bin="411111",
                    card_last4="7788",
                    card_issuer_country="IN",
                    ip_address="103.21.244.10",
                    device_fingerprint="dev_diya_macbook",
                    country="IN",
                    city="Kochi",
                    created_at=now - timedelta(days=40 + i * 25),
                )
            )
            session.add(
                Dispute(
                    id=f"dsp_diya_prior_{i}",
                    transaction_id=f"txn_diya_prior_{i}",
                    reason_code="PRODUCT_NOT_AS_DESCRIBED",
                    description="Item did not match the listing.",
                    amount_paise=200_000,
                    status=DisputeStatus.RESOLVED_REFUNDED,
                    raised_at=now - timedelta(days=38 + i * 25),
                    resolved_at=now - timedelta(days=36 + i * 25),
                    resolution="refund",
                )
            )
        session.add(
            Dispute(
                id="dsp_003",
                transaction_id="txn_friendly_003",
                reason_code="PRODUCT_NOT_AS_DESCRIBED",
                description=(
                    "The in-game currency pack was not what I expected from the store page. "
                    "I want my money back."
                ),
                amount_paise=299_900,
                status=DisputeStatus.OPEN,
                raised_at=now - timedelta(hours=20),
            )
        )

        # --- Scenario 4: clean signals, but above the high-value guardrail
        session.add(
            Transaction(
                id="txn_highvalue_004",
                merchant_id="mrc_travel",
                customer_id="cst_meera",
                amount_paise=8_450_000,  # Rs. 84,500
                status=TransactionStatus.CAPTURED,
                method="card",
                card_bin="411111",
                card_last4="1122",
                card_issuer_country="IN",
                ip_address="152.58.90.17",
                device_fingerprint="dev_meera_iphone14",
                country="IN",
                city="Chennai",
                created_at=now - timedelta(days=3),
            )
        )
        session.add(
            Dispute(
                id="dsp_004",
                transaction_id="txn_highvalue_004",
                reason_code="DUPLICATE_CHARGE",
                description=(
                    "I was charged twice for the same Chennai-Singapore booking. "
                    "The airline confirmed only one ticket was issued."
                ),
                amount_paise=8_450_000,
                status=DisputeStatus.OPEN,
                raised_at=now - timedelta(hours=30),
            )
        )

    print("Seeded: 3 merchants, 4 customers, 4 open disputes (dsp_001..dsp_004).")


if __name__ == "__main__":
    seed()
