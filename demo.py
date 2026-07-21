"""End-to-end demo: run every open dispute through the agent graph.

    python demo.py            # run all seeded scenarios
    python demo.py dsp_002    # run one
    python demo.py --reseed   # rebuild the dataset first
"""

from __future__ import annotations

import sys

from app.agents.graph import resume_investigation, start_investigation
from app.db.seed import seed
from app.db.session import init_db, session_scope
from app.tools.sql_tools import list_open_disputes

BAR = "=" * 78


def _print_case(result: dict) -> None:
    print(BAR)
    print(f"DISPUTE {result['dispute_id']}   (case {result['case_run_id']})")
    print(BAR)

    if result.get("error"):
        print(f"  ERROR: {result['error']}")
        return

    print(f"  Risk score      : {result['risk_score']}/100  [{result['risk_band']}]")
    print(f"  Decision        : {result['decision']}  (by {result['decided_by']})")
    print(f"  Case status     : {result['status']}")

    adj = result.get("adjudication") or {}
    print(f"  Fraud typology  : {adj.get('fraud_typology')}")
    print(f"  Analyst source  : {adj.get('source')}  (confidence {adj.get('confidence')})")

    print("\n  Triggered signals:")
    for name in result["triggered_signals"] or ["(none)"]:
        print(f"    - {name}")

    print("\n  Analyst assessment:")
    for line in (adj.get("assessment") or "").splitlines() or [""]:
        print(f"    {line}")
    if adj.get("dissent"):
        print(f"\n  Counter-argument: {adj['dissent']}")

    print("\n  Policy reasoning:")
    for reason in result["decision_reasons"]:
        print(f"    - {reason}")

    action = result.get("action_result")
    if action:
        print(f"\n  Action taken    : {action}")
    if result.get("fraud_alert"):
        print(f"  Fraud alert     : {result['fraud_alert']['alert_id']} "
              f"({result['fraud_alert']['severity']})")

    print("\n  Notifications:")
    for note in result["notifications"]:
        print(f"    -> {note['audience']:8s} [{note.get('mode')}] {note['subject']}")

    print(f"\n  Audit trail     : {len(result['trace'])} recorded steps")
    for step in result["trace"]:
        tool = f" via {step['tool']}" if step.get("tool") else ""
        print(f"    {step.get('sequence', '?'):>3}. [{step['agent']}] {step['step']}{tool}")
    print()


def main() -> None:
    args = [a for a in sys.argv[1:]]

    if "--reseed" in args:
        seed()
        args.remove("--reseed")

    init_db()

    if args:
        dispute_ids = args
    else:
        with session_scope() as session:
            dispute_ids = [d["id"] for d in list_open_disputes(session)]

    if not dispute_ids:
        print("No open disputes. Run: python demo.py --reseed")
        return

    paused: list[tuple[str, str]] = []

    for dispute_id in dispute_ids:
        result = start_investigation(dispute_id)
        _print_case(result)
        if result["status"] == "awaiting_human":
            paused.append((result["case_run_id"], dispute_id))

    if paused:
        print(BAR)
        print("HUMAN-IN-THE-LOOP: the graph is paused on these cases.")
        print(BAR)
        for case_run_id, dispute_id in paused:
            print(f"  {dispute_id}  ->  case {case_run_id}")
        print("\nSimulating a reviewer approving the first paused case...\n")

        case_run_id, dispute_id = paused[0]
        resumed = resume_investigation(
            case_run_id,
            human_decision="approve_refund",
            notes="Reviewed the delivery evidence; the customer's account is clean.",
        )
        _print_case(resumed)


if __name__ == "__main__":
    main()
