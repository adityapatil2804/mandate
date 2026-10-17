"""Mandate CLI.

  python -m cli.mandate verify                 check ledger integrity (hashes, signatures, chain)
  python -m cli.mandate replay <task_id>       show everything a task attempted, in order
  python -m cli.mandate tasks                  list tasks with allow/deny counts
"""
import argparse
import os
import sys
from collections import Counter
from datetime import datetime

from gateway.keys import load_or_create
from gateway.ledger import Ledger

DATA = os.environ.get("MANDATE_DATA", "data")


def ledger():
    return Ledger(os.path.join(DATA, "ledger.jsonl"), load_or_create(os.path.join(DATA, "keys/ledger.pem")))


def cmd_verify(_):
    ok, msg = ledger().verify()
    print(("VALID  " if ok else "TAMPERED  ") + msg)
    return 0 if ok else 1


def cmd_replay(a):
    recs = list(ledger().records(a.task))
    if not recs:
        print(f"no records for {a.task}")
        return 1
    r0 = recs[0]
    print(f"task {a.task}  human={r0['sub']}  agent={r0['act']}  policy={r0['policy']}\n")
    for r in recs:
        t = datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S")
        mark = "ALLOW" if r["decision"] == "ALLOW" else "DENY "
        why = ("  <- " + "; ".join(r["reasons"])) if r["reasons"] else ""
        print(f"  #{r['seq']:<5} {t}  {mark}  {r['tool']:<13} args={r['args_hash'][:10]}{why}")
    c = Counter(r["decision"] for r in recs)
    print(f"\n  {c['ALLOW']} allowed, {c['DENY']} denied")
    return 0


def cmd_tasks(_):
    agg = {}
    for r in ledger().records():
        if r["task"]:
            agg.setdefault(r["task"], Counter())[r["decision"]] += 1
    for t, c in agg.items():
        print(f"{t}  allow={c['ALLOW']:<4} deny={c['DENY']}")
    return 0


def main():
    p = argparse.ArgumentParser(prog="mandate")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    r = sub.add_parser("replay")
    r.add_argument("task")
    r.set_defaults(fn=cmd_replay)
    sub.add_parser("tasks").set_defaults(fn=cmd_tasks)
    a = p.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
