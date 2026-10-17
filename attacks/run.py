"""Benchmark: attack block rate, utility false-block rate, gateway decision latency.

    python -m attacks.run            # human-readable report
    python -m attacks.run --json     # machine-readable (for CI / README badge)
"""
import argparse
import base64
import json
import os
import statistics
import sys
from pathlib import Path

import jwt
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .harness import OPA, make_gateway

HERE = Path(__file__).resolve().parent / "scenarios"


class SkipScenario(Exception):
    pass


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def make_token(gw, sc):
    mode = sc.get("token", "valid")
    ttl = -10 if mode == "expired" else None
    token, claims = gw.broker.issue("alice@corp.com", "agent:test", sc["template"], sc.get("params", {}), ttl=ttl)
    if mode == "forged":
        token = jwt.encode(claims, Ed25519PrivateKey.generate(), algorithm="EdDSA")
    elif mode == "tampered":
        h, _, s = token.split(".")
        widened = {**claims, "scope": [{"tool": "email.send", "constraints": {"domains": ["evil.com"]}}]}
        token = f"{h}.{_b64(widened)}.{s}"
    elif mode == "alg_none":
        token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}."
    elif mode == "revoked":
        gw.broker.revoke(claims["task"])
    elif mode == "missing":
        token = ""
    return token, claims


def setup(gw, sc, claims):
    tdir = Path(gw.broker.task_dir(claims["task"]))
    s = sc.get("setup", {})
    for rel, content in s.get("files", {}).items():
        (tdir / rel).parent.mkdir(parents=True, exist_ok=True)
        (tdir / rel).write_text(content)
    if "symlink" in s:
        tgt = s["symlink"]["target"]
        tgt = str(tdir / tgt.split(":", 1)[1]) if tgt.startswith("INSIDE:") else tgt
        try:
            (tdir / s["symlink"]["name"]).symlink_to(tgt)
        except OSError as e:  # Windows without Developer Mode can't create symlinks
            raise SkipScenario("needs symlink permission (enable Windows Developer Mode)") from e
    sib = None
    if "sibling_suffix" in s:
        sib = tdir.parent / (tdir.name + s["sibling_suffix"])
        sib.mkdir(exist_ok=True)
    return tdir, sib


def run_scenario(gw, sc):
    token, claims = make_token(gw, sc)
    tdir, sib = setup(gw, sc, claims)
    out = []
    for st in sc["steps"]:
        args = dict(st["args"])
        if sib and isinstance(args.get("path"), str):
            args["path"] = args["path"].replace("SIBLING", f"../{sib.name}")
        r = gw.call(token, st["tool"], args)
        out.append((st, r))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--latency-iters", type=int, default=1000)
    a = ap.parse_args()

    attacks = yaml.safe_load((HERE / "attacks.yaml").read_text())
    utility = yaml.safe_load((HERE / "utility.yaml").read_text())

    with OPA() as opa:
        gw = make_gateway(opa.url)
        rows, lat = [], []

        blocked, skipped = 0, []
        for sc in attacks["attacks"]:
            try:
                res = run_scenario(gw, sc)
            except SkipScenario as e:
                skipped.append(sc["id"])
                rows.append(("attack", sc["id"], sc["category"], sc["desc"], "SKIPPED", str(e)))
                continue
            ok = all(not r.allowed for st, r in res if st.get("malicious", True))
            blocked += ok
            reason = next((r.reasons[0] for st, r in res if not r.allowed and r.reasons), "")
            rows.append(("attack", sc["id"], sc["category"], sc["desc"], "BLOCKED" if ok else "MISSED", reason))
            lat += [r.decision_ms for _, r in res]

        false_blocks = 0
        for sc in utility["workflows"]:
            try:
                res = run_scenario(gw, sc)
            except SkipScenario as e:
                skipped.append(sc["id"])
                rows.append(("utility", sc["id"], "workflow", sc["desc"], "SKIPPED", str(e)))
                continue
            ok = all(r.allowed for _, r in res)
            false_blocks += not ok
            reason = next((r.reasons[0] for _, r in res if not r.allowed and r.reasons), "")
            rows.append(("utility", sc["id"], "workflow", sc["desc"], "PASS" if ok else "FALSE BLOCK", reason))
            lat += [r.decision_ms for _, r in res]

        through = 0
        for sc in attacks.get("known_limitations", []):
            res = run_scenario(gw, sc)
            got = all(r.allowed for _, r in res)
            through += got
            rows.append(("limit", sc["id"], sc["category"], sc["desc"], "NOT STOPPED" if got else "stopped", ""))

        # Steady-state latency: allowed decisions on a warm gateway (tool execution excluded).
        token, _ = gw.broker.issue("alice@corp.com", "agent:bench", "local_notes", {})
        gw.execute = False
        steady = [gw.call(token, "fs.list", {"path": "."}).decision_ms for _ in range(a.latency_iters)]
        ok_ledger, ledger_msg = gw.ledger.verify()

    q = statistics.quantiles(steady, n=100)
    n_att = len(attacks["attacks"]) - sum(i.startswith("A") for i in skipped)
    n_util = len(utility["workflows"]) - sum(i.startswith("U") for i in skipped)
    summary = {
        "attacks": n_att, "blocked": blocked, "block_rate": round(blocked / n_att, 4),
        "workflows": n_util, "false_blocks": false_blocks, "false_block_rate": round(false_blocks / n_util, 4),
        "known_limitations": len(attacks.get("known_limitations", [])), "limitations_not_stopped": through,
        "latency_ms": {"p50": round(q[49], 2), "p95": round(q[94], 2), "p99": round(q[98], 2),
                       "iters": a.latency_iters},
        "ledger": ledger_msg, "skipped": skipped,
    }

    if a.json:
        print(json.dumps({"summary": summary, "rows": rows}, indent=2))
    else:
        cur = None
        for kind, sid, cat, desc, res, why in rows:
            if kind != cur:
                cur = kind
                print({"attack": "\nATTACKS", "utility": "\nLEGITIMATE WORKFLOWS",
                       "limit": "\nKNOWN LIMITATIONS (expected to get through)"}[kind])
            print(f"  {sid}  {res:<12} {cat:<17} {desc}" + (f"   [{why}]" if why and kind == "attack" else ""))
            if why and kind == "utility":
                print(f"         reason: {why}")
        s = summary
        print("\nRESULTS")
        print(f"  attacks blocked     {s['blocked']}/{s['attacks']}  ({s['block_rate']:.1%})")
        print(f"  false blocks        {s['false_blocks']}/{s['workflows']}  ({s['false_block_rate']:.1%})")
        print(f"  known limitations   {s['limitations_not_stopped']}/{s['known_limitations']} not stopped (by design)")
        L = s["latency_ms"]
        print(f"  decision latency    p50 {L['p50']} ms   p95 {L['p95']} ms   p99 {L['p99']} ms   (n={L['iters']})")
        print(f"  ledger              {s['ledger']}")
        if skipped:
            print(f"  skipped             {', '.join(skipped)}  (symlinks need Windows Developer Mode)")

    sys.exit(0 if blocked == n_att and false_blocks == 0 and ok_ledger else 1)


if __name__ == "__main__":
    main()
