"""The enforcement point. Every tool call goes: verify token -> parse args -> policy
-> execute with real credentials -> ledger. Any failure before execution is a deny.
"""
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from .broker import Broker, TokenError
from .keys import load_or_create
from .ledger import Ledger, args_hash
from .parsers import ParseError, parse
from .policy import PolicyClient
from .tools import TOOLS


@dataclass
class CallResult:
    allowed: bool
    reasons: list[str]
    result: dict | None = None
    decision_ms: float = 0.0
    seq: int = 0

    def to_dict(self):
        return {"allowed": self.allowed, "reasons": self.reasons, "result": self.result,
                "decision_ms": round(self.decision_ms, 3), "ledger_seq": self.seq}


@dataclass
class Gateway:
    broker: Broker
    policy: PolicyClient
    ledger: Ledger
    execute: bool = True
    usage: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def from_env(cls):
        data = os.environ.get("MANDATE_DATA", "data")
        ws = os.path.realpath(os.environ.get("MANDATE_WORKSPACE", os.path.join(data, "workspace")))
        os.makedirs(ws, exist_ok=True)
        return cls(
            broker=Broker(load_or_create(os.path.join(data, "keys/token.pem")), ws),
            policy=PolicyClient(os.environ.get("OPA_URL", "http://127.0.0.1:8181"),
                                os.environ.get("MANDATE_POLICY_DIR", "policies")),
            ledger=Ledger(os.path.join(data, "ledger.jsonl"), load_or_create(os.path.join(data, "keys/ledger.pem"))),
        )

    def call(self, token: str, tool: str, args: dict) -> CallResult:
        t0 = time.perf_counter()
        raw_hash = args_hash(args)  # hash what the agent actually sent, before normalization
        args = dict(args) if isinstance(args, dict) else args
        claims, reasons, allowed = None, [], False
        try:
            claims = self.broker.verify(token)
            if tool not in TOOLS:
                raise ParseError(f"unknown tool {tool}")
            parsed = parse(tool, args, self.broker.task_dir(claims["task"]))
            # Read budget, decide, and reserve budget atomically so concurrent calls can't overshoot.
            with self._lock:
                allowed, reasons = self.policy.decide({
                    "token": claims, "tool": tool, "parsed": parsed,
                    "usage": dict(self.usage[claims["task"]]), "now": int(time.time()),
                })
                if allowed:
                    self.usage[claims["task"]][tool] += 1
        except (TokenError, ParseError) as e:
            allowed, reasons = False, [str(e)]

        decision_ms = (time.perf_counter() - t0) * 1000

        rec = self.ledger.append(
            task=claims["task"] if claims else None,
            sub=claims["sub"] if claims else None,
            act=claims["act"]["sub"] if claims else None,
            tool=tool, args_hash=raw_hash,
            decision="ALLOW" if allowed else "DENY",
            reasons=reasons, policy=self.policy.version,
        )
        res = CallResult(allowed, reasons, None, decision_ms, rec["seq"])
        if allowed and self.execute:
            try:
                res.result = TOOLS[tool](parsed, args)
            except Exception as e:
                res.result = {"error": f"tool failed: {type(e).__name__}: {e}"}
        return res
