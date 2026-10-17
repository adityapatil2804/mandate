"""Append-only audit ledger: hash-chained JSONL, every record Ed25519-signed.

Tamper-evident, not tamper-proof: someone holding the ledger key can rewrite
the whole chain. Mitigation: periodically publish the head hash somewhere
external (see `head()`), e.g. a transparency log or a Git commit.
"""
import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def args_hash(args) -> str:
    return hashlib.sha256(canonical(args)).hexdigest()


class Ledger:
    def __init__(self, path, signing_key):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._key = signing_key
        self._pub = signing_key.public_key()
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()
        # Keep one handle open: reopening per record is slow on Windows (antivirus scans each open).
        self._fh = self.path.open("a", encoding="utf-8")

    def _tail(self):
        seq, prev = 0, GENESIS
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    seq, prev = r["seq"], r["hash"]
        return seq, prev

    def append(self, **fields) -> dict:
        with self._lock:
            body = {"seq": self._seq + 1, "ts": round(time.time(), 3), **fields, "prev_hash": self._prev}
            h = hashlib.sha256(canonical(body)).hexdigest()
            rec = {**body, "hash": h, "sig": self._key.sign(bytes.fromhex(h)).hex()}
            self._fh.write(json.dumps(rec, sort_keys=True) + "\n")
            self._fh.flush()
            self._seq, self._prev = rec["seq"], h
            return rec

    def head(self) -> dict:
        return {"seq": self._seq, "hash": self._prev}

    def records(self, task: str | None = None):
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    if task is None or r.get("task") == task:
                        yield r

    def verify(self) -> tuple[bool, str]:
        """Recompute every hash, check every signature and every back-link."""
        prev, expected_seq = GENESIS, 1
        for r in self.records():
            body = {k: v for k, v in r.items() if k not in ("hash", "sig")}
            if r["seq"] != expected_seq:
                return False, f"sequence gap at seq {r['seq']} (expected {expected_seq})"
            if body["prev_hash"] != prev:
                return False, f"broken chain at seq {r['seq']}"
            if hashlib.sha256(canonical(body)).hexdigest() != r["hash"]:
                return False, f"record modified at seq {r['seq']}"
            try:
                self._pub.verify(bytes.fromhex(r["sig"]), bytes.fromhex(r["hash"]))
            except Exception:
                return False, f"bad signature at seq {r['seq']}"
            prev, expected_seq = r["hash"], expected_seq + 1
        return True, f"ok: {expected_seq - 1} records, head {prev[:12]}"
