"""OPA client. Fails closed: any error, timeout or malformed answer is a deny."""
import hashlib
import http.client
import json
import threading
from pathlib import Path
from urllib.parse import urlsplit


class PolicyClient:
    def __init__(self, opa_url: str, policy_dir: str | None = None, timeout: float = 0.5):
        u = urlsplit(opa_url)
        self.host, self.port = u.hostname, u.port or 8181
        self.timeout = timeout
        self.version = self._version(policy_dir)
        self._local = threading.local()

    @staticmethod
    def _version(policy_dir):
        if not policy_dir:
            return "unknown"
        h = hashlib.sha256()
        for p in sorted(Path(policy_dir).glob("*.rego")):
            if not p.name.endswith("_test.rego"):
                h.update(p.read_bytes())
        return h.hexdigest()[:12]

    def decide(self, inp: dict) -> tuple[bool, list[str]]:
        try:
            status, body = self._post(json.dumps({"input": inp}))
            if status != 200:
                return False, [f"policy engine error (HTTP {status})"]
            d = body.get("result")
            if not isinstance(d, dict) or not isinstance(d.get("allow"), bool):
                return False, ["policy engine returned no decision"]
            return d["allow"] is True, list(d.get("reasons", []))
        except Exception as e:  # fail closed
            return False, [f"policy engine unavailable: {type(e).__name__}"]

    def _post(self, payload: str):
        """Reuse one keep-alive connection per thread (a new TCP connect per call costs ~15 ms on Windows).
        If a reused connection went stale, reconnect once."""
        for attempt in (0, 1):
            conn = getattr(self._local, "conn", None)
            if conn is None:
                conn = self._local.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            try:
                conn.request("POST", "/v1/data/mandate/decision", payload, {"Content-Type": "application/json"})
                resp = conn.getresponse()
                return resp.status, json.loads(resp.read())
            except (http.client.HTTPException, ConnectionError, OSError):
                conn.close()
                self._local.conn = None
                if attempt:
                    raise
