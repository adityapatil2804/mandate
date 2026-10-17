"""Shared test/benchmark harness: starts a throwaway OPA server and builds a Gateway
in a temp directory, so runs are isolated and repeatable.
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from gateway.broker import Broker
from gateway.core import Gateway
from gateway.keys import load_or_create
from gateway.ledger import Ledger
from gateway.policy import PolicyClient

ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = ROOT / "policies"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class OPA:
    def __init__(self):
        self.bin = os.environ.get("OPA_BIN") or shutil.which("opa") or "/tmp/opa"
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc = None

    def __enter__(self):
        policies = [str(p) for p in POLICY_DIR.glob("*.rego") if not p.name.endswith("_test.rego")]
        self.proc = subprocess.Popen(
            [self.bin, "run", "--server", "--addr", f"127.0.0.1:{self.port}", "--log-level", "error", *policies],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            try:
                opener.open(self.url + "/health", timeout=0.2)
                return self
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("OPA did not start")

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait()


def make_gateway(opa_url: str, data_dir: str | None = None) -> Gateway:
    data = Path(data_dir or tempfile.mkdtemp(prefix="mandate-"))
    ws = data / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MANDATE_DRY_HTTP", "1")
    os.environ["MANDATE_OUTBOX"] = str(data / "outbox.jsonl")
    return Gateway(
        broker=Broker(load_or_create(data / "keys/token.pem"), os.path.realpath(ws)),
        policy=PolicyClient(opa_url, str(POLICY_DIR)),
        ledger=Ledger(data / "ledger.jsonl", load_or_create(data / "keys/ledger.pem")),
    )
