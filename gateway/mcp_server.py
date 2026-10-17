"""MCP (stdio) front-end. The agent's MCP client launches this; it holds only the task
token and forwards every tool call to the gateway. No real credentials live here.

    MANDATE_URL=http://localhost:8080 MANDATE_TOKEN=<task token> python -m gateway.mcp_server

Claude Desktop / any MCP client config:
    {"command": "python", "args": ["-m", "gateway.mcp_server"],
     "env": {"MANDATE_URL": "...", "MANDATE_TOKEN": "..."}}
"""
import json
import os
import sys
import urllib.error
import urllib.request

from .tools import TOOL_SCHEMAS

PROTOCOL = "2025-06-18"
URL = os.environ.get("MANDATE_URL", "http://localhost:8080")
TOKEN = os.environ.get("MANDATE_TOKEN", "")

_TYPES = {"string": {"type": "string"},
          "string|array": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}}


def mcp_name(tool: str) -> str:
    return tool.replace(".", "_")


TOOLS_BY_MCP = {mcp_name(t): t for t in TOOL_SCHEMAS}


def tools_list():
    return [{
        "name": mcp_name(t),
        "description": f"{t} (routed through the Mandate gateway; calls outside your task grant are denied)",
        "inputSchema": {"type": "object", "properties": {k: _TYPES[v] for k, v in s.items()}},
    } for t, s in TOOL_SCHEMAS.items()]


def forward(tool: str, args: dict) -> dict:
    req = urllib.request.Request(
        f"{URL}/v1/call", json.dumps({"tool": tool, "args": args}).encode(),
        {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def handle(msg: dict):
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "mandate", "version": "0.1.0"}}
    if method == "tools/list":
        return {"tools": tools_list()}
    if method == "tools/call":
        p = msg.get("params", {})
        tool = TOOLS_BY_MCP.get(p.get("name"))
        if not tool:
            return {"content": [{"type": "text", "text": "unknown tool"}], "isError": True}
        r = forward(tool, p.get("arguments", {}))
        if r.get("allowed"):
            return {"content": [{"type": "text", "text": json.dumps(r.get("result"))}]}
        return {"content": [{"type": "text", "text": "DENIED by Mandate: " + "; ".join(r.get("reasons", []))}],
                "isError": True}
    if method == "ping":
        return {}
    if mid is None:  # notification
        return None
    raise LookupError(method)


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        try:
            result = handle(msg)
            if msg.get("id") is None:
                continue
            out = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        except LookupError as e:
            out = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": f"method not found: {e}"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
