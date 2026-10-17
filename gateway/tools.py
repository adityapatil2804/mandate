"""Tool adapters. Only the gateway runs these, and only the gateway holds the real
credentials (SMTP password, GitHub token). The agent never sees them.
"""
import json
import os
import smtplib
import time
import urllib.request
from email.message import EmailMessage
from pathlib import Path

MAX_READ = 1_000_000


def fs_read(parsed, args):
    p = Path(parsed["path"])
    if not p.is_file():
        return {"error": "not a file"}
    return {"content": p.read_text(errors="replace")[:MAX_READ]}


def fs_list(parsed, args):
    p = Path(parsed["path"])
    if not p.is_dir():
        return {"error": "not a directory"}
    return {"entries": sorted(x.name + ("/" if x.is_dir() else "") for x in p.iterdir())}


def fs_write(parsed, args):
    p = Path(parsed["path"])
    p.parent.mkdir(parents=True, exist_ok=True)
    content = str(args.get("content", ""))
    p.write_text(content)
    return {"written": len(content)}


def email_send(parsed, args):
    to = [r["address"] for r in parsed["recipients"]]
    host = os.environ.get("SMTP_HOST")
    if host:
        msg = EmailMessage()
        msg["From"] = os.environ["SMTP_FROM"]
        msg["To"] = ", ".join(to)
        msg["Subject"] = args.get("subject", "")
        msg.set_content(args.get("body", ""))
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587))) as s:
            s.starttls()
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            s.send_message(msg)
        return {"sent": len(to)}
    # Default: local outbox, so the demo is free and offline.
    outbox = Path(os.environ.get("MANDATE_OUTBOX", "data/outbox.jsonl"))
    outbox.parent.mkdir(parents=True, exist_ok=True)
    with outbox.open("a") as f:
        f.write(json.dumps({"ts": time.time(), "to": to, "subject": args.get("subject", ""),
                            "body": args.get("body", "")}) + "\n")
    return {"sent": len(to), "outbox": str(outbox)}


def http_request(parsed, args):
    if os.environ.get("MANDATE_DRY_HTTP"):
        return {"status": 200, "dry_run": True}
    req = urllib.request.Request(args["url"], method=parsed["method"])
    req.add_header("User-Agent", "mandate-gateway")
    gh = os.environ.get("GITHUB_TOKEN")
    if gh and parsed["host"] == "api.github.com":
        req.add_header("Authorization", f"Bearer {gh}")  # credential injected here, never by the agent
    with urllib.request.urlopen(req, timeout=10) as r:
        return {"status": r.status, "body": r.read(MAX_READ).decode(errors="replace")}


TOOLS = {
    "fs.read": fs_read,
    "fs.list": fs_list,
    "fs.write": fs_write,
    "email.send": email_send,
    "http.request": http_request,
}

TOOL_SCHEMAS = {
    "fs.read": {"path": "string"},
    "fs.list": {"path": "string"},
    "fs.write": {"path": "string", "content": "string"},
    "email.send": {"to": "string|array", "cc": "string|array", "subject": "string", "body": "string"},
    "http.request": {"url": "string", "method": "string"},
}
