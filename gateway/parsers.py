"""Turn raw tool arguments into the structured, trusted facts the policy sees.

Anything ambiguous is rejected here (fail closed) instead of being passed to the
policy as a string to interpret.
"""
import os
import re
from urllib.parse import urlsplit


class ParseError(Exception):
    pass


_EMAIL = re.compile(r"^[a-z0-9._%+\-]+@([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)$")
_HOST = re.compile(r"^[a-z0-9.\-]+$")


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        return [s for s in re.split(r"[,;]", v) if s.strip()]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    raise ParseError("recipients must be a string or list of strings")


def parse_email(args: dict) -> dict:
    raw = _as_list(args.get("to")) + _as_list(args.get("cc")) + _as_list(args.get("bcc"))
    if not raw:
        raise ParseError("no recipients")
    recipients = []
    for addr in raw:
        a = addr.strip().lower()
        m = _EMAIL.match(a)
        if not m:
            # catches "Name <x@evil.com>", "a@b@c", quoted locals, unicode homoglyphs, etc.
            raise ParseError(f"unparseable recipient: {addr!r}")
        recipients.append({"address": a, "domain": m.group(1)})
    subject = args.get("subject", "")
    if not isinstance(subject, str) or "\r" in subject or "\n" in subject:
        raise ParseError("invalid subject (header injection)")
    body = args.get("body", "")
    if isinstance(body, (int, float)) and not isinstance(body, bool):
        args["body"] = str(body)  # models sometimes emit bare numbers; harmless to coerce
    elif not isinstance(body, str):
        raise ParseError("body must be a string")
    return {"recipients": recipients}


def parse_fs(args: dict, task_dir: str) -> dict:
    path = args.get("path", ".")
    if not isinstance(path, str) or "\x00" in path:
        raise ParseError("invalid path")
    # realpath resolves "..", and follows symlinks, so links pointing outside are caught.
    resolved = os.path.realpath(os.path.join(task_dir, path))
    return {"path": resolved.replace("\\", "/")}  # one separator style, so Windows paths match the grant


def parse_http(args: dict) -> dict:
    url = args.get("url")
    if not isinstance(url, str):
        raise ParseError("url required")
    method = str(args.get("method", "GET")).upper()
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError as e:
        raise ParseError(f"bad url: {e}") from e
    if u.username or u.password:
        raise ParseError("credentials in url not allowed")
    host = (u.hostname or "").rstrip(".").lower()
    if not host or not _HOST.match(host):
        raise ParseError(f"bad host: {u.hostname!r}")
    if port not in (None, 443):
        raise ParseError(f"port {port} not allowed")
    return {"host": host, "scheme": u.scheme.lower(), "method": method, "path": u.path}


def parse(tool: str, args: dict, task_dir: str) -> dict:
    if not isinstance(args, dict):
        raise ParseError("args must be an object")
    if tool == "email.send":
        return parse_email(args)
    if tool in ("fs.read", "fs.write", "fs.list"):
        return parse_fs(args, task_dir)
    if tool == "http.request":
        return parse_http(args)
    raise ParseError(f"unknown tool {tool}")
