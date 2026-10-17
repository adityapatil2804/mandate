"""Scope templates.

Scope is derived from the human's request (trusted) BEFORE the agent reads any
untrusted data, so injected text can never widen its own grant. Each template
maps a task type plus human-supplied parameters to a minimal grant.
"""

TEMPLATES = {
    # "Summarize these files and email the summary to my team"
    "summarize_and_email": lambda p: [
        {"tool": "fs.read", "constraints": {}},
        {"tool": "fs.list", "constraints": {}},
        {
            "tool": "email.send",
            "constraints": {
                "domains": p["email_domains"],
                "max_calls": p.get("max_emails", 3),
                "max_recipients": p.get("max_recipients", 10),
            },
        },
    ],
    # "Look at the issues in repo X and write a triage report"
    "repo_triage": lambda p: [
        {
            "tool": "http.request",
            "constraints": {
                "domains": p.get("http_domains", ["api.github.com"]),
                "methods": ["GET"],
                "max_calls": p.get("max_requests", 30),
            },
        },
        {"tool": "fs.write", "constraints": {"max_calls": 10}},
        {"tool": "fs.read", "constraints": {}},
    ],
    # "Read this folder and write notes" (no network, no email)
    "local_notes": lambda p: [
        {"tool": "fs.read", "constraints": {}},
        {"tool": "fs.list", "constraints": {}},
        {"tool": "fs.write", "constraints": {"max_calls": 20}},
    ],
}

# Grants whose use should be flagged for step-up approval (stretch goal hook).
HIGH_RISK_TOOLS = {"email.send"}


def derive_scope(template: str, params: dict, task_dir: str) -> list[dict]:
    if template not in TEMPLATES:
        raise ValueError(f"unknown task template: {template}")
    scope = TEMPLATES[template](params)
    tools = [g["tool"] for g in scope]
    if len(tools) != len(set(tools)):
        raise ValueError("template produced duplicate grants")  # policy assumes one grant per tool
    for g in scope:
        if g["tool"].startswith("fs."):
            g["constraints"]["path_prefix"] = task_dir.replace("\\", "/")
    return scope
