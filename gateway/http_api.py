"""HTTP API.  Run: uvicorn gateway.http_api:app --port 8080

POST /v1/tasks              (admin)  issue a task token        {human, agent, template, params, ttl}
POST /v1/tasks/{id}/revoke  (admin)  kill a task immediately
POST /v1/call               (agent)  Authorization: Bearer <task token>   {tool, args}
GET  /v1/ledger/head                 current head hash (publish this externally)
GET  /healthz
"""
import hmac
import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .core import Gateway

gw = Gateway.from_env()
ADMIN_KEY = os.environ.get("MANDATE_ADMIN_KEY", "")


def _admin(req: Request) -> bool:
    # In production this is the human's own login (OIDC). A shared key keeps the demo simple.
    return bool(ADMIN_KEY) and hmac.compare_digest(req.headers.get("x-admin-key", ""), ADMIN_KEY)


async def issue(req: Request):
    if not _admin(req):
        return JSONResponse({"error": "forbidden"}, 403)
    b = await req.json()
    try:
        token, claims = gw.broker.issue(b["human"], b["agent"], b["template"], b.get("params", {}), b.get("ttl"))
    except (KeyError, ValueError) as e:
        return JSONResponse({"error": str(e)}, 400)
    return JSONResponse({"token": token, "claims": claims})


async def revoke(req: Request):
    if not _admin(req):
        return JSONResponse({"error": "forbidden"}, 403)
    gw.broker.revoke(req.path_params["task_id"])
    return JSONResponse({"revoked": req.path_params["task_id"]})


async def call(req: Request):
    auth = req.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        b = await req.json()
        tool, args = b["tool"], b.get("args", {})
    except Exception:
        return JSONResponse({"error": "body must be {tool, args}"}, 400)
    res = gw.call(token, tool, args)
    return JSONResponse(res.to_dict(), 200 if res.allowed else 403)


async def head(req: Request):
    return JSONResponse(gw.ledger.head())


async def health(req: Request):
    return JSONResponse({"ok": True, "policy": gw.policy.version})


app = Starlette(routes=[
    Route("/v1/tasks", issue, methods=["POST"]),
    Route("/v1/tasks/{task_id}/revoke", revoke, methods=["POST"]),
    Route("/v1/call", call, methods=["POST"]),
    Route("/v1/ledger/head", head),
    Route("/healthz", health),
])
