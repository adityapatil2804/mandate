"""Delegation broker: issues short-lived, task-scoped tokens and tracks revocation.

Claims follow OAuth 2.0 Token Exchange (RFC 8693): `sub` is the delegating human,
`act.sub` is the acting agent.
"""
import secrets
import time

import jwt

from .templates import derive_scope

ISSUER = "mandate-broker"


class TokenError(Exception):
    pass


class Broker:
    def __init__(self, signing_key, workspace_root: str, default_ttl: int = 3600):
        self._key = signing_key
        self._pub = signing_key.public_key()
        self.workspace_root = workspace_root
        self.default_ttl = default_ttl
        self._revoked: set[str] = set()
        self._tasks: dict[str, dict] = {}

    def issue(self, human: str, agent: str, template: str, params: dict | None = None,
              ttl: int | None = None, task_dir: str | None = None) -> tuple[str, dict]:
        task_id = "t_" + secrets.token_hex(4)
        if task_dir is None:
            import os
            task_dir = os.path.realpath(os.path.join(self.workspace_root, task_id))
            os.makedirs(task_dir, exist_ok=True)
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": human,
            "act": {"sub": agent},
            "task": task_id,
            "template": template,
            "scope": derive_scope(template, params or {}, task_dir),
            "iat": now,
            "exp": now + (ttl or self.default_ttl),
            "jti": secrets.token_hex(8),
        }
        token = jwt.encode(claims, self._key, algorithm="EdDSA")
        self._tasks[task_id] = {"claims": claims, "task_dir": task_dir}
        return token, claims

    def verify(self, token: str) -> dict:
        try:
            claims = jwt.decode(
                token, self._pub, algorithms=["EdDSA"], issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "task", "scope"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise TokenError("token expired") from e
        except jwt.InvalidTokenError as e:
            raise TokenError(f"invalid token: {e}") from e
        if claims["task"] in self._revoked:
            raise TokenError("task revoked")
        if claims["task"] not in self._tasks:
            raise TokenError("unknown task")
        return claims

    def revoke(self, task_id: str) -> None:
        self._revoked.add(task_id)

    def task_dir(self, task_id: str) -> str:
        return self._tasks[task_id]["task_dir"]
