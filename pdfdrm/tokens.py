"""Kurzlebige signierte Tokens (JWT, HS256) und Rate-Limiting."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

import jwt

from .db import new_id
from .service import Unauthorized

ISSUER = "pdfdrm"


class TokenIssuer:
    def __init__(self, secret: bytes):
        self._secret = secret

    def _encode(self, claims: dict[str, Any], ttl: int) -> str:
        now = int(time.time())
        payload = {"iss": ISSUER, "iat": now, "exp": now + ttl, "jti": new_id(), **claims}
        return jwt.encode(payload, self._secret, algorithm="HS256")

    def decode(self, token: str, expected_type: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=ISSUER,
                options={"require": ["exp", "iat", "iss", "sub", "typ"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise Unauthorized("token_expired", "Token abgelaufen") from exc
        except jwt.PyJWTError as exc:
            raise Unauthorized("invalid_token", "Ungültiges Token") from exc
        if claims.get("typ") != expected_type:
            raise Unauthorized("invalid_token", "Falscher Token-Typ")
        return claims

    def access_token(self, user_id: str, ttl: int) -> str:
        return self._encode({"sub": user_id, "typ": "access"}, ttl)

    def view_token(
        self, user_id: str, license_id: str, document_id: str, device_id: str, sid: str, ttl: int
    ) -> str:
        return self._encode(
            {
                "sub": user_id,
                "typ": "view",
                "lic": license_id,
                "doc": document_id,
                "dev": device_id,
                "sid": sid,
            },
            ttl,
        )


class RateLimiter:
    """Sliding-Window-Limiter im Speicher (pro Prozess).

    Begrenzt, wie schnell eine Sitzung Seiten abrufen kann, und erschwert so
    das automatisierte "Abgrasen" ganzer Dokumente.
    """

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10_000:
                self._gc(now)
            return True

    def _gc(self, now: float) -> None:
        for key in [k for k, q in self._hits.items() if not q or q[-1] <= now - self.window]:
            del self._hits[key]
