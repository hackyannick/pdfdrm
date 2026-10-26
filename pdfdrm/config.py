"""Konfiguration über Umgebungsvariablen (Präfix ``PDFDRM_``)."""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"PDFDRM_{name}", default)


def _load_or_create_secret(path: Path, nbytes: int) -> bytes:
    """Liest ein Secret aus einer Datei oder legt es (nur für Entwicklung) an."""
    if path.exists():
        return base64.b64decode(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_bytes(nbytes)
    path.write_text(base64.b64encode(value).decode())
    os.chmod(path, 0o600)
    return value


@dataclass
class Settings:
    data_dir: Path
    master_key: bytes
    jwt_secret: bytes
    admin_api_key: str
    access_token_ttl: int = 3600
    view_session_ttl: int = 1800
    max_pages_per_minute: int = 60
    max_render_scale: float = 3.0
    watermark_opacity: int = 60
    login_max_failures: int = 5
    login_lockout_seconds: int = 300

    @property
    def db_path(self) -> Path:
        return self.data_dir / "pdfdrm.sqlite3"

    @property
    def storage_dir(self) -> Path:
        return self.data_dir / "documents"

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(_env("DATA_DIR", "./data")).resolve()

        raw_master = _env("MASTER_KEY")
        master_key = (
            base64.b64decode(raw_master)
            if raw_master
            else _load_or_create_secret(data_dir / "master.key", 32)
        )
        if len(master_key) != 32:
            raise ValueError("PDFDRM_MASTER_KEY muss 32 Bytes (base64-kodiert) lang sein")

        raw_jwt = _env("JWT_SECRET")
        jwt_secret = (
            raw_jwt.encode() if raw_jwt else _load_or_create_secret(data_dir / "jwt.key", 32)
        )

        admin_api_key = _env("ADMIN_API_KEY")
        if not admin_api_key:
            key_file = data_dir / "admin_api.key"
            admin_api_key = base64.urlsafe_b64encode(
                _load_or_create_secret(key_file, 32)
            ).decode().rstrip("=")

        return cls(
            data_dir=data_dir,
            master_key=master_key,
            jwt_secret=jwt_secret,
            admin_api_key=admin_api_key,
            access_token_ttl=int(_env("ACCESS_TOKEN_TTL", "3600")),
            view_session_ttl=int(_env("VIEW_SESSION_TTL", "1800")),
            max_pages_per_minute=int(_env("MAX_PAGES_PER_MINUTE", "60")),
            max_render_scale=float(_env("MAX_RENDER_SCALE", "3.0")),
            watermark_opacity=int(_env("WATERMARK_OPACITY", "60")),
            login_max_failures=int(_env("LOGIN_MAX_FAILURES", "5")),
            login_lockout_seconds=int(_env("LOGIN_LOCKOUT_SECONDS", "300")),
        )
