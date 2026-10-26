"""Geschäftslogik: Benutzer, Dokumente, Lizenzen, Geräte.

Wird von der HTTP-API und der CLI gemeinsam genutzt.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any

from . import crypto, render
from .config import Settings
from .db import Database, new_id


class DrmError(Exception):
    """Fachlicher Fehler mit maschinenlesbarem Code."""

    status = 400

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class NotFound(DrmError):
    status = 404


class Forbidden(DrmError):
    status = 403


class Unauthorized(DrmError):
    status = 401


class Conflict(DrmError):
    status = 409


@dataclass
class LicenseOptions:
    valid_from: float | None = None
    valid_until: float | None = None
    max_devices: int | None = None
    max_opens: int | None = None
    allow_print: bool = False
    allow_download: bool = False
    watermark_text: str | None = None


def _public_user(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row[k] for k in ("id", "email", "name", "active", "created_at")}


def _public_document(row: dict[str, Any]) -> dict[str, Any]:
    return {
        k: row[k]
        for k in ("id", "title", "filename", "page_count", "size_bytes", "sha256", "created_at")
    }


class DrmService:
    def __init__(self, settings: Settings, db: Database | None = None):
        self.settings = settings
        self.db = db or Database(settings.db_path)
        settings.storage_dir.mkdir(parents=True, exist_ok=True)

    # --- Benutzer -----------------------------------------------------------

    def create_user(self, email: str, password: str, name: str = "") -> dict[str, Any]:
        email = email.strip()
        if "@" not in email:
            raise DrmError("invalid_email", "Ungültige E-Mail-Adresse")
        if len(password) < 8:
            raise DrmError("weak_password", "Passwort muss mindestens 8 Zeichen haben")
        if self.db.one("SELECT 1 FROM users WHERE email = ?", (email,)):
            raise Conflict("user_exists", "Benutzer existiert bereits")
        user_id = new_id()
        self.db.execute(
            "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, email, name, crypto.hash_password(password), time.time()),
        )
        self.db.audit("user.created", user_id=user_id)
        return self.get_user(user_id)

    def get_user(self, user_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not row:
            raise NotFound("user_not_found", "Benutzer nicht gefunden")
        return _public_user(row)

    def list_users(self) -> list[dict[str, Any]]:
        return [_public_user(r) for r in self.db.all("SELECT * FROM users ORDER BY created_at")]

    def set_user_active(self, user_id: str, active: bool) -> dict[str, Any]:
        self.get_user(user_id)
        self.db.execute("UPDATE users SET active = ? WHERE id = ?", (int(active), user_id))
        self.db.audit("user.activated" if active else "user.deactivated", user_id=user_id)
        return self.get_user(user_id)

    def set_password(self, user_id: str, password: str) -> None:
        if len(password) < 8:
            raise DrmError("weak_password", "Passwort muss mindestens 8 Zeichen haben")
        self.get_user(user_id)
        self.db.execute(
            "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = 0 WHERE id = ?",
            (crypto.hash_password(password), user_id),
        )
        self.db.audit("user.password_changed", user_id=user_id)

    def authenticate(self, email: str, password: str, ip: str | None = None) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM users WHERE email = ?", (email.strip(),))
        now = time.time()
        if not row:
            # Konstante Laufzeit annähern, um Benutzer-Enumeration zu erschweren.
            crypto.verify_password(password, crypto.hash_password("dummy-password"))
            raise Unauthorized("invalid_credentials", "E-Mail oder Passwort falsch")
        if row["locked_until"] > now:
            self.db.audit("auth.locked", user_id=row["id"], ip=ip)
            raise Unauthorized("account_locked", "Zu viele Fehlversuche, bitte später erneut")
        if not crypto.verify_password(password, row["password_hash"]):
            failures = row["failed_logins"] + 1
            locked_until = 0.0
            if failures >= self.settings.login_max_failures:
                locked_until = now + self.settings.login_lockout_seconds
                failures = 0
            self.db.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (failures, locked_until, row["id"]),
            )
            self.db.audit("auth.failed", user_id=row["id"], ip=ip)
            raise Unauthorized("invalid_credentials", "E-Mail oder Passwort falsch")
        if not row["active"]:
            self.db.audit("auth.inactive", user_id=row["id"], ip=ip)
            raise Forbidden("user_inactive", "Benutzerkonto ist deaktiviert")
        self.db.execute(
            "UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (row["id"],)
        )
        self.db.audit("auth.login", user_id=row["id"], ip=ip)
        return _public_user(row)

    def require_active_user(self, user_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not row or not row["active"]:
            raise Unauthorized("user_inactive", "Benutzerkonto ist nicht aktiv")
        return _public_user(row)

    # --- Dokumente ----------------------------------------------------------

    def _blob_path(self, doc_id: str):
        return self.settings.storage_dir / f"{doc_id}.bin"

    def add_document(self, data: bytes, filename: str, title: str | None = None) -> dict[str, Any]:
        page_count = render.inspect_pdf(data)
        doc_id = new_id()
        dek = crypto.generate_key()
        blob = crypto.encrypt(dek, data, b"doc:" + doc_id.encode())
        wrapped = crypto.wrap_key(self.settings.master_key, dek, doc_id)

        path = self._blob_path(doc_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, path)

        self.db.execute(
            "INSERT INTO documents (id, title, filename, page_count, size_bytes, sha256,"
            " wrapped_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                doc_id,
                title or filename,
                filename,
                page_count,
                len(data),
                hashlib.sha256(data).hexdigest(),
                wrapped,
                time.time(),
            ),
        )
        self.db.audit("document.added", document_id=doc_id, detail=filename)
        return self.get_document(doc_id)

    def get_document(self, doc_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM documents WHERE id = ?", (doc_id,))
        if not row:
            raise NotFound("document_not_found", "Dokument nicht gefunden")
        return _public_document(row)

    def list_documents(self) -> list[dict[str, Any]]:
        return [
            _public_document(r) for r in self.db.all("SELECT * FROM documents ORDER BY created_at")
        ]

    def delete_document(self, doc_id: str) -> None:
        self.get_document(doc_id)
        self.db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        self._blob_path(doc_id).unlink(missing_ok=True)
        self.db.audit("document.deleted", document_id=doc_id)

    def load_plaintext(self, doc_id: str) -> bytes:
        """Entschlüsselt ein Dokument – nur im Speicher, nie auf Platte."""
        row = self.db.one("SELECT wrapped_key FROM documents WHERE id = ?", (doc_id,))
        if not row:
            raise NotFound("document_not_found", "Dokument nicht gefunden")
        dek = crypto.unwrap_key(self.settings.master_key, row["wrapped_key"], doc_id)
        return crypto.decrypt(dek, self._blob_path(doc_id).read_bytes(), b"doc:" + doc_id.encode())

    def rotate_master_key(self, new_master_key: bytes) -> int:
        """Wrappt alle Dokumentschlüssel mit einem neuen Master-Key neu."""
        if len(new_master_key) != crypto.KEY_SIZE:
            raise DrmError("invalid_key", "Master-Key muss 32 Bytes lang sein")
        count = 0
        with self.db.transaction() as conn:
            for row in conn.execute("SELECT id, wrapped_key FROM documents").fetchall():
                dek = crypto.unwrap_key(self.settings.master_key, row["wrapped_key"], row["id"])
                conn.execute(
                    "UPDATE documents SET wrapped_key = ? WHERE id = ?",
                    (crypto.wrap_key(new_master_key, dek, row["id"]), row["id"]),
                )
                count += 1
        self.settings.master_key = new_master_key
        self.db.audit("system.master_key_rotated", detail=str(count))
        return count

    # --- Lizenzen -----------------------------------------------------------

    def grant_license(self, user_id: str, document_id: str, opts: LicenseOptions) -> dict[str, Any]:
        self.get_user(user_id)
        self.get_document(document_id)
        if opts.valid_from and opts.valid_until and opts.valid_until <= opts.valid_from:
            raise DrmError("invalid_period", "valid_until muss nach valid_from liegen")
        for field_name in ("max_devices", "max_opens"):
            value = getattr(opts, field_name)
            if value is not None and value < 1:
                raise DrmError("invalid_limit", f"{field_name} muss >= 1 sein")
        lic_id = new_id()
        self.db.execute(
            "INSERT INTO licenses (id, user_id, document_id, valid_from, valid_until, max_devices,"
            " max_opens, allow_print, allow_download, watermark_text, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                lic_id,
                user_id,
                document_id,
                opts.valid_from,
                opts.valid_until,
                opts.max_devices,
                opts.max_opens,
                int(opts.allow_print),
                int(opts.allow_download),
                opts.watermark_text,
                time.time(),
            ),
        )
        self.db.audit("license.granted", user_id=user_id, document_id=document_id, license_id=lic_id)
        return self.get_license(lic_id)

    def get_license(self, lic_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM licenses WHERE id = ?", (lic_id,))
        if not row:
            raise NotFound("license_not_found", "Lizenz nicht gefunden")
        row["devices"] = self.db.all(
            "SELECT device_id, first_seen, last_seen FROM license_devices WHERE license_id = ?"
            " ORDER BY first_seen",
            (lic_id,),
        )
        row["allow_print"] = bool(row["allow_print"])
        row["allow_download"] = bool(row["allow_download"])
        row["revoked"] = bool(row["revoked"])
        return row

    def list_licenses(
        self, user_id: str | None = None, document_id: str | None = None
    ) -> list[dict[str, Any]]:
        sql, params = "SELECT id FROM licenses WHERE 1=1", []
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        if document_id:
            sql += " AND document_id = ?"
            params.append(document_id)
        sql += " ORDER BY created_at"
        return [self.get_license(r["id"]) for r in self.db.all(sql, tuple(params))]

    def update_license(self, lic_id: str, **changes: Any) -> dict[str, Any]:
        allowed = {
            "valid_from",
            "valid_until",
            "max_devices",
            "max_opens",
            "allow_print",
            "allow_download",
            "watermark_text",
        }
        changes = {k: v for k, v in changes.items() if k in allowed}
        self.get_license(lic_id)
        if changes:
            cols = ", ".join(f"{k} = ?" for k in changes)
            values = [int(v) if isinstance(v, bool) else v for v in changes.values()]
            self.db.execute(f"UPDATE licenses SET {cols} WHERE id = ?", (*values, lic_id))
            self.db.audit("license.updated", license_id=lic_id, detail=",".join(sorted(changes)))
        return self.get_license(lic_id)

    def revoke_license(self, lic_id: str) -> dict[str, Any]:
        self.get_license(lic_id)
        self.db.execute(
            "UPDATE licenses SET revoked = 1, revoked_at = ? WHERE id = ?", (time.time(), lic_id)
        )
        self.db.audit("license.revoked", license_id=lic_id)
        return self.get_license(lic_id)

    def remove_device(self, lic_id: str, device_id: str) -> dict[str, Any]:
        self.db.execute(
            "DELETE FROM license_devices WHERE license_id = ? AND device_id = ?",
            (lic_id, device_id),
        )
        self.db.audit("license.device_removed", license_id=lic_id, device_id=device_id)
        return self.get_license(lic_id)

    def library(self, user_id: str) -> list[dict[str, Any]]:
        now = time.time()
        rows = self.db.all(
            "SELECT l.*, d.title, d.page_count FROM licenses l JOIN documents d"
            " ON d.id = l.document_id WHERE l.user_id = ? AND l.revoked = 0"
            " ORDER BY d.title",
            (user_id,),
        )
        result = []
        for r in rows:
            if r["valid_until"] is not None and r["valid_until"] < now:
                continue
            result.append(
                {
                    "license_id": r["id"],
                    "document_id": r["document_id"],
                    "title": r["title"],
                    "page_count": r["page_count"],
                    "valid_from": r["valid_from"],
                    "valid_until": r["valid_until"],
                    "max_opens": r["max_opens"],
                    "open_count": r["open_count"],
                    "allow_print": bool(r["allow_print"]),
                    "allow_download": bool(r["allow_download"]),
                }
            )
        return result

    # --- Lizenzprüfung ------------------------------------------------------

    @staticmethod
    def _check_validity(lic: dict[str, Any], now: float) -> None:
        if lic["revoked"]:
            raise Forbidden("license_revoked", "Lizenz wurde widerrufen")
        if lic["valid_from"] is not None and now < lic["valid_from"]:
            raise Forbidden("license_not_yet_valid", "Lizenz ist noch nicht gültig")
        if lic["valid_until"] is not None and now > lic["valid_until"]:
            raise Forbidden("license_expired", "Lizenz ist abgelaufen")

    def _find_license(self, user_id: str, document_id: str, conn) -> dict[str, Any]:
        """Wählt die "beste" aktive Lizenz eines Benutzers für ein Dokument."""
        rows = conn.execute(
            "SELECT * FROM licenses WHERE user_id = ? AND document_id = ? AND revoked = 0"
            " ORDER BY (valid_until IS NULL) DESC, valid_until DESC",
            (user_id, document_id),
        ).fetchall()
        now = time.time()
        last_error: DrmError = Forbidden("no_license", "Keine Lizenz für dieses Dokument")
        for row in rows:
            lic = dict(row)
            try:
                self._check_validity(lic, now)
                if lic["max_opens"] is not None and lic["open_count"] >= lic["max_opens"]:
                    raise Forbidden("open_limit_reached", "Maximale Anzahl Öffnungen erreicht")
                return lic
            except DrmError as exc:
                last_error = exc
        raise last_error

    def open_document(
        self, user_id: str, document_id: str, device_id: str, ip: str | None = None
    ) -> dict[str, Any]:
        """Prüft Lizenz, bindet das Gerät und zählt die Öffnung.

        Läuft in einer Transaktion, damit parallele Öffnungen keine Limits
        umgehen können.
        """
        if not device_id or len(device_id) > 128:
            raise DrmError("invalid_device", "Ungültige Geräte-ID")
        self.require_active_user(user_id)
        now = time.time()
        try:
            with self.db.transaction() as conn:
                lic = self._find_license(user_id, document_id, conn)
                known = conn.execute(
                    "SELECT 1 FROM license_devices WHERE license_id = ? AND device_id = ?",
                    (lic["id"], device_id),
                ).fetchone()
                if known:
                    conn.execute(
                        "UPDATE license_devices SET last_seen = ? WHERE license_id = ? AND device_id = ?",
                        (now, lic["id"], device_id),
                    )
                else:
                    if lic["max_devices"] is not None:
                        (count,) = conn.execute(
                            "SELECT COUNT(*) FROM license_devices WHERE license_id = ?",
                            (lic["id"],),
                        ).fetchone()
                        if count >= lic["max_devices"]:
                            raise Forbidden(
                                "device_limit_reached", "Maximale Anzahl Geräte erreicht"
                            )
                    conn.execute(
                        "INSERT INTO license_devices (license_id, device_id, first_seen, last_seen)"
                        " VALUES (?, ?, ?, ?)",
                        (lic["id"], device_id, now, now),
                    )
                conn.execute(
                    "UPDATE licenses SET open_count = open_count + 1 WHERE id = ?", (lic["id"],)
                )
        except DrmError as exc:
            self.db.audit(
                "document.open_denied",
                user_id=user_id,
                document_id=document_id,
                device_id=device_id,
                ip=ip,
                detail=exc.code,
            )
            raise
        self.db.audit(
            "document.opened",
            user_id=user_id,
            document_id=document_id,
            license_id=lic["id"],
            device_id=device_id,
            ip=ip,
        )
        return self.get_license(lic["id"])

    def validate_session_license(
        self, license_id: str, user_id: str, document_id: str, device_id: str
    ) -> dict[str, Any]:
        """Prüft bei jedem Seitenabruf erneut, ob die Lizenz noch gilt.

        Dadurch wirken Widerruf, Ablauf, Benutzer-Sperre und Geräte-Entfernung
        sofort – nicht erst beim nächsten Öffnen.
        """
        self.require_active_user(user_id)
        lic = self.db.one("SELECT * FROM licenses WHERE id = ?", (license_id,))
        if not lic or lic["user_id"] != user_id or lic["document_id"] != document_id:
            raise Forbidden("no_license", "Keine Lizenz für dieses Dokument")
        self._check_validity(lic, time.time())
        if not self.db.one(
            "SELECT 1 FROM license_devices WHERE license_id = ? AND device_id = ?",
            (license_id, device_id),
        ):
            raise Forbidden("device_not_authorized", "Gerät ist nicht (mehr) freigeschaltet")
        return lic

    def watermark_for(self, lic: dict[str, Any], user: dict[str, Any]) -> render.Watermark:
        stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        lines = [lic.get("watermark_text") or user["email"], f"Lizenz {lic['id'][:8]}", stamp]
        return render.Watermark(tuple(lines), opacity=self.settings.watermark_opacity)

    def audit_log(
        self, limit: int = 200, user_id: str | None = None, document_id: str | None = None
    ) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM audit_log WHERE 1=1", []
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        if document_id:
            sql += " AND document_id = ?"
            params.append(document_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        return self.db.all(sql, tuple(params))
