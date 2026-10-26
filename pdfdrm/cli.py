"""Kommandozeile zur Administration: ``python -m pdfdrm <befehl>``."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import crypto
from .config import Settings
from .service import DrmError, DrmService, LicenseOptions


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _parse_time(value: str | None) -> float | None:
    """Akzeptiert ISO-Datum/-Zeit oder relative Angaben wie ``30d``/``12h``."""
    if not value:
        return None
    units = {"d": "days", "h": "hours", "m": "minutes"}
    if value[-1] in units and value[:-1].isdigit():
        delta = timedelta(**{units[value[-1]]: int(value[:-1])})
        return (datetime.now(timezone.utc) + delta).timestamp()
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pdfdrm", description="PDF DRM Server – Administration")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="Server starten")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    sub.add_parser("admin-key", help="Admin-API-Schlüssel anzeigen")

    s = sub.add_parser("user-add", help="Benutzer anlegen")
    s.add_argument("email")
    s.add_argument("--name", default="")
    s.add_argument("--password", help="Wird sonst interaktiv abgefragt")

    sub.add_parser("user-list", help="Benutzer auflisten")

    s = sub.add_parser("user-disable", help="Benutzer sperren")
    s.add_argument("user_id")

    s = sub.add_parser("doc-add", help="PDF verschlüsselt importieren")
    s.add_argument("path", type=Path)
    s.add_argument("--title")

    sub.add_parser("doc-list", help="Dokumente auflisten")

    s = sub.add_parser("doc-delete", help="Dokument löschen")
    s.add_argument("document_id")

    s = sub.add_parser("grant", help="Lizenz vergeben")
    s.add_argument("user_id")
    s.add_argument("document_id")
    s.add_argument("--from", dest="valid_from", help="ISO-Zeit oder z. B. 1d")
    s.add_argument("--until", dest="valid_until", help="ISO-Zeit oder z. B. 30d")
    s.add_argument("--max-devices", type=int)
    s.add_argument("--max-opens", type=int)
    s.add_argument("--print", dest="allow_print", action="store_true")
    s.add_argument("--download", dest="allow_download", action="store_true")
    s.add_argument("--watermark", dest="watermark_text")

    s = sub.add_parser("revoke", help="Lizenz widerrufen")
    s.add_argument("license_id")

    s = sub.add_parser("license-list", help="Lizenzen auflisten")
    s.add_argument("--user")
    s.add_argument("--document")

    s = sub.add_parser("audit", help="Audit-Log anzeigen")
    s.add_argument("--limit", type=int, default=50)

    sub.add_parser("rotate-master-key", help="Master-Key rotieren (Dokumentschlüssel neu wrappen)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()

    if args.cmd == "serve":
        import uvicorn

        from .app import create_app

        uvicorn.run(create_app(settings), host=args.host, port=args.port)
        return 0

    if args.cmd == "admin-key":
        print(settings.admin_api_key)
        return 0

    svc = DrmService(settings)
    try:
        if args.cmd == "user-add":
            password = args.password or getpass.getpass("Passwort: ")
            _print(svc.create_user(args.email, password, args.name))
        elif args.cmd == "user-list":
            _print(svc.list_users())
        elif args.cmd == "user-disable":
            _print(svc.set_user_active(args.user_id, False))
        elif args.cmd == "doc-add":
            _print(svc.add_document(args.path.read_bytes(), args.path.name, args.title))
        elif args.cmd == "doc-list":
            _print(svc.list_documents())
        elif args.cmd == "doc-delete":
            svc.delete_document(args.document_id)
            print("gelöscht")
        elif args.cmd == "grant":
            _print(
                svc.grant_license(
                    args.user_id,
                    args.document_id,
                    LicenseOptions(
                        valid_from=_parse_time(args.valid_from),
                        valid_until=_parse_time(args.valid_until),
                        max_devices=args.max_devices,
                        max_opens=args.max_opens,
                        allow_print=args.allow_print,
                        allow_download=args.allow_download,
                        watermark_text=args.watermark_text,
                    ),
                )
            )
        elif args.cmd == "revoke":
            _print(svc.revoke_license(args.license_id))
        elif args.cmd == "license-list":
            _print(svc.list_licenses(args.user, args.document))
        elif args.cmd == "audit":
            _print(svc.audit_log(args.limit))
        elif args.cmd == "rotate-master-key":
            return _rotate(svc, settings)
    except DrmError as exc:
        print(f"Fehler ({exc.code}): {exc.message}", file=sys.stderr)
        return 1
    return 0


def _rotate(svc: DrmService, settings: Settings) -> int:
    new_key = crypto.generate_key()
    encoded = base64.b64encode(new_key).decode()
    key_file = settings.data_dir / "master.key"
    from_env = bool(os.environ.get("PDFDRM_MASTER_KEY"))
    if not from_env:
        # Neuen Schlüssel zuerst sichern, damit er bei einem Abbruch nicht verloren geht.
        staged = key_file.with_suffix(".key.new")
        staged.write_text(encoded)
        os.chmod(staged, 0o600)
    count = svc.rotate_master_key(new_key)
    if from_env:
        print(f"{count} Dokumentschlüssel neu gewrappt.")
        print("Neuen Wert jetzt als PDFDRM_MASTER_KEY setzen:")
        print(encoded)
    else:
        os.replace(key_file.with_suffix(".key.new"), key_file)
        print(f"{count} Dokumentschlüssel neu gewrappt, {key_file} aktualisiert.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
