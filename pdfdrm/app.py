"""HTTP-API und Web-Viewer (FastAPI)."""

import hmac
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import render
from .config import Settings
from .db import new_id
from .service import DrmError, DrmService, Forbidden, LicenseOptions, NotFound, Unauthorized
from .tokens import RateLimiter, TokenIssuer

STATIC_DIR = Path(__file__).parent / "static"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024

NO_STORE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
}


# --- Request-Modelle --------------------------------------------------------


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)
    name: str = ""


class UserUpdate(BaseModel):
    active: bool | None = None
    password: str | None = Field(default=None, min_length=8)


class LicenseCreate(BaseModel):
    user_id: str
    document_id: str
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    max_devices: int | None = Field(default=None, ge=1)
    max_opens: int | None = Field(default=None, ge=1)
    allow_print: bool = False
    allow_download: bool = False
    watermark_text: str | None = Field(default=None, max_length=200)


class LicenseUpdate(BaseModel):
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    max_devices: int | None = Field(default=None, ge=1)
    max_opens: int | None = Field(default=None, ge=1)
    allow_print: bool | None = None
    allow_download: bool | None = None
    watermark_text: str | None = Field(default=None, max_length=200)


class LoginRequest(BaseModel):
    email: str
    password: str


class OpenRequest(BaseModel):
    device_id: str = Field(min_length=8, max_length=128)


def _ts(value: datetime | None) -> float | None:
    return value.timestamp() if value else None


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise Unauthorized("missing_token", "Authorization-Header fehlt")
    return authorization[7:].strip()


def create_app(settings: Settings | None = None, service: DrmService | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    svc = service or DrmService(settings)
    tokens = TokenIssuer(settings.jwt_secret)
    page_limiter = RateLimiter(settings.max_pages_per_minute)

    app = FastAPI(
        title="PDF DRM Server",
        version="0.1.0",
        description="Verschlüsselte PDF-Ablage mit Lizenzverwaltung und geschütztem Viewer.",
    )
    app.state.service = svc
    app.state.settings = settings

    @app.exception_handler(DrmError)
    async def _drm_error(_: Request, exc: DrmError):
        return JSONResponse(
            {"error": exc.code, "message": exc.message}, status_code=exc.status, headers=NO_STORE
        )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self';"
                " frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
        return response

    # --- Abhängigkeiten -----------------------------------------------------

    def require_admin(x_admin_key: Annotated[str | None, Header()] = None) -> None:
        if not x_admin_key or not hmac.compare_digest(
            x_admin_key.encode(), settings.admin_api_key.encode()
        ):
            raise Unauthorized("invalid_admin_key", "Ungültiger Admin-Schlüssel")

    def current_user(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
        claims = tokens.decode(_bearer(authorization), "access")
        return svc.require_active_user(claims["sub"])

    def view_session(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> dict[str, Any]:
        claims = tokens.decode(_bearer(authorization), "view")
        lic = svc.validate_session_license(claims["lic"], claims["sub"], claims["doc"], claims["dev"])
        return {"claims": claims, "license": lic, "user": svc.get_user(claims["sub"])}

    Admin = Depends(require_admin)

    # --- Admin-API ----------------------------------------------------------

    @app.post("/api/admin/users", dependencies=[Admin], status_code=201)
    def admin_create_user(body: UserCreate):
        return svc.create_user(body.email, body.password, body.name)

    @app.get("/api/admin/users", dependencies=[Admin])
    def admin_list_users():
        return svc.list_users()

    @app.patch("/api/admin/users/{user_id}", dependencies=[Admin])
    def admin_update_user(user_id: str, body: UserUpdate):
        if body.password is not None:
            svc.set_password(user_id, body.password)
        if body.active is not None:
            svc.set_user_active(user_id, body.active)
        return svc.get_user(user_id)

    @app.post("/api/admin/documents", dependencies=[Admin], status_code=201)
    async def admin_upload_document(
        file: Annotated[UploadFile, File()], title: Annotated[str | None, Form()] = None
    ):
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise DrmError("file_too_large", "Datei ist zu groß")
        try:
            return svc.add_document(data, file.filename or "dokument.pdf", title)
        except render.InvalidPdfError as exc:
            raise DrmError("invalid_pdf", str(exc)) from exc

    @app.get("/api/admin/documents", dependencies=[Admin])
    def admin_list_documents():
        return svc.list_documents()

    @app.get("/api/admin/documents/{doc_id}", dependencies=[Admin])
    def admin_get_document(doc_id: str):
        return svc.get_document(doc_id)

    @app.delete("/api/admin/documents/{doc_id}", dependencies=[Admin], status_code=204)
    def admin_delete_document(doc_id: str):
        svc.delete_document(doc_id)
        return Response(status_code=204)

    @app.post("/api/admin/licenses", dependencies=[Admin], status_code=201)
    def admin_grant_license(body: LicenseCreate):
        return svc.grant_license(
            body.user_id,
            body.document_id,
            LicenseOptions(
                valid_from=_ts(body.valid_from),
                valid_until=_ts(body.valid_until),
                max_devices=body.max_devices,
                max_opens=body.max_opens,
                allow_print=body.allow_print,
                allow_download=body.allow_download,
                watermark_text=body.watermark_text,
            ),
        )

    @app.get("/api/admin/licenses", dependencies=[Admin])
    def admin_list_licenses(user_id: str | None = None, document_id: str | None = None):
        return svc.list_licenses(user_id, document_id)

    @app.get("/api/admin/licenses/{lic_id}", dependencies=[Admin])
    def admin_get_license(lic_id: str):
        return svc.get_license(lic_id)

    @app.patch("/api/admin/licenses/{lic_id}", dependencies=[Admin])
    def admin_update_license(lic_id: str, body: LicenseUpdate):
        changes = body.model_dump(exclude_unset=True)
        for key in ("valid_from", "valid_until"):
            if key in changes:
                changes[key] = _ts(changes[key])
        return svc.update_license(lic_id, **changes)

    @app.post("/api/admin/licenses/{lic_id}/revoke", dependencies=[Admin])
    def admin_revoke_license(lic_id: str):
        return svc.revoke_license(lic_id)

    @app.delete("/api/admin/licenses/{lic_id}/devices/{device_id}", dependencies=[Admin])
    def admin_remove_device(lic_id: str, device_id: str):
        return svc.remove_device(lic_id, device_id)

    @app.get("/api/admin/audit", dependencies=[Admin])
    def admin_audit(
        limit: int = 200, user_id: str | None = None, document_id: str | None = None
    ):
        return svc.audit_log(limit, user_id, document_id)

    # --- Benutzer-API -------------------------------------------------------

    @app.post("/api/auth/login")
    def login(body: LoginRequest, request: Request):
        user = svc.authenticate(body.email, body.password, _client_ip(request))
        return JSONResponse(
            {
                "access_token": tokens.access_token(user["id"], settings.access_token_ttl),
                "token_type": "bearer",
                "expires_in": settings.access_token_ttl,
                "user": user,
            },
            headers=NO_STORE,
        )

    @app.get("/api/me")
    def me(user: Annotated[dict, Depends(current_user)]):
        return user

    @app.get("/api/library")
    def library(user: Annotated[dict, Depends(current_user)]):
        return svc.library(user["id"])

    @app.post("/api/documents/{doc_id}/open")
    def open_document(
        doc_id: str,
        body: OpenRequest,
        request: Request,
        user: Annotated[dict, Depends(current_user)],
    ):
        doc = svc.get_document(doc_id)
        lic = svc.open_document(user["id"], doc_id, body.device_id, _client_ip(request))
        sid = new_id()
        token = tokens.view_token(
            user["id"], lic["id"], doc_id, body.device_id, sid, settings.view_session_ttl
        )
        return JSONResponse(
            {
                "view_token": token,
                "expires_in": settings.view_session_ttl,
                "document": {"id": doc["id"], "title": doc["title"], "page_count": doc["page_count"]},
                "permissions": {
                    "print": lic["allow_print"],
                    "download": lic["allow_download"],
                },
                "license": {
                    "id": lic["id"],
                    "valid_until": lic["valid_until"],
                    "max_opens": lic["max_opens"],
                    "open_count": lic["open_count"],
                },
            },
            headers=NO_STORE,
        )

    @app.post("/api/view/refresh")
    def refresh_view(session: Annotated[dict, Depends(view_session)]):
        c = session["claims"]
        token = tokens.view_token(
            c["sub"], c["lic"], c["doc"], c["dev"], c["sid"], settings.view_session_ttl
        )
        return JSONResponse(
            {"view_token": token, "expires_in": settings.view_session_ttl}, headers=NO_STORE
        )

    @app.get("/api/view/pages/{page}")
    def view_page(
        page: int,
        request: Request,
        session: Annotated[dict, Depends(view_session)],
        scale: Annotated[float, Query(gt=0.1)] = 1.5,
    ):
        c = session["claims"]
        if not page_limiter.hit(c["sid"]):
            svc.db.audit(
                "view.rate_limited",
                user_id=c["sub"],
                document_id=c["doc"],
                license_id=c["lic"],
                device_id=c["dev"],
                ip=_client_ip(request),
            )
            raise DrmError("rate_limited", "Zu viele Seitenabrufe, bitte kurz warten")
        doc = svc.get_document(c["doc"])
        if not 1 <= page <= doc["page_count"]:
            raise NotFound("page_not_found", "Seite existiert nicht")
        scale = min(scale, settings.max_render_scale)
        wm = svc.watermark_for(session["license"], session["user"])
        image = render.render_page(svc.load_plaintext(c["doc"]), page - 1, scale, wm)
        svc.db.audit(
            "view.page",
            user_id=c["sub"],
            document_id=c["doc"],
            license_id=c["lic"],
            device_id=c["dev"],
            ip=_client_ip(request),
            detail=str(page),
        )
        return Response(image, media_type="image/webp", headers=NO_STORE)

    @app.post("/api/view/download")
    def download(request: Request, session: Annotated[dict, Depends(view_session)]):
        c, lic = session["claims"], session["license"]
        if not lic["allow_download"]:
            raise Forbidden("download_not_allowed", "Download ist für diese Lizenz nicht erlaubt")
        doc = svc.get_document(c["doc"])
        wm = svc.watermark_for(lic, session["user"])
        pdf = render.export_protected_pdf(
            svc.load_plaintext(c["doc"]),
            wm,
            allow_print=bool(lic["allow_print"]),
            license_id=lic["id"],
        )
        svc.db.audit(
            "document.downloaded",
            user_id=c["sub"],
            document_id=c["doc"],
            license_id=c["lic"],
            device_id=c["dev"],
            ip=_client_ip(request),
        )
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", doc["title"]).strip("_") or "dokument"
        if not safe.lower().endswith(".pdf"):
            safe += ".pdf"
        return Response(
            pdf,
            media_type="application/pdf",
            headers={**NO_STORE, "Content-Disposition": f'attachment; filename="{safe}"'},
        )

    @app.get("/api/health")
    def health():
        return {"status": "ok", "time": time.time()}

    # --- Viewer -------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers=NO_STORE)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
