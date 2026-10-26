import io
import time

import pytest
from PIL import Image
from pypdf import PdfReader

from pdfdrm import crypto
from pdfdrm.app import create_app
from pdfdrm.service import Forbidden, LicenseOptions

from fastapi.testclient import TestClient

DEVICE = "device-aaaaaaaa"


def setup_user_doc(client, admin, pdf_bytes, **license_opts):
    user = client.post(
        "/api/admin/users",
        json={"email": "leser@example.com", "password": "geheim123", "name": "Leser"},
        headers=admin,
    ).json()
    doc = client.post(
        "/api/admin/documents",
        files={"file": ("buch.pdf", pdf_bytes, "application/pdf")},
        data={"title": "Mein Buch"},
        headers=admin,
    ).json()
    lic = client.post(
        "/api/admin/licenses",
        json={"user_id": user["id"], "document_id": doc["id"], **license_opts},
        headers=admin,
    ).json()
    return user, doc, lic


def login(client):
    res = client.post("/api/auth/login", json={"email": "leser@example.com", "password": "geheim123"})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def open_doc(client, auth, doc_id, device=DEVICE):
    return client.post(f"/api/documents/{doc_id}/open", json={"device_id": device}, headers=auth)


def view_headers(res):
    return {"Authorization": f"Bearer {res.json()['view_token']}"}


# --- Krypto -----------------------------------------------------------------


def test_document_encrypted_at_rest(service, settings, pdf_bytes):
    doc = service.add_document(pdf_bytes, "a.pdf")
    blob = (settings.storage_dir / f"{doc['id']}.bin").read_bytes()
    assert b"%PDF" not in blob
    assert pdf_bytes not in blob
    assert service.load_plaintext(doc["id"]) == pdf_bytes


def test_tampered_blob_rejected(service, settings, pdf_bytes):
    doc = service.add_document(pdf_bytes, "a.pdf")
    path = settings.storage_dir / f"{doc['id']}.bin"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(crypto.DecryptionError):
        service.load_plaintext(doc["id"])


def test_master_key_rotation(service, pdf_bytes):
    doc = service.add_document(pdf_bytes, "a.pdf")
    assert service.rotate_master_key(crypto.generate_key()) == 1
    assert service.load_plaintext(doc["id"]) == pdf_bytes


def test_password_hashing():
    h = crypto.hash_password("korrekt-pferd")
    assert crypto.verify_password("korrekt-pferd", h)
    assert not crypto.verify_password("falsch", h)


# --- API: Grundablauf --------------------------------------------------------


def test_admin_requires_key(client):
    assert client.get("/api/admin/users").status_code == 401
    assert client.get("/api/admin/users", headers={"X-Admin-Key": "nope"}).status_code == 401


def test_invalid_pdf_rejected(client, admin):
    res = client.post(
        "/api/admin/documents",
        files={"file": ("x.pdf", b"kein pdf", "application/pdf")},
        headers=admin,
    )
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_pdf"


def test_full_flow_view_page(client, admin, pdf_bytes):
    _, doc, _ = setup_user_doc(client, admin, pdf_bytes)
    auth = login(client)

    library = client.get("/api/library", headers=auth).json()
    assert [d["title"] for d in library] == ["Mein Buch"]

    res = open_doc(client, auth, doc["id"])
    assert res.status_code == 200, res.text
    assert res.json()["document"]["page_count"] == 3
    vh = view_headers(res)

    page = client.get("/api/view/pages/1?scale=1", headers=vh)
    assert page.status_code == 200
    assert page.headers["content-type"] == "image/webp"
    assert "no-store" in page.headers["cache-control"]
    img = Image.open(io.BytesIO(page.content))
    assert img.size == (595, 842)

    assert client.get("/api/view/pages/4", headers=vh).status_code == 404
    # Access-Token ist kein View-Token.
    assert client.get("/api/view/pages/1", headers=auth).status_code == 401


def test_watermark_changes_rendering(service, pdf_bytes):
    from pdfdrm import render

    plain = render.render_page(pdf_bytes, 0, 1.0, render.Watermark(("a",), opacity=0), fmt="PNG")
    marked = render.render_page(
        pdf_bytes, 0, 1.0, render.Watermark(("leser@example.com",), opacity=120), fmt="PNG"
    )
    assert plain != marked


def test_no_access_without_license(client, admin, pdf_bytes):
    setup_user_doc(client, admin, pdf_bytes)
    other = client.post(
        "/api/admin/documents",
        files={"file": ("x.pdf", pdf_bytes, "application/pdf")},
        headers=admin,
    ).json()
    auth = login(client)
    res = open_doc(client, auth, other["id"])
    assert res.status_code == 403
    assert res.json()["error"] == "no_license"


# --- Lizenzregeln -----------------------------------------------------------


def test_revocation_takes_effect_immediately(client, admin, pdf_bytes):
    _, doc, lic = setup_user_doc(client, admin, pdf_bytes)
    auth = login(client)
    vh = view_headers(open_doc(client, auth, doc["id"]))
    assert client.get("/api/view/pages/1", headers=vh).status_code == 200

    client.post(f"/api/admin/licenses/{lic['id']}/revoke", headers=admin)
    res = client.get("/api/view/pages/1", headers=vh)
    assert res.status_code == 403
    assert res.json()["error"] == "license_revoked"
    assert open_doc(client, auth, doc["id"]).status_code == 403
    assert client.get("/api/library", headers=auth).json() == []


def test_expired_license(client, admin, pdf_bytes):
    _, doc, _ = setup_user_doc(
        client, admin, pdf_bytes, valid_until="2000-01-01T00:00:00Z"
    )
    auth = login(client)
    res = open_doc(client, auth, doc["id"])
    assert res.status_code == 403
    assert res.json()["error"] == "license_expired"


def test_not_yet_valid_license(client, admin, pdf_bytes):
    _, doc, _ = setup_user_doc(client, admin, pdf_bytes, valid_from="2999-01-01T00:00:00Z")
    res = open_doc(client, login(client), doc["id"])
    assert res.json()["error"] == "license_not_yet_valid"


def test_device_limit(client, admin, pdf_bytes):
    _, doc, lic = setup_user_doc(client, admin, pdf_bytes, max_devices=1)
    auth = login(client)
    assert open_doc(client, auth, doc["id"], "device-11111111").status_code == 200
    assert open_doc(client, auth, doc["id"], "device-11111111").status_code == 200
    res = open_doc(client, auth, doc["id"], "device-22222222")
    assert res.status_code == 403
    assert res.json()["error"] == "device_limit_reached"

    # Admin entfernt das alte Gerät -> neues Gerät erlaubt, alte Sitzung ungültig.
    vh_old = view_headers(open_doc(client, auth, doc["id"], "device-11111111"))
    client.delete(f"/api/admin/licenses/{lic['id']}/devices/device-11111111", headers=admin)
    assert client.get("/api/view/pages/1", headers=vh_old).json()["error"] == "device_not_authorized"
    assert open_doc(client, auth, doc["id"], "device-22222222").status_code == 200


def test_open_limit(client, admin, pdf_bytes):
    _, doc, _ = setup_user_doc(client, admin, pdf_bytes, max_opens=2)
    auth = login(client)
    assert open_doc(client, auth, doc["id"]).status_code == 200
    assert open_doc(client, auth, doc["id"]).status_code == 200
    res = open_doc(client, auth, doc["id"])
    assert res.status_code == 403
    assert res.json()["error"] == "open_limit_reached"


def test_deactivated_user_loses_access(client, admin, pdf_bytes):
    user, doc, _ = setup_user_doc(client, admin, pdf_bytes)
    auth = login(client)
    vh = view_headers(open_doc(client, auth, doc["id"]))
    client.patch(f"/api/admin/users/{user['id']}", json={"active": False}, headers=admin)
    assert client.get("/api/view/pages/1", headers=vh).status_code == 401
    assert client.get("/api/library", headers=auth).status_code == 401


def test_login_lockout(client, admin, pdf_bytes):
    setup_user_doc(client, admin, pdf_bytes)
    for _ in range(5):
        r = client.post("/api/auth/login", json={"email": "leser@example.com", "password": "falsch!!"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"email": "leser@example.com", "password": "geheim123"})
    assert r.json()["error"] == "account_locked"


def test_rate_limit(settings, service, admin, pdf_bytes):
    settings.max_pages_per_minute = 2
    client = TestClient(create_app(settings, service))
    _, doc, _ = setup_user_doc(client, admin, pdf_bytes)
    vh = view_headers(open_doc(client, login(client), doc["id"]))
    assert client.get("/api/view/pages/1?scale=0.5", headers=vh).status_code == 200
    assert client.get("/api/view/pages/2?scale=0.5", headers=vh).status_code == 200
    res = client.get("/api/view/pages/3?scale=0.5", headers=vh)
    assert res.json()["error"] == "rate_limited"


def test_concurrent_opens_respect_limit(service, pdf_bytes):
    from concurrent.futures import ThreadPoolExecutor

    user = service.create_user("a@example.com", "geheim123")
    doc = service.add_document(pdf_bytes, "a.pdf")
    service.grant_license(user["id"], doc["id"], LicenseOptions(max_opens=3, max_devices=2))

    def attempt(i):
        try:
            service.open_document(user["id"], doc["id"], f"device-{i % 4:08d}")
            return True
        except Forbidden:
            return False

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(attempt, range(20)))
    assert sum(results) <= 3
    devices = service.list_licenses(user["id"])[0]["devices"]
    assert len(devices) <= 2


# --- Download ---------------------------------------------------------------


def test_download_forbidden_by_default(client, admin, pdf_bytes):
    _, doc, _ = setup_user_doc(client, admin, pdf_bytes)
    vh = view_headers(open_doc(client, login(client), doc["id"]))
    res = client.post("/api/view/download", headers=vh)
    assert res.status_code == 403


def test_download_protected_pdf(client, admin, pdf_bytes):
    _, doc, lic = setup_user_doc(client, admin, pdf_bytes, allow_download=True)
    vh = view_headers(open_doc(client, login(client), doc["id"]))
    res = client.post("/api/view/download", headers=vh)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"

    reader = PdfReader(io.BytesIO(res.content))
    assert reader.is_encrypted
    reader.decrypt("")
    assert len(reader.pages) == 3
    assert reader.metadata["/PdfDrmLicense"] == lic["id"]
    # Kein Drucken erlaubt (Bit 3 der Permissions).
    assert not reader.user_access_permissions & 4
    # Gerastert: keine extrahierbare Textebene.
    assert "GEHEIM" not in reader.pages[0].extract_text()


def test_audit_log_records_views(client, admin, pdf_bytes):
    _, doc, _ = setup_user_doc(client, admin, pdf_bytes)
    vh = view_headers(open_doc(client, login(client), doc["id"]))
    client.get("/api/view/pages/2?scale=0.5", headers=vh)
    events = [e["event"] for e in client.get("/api/admin/audit", headers=admin).json()]
    for expected in ("view.page", "document.opened", "auth.login", "license.granted"):
        assert expected in events


def test_view_token_refresh(client, admin, pdf_bytes):
    _, doc, lic = setup_user_doc(client, admin, pdf_bytes)
    vh = view_headers(open_doc(client, login(client), doc["id"]))
    res = client.post("/api/view/refresh", headers=vh)
    assert res.status_code == 200
    vh2 = view_headers(res)
    assert client.get("/api/view/pages/1?scale=0.5", headers=vh2).status_code == 200
    client.post(f"/api/admin/licenses/{lic['id']}/revoke", headers=admin)
    assert client.post("/api/view/refresh", headers=vh2).status_code == 403


def test_viewer_served_with_csp(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert client.get("/static/viewer.js").status_code == 200
