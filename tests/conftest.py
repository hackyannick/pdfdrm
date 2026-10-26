import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from pdfdrm import crypto
from pdfdrm.app import create_app
from pdfdrm.config import Settings
from pdfdrm.service import DrmService

ADMIN_KEY = "test-admin-key"


def make_pdf(pages: int = 3) -> bytes:
    images = []
    for i in range(pages):
        img = Image.new("RGB", (595, 842), "white")
        ImageDraw.Draw(img).text((50, 50), f"Seite {i + 1} - GEHEIM", fill="black")
        images.append(img)
    out = io.BytesIO()
    images[0].save(out, format="PDF", save_all=True, append_images=images[1:])
    return out.getvalue()


@pytest.fixture
def settings(tmp_path):
    return Settings(
        data_dir=tmp_path,
        master_key=crypto.generate_key(),
        jwt_secret=b"x" * 32,
        admin_api_key=ADMIN_KEY,
        max_pages_per_minute=1000,
    )


@pytest.fixture
def service(settings):
    return DrmService(settings)


@pytest.fixture
def client(settings, service):
    return TestClient(create_app(settings, service))


@pytest.fixture
def admin():
    return {"X-Admin-Key": ADMIN_KEY}


@pytest.fixture
def pdf_bytes():
    return make_pdf()
