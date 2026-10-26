"""Serverseitiges Rendering von PDF-Seiten mit eingebranntem Wasserzeichen.

Das Original-PDF verlässt den Server nie. Clients bekommen nur Rasterbilder
einzelner Seiten, in die ein personalisiertes Wasserzeichen eingebrannt ist.
Für den (optionalen) Offline-Export wird ein reines Bild-PDF erzeugt: ohne
Textebene, mit Wasserzeichen und PDF-Verschlüsselung samt Rechte-Flags.
"""

from __future__ import annotations

import io
import math
import secrets
import threading
from dataclasses import dataclass

import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader, PdfWriter
from pypdf.constants import UserAccessPermissions

# PDFium ist nicht threadsicher; FastAPI führt sync-Endpunkte im Threadpool aus.
_PDFIUM_LOCK = threading.Lock()


class InvalidPdfError(ValueError):
    pass


@dataclass(frozen=True)
class Watermark:
    lines: tuple[str, ...]
    opacity: int = 60  # 0..255

    @property
    def text(self) -> str:
        return "  ·  ".join(self.lines)


def inspect_pdf(data: bytes) -> int:
    """Validiert ein PDF und liefert die Seitenzahl."""
    with _PDFIUM_LOCK:
        try:
            pdf = pdfium.PdfDocument(data)
        except pdfium.PdfiumError as exc:
            raise InvalidPdfError(f"Kein gültiges PDF: {exc}") from exc
        try:
            count = len(pdf)
        finally:
            pdf.close()
    if count < 1:
        raise InvalidPdfError("PDF enthält keine Seiten")
    return count


def _render_raw(pdf: pdfium.PdfDocument, index: int, scale: float) -> Image.Image:
    page = pdf[index]
    try:
        bitmap = page.render(scale=scale, may_draw_forms=True)
        try:
            return bitmap.to_pil().convert("RGB")
        finally:
            bitmap.close()
    finally:
        page.close()


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    return ImageFont.load_default(size=max(8, size))


def apply_watermark(img: Image.Image, wm: Watermark) -> Image.Image:
    """Brennt ein gekacheltes, diagonales Wasserzeichen plus Fußzeile ein."""
    w, h = img.size
    base = img.convert("RGBA")

    # Diagonal gekachelter Text auf einer größeren Ebene, die anschließend
    # gedreht und mittig zugeschnitten wird.
    diag = int(math.hypot(w, h)) + 2
    layer = Image.new("RGBA", (diag, diag), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    font_size = max(12, int(min(w, h) / 28))
    font = _font(font_size)
    text = wm.text
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    tw, th = right - left, bottom - top
    step_x, step_y = tw + font_size * 3, th + font_size * 4
    fill = (120, 120, 120, wm.opacity)
    for row, y in enumerate(range(0, diag, step_y)):
        offset = (row % 2) * (step_x // 2)
        for x in range(-step_x, diag, step_x):
            draw.text((x + offset, y), text, font=font, fill=fill)
    layer = layer.rotate(30, resample=Image.BICUBIC)
    ox, oy = (diag - w) // 2, (diag - h) // 2
    layer = layer.crop((ox, oy, ox + w, oy + h))
    base = Image.alpha_composite(base, layer)

    # Gut lesbare Fußzeile.
    foot = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    fdraw = ImageDraw.Draw(foot)
    ffont = _font(max(10, int(h / 90)))
    fl, ft, fr, fb = fdraw.textbbox((0, 0), text, font=ffont)
    pad = 4
    y = h - (fb - ft) - pad * 3
    fdraw.rectangle((0, y - pad, w, h), fill=(255, 255, 255, 170))
    fdraw.text((pad * 2, y - ft), text, font=ffont, fill=(60, 60, 60, 230))
    base = Image.alpha_composite(base, foot)
    return base.convert("RGB")


def render_page(
    data: bytes, index: int, scale: float, wm: Watermark, fmt: str = "WEBP", quality: int = 85
) -> bytes:
    with _PDFIUM_LOCK:
        pdf = pdfium.PdfDocument(data)
        try:
            if not 0 <= index < len(pdf):
                raise IndexError(index)
            img = _render_raw(pdf, index, scale)
        finally:
            pdf.close()
    img = apply_watermark(img, wm)
    out = io.BytesIO()
    img.save(out, format=fmt, quality=quality)
    return out.getvalue()


def export_protected_pdf(
    data: bytes,
    wm: Watermark,
    *,
    allow_print: bool,
    license_id: str,
    scale: float = 2.0,
    user_password: str = "",
) -> bytes:
    """Erzeugt ein gerastertes, wasserzeichenbehaftetes und verschlüsseltes PDF.

    Durch die Rasterung gibt es keine Textebene mehr, aus der kopiert werden
    könnte. Die PDF-Rechte-Flags (Drucken etc.) werden von gängigen Readern
    respektiert, sind technisch aber nicht erzwingbar – das Wasserzeichen
    bleibt die eigentliche Absicherung des Offline-Exports.
    """
    pages: list[Image.Image] = []
    with _PDFIUM_LOCK:
        pdf = pdfium.PdfDocument(data)
        try:
            for i in range(len(pdf)):
                pages.append(_render_raw(pdf, i, scale))
        finally:
            pdf.close()
    pages = [apply_watermark(p, wm) for p in pages]

    raster = io.BytesIO()
    pages[0].save(
        raster,
        format="PDF",
        save_all=True,
        append_images=pages[1:],
        resolution=72.0 * scale,
        quality=85,
    )

    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(raster.getvalue())))
    writer.add_metadata(
        {
            "/Producer": "pdfdrm",
            "/PdfDrmLicense": license_id,
            "/PdfDrmWatermark": wm.text,
        }
    )
    permissions = UserAccessPermissions(0)
    if allow_print:
        permissions |= UserAccessPermissions.PRINT | UserAccessPermissions.PRINT_TO_REPRESENTATION
    writer.encrypt(
        user_password=user_password,
        owner_password=secrets.token_urlsafe(32),
        permissions_flag=permissions,
        algorithm="AES-256",
    )
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
