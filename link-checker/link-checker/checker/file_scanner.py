"""فحص الملفات والصور المرفوعة. الملف بيتقري في الذاكرة بس: مش بيتحفظ ومش بيتنفذ أبدًا."""
import hashlib
import os

from . import database as db
from . import virustotal
from .scoring import build_result

IMAGE_EXTS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
DOC_EXTS = IMAGE_EXTS | {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"}
DANGEROUS_EXTS = {"exe", "scr", "bat", "cmd", "com", "msi", "dll", "js", "vbs", "ps1",
                  "jar", "hta", "lnk", "apk", "sh"}
MACRO_EXTS = {"docm", "xlsm", "pptm"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "gz", "iso"}

SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"),
    (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"), (b"MZ", "exe"), (b"\x7fELF", "elf"),
    (b"Rar!", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b", "gz"),
]
TYPE_EXTS = {
    "png": {"png"}, "jpg": {"jpg", "jpeg"}, "gif": {"gif"}, "webp": {"webp"}, "pdf": {"pdf"},
    "zip": {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "apk", "jar", "odt"},
    "exe": {"exe", "dll", "scr", "sys"}, "elf": set(), "rar": {"rar"}, "7z": {"7z"}, "gz": {"gz"},
}
SCRIPT_MARKERS = [b"<?php", b"<script", b"powershell", b"cmd.exe", b"eval("]
PDF_MARKERS = [b"/JavaScript", b"/Launch", b"/EmbeddedFile"]


def detect_type(head: bytes):
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    for magic, kind in SIGNATURES:
        if head.startswith(magic):
            return kind
    return None


def _trailing_bytes(data: bytes, kind: str) -> int:
    if kind == "jpg":
        i = data.rfind(b"\xff\xd9")
        return len(data) - (i + 2) if i != -1 else 0
    if kind == "png":
        i = data.rfind(b"IEND")
        return len(data) - (i + 8) if i != -1 else 0
    return 0


def scan_file(filename: str, data: bytes, use_vt: bool = False) -> dict:
    if not data:
        return {"error": "الملف فاضي"}
    name = os.path.basename((filename or "").replace("\\", "/"))[:255] or "unnamed"
    parts = name.lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    sha256 = hashlib.sha256(data).hexdigest()
    kind = detect_type(data[:16])
    signals = []

    def add(label, points):
        signals.append({"label": label, "points": points})

    known = db.find_hash(sha256)
    if known:
        add(f"الهاش معروف في قاعدة الملفات الخبيثة/الاختبار: {known}", 100)

    if kind in ("exe", "elf"):
        add("الملف تنفيذي (Executable)", 30)
        if ext and ext not in TYPE_EXTS[kind]:
            add(f"امتداده .{ext} بيخبي إنه ملف تنفيذي", 40)
    elif kind and ext in (DOC_EXTS | ARCHIVE_EXTS) and ext not in TYPE_EXTS[kind]:
        add(f"الامتداد .{ext} مش مطابق لنوع المحتوى الحقيقي ({kind})", 25)
    elif kind is None and ext in (IMAGE_EXTS | {"pdf"}):
        add(f"الامتداد .{ext} بس المحتوى مش بالشكل المتوقع للنوع ده", 20)

    if len(parts) >= 3 and parts[-1] in DANGEROUS_EXTS and parts[-2] in DOC_EXTS:
        add("امتداد مزدوج مخادع (زي invoice.pdf.exe)", 40)
    if ext in DANGEROUS_EXTS:
        add(f"امتداد خطير (.{ext})", 35)
    if ext in MACRO_EXTS:
        add("ملف أوفيس فيه ماكرو (Macro)", 25)
    if ext in ARCHIVE_EXTS:
        add("ملف مضغوط (محتواه مش بيتفحص هنا)", 10)

    if kind in ("png", "jpg", "gif", "webp"):
        if _trailing_bytes(data, kind) > 1024:
            add("فيه بيانات زيادة بعد نهاية الصورة (ممكن تكون مدفونة)", 15)
        low = data.lower()
        hits = [m.decode() for m in SCRIPT_MARKERS if m in low]
        if hits:
            add("كود مشبوه جوه الصورة: " + ", ".join(hits), 35)
    if kind == "pdf" and any(m in data for m in PDF_MARKERS):
        add("الـ PDF فيه JavaScript أو ملفات مضمّنة", 20)

    vt = virustotal.lookup_hash(sha256) if use_vt else None
    reason = None if signals else "مفيش مؤشرات خطر واضحة (الفحص على الامتداد والمحتوى والهاش)، ده مش ضمان إنه آمن 100%"
    return build_result(signals, vt, reason, {
        "file": {"name": name, "size": len(data), "sha256": sha256, "type": kind or "غير معروف"}})
