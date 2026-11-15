"""فحص اللينكات: قاعدة البيانات + تحليل الشكل + VirusTotal (اختياري)."""
import config

from . import database as db
from . import virustotal
from .heuristics import run_heuristics
from .scoring import build_result
from .urls import get_domain, normalize


def analyze_url(url: str, use_vt: bool = False) -> dict:
    url = (url or "").strip()
    if not url:
        return {"error": "ابعت لينك", "code": "empty_url"}
    if len(url) > config.MAX_URL_LENGTH:
        return {"error": "اللينك طويل زيادة", "code": "url_too_long",
                "max": config.MAX_URL_LENGTH}

    try:
        signals = run_heuristics(url)
        norm, domain = normalize(url), get_domain(url)
    except ValueError:
        return build_result([{"code": "invalid_url", "label": "شكل اللينك غير صالح",
                              "points": 30, "params": {}}])

    source = db.find_exact(norm)
    if source:
        signals.insert(0, {"code": "db_exact", "label": f"اللينك موجود بالظبط في قاعدة {source}",
                           "points": 100, "params": {"source": source}})
    else:
        count, sources = db.domain_stats(domain)
        if count:
            signals.insert(0, {"code": "db_domain",
                               "label": f"الدومين ظهر في {count} لينك خبيث (المصدر: {sources})",
                               "points": 50, "params": {"count": str(count), "sources": sources}})

    vt = virustotal.lookup_url(url) if use_vt else None
    return build_result(signals, vt)
