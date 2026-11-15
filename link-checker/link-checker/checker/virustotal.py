"""VirusTotal (اختياري): بيتطلب VT_API_KEY. للملفات بنبعت الهاش بس، مش الملف نفسه."""
import base64
import json
import urllib.error
import urllib.request

import config


def _get(path: str) -> dict:
    if not config.VT_API_KEY:
        return {"error": "ضيف VT_API_KEY كمتغير بيئة الأول"}
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/{path}",
                                 headers={"x-apikey": config.VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "VirusTotal معندوش تحليل لده لسه"}
        if e.code == 429:
            return {"error": "وصلت للحد المسموح من طلبات VirusTotal، جرب بعد دقيقة"}
        return {"error": f"VirusTotal رجّع HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError):
        return {"error": "مقدرتش أوصل لـ VirusTotal"}
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}


def lookup_url(url: str) -> dict:
    if "://" not in url:
        url = "http://" + url
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _get(f"urls/{url_id}")


def lookup_hash(sha256: str) -> dict:
    return _get(f"files/{sha256}")
