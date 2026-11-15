"""تحديث قاعدة اللينكات الخبيثة من الفيدز الخارجية."""
import time
import urllib.error
import urllib.request

import config
from . import database as db
from .urls import get_domain, normalize


def update_feeds():
    for name, feed_url in config.FEEDS.items():
        print(f"[+] تحميل {name} ...")
        headers = {"User-Agent": "student-link-checker/1.0"}
        if config.ABUSECH_AUTH_KEY and "abuse.ch" in feed_url:
            headers["Auth-Key"] = config.ABUSECH_AUTH_KEY
        try:
            req = urllib.request.Request(feed_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                lines = r.read().decode("utf-8", errors="ignore").splitlines()
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"    فشل: {e}")
            continue
        now = int(time.time())
        rows = [(normalize(l), get_domain(l), name, now)
                for l in (x.strip() for x in lines) if l and not l.startswith("#")]
        db.insert_threats(rows)
        print(f"    تمت إضافة {len(rows)} لينك")
    print(f"[✓] إجمالي السجلات في القاعدة: {db.count_threats()}")
