"""إعدادات المشروع - كل حاجة بتتغير من هنا أو من متغيرات البيئة."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "threats.db"))

VT_API_KEY = os.environ.get("5edcb275f757b266ad24b1dbcde3aa2b6dab677028f6e0884ab482ab48944afa", "")
ABUSECH_AUTH_KEY = os.environ.get("d0eb1f3f1e14e7c0913f021a4bf4f6fedcdd71efaf719365", "")  

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "16"))
MAX_URL_LENGTH = 2048

FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
}
