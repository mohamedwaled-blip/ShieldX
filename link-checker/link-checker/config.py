"""إعدادات المشروع - كل حاجة بتتغير من هنا أو من متغيرات البيئة."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "threats.db"))

# المفاتيح بتتحط كمتغيرات بيئة (أو في ملف .env محلي) ومش جوه الكود أبدًا
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "")  # URLhaus ساعات بيطلبه (مجاني)

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "16"))
MAX_URL_LENGTH = 2048

FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
}
