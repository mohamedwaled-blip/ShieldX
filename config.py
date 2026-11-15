"""إعدادات المشروع - كل حاجة بتتغير من هنا أو من متغيرات البيئة."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """بيقرا ملف .env جنب config.py (سطر لكل KEY=VALUE). متغيرات البيئة الحقيقية ليها الأولوية."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_dotenv(BASE_DIR / ".env")

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
