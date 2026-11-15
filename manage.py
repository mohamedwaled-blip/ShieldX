"""أوامر الـ terminal:
    python manage.py update                  # تحديث القاعدة من الفيدز
    python manage.py check <url> [--vt]      # فحص لينك
    python manage.py add-hash <sha256> <name> # إضافة هاش ملف خبيث للقاعدة
"""
import sys

from checker import analyze_url, database as db
from checker.feeds import update_feeds


def main():
    args = sys.argv[1:]
    if args[:1] == ["update"]:
        update_feeds()
    elif args[:1] == ["check"] and len(args) >= 2:
        res = analyze_url(args[1], use_vt="--vt" in args)
        print(f"{res.get('verdict')} ({res.get('score')}%) - {res.get('reason', res.get('error'))}")
        for s in res.get("signals", []):
            print(f"  +{s['points']}  {s['label']}")
    elif args[:1] == ["add-hash"] and len(args) >= 3:
        db.add_hash(args[1], " ".join(args[2:]))
        print("تمت الإضافة")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
