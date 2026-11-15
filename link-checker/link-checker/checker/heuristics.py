"""فحص شكل اللينك نفسه (بدون قاعدة بيانات): بيكشف اللينكات المخادعة حتى لو جديدة."""
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import unquote, urlparse

from .brands import BRANDS, KEYWORDS, OFFICIAL_DOMAINS, SHORTENERS, SUSPICIOUS_TLDS
from .urls import registrable_domain

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_EXEC_EXT = re.compile(r"\.(exe|apk|scr|msi|bat|cmd|ps1|vbs|jar|hta)$")
_REDIRECT = re.compile(r"(url|redirect|next|goto|link|target|continue)=https?", re.I)


def _squash(text: str) -> str:
    """بيرجّع الكلمة المقلّدة لشكلها الأصلي: faceb00k -> facebook , paypa1 -> paypal"""
    return text.lower().translate(_LEET).replace("rn", "m").replace("vv", "w").replace("-", "")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def run_heuristics(url: str) -> list:
    """بيرجّع list من {label, points}. ممكن يرفع ValueError لو اللينك شكله مش صالح."""
    had_scheme = "://" in url
    p = urlparse(url if had_scheme else "http://" + url)
    host = (p.hostname or "").lower()
    netloc = p.netloc.lower()
    path_q = unquote(p.path + "?" + p.query).lower()
    signals = []

    def add(label, points):
        signals.append({"label": label, "points": points})

    if not host:
        add("اللينك مفيهوش دومين صالح", 30)
        return signals

    is_ip = _is_ip(host)
    reg = host if is_ip else registrable_domain(host)

    if reg in SHORTENERS:
        add("لينك مختصر بيخبي الوجهة الحقيقية", 15)
    if "@" in netloc:
        add("فيه علامة @ في اللينك (بتخبي الدومين الحقيقي)", 25)
    if reg in OFFICIAL_DOMAINS and "@" not in netloc:
        return signals  # دومين رسمي معروف

    if had_scheme and p.scheme == "http":
        add("بدون HTTPS", 10)
    if is_ip:
        add("اللينك بيستخدم IP بدل اسم دومين", 30)
    if "xn--" in host or any(ord(c) > 127 for c in host):
        add("دومين بحروف مموّهة (Punycode/Unicode)", 30)
    if len(p.geturl()) > 75:
        add("لينك طويل بشكل مريب", 10)
    if not is_ip:
        sub = host[: -len(reg)].strip(".") if host.endswith(reg) else ""
        if sub and len(sub.split(".")) >= 3:
            add("عدد كبير من الدومينات الفرعية", 15)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add(f"امتداد دومين شائع في الاحتيال (.{host.rsplit('.', 1)[-1]})", 15)
        if sum(c.isdigit() for c in reg.split(".")[0]) >= 4:
            add("أرقام كتير في اسم الدومين", 10)
    if host.count("-") >= 3:
        add("شرطات كتير في الدومين", 10)
    try:
        if p.port not in (None, 80, 443):
            add(f"بورت غير عادي ({p.port})", 10)
    except ValueError:
        add("بورت غير صالح", 10)
    if _REDIRECT.search(p.query):
        add("فيه رابط تحويل (redirect) جوه اللينك", 10)
    if _EXEC_EXT.search(p.path.lower()):
        add("اللينك بيحمّل ملف تنفيذي", 20)

    found = [k for k in KEYWORDS if k in (host + path_q)]
    if found:
        add("كلمات شائعة في الاحتيال: " + ", ".join(found), min(len(found) * 5, 20))

    # انتحال براند: أقوى مؤشر على اللينكات المخادعة
    squashed_netloc = _squash(netloc)
    reg_label = _squash(reg.split(".")[0])
    best = None
    for brand in BRANDS:
        if brand in netloc.replace("-", ""):
            cand = (40, f"اسم «{brand}» ظاهر في الدومين لكن الدومين الأساسي ({reg}) مش الرسمي")
        elif brand in squashed_netloc:
            cand = (45, f"الدومين بيقلّد اسم «{brand}» بأرقام أو حروف مشابهة")
        elif len(brand) >= 6 and SequenceMatcher(None, reg_label, brand).ratio() >= 0.86:
            cand = (45, f"الدومين قريب جدًا من «{brand}» بحرف زيادة أو ناقص (Typosquatting)")
        elif brand in path_q:
            cand = (15, f"اسم «{brand}» موجود في المسار بس الدومين مش رسمي")
        else:
            continue
        if best is None or cand[0] > best[0]:
            best = cand
    if best:
        add(best[1], best[0])
    return signals
