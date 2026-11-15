"""بيانات الفحص: البراندات المشهورة ودومناتها الرسمية + قوايم المؤشرات. راجعها وزوّد عليها."""

BRANDS = {
    "facebook": {"facebook.com", "fb.com", "fb.me", "messenger.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "google": {"google.com", "google.com.eg", "gmail.com", "googleapis.com", "gstatic.com", "goo.gl"},
    "youtube": {"youtube.com", "youtu.be"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.eg", "amazon.sa"},
    "paypal": {"paypal.com", "paypal.me"},
    "netflix": {"netflix.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "telegram": {"telegram.org", "t.me"},
    "tiktok": {"tiktok.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "binance": {"binance.com"},
    "vodafone": {"vodafone.com", "vodafone.com.eg"},
    "etisalat": {"etisalat.eg", "etisalat.com"},
    "fawry": {"fawry.com", "fawrypay.com"},
}
OFFICIAL_DOMAINS = set().union(*BRANDS.values())

KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm",
            "password", "banking", "wallet", "suspend", "billing", "recover",
            "gift", "free", "bonus", "prize"]

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
                   "work", "support", "country", "loan", "review", "icu", "cyou", "buzz"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "ow.ly", "shorturl.at", "tiny.cc"}
