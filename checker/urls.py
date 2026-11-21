
from urllib.parse import urlparse

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "com.eg", "gov.eg", "edu.eg", "org.eg", "net.eg",
    "com.au", "co.in", "com.br", "co.jp", "com.sa", "com.tr",
}


def normalize(url: str) -> str:
 
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path = p.path.rstrip("/")
    query = f"?{p.query}" if p.query else ""
    return f"{host}{path}{query}"


def get_domain(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def registrable_domain(host: str) -> str:
    """الدومين الأساسي: mail.google.com -> google.com ، a.b.com.eg -> b.com.eg"""
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
