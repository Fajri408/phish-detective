import requests
from urllib.parse import urlparse

# Daftar domain shortener yang umum
SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rebrand.ly",
    "buff.ly",
    "adf.ly",
    "shorturl.at",
    "cutt.ly",
]


def normalize_url(url: str) -> str:
    """
    Pastikan URL punya skema (http/https).
    Kalau belum ada, tambahkan 'http://' sebagai default
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    return url


def is_short_url(url: str) -> bool:
    """
    Cek apakah URL berasal dari layanan shortener
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    for short_domain in SHORTENER_DOMAINS:
        if short_domain in domain:
            return True
    return False


def expand_url(url: str, timeout: int = 5) -> str:
    """
    Lakukan HEAD request untuk mendapatkan URL asli dari short URL
    """
    url = normalize_url(url)
    try:
        response = requests.head(url, allow_redirects=True, timeout=timeout)
        return response.url
    except Exception as e:
        print(f"[WARNING] Gagal expand URL: {url} -> {e}")
        return url  # fallback: kembalikan URL aslinya Kalau gagal
