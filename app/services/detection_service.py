import os
import pickle
import numpy as np
from app.core.model import DetectionResult
from app.features.fextract import FeatureExtraction
from app.utils import feature_names, feature_explanations
from app.utils.whitelist_checker import WhitelistChecker
from urllib.parse import urlparse
from app.utils.convert_feature_urtil import convert_feature
import Levenshtein
import tldextract

# Load model saat modul pertama kali diimport
MODEL_PATH = os.getenv("MODEL_PATH", "app/models/catboost_terbaru.pkl")

# Load model menggunakan pickle
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Load whitelist checker saat startup
whitelist_checker = WhitelistChecker()


def detect_phishing(url: str) -> DetectionResult:
    """
    Deteksi apakah URL merupakan phishing atau tidak
    :param url: URL yang akan dianalisis
    :return: dictionary dengan hasil deteksi dan confidence

    Examples:
        # Deteksi url "https://no-safe.microsaas.my.id".
        detect_phishing("https://no-safe.microsaas.my.id")
    """
    # Parse domain untuk cek whitelist terlebih dahulu
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # Cek whitelist terlebih dahulu (paling cepat)
    if whitelist_checker.is_whitelisted(domain):
        return DetectionResult(
            url=url,
            safe_percentage=100.0,
            phishing_percentage=0.0,
            features=[],
            warning="Domain terdaftar dalam whitelist (aman)",
        )
    
    feature_data = []
    # Ekstraksi fitur dari URL

    #mode NOMRAL
    obj = FeatureExtraction(url)

    #mode cepat
    # obj = OptimizedFeatureExtraction(url, fast_mode=True, timeout=3)
    features = obj.getFeaturesList()  # dictionary

    # Pastikan hanya 30 fitur pertama yang dipakai model
    x = np.array(features[:30]).reshape(1, -1)

    # Prediksi probabilitas
    y_pro_non_phishing = round(float(model.predict_proba(x)[0, 1]) * 100, 2)  # Aman
    y_pro_phishing = round(100 - y_pro_non_phishing, 2)  # Beresiko phishing

    # --- POST-PROCESSING: Fitur baru ---
    
    # 1. Fuzzy Whitelist Check (untuk typo pada domain terpercaya)
    is_fuzzy_whitelisted_typo = False
    queried_tld = tldextract.extract(domain)
    if not whitelist_checker.is_whitelisted(domain):
        for whitelisted_domain in whitelist_checker.whitelist_domains:
            try:
                whitelisted_tld = tldextract.extract(whitelisted_domain)
                # Bandingkan root domain dengan root domain, subdomain dengan subdomain yang root-nya sama
                if queried_tld.subdomain == '' and whitelisted_tld.subdomain == '':
                    # Keduanya root domain
                    distance = Levenshtein.distance(domain, whitelisted_domain)
                    if 1 <= distance <= 2:
                        is_fuzzy_whitelisted_typo = True
                        break
                elif queried_tld.subdomain != '' and whitelisted_tld.subdomain != '' and \
                     queried_tld.registered_domain == whitelisted_tld.registered_domain:
                    # Keduanya subdomain, dan root-nya sama
                    distance = Levenshtein.distance(domain, whitelisted_domain)
                    if 1 <= distance <= 2:
                        is_fuzzy_whitelisted_typo = True
                        break
            except Exception:
                continue

    # 2. Ambil hasil check dari semua fitur post-processing
    is_homoglyph = (obj.HasHomoglyphs() == -1)
    is_typosquat = (obj.TyposquattingDomain() == -1)
    is_suspicious_tld = (obj.SuspiciousTLD() == -1)
    is_excessive_subdomain = (obj.ExcessiveSubdomains() == -1)
    is_suspicious_keyword = (obj.SuspiciousKeywordInDomain() == -1)

    # Bobot untuk masing-masing red flag
    weights = {
        'fuzzy_typo': 0.35,
        'homoglyph': 0.25,
        'typosquat': 0.20,
        'suspicious_tld': 0.10,
        'excessive_subdomain': 0.05,
        'suspicious_keyword': 0.05,
    }
    score = 0
    if is_fuzzy_whitelisted_typo:
        score += weights['fuzzy_typo']
    if is_homoglyph:
        score += weights['homoglyph']
    if is_typosquat:
        score += weights['typosquat']
    if is_suspicious_tld:
        score += weights['suspicious_tld']
    if is_excessive_subdomain:
        score += weights['excessive_subdomain']
    if is_suspicious_keyword:
        score += weights['suspicious_keyword']

    # Gabungkan dengan prediksi model
    final_phishing = y_pro_phishing + (100 - y_pro_phishing) * score
    final_safe = 100 - final_phishing

    # Pastikan tetap di range 0-100
    final_phishing = min(max(final_phishing, 0), 100)
    final_safe = 100 - final_phishing

    # Gabungkan warning spesifik untuk ditampilkan ke user
    warnings = []
    if is_fuzzy_whitelisted_typo:
        warnings.append('Domain sangat mirip dengan domain di whitelist (potensi typosquatting institusi)')
    if is_homoglyph:
        warnings.append('Domain mengandung karakter yang membingungkan/mirip (homoglyph attack)')
    if is_typosquat:
        warnings.append('Domain mirip dengan domain populer global (typosquatting)')
    if is_suspicious_tld:
        warnings.append('TLD domain mencurigakan')
    if is_excessive_subdomain:
        warnings.append('Terlalu banyak subdomain')
    if is_suspicious_keyword:
        warnings.append('Domain mengandung kata kunci mencurigakan')

    warning = '; '.join(warnings) if warnings else None

    feature_data = [
        {
            "feature": feature_names[i],
            "result": convert_feature(features[i]),
            "explanation": feature_explanations.get(feature_names[i], {}).get(
                features[i], "Tidak ada informasi lebih lanjut."
            ),
        }
        for i in range(len(feature_names))
    ]

    return DetectionResult(
        url=url,
        safe_percentage=round(final_safe, 2),
        phishing_percentage=round(final_phishing, 2),
        features=feature_data,
        warning=warning,
    )
