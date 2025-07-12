import ipaddress
import re
import requests
import socket
import whois
from datetime import date
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search(
            "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
            "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
            "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
            "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net",
            self.url,
        )
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@", self.url):
            return -1
        return 1

    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind("//") > 6:
            return -1
        return 1

    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall("\-", self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def Https(self):
        try:
            https = self.urlparse.scheme
            if "https" in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if expiration_date is None or creation_date is None:
                return -1

            age = (expiration_date.year - creation_date.year) * 12 + (
                expiration_date.month - creation_date.month
            )
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            # Pastikan self.soup adalah objek BeautifulSoup
            if not hasattr(self.soup, "find_all"):
                return -1  # Jika self.soup bukan objek BeautifulSoup, anggap phishing

            base_domain = urlparse(self.url).netloc
            favicon_url = None

            # Cari favicon dalam tag <link rel="icon">
            for link in self.soup.find_all("link", rel=["icon", "shortcut icon"]):
                href = link.get("href", "")
                if href:
                    favicon_url = urljoin(self.url, href)  # Pastikan URL absolut
                    break  # Ambil favicon pertama yang ditemukan

            if not favicon_url:
                return -1  # Jika tidak ditemukan favicon, anggap phishing

            # Periksa apakah favicon berasal dari domain yang sama atau eksternal
            parsed_favicon = urlparse(favicon_url)
            if parsed_favicon.netloc == "" or parsed_favicon.netloc == base_domain:
                return 1  # Aman (favicon dari domain yang sama)
            else:
                return -1  # Berbahaya (favicon dari domain lain)

        except Exception as e:
            print(f"Error in Favicon: {e}")
            return -1  # Jika error, anggap phishing

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if "https" in self.domain:
                return -1
            return 1
        except:
            return -1

    # 13. RequestURL
    def RequestURL(self):
        try:
            success, i = 0, 0  # Inisialisasi variabel success dan i

            for img in self.soup.find_all("img", src=True):
                dots = [x.start(0) for x in re.finditer("\.", img["src"])]
                if (
                    self.url in img["src"]
                    or self.domain in img["src"]
                    or len(dots) == 1
                ):
                    success += 1
                i += 1

            for audio in self.soup.find_all("audio", src=True):
                dots = [x.start(0) for x in re.finditer("\.", audio["src"])]
                if (
                    self.url in audio["src"]
                    or self.domain in audio["src"]
                    or len(dots) == 1
                ):
                    success += 1
                i += 1

            for embed in self.soup.find_all("embed", src=True):
                dots = [x.start(0) for x in re.finditer("\.", embed["src"])]
                if (
                    self.url in embed["src"]
                    or self.domain in embed["src"]
                    or len(dots) == 1
                ):
                    success += 1
                i += 1

            for iframe in self.soup.find_all("iframe", src=True):
                dots = [x.start(0) for x in re.finditer("\.", iframe["src"])]
                if (
                    self.url in iframe["src"]
                    or self.domain in iframe["src"]
                    or len(dots) == 1
                ):
                    success += 1
                i += 1

            if i == 0:  # Jika tidak ada elemen ditemukan, return 1 (tidak mencurigakan)
                return 1

            percentage = (success / float(i)) * 100

            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                return -1
        except:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0

            for a in self.soup.find_all("a", href=True):
                href = a["href"]
                # Jika href berisi simbol #, javascript, mailto, atau domain berbeda
                if (
                    "#" in href
                    or "javascript" in href.lower()
                    or "mailto" in href.lower()
                    or not (self.url in href or self.domain in href)
                ):
                    unsafe += 1
                i += 1

            if i == 0:  # Jika tidak ada anchor ditemukan, return 1
                return 1

            percentage = (unsafe / float(i)) * 100

            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0

            for link in self.soup.find_all("link", href=True):
                dots = [x.start(0) for x in re.finditer("\.", link["href"])]
                if (
                    self.url in link["href"]
                    or self.domain in link["href"]
                    or len(dots) == 1
                ):
                    success = success + 1
                i = i + 1

            for script in self.soup.find_all("script", src=True):
                dots = [x.start(0) for x in re.finditer("\.", script["src"])]
                if (
                    self.url in script["src"]
                    or self.domain in script["src"]
                    or len(dots) == 1
                ):
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif (percentage >= 17.0) and (percentage < 81.0):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all("form", action=True)) == 0:
                return 1
            else:
                for form in self.soup.find_all("form", action=True):
                    if form["action"] == "" or form["action"] == "about:blank":
                        return -1
                    elif (
                        self.url not in form["action"]
                        and self.domain not in form["action"]
                    ):
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.search(r"mail\(|mailto:", self.soup.text, re.IGNORECASE):
                return -1
            return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.domain in self.url:
                return 1
            return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return -1
            else:
                return 1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.search(r"event.button\s*==\s*2", self.response.text):
                return -1
            return 1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(
                r"alert\(|window\.open\(|confirm\(|prompt\(", self.response.text
            ):
                return -1  # Indikasi phishing
            return 1  # Aman
        except:
            return -1  # Jika terjadi error, lebih baik anggap sebagai phishing

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.search(r"<iframe|frameborder", self.response.text, re.IGNORECASE):
                return -1
            else:
                return 1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date is None:
                return -1

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (
                today.month - creation_date.month
            )
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (
                today.month - creation_date.month
            )
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    def WebsiteTraffic(self):
        """Menggunakan Wayback Machine (archive.org) untuk memperkirakan popularitas website."""
        try:
            archive_url = f"https://web.archive.org/web/*/{self.url}"

            # Meningkatkan timeout untuk menghindari error akibat waktu request terlalu pendek
            response = requests.get(archive_url, timeout=10)

            # Memeriksa apakah status code response berhasil
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")

                # Mencari semua link snapshot arsip
                snapshot_links = soup.find_all("a", href=True)

                # Menentukan threshold jumlah snapshot
                if len(snapshot_links) > 10:
                    return 1  # Website dengan traffic tinggi
                elif 5 <= len(snapshot_links) <= 10:
                    return 0  # Website dengan traffic sedang
                else:
                    return -1  # Website dengan traffic rendah
            else:
                return -1  # Tidak ada data arsip, anggap traffic rendah

        except requests.exceptions.Timeout:
            print(f"Timeout saat mengambil data dari: {self.url}")
            return -1  # Jika timeout, anggap traffic rendah

        except requests.exceptions.RequestException as e:
            print(f"Terjadi kesalahan saat request: {e}")
            return -1  # Jika ada error lain, anggap traffic rendah

    def PageRank(self):
        """Menggunakan Open PageRank API untuk mendapatkan PageRank."""
        try:
            api_key = (
                "k04gccsks8ggswosc8o8s4wg0400kkgc84ogooc8"  # Ganti dengan API Key Anda
            )
            url = (
                f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={self.domain}"
            )
            headers = {"API-OPR": api_key}
            response = requests.get(url, headers=headers, timeout=5)
            result = response.json()

            if "response" in result and len(result["response"]) > 0:
                rank = result["response"][0].get("page_rank_decimal", 0)
                return 1 if rank >= 5 else -1
            return -1
        except Exception as e:
            print(f"Error PageRank: {e}")
            return -1

    # . GoogleIndex
    def GoogleIndex(self):
        try:
            query = f"site:{self.domain}"
            response = requests.get(
                f"https://www.google.com/search?q={query}",
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if (
                "tidak ditemukan" in response.text.lower()
                or "tidak ada hasil" in response.text.lower()
                or "no results" in response.text.lower()
            ):
                return -1
            return 1
        except:
            return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            # Pastikan self.soup adalah objek BeautifulSoup
            if not hasattr(self.soup, "find_all"):
                return -1  # Jika self.soup bukan objek BeautifulSoup, anggap phishing

            total_links = len(self.soup.find_all("a", href=True))
            if total_links == 0:
                return 1  # Aman jika tidak ada link

            internal_links = 0
            base_domain = urlparse(self.url).netloc

            for link in self.soup.find_all("a", href=True):
                href = link["href"]
                parsed_href = urlparse(href)

                # Hitung hanya link yang mengarah ke domain yang sama (internal)
                if parsed_href.netloc == "" or parsed_href.netloc == base_domain:
                    internal_links += 1

            ratio = internal_links / total_links

            # Aturan pengklasifikasian berdasarkan rasio
            if ratio < 0.2:
                return -1  # Berbahaya, banyak link eksternal
            elif 0.2 <= ratio <= 0.5:
                return 0  # Meragukan
            else:
                return 1  # Aman, mayoritas link internal
        except Exception as e:
            print(f"Error in LinksPointingToPage: {e}")
            return -1  # Jika error, anggap sebagai phishing

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                "at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
                self.url,
            )
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                "146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
                "107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
                "118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|"
                "216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
                "34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|"
                "216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42",
                ip_address,
            )
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features
