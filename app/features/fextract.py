import ipaddress
import re
import requests
import socket
import whois
import ssl
from datetime import date, datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import tldextract
import dns.resolver
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import Levenshtein  # Tambahkan ini untuk deteksi typo domain
try:
    import confusables
except ImportError:
    confusables = None


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""
        self.extracted_domain = None
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self._initialize_data()
        self._extract_features()

    def _initialize_data(self):
        """Initialize all necessary data for feature extraction"""
        try:
            # Parse URL
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc.lower()
            
            # Use tldextract for better domain parsing
            self.extracted_domain = tldextract.extract(self.url)
            
            # Get webpage content
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            self.response = self.session.get(self.url, headers=headers, timeout=10, allow_redirects=True)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
            
        except Exception as e:
            print(f"Error initializing data for {self.url}: {e}")
            pass

        try:
            # Get WHOIS data with better error handling
            if self.domain and not self._is_ip_address(self.domain):
                self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print(f"WHOIS lookup failed for {self.domain}: {e}")
            pass

    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    def _extract_features(self):
        """Extract all features"""
        feature_methods = [
            self.UsingIp, self.longUrl, self.shortUrl, self.symbol,
            self.redirecting, self.prefixSuffix, self.SubDomains, self.Https,
            self.DomainRegLen, self.Favicon, self.NonStdPort, self.HTTPSDomainURL,
            self.RequestURL, self.AnchorURL, self.LinksInScriptTags, 
            self.ServerFormHandler, self.InfoEmail, self.AbnormalURL,
            self.WebsiteForwarding, self.StatusBarCust, self.DisableRightClick,
            self.UsingPopupWindow, self.IframeRedirection, self.AgeofDomain,
            self.DNSRecording, self.WebsiteTraffic, self.PageRank,
            self.GoogleIndex, self.LinksPointingToPage, self.StatsReport,
            self.TyposquattingDomain, self.HasHomoglyphs  # Tambahkan fitur baru di sini
        ]
        
        for method in feature_methods:
            try:
                self.features.append(method())
            except Exception as e:
                print(f"Error in {method.__name__}: {e}")
                self.features.append(-1)  # Default to suspicious on error

    # 1. Using IP Address
    def UsingIp(self):
        try:
            # Remove port if present
            domain_clean = self.domain.split(':')[0]
            ipaddress.ip_address(domain_clean)
            return -1  # Suspicious
        except ValueError:
            return 1   # Legitimate

    # 2. Long URL
    def longUrl(self):
        url_length = len(self.url)
        if url_length < 54:
            return 1   # Legitimate
        elif url_length <= 75:
            return 0   # Suspicious
        else:
            return -1  # Phishing

    # 3. Short URL Service
    def shortUrl(self):
        shortening_services = [
            'bit\.ly', 'goo\.gl', 'shorte\.st', 'go2l\.ink', 'x\.co', 'ow\.ly',
            't\.co', 'tinyurl', 'tr\.im', 'is\.gd', 'cli\.gs', 'yfrog\.com',
            'migre\.me', 'ff\.im', 'tiny\.cc', 'url4\.eu', 'twit\.ac', 'su\.pr',
            'twurl\.nl', 'snipurl\.com', 'short\.to', 'budurl\.com', 'ping\.fm',
            'post\.ly', 'just\.as', 'bkite\.com', 'snipr\.com', 'fic\.kr',
            'loopt\.us', 'doiop\.com', 'short\.ie', 'kl\.am', 'wp\.me',
            'rubyurl\.com', 'om\.ly', 'to\.ly', 'bit\.do', 'lnkd\.in',
            'db\.tt', 'qr\.ae', 'adf\.ly', 'bitly\.com', 'cur\.lv',
            'tinyurl\.com', 'ity\.im', 'q\.gs', 'po\.st', 'bc\.vc',
            'twitthis\.com', 'u\.to', 'j\.mp', 'buzurl\.com', 'cutt\.us',
            'u\.bb', 'yourls\.org', 'prettylinkpro\.com', 'scrnch\.me',
            'filoops\.info', 'vzturl\.com', 'qr\.net', '1url\.com',
            'tweez\.me', 'v\.gd', 'link\.zip\.net', 'tly\.io', 'rebrand\.ly'
        ]
        
        pattern = '|'.join(shortening_services)
        if re.search(pattern, self.url, re.IGNORECASE):
            return -1  # Phishing
        return 1       # Legitimate

    # 4. @ Symbol in URL
    def symbol(self):
        if '@' in self.url:
            return -1  # Phishing
        return 1       # Legitimate

    # 5. Redirecting using "//"
    def redirecting(self):
        # Count occurrences of "//" after the protocol
        protocol_end = self.url.find('://') + 3
        if protocol_end > 2:
            remaining_url = self.url[protocol_end:]
            if '//' in remaining_url:
                return -1  # Phishing
        return 1           # Legitimate

    # 6. Prefix-Suffix in Domain
    def prefixSuffix(self):
        if not self.extracted_domain:
            return -1
        domain_main = self.extracted_domain.domain
        if '-' in domain_main:
            return -1  # Phishing
        return 1  # Legitimate

    # 7. Number of Subdomains
    def SubDomains(self):
        if not self.extracted_domain:
            # Fallback method
            dot_count = self.domain.count('.')
        else:
            subdomain = self.extracted_domain.subdomain
            if not subdomain:
                dot_count = 0
            else:
                dot_count = subdomain.count('.') + 1
        
        if dot_count <= 1:
            return 1   # Legitimate
        elif dot_count == 2:
            return 0   # Suspicious
        else:
            return -1  # Phishing

    # 8. HTTPS Protocol
    def Https(self):
        if self.urlparse.scheme == 'https':
            # Additional check for valid SSL certificate
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        return 1  # Legitimate HTTPS
            except:
                return 0      # HTTPS but certificate issues
        return -1             # No HTTPS

    # 9. Domain Registration Length
    def DomainRegLen(self):
        try:
            if not self.whois_response:
                return -1
            
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            
            # Handle list format
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if not expiration_date or not creation_date:
                return -1
            
            # Calculate registration period in months
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            
            months = (expiration_date.year - creation_date.year) * 12 + \
                    (expiration_date.month - creation_date.month)
            
            if months >= 12:
                return 1   # Legitimate (registered for 1+ years)
            else:
                return -1  # Suspicious (short registration)
                
        except Exception as e:
            return -1

    # 10. Favicon Analysis
    def Favicon(self):
        try:
            if not self.soup:
                return -1
            
            favicon_links = self.soup.find_all('link', rel=re.compile(r'icon|shortcut icon', re.I))
            
            if not favicon_links:
                return -1  # No favicon found
            
            for link in favicon_links:
                href = link.get('href', '')
                if href:
                    favicon_url = urljoin(self.url, href)
                    favicon_domain = urlparse(favicon_url).netloc.lower()
                    
                    if favicon_domain == self.domain or not favicon_domain:
                        return 1   # Legitimate (same domain)
                    else:
                        return -1  # Suspicious (external domain)
            
            return -1
        except:
            return -1

    # 11. Non Standard Port
    def NonStdPort(self):
        port = self.urlparse.port
        if port and port not in [80, 443, 8080, 8443]:
            return -1  # Suspicious
        return 1       # Legitimate

    # 12. HTTPS in Domain URL
    def HTTPSDomainURL(self):
        if 'https' in self.domain.lower():
            return -1  # Suspicious (HTTPS shouldn't be in domain name)
        return 1       # Legitimate

    # 13. Request URL Analysis
    def RequestURL(self):
        try:
            if not self.soup:
                return 1
            
            total_resources = 0
            external_resources = 0
            
            # Check various resource types
            resource_tags = [
                ('img', 'src'), ('audio', 'src'), ('embed', 'src'),
                ('iframe', 'src'), ('video', 'src'), ('source', 'src'),
                ('link', 'href'), ('script', 'src')
            ]
            
            for tag, attr in resource_tags:
                elements = self.soup.find_all(tag, **{attr: True})
                for element in elements:
                    resource_url = element.get(attr, '')
                    if resource_url:
                        total_resources += 1
                        resource_domain = urlparse(urljoin(self.url, resource_url)).netloc.lower()
                        
                        if resource_domain and resource_domain != self.domain:
                            external_resources += 1
            
            if total_resources == 0:
                return 1
            
            external_percentage = (external_resources / total_resources) * 100
            
            if external_percentage < 22:
                return 1   # Legitimate
            elif external_percentage < 61:
                return 0   # Suspicious
            else:
                return -1  # Phishing
                
        except:
            return -1

    # 14. Anchor URL Analysis
    def AnchorURL(self):
        try:
            if not self.soup:
                return 1
            
            anchors = self.soup.find_all('a', href=True)
            if not anchors:
                return 1
            
            suspicious_anchors = 0
            
            for anchor in anchors:
                href = anchor.get('href', '').lower()
                
                # Check for suspicious patterns
                if (href.startswith('#') or 
                    href.startswith('javascript:') or 
                    href.startswith('mailto:') or
                    href == '' or
                    href == 'about:blank'):
                    suspicious_anchors += 1
                    continue
                
                # Check if external link
                if href.startswith('http'):
                    anchor_domain = urlparse(href).netloc.lower()
                    if anchor_domain != self.domain:
                        suspicious_anchors += 1
            
            suspicious_percentage = (suspicious_anchors / len(anchors)) * 100
            
            if suspicious_percentage < 31:
                return 1   # Legitimate
            elif suspicious_percentage < 67:
                return 0   # Suspicious
            else:
                return -1  # Phishing
                
        except:
            return -1

    # 15. Links in Script Tags
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return 1
            
            total_links = 0
            external_links = 0
            
            # Check link tags
            for link in self.soup.find_all('link', href=True):
                href = link.get('href', '')
                if href:
                    total_links += 1
                    link_domain = urlparse(urljoin(self.url, href)).netloc.lower()
                    if link_domain and link_domain != self.domain:
                        external_links += 1
            
            # Check script tags
            for script in self.soup.find_all('script', src=True):
                src = script.get('src', '')
                if src:
                    total_links += 1
                    script_domain = urlparse(urljoin(self.url, src)).netloc.lower()
                    if script_domain and script_domain != self.domain:
                        external_links += 1
            
            if total_links == 0:
                return 1
            
            external_percentage = (external_links / total_links) * 100
            
            if external_percentage < 17:
                return 1   # Legitimate
            elif external_percentage < 81:
                return 0   # Suspicious
            else:
                return -1  # Phishing
                
        except:
            return -1

    # 16. Server Form Handler
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return 1
            
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            
            for form in forms:
                action = form.get('action', '').lower().strip()
                
                if not action or action == 'about:blank':
                    return -1  # Phishing
                
                if action.startswith('http'):
                    action_domain = urlparse(action).netloc.lower()
                    if action_domain != self.domain:
                        return 0   # Suspicious
            
            return 1  # Legitimate
        except:
            return -1

    # 17. Info Email
    def InfoEmail(self):
        try:
            if not self.soup:
                return 1
            
            # Check for mailto links or email-related JavaScript
            email_patterns = [
                r'mailto:',
                r'mail\s*\(',
                r'email\s*\(',
                r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ]
            
            page_text = self.soup.get_text().lower()
            for pattern in email_patterns:
                if re.search(pattern, page_text, re.IGNORECASE):
                    return -1  # Phishing (suspicious email usage)
            
            return 1  # Legitimate
        except:
            return -1

    # 18. Abnormal URL
    def AbnormalURL(self):
        try:
            if not self.whois_response:
                return -1
            
            # Check if the domain in URL matches WHOIS domain
            registrar_url = getattr(self.whois_response, 'domain_name', '')
            if isinstance(registrar_url, list):
                registrar_url = registrar_url[0] if registrar_url else ''
            
            if registrar_url and self.domain.lower() in registrar_url.lower():
                return 1   # Legitimate
            else:
                return -1  # Suspicious
        except:
            return -1

    # 19. Website Forwarding
    def WebsiteForwarding(self):
        try:
            if not hasattr(self, 'response') or not self.response:
                return -1
            
            redirect_count = len(self.response.history)
            
            if redirect_count <= 1:
                return 1   # Legitimate
            elif redirect_count <= 4:
                return 0   # Suspicious
            else:
                return -1  # Phishing
        except:
            return -1

    # 20. Status Bar Customization
    def StatusBarCust(self):
        try:
            if not self.response:
                return 1
            
            # Look for status bar customization scripts
            suspicious_patterns = [
                r'onmouseover\s*=.*window\.status',
                r'window\.status\s*=',
                r'status\s*=.*return\s+true'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, self.response.text, re.IGNORECASE):
                    return -1  # Phishing
            
            return 1  # Legitimate
        except:
            return -1

    # 21. Disable Right Click
    def DisableRightClick(self):
        try:
            if not self.response:
                return 1
            
            # Look for right-click disabling code
            patterns = [
                r'event\.button\s*==\s*2',
                r'contextmenu.*return\s+false',
                r'oncontextmenu\s*=.*false',
                r'document\.oncontextmenu'
            ]
            
            for pattern in patterns:
                if re.search(pattern, self.response.text, re.IGNORECASE):
                    return -1  # Phishing
            
            return 1  # Legitimate
        except:
            return -1

    # 22. Using Popup Window
    def UsingPopupWindow(self):
        try:
            if not self.response:
                return 1
            
            # Look for popup-related JavaScript
            patterns = [
                r'window\.open\s*\(',
                r'alert\s*\(',
                r'confirm\s*\(',
                r'prompt\s*\(',
                r'showModalDialog'
            ]
            
            for pattern in patterns:
                if re.search(pattern, self.response.text, re.IGNORECASE):
                    return -1  # Phishing
            
            return 1  # Legitimate
        except:
            return -1

    # 23. IFrame Redirection
    def IframeRedirection(self):
        try:
            if not self.soup:
                return 1
            
            iframes = self.soup.find_all('iframe')
            
            if iframes:
                for iframe in iframes:
                    src = iframe.get('src', '')
                    if src:
                        iframe_domain = urlparse(urljoin(self.url, src)).netloc.lower()
                        if iframe_domain and iframe_domain != self.domain:
                            return -1  # Phishing (external iframe)
                
                # Check for invisible iframes
                for iframe in iframes:
                    style = iframe.get('style', '').lower()
                    width = iframe.get('width', '')
                    height = iframe.get('height', '')
                    
                    if ('display:none' in style or 'visibility:hidden' in style or
                        width == '0' or height == '0' or width == '1' or height == '1'):
                        return -1  # Phishing (hidden iframe)
                
                return 0  # Suspicious (has iframes)
            
            return 1  # Legitimate (no iframes)
        except:
            return -1

    # 24. Age of Domain
    def AgeofDomain(self):
        try:
            if not self.whois_response:
                return -1
            
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if not creation_date:
                return -1
            
            # Handle string dates
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d').date()
            elif hasattr(creation_date, 'date'):
                creation_date = creation_date.date()
            
            today = date.today()
            age_months = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            
            if age_months >= 6:
                return 1   # Legitimate (6+ months old)
            else:
                return -1  # Suspicious (very new domain)
        except:
            return -1

    # 25. DNS Recording
    def DNSRecording(self):
        try:
            if not self.domain:
                return -1
            
            # Try to resolve DNS records
            try:
                dns.resolver.resolve(self.domain, 'A')
                dns_exists = True
            except:
                dns_exists = False
            
            # Also check domain age as secondary indicator
            age_result = self.AgeofDomain()
            
            if dns_exists and age_result == 1:
                return 1   # Legitimate
            elif dns_exists:
                return 0   # Suspicious
            else:
                return -1  # Phishing
        except:
            return -1

    # 26. Website Traffic (simplified)
    def WebsiteTraffic(self):
        try:
            # Check for common high-traffic indicators in HTML
            if not self.soup:
                return -1
            
            # Look for analytics tracking codes
            analytics_indicators = [
                'google-analytics.com',
                'googletagmanager.com',
                'facebook.com/tr',
                'google.com/analytics',
                'gtag(',
                'ga(',
                '_gaq.push'
            ]
            
            page_html = str(self.soup).lower()
            analytics_count = sum(1 for indicator in analytics_indicators if indicator in page_html)
            
            if analytics_count >= 2:
                return 1   # Likely legitimate (multiple analytics)
            elif analytics_count == 1:
                return 0   # Possibly legitimate
            else:
                return -1  # Suspicious (no analytics)
        except:
            return -1

    # 27. PageRank (simplified check)
    def PageRank(self):
        try:
            # Check for presence of social media links and established elements
            if not self.soup:
                return -1
            
            social_indicators = [
                'facebook.com',
                'twitter.com',
                'instagram.com',
                'linkedin.com',
                'youtube.com',
                'plus.google.com'
            ]
            
            page_html = str(self.soup).lower()
            social_count = sum(1 for indicator in social_indicators if indicator in page_html)
            
            if social_count >= 3:
                return 1   # Likely established site
            elif social_count >= 1:
                return 0   # Some establishment
            else:
                return -1  # Suspicious
        except:
            return -1

    # 28. Google Index (simplified)
    def GoogleIndex(self):
        try:
            if not self.soup:
                return -1
            # Jika soup tidak mengandung tag <html>, kemungkinan bukan halaman utama
            if not self.soup.find('html'):
                return 1
            # Cek meta robots
            meta_robots = self.soup.find('meta', attrs={'name': 'robots'})
            if meta_robots and 'noindex' in meta_robots.get('content', '').lower():
                return -1
            # Jika tidak ada tag robots noindex, anggap legitimate
            return 1
        except:
            return -1

    # 29. Links Pointing to Page
    def LinksPointingToPage(self):
        try:
            if not self.soup:
                return -1
            
            all_links = self.soup.find_all('a', href=True)
            if not all_links:
                return 1
            
            internal_links = 0
            external_links = 0
            
            for link in all_links:
                href = link.get('href', '').strip()
                if not href or href.startswith('#'):
                    continue
                
                if href.startswith(('http://', 'https://')):
                    link_domain = urlparse(href).netloc.lower()
                    if link_domain == self.domain:
                        internal_links += 1
                    else:
                        external_links += 1
                else:
                    internal_links += 1  # Relative links are internal
            
            total_links = internal_links + external_links
            if total_links == 0:
                return 1
            
            internal_ratio = internal_links / total_links
            
            if internal_ratio >= 0.8:
                return 1   # Legitimate (mostly internal links)
            elif internal_ratio >= 0.4:
                return 0   # Suspicious
            else:
                return -1  # Phishing (too many external links)
        except:
            return -1

    # 30. Statistical Report
    def StatsReport(self):
        try:
            # Check against known phishing hosting services and IPs
            suspicious_hosts = [
                'at.ua', 'usa.cc', 'baltazarpresentes.com.br', 'pe.hu',
                'esy.es', 'hol.es', 'sweddy.com', 'myjino.ru', '96.lt',
                '000webhost.com', 'freehosting.com', 'freehostia.com'
            ]
            
            # Check if domain uses suspicious hosting
            for host in suspicious_hosts:
                if host in self.domain.lower():
                    return -1
            
            # Check IP ranges (simplified)
            try:
                ip = socket.gethostbyname(self.domain)
                # Check for some known suspicious IP ranges
                if ip.startswith(('192.168.', '10.', '172.16.', '127.')):
                    return -1  # Private/local IPs are suspicious for public sites
            except:
                pass
            
            return 1  # Appears legitimate
        except:
            return 1

    # Typosquatting Domain Detection
    def TyposquattingDomain(self):
        try:
            POPULAR_DOMAINS = [
                'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
                'linkedin.com', 'wikipedia.org', 'yahoo.com', 'whatsapp.com', 'amazon.com',
                'tiktok.com', 'paypal.com', 'netflix.com', 'microsoft.com', 'apple.com',
                'office.com', 'bing.com', 'live.com', 'vk.com', 'reddit.com', 'pinterest.com',
                'tumblr.com', 'ebay.com', 'github.com', 'stackoverflow.com', 'dropbox.com',
                'wordpress.com', 'blogspot.com', 'adobe.com', 'imdb.com', 'fandom.com',
                'quora.com', 'slack.com', 'zoom.us', 'canva.com', 'spotify.com', 'telegram.org',
                'medium.com', 'booking.com', 'airbnb.com', 'coursera.org', 'udemy.com',
                'shopee.com', 'tokopedia.com', 'bukalapak.com', 'lazada.com', 'detik.com',
                'kompas.com', 'tribunnews.com', 'liputan6.com', 'cnnindonesia.com', 'kumparan.com'
            ]
            if not self.extracted_domain:
                return 1
            domain = self.extracted_domain.domain + '.' + self.extracted_domain.suffix
            for popular in POPULAR_DOMAINS:
                if Levenshtein.distance(domain, popular) <= 2 and domain != popular:
                    return -1  # Phishing
            return 1  # Legitimate
        except Exception as e:
            return -1

    # --- Fitur Post-Processing ---
    def HasHomoglyphs(self):
        try:
            if not confusables:
                print("⚠️ `confusables` library not found, skipping homoglyph check. Run `pip install confusables`")
                return 1 # Cannot check, assume legitimate
            
            if confusables.is_dangerous(self.domain):
                return -1  # Phishing
            return 1       # Legitimate
        except Exception:
            return -1 # Fail on the side of caution

    def SuspiciousTLD(self):
        try:
            suspicious_tlds = ['.xyz', '.top', '.gq', '.ml', '.cf', '.tk', '.pw', '.work', '.support', '.info']
            if self.extracted_domain and any(self.extracted_domain.suffix.endswith(tld.replace('.', '')) for tld in suspicious_tlds):
                return -1
            return 1
        except:
            return -1

    def ExcessiveSubdomains(self):
        try:
            if not self.extracted_domain:
                return 1
            subdomain = self.extracted_domain.subdomain
            if not subdomain:
                return 1
            dot_count = subdomain.count('.') + 1
            if dot_count >= 3:
                return -1  # Sangat banyak subdomain
            elif dot_count == 2:
                return 0   # Cukup banyak
            else:
                return 1   # Aman
        except:
            return -1

    def SuspiciousKeywordInDomain(self):
        try:
            keywords = ['login', 'secure', 'update', 'verify', 'account', 'banking', 'signin', 'webmail', 'support', 'admin', 'pay', 'confirm', 'auth', 'wallet']
            domain_full = self.domain.lower()
            for kw in keywords:
                if kw in domain_full:
                    return -1
            return 1
        except:
            return -1

    def getFeaturesList(self):
        """Return the extracted features list"""
        return self.features

    def getFeatureNames(self):
        """Return feature names for reference"""
        return [
            'UsingIp', 'longUrl', 'shortUrl', 'symbol', 'redirecting',
            'prefixSuffix', 'SubDomains', 'Https', 'DomainRegLen', 'Favicon',
            'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
            'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
            'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
            'StatsReport', 'TyposquattingDomain', 'HasHomoglyphs'  # Tambahkan nama fitur baru di sini
        ]

    def get_feature_report(self):
        """Return a detailed report of feature analysis"""
        features = self.getFeaturesList()
        feature_names = self.getFeatureNames()
        
        report = []
        for i, (name, value) in enumerate(zip(feature_names, features)):
            status = "Legitimate" if value == 1 else "Suspicious" if value == 0 else "Phishing"
            report.append(f"{i+1:2d}. {name:20s}: {value:2d} ({status})")
        
        return "\n".join(report)