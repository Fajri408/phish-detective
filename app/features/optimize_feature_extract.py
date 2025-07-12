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
import asyncio
import aiohttp
import concurrent.futures
from functools import lru_cache
import threading
import time


class OptimizedFeatureExtraction:
    def __init__(self, url, timeout=5, fast_mode=False):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""
        self.extracted_domain = None
        self.timeout = timeout
        self.fast_mode = fast_mode
        
        # Cache untuk DNS dan IP resolution
        self._dns_cache = {}
        self._ip_cache = {}
        
        # Setup session dengan optimasi
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2 if fast_mode else 3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=0.5 if fast_mode else 1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self._initialize_data()
        self._extract_features_parallel()

    def _initialize_data(self):
        """Initialize data dengan parallel processing"""
        try:
            # Parse URL terlebih dahulu (cepat)
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc.lower()
            self.extracted_domain = tldextract.extract(self.url)
            
            # Parallel execution untuk web scraping dan WHOIS
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                # Submit tasks
                web_future = executor.submit(self._fetch_webpage)
                whois_future = executor.submit(self._fetch_whois) if not self.fast_mode else None
                
                # Get results
                self.response, self.soup = web_future.result()
                if whois_future and not self.fast_mode:
                    self.whois_response = whois_future.result()
                    
        except Exception as e:
            print(f"Error initializing data for {self.url}: {e}")

    def _fetch_webpage(self):
        """Fetch webpage dengan timeout optimized"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            # Gunakan HEAD request dulu untuk cek availability (lebih cepat)
            if self.fast_mode:
                try:
                    head_response = self.session.head(self.url, headers=headers, timeout=2, allow_redirects=True)
                    if head_response.status_code >= 400:
                        return None, None
                except:
                    pass
            
            response = self.session.get(
                self.url, 
                headers=headers, 
                timeout=self.timeout, 
                allow_redirects=True,
                stream=True  # Stream untuk handling large files
            )
            
            # Limit response size untuk mencegah timeout pada file besar
            content = ""
            size_limit = 1024 * 1024 if self.fast_mode else 5 * 1024 * 1024  # 1MB atau 5MB
            
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                content += chunk
                if len(content) > size_limit:
                    break
            
            soup = BeautifulSoup(content, "html.parser")
            return response, soup
            
        except Exception as e:
            print(f"Error fetching webpage: {e}")
            return None, None

    def _fetch_whois(self):
        """Fetch WHOIS dengan timeout dan error handling"""
        try:
            if self.domain and not self._is_ip_address(self.domain):
                # Set timeout untuk WHOIS query
                return whois.whois(self.domain)
        except Exception as e:
            print(f"WHOIS lookup failed for {self.domain}: {e}")
            return None

    @lru_cache(maxsize=128)
    def _is_ip_address(self, domain):
        """Cached IP address check"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    @lru_cache(maxsize=128)
    def _resolve_dns_cached(self, domain):
        """Cached DNS resolution"""
        try:
            return str(dns.resolver.resolve(domain, 'A')[0])
        except:
            return None

    def _extract_features_parallel(self):
        """Extract features dengan parallel processing"""
        # Kategorikan feature berdasarkan dependency
        # URL-based features (cepat, tidak perlu network)
        url_features = [
            self.UsingIp, self.longUrl, self.shortUrl, self.symbol,
            self.redirecting, self.prefixSuffix, self.SubDomains, 
            self.NonStdPort, self.HTTPSDomainURL
        ]
        
        # Network-based features (lambat, perlu network)
        network_features = [
            self.Https, self.DNSRecording
        ]
        
        # Content-based features (medium, perlu HTML)
        content_features = [
            self.Favicon, self.RequestURL, self.AnchorURL, self.LinksInScriptTags,
            self.ServerFormHandler, self.InfoEmail, self.StatusBarCust,
            self.DisableRightClick, self.UsingPopupWindow, self.IframeRedirection,
            self.WebsiteTraffic, self.PageRank, self.GoogleIndex, self.LinksPointingToPage
        ]
        
        # WHOIS-based features (sangat lambat)
        whois_features = [
            self.DomainRegLen, self.AbnormalURL, self.AgeofDomain
        ]
        
        # Response-based features
        response_features = [
            self.WebsiteForwarding, self.StatsReport
        ]
        
        # Execute dalam parallel
        all_results = [None] * 30  # Total 30 features
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            # URL features (cepat)
            for i, method in enumerate(url_features):
                future = executor.submit(self._safe_execute, method)
                futures.append((future, i))
            
            # Network features 
            for i, method in enumerate(network_features):
                future = executor.submit(self._safe_execute, method)
                futures.append((future, i + len(url_features)))
            
            # Content features
            for i, method in enumerate(content_features):
                future = executor.submit(self._safe_execute, method)
                futures.append((future, i + len(url_features) + len(network_features)))
            
            # WHOIS features (skip dalam fast mode)
            if not self.fast_mode:
                for i, method in enumerate(whois_features):
                    future = executor.submit(self._safe_execute, method)
                    futures.append((future, i + len(url_features) + len(network_features) + len(content_features)))
            
            # Response features
            for i, method in enumerate(response_features):
                future = executor.submit(self._safe_execute, method)
                futures.append((future, i + len(url_features) + len(network_features) + len(content_features) + (len(whois_features) if not self.fast_mode else 0)))
            
            # Collect results
            for future, index in futures:
                try:
                    result = future.result(timeout=self.timeout)
                    all_results[index] = result
                except:
                    all_results[index] = -1
        
        # Fill fast mode WHOIS features dengan estimasi
        if self.fast_mode:
            whois_start = len(url_features) + len(network_features) + len(content_features)
            for i in range(len(whois_features)):
                all_results[whois_start + i] = self._estimate_whois_feature(i)
        
        self.features = all_results

    def _safe_execute(self, method):
        """Safely execute feature method dengan timeout"""
        try:
            return method()
        except Exception as e:
            print(f"Error in {method.__name__}: {e}")
            return -1

    def _estimate_whois_feature(self, feature_index):
        """Estimasi WHOIS features untuk fast mode"""
        # Gunakan heuristic sederhana
        if feature_index == 0:  # DomainRegLen
            # Cek apakah domain menggunakan common TLD
            if self.extracted_domain and self.extracted_domain.suffix in ['.com', '.org', '.net', '.edu', '.gov']:
                return 1
            return -1
        elif feature_index == 1:  # AbnormalURL
            return 1 if self.domain else -1
        elif feature_index == 2:  # AgeofDomain
            # Estimasi berdasarkan domain complexity
            if self.extracted_domain and len(self.extracted_domain.domain) > 8:
                return 1
            return -1
        return -1

    # Optimized feature methods (simplified versions of original methods)
    
    def UsingIp(self):
        try:
            domain_clean = self.domain.split(':')[0]
            ipaddress.ip_address(domain_clean)
            return -1
        except ValueError:
            return 1

    def longUrl(self):
        url_length = len(self.url)
        return 1 if url_length < 54 else (0 if url_length <= 75 else -1)

    def shortUrl(self):
        # Shortened service list (most common ones)
        shortening_services = [
            'bit.ly', 'goo.gl', 't.co', 'tinyurl', 'is.gd', 'ow.ly',
            'tiny.cc', 'short.to', 'wp.me', 'bitly.com', 'j.mp'
        ]
        
        for service in shortening_services:
            if service in self.url.lower():
                return -1
        return 1

    def symbol(self):
        return -1 if '@' in self.url else 1

    def redirecting(self):
        protocol_end = self.url.find('://') + 3
        if protocol_end > 2:
            remaining_url = self.url[protocol_end:]
            if '//' in remaining_url:
                return -1
        return 1

    def prefixSuffix(self):
        if not self.extracted_domain:
            return -1
        domain_parts = self.extracted_domain.domain
        return -1 if '-' in domain_parts else 1

    def SubDomains(self):
        if not self.extracted_domain:
            dot_count = self.domain.count('.')
        else:
            subdomain = self.extracted_domain.subdomain
            dot_count = subdomain.count('.') + 1 if subdomain else 0
        
        return 1 if dot_count <= 1 else (0 if dot_count == 2 else -1)

    def Https(self):
        if self.urlparse.scheme == 'https':
            # Quick SSL check (simplified)
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.domain, 443), timeout=2) as sock:
                    with context.wrap_socket(sock) as ssock:
                        return 1
            except:
                return 0
        return -1

    def NonStdPort(self):
        port = self.urlparse.port
        return -1 if port and port not in [80, 443, 8080, 8443] else 1

    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain.lower() else 1

    # Simplified content-based features
    def Favicon(self):
        if not self.soup:
            return -1
        
        favicon_links = self.soup.find_all('link', rel=re.compile(r'icon', re.I), limit=3)
        if not favicon_links:
            return -1
        
        for link in favicon_links:
            href = link.get('href', '')
            if href and not href.startswith('http'):
                return 1  # Relative path = same domain
            elif href:
                favicon_domain = urlparse(href).netloc.lower()
                if favicon_domain == self.domain:
                    return 1
        return -1

    def RequestURL(self):
        if not self.soup:
            return 1
        
        # Quick sampling instead of checking all resources
        sample_tags = self.soup.find_all(['img', 'script', 'link'], limit=20)
        if not sample_tags:
            return 1
        
        external_count = 0
        for tag in sample_tags:
            src = tag.get('src') or tag.get('href', '')
            if src and src.startswith('http'):
                resource_domain = urlparse(src).netloc.lower()
                if resource_domain != self.domain:
                    external_count += 1
        
        external_percentage = (external_count / len(sample_tags)) * 100
        return 1 if external_percentage < 22 else (0 if external_percentage < 61 else -1)

    def AnchorURL(self):
        if not self.soup:
            return 1
        
        # Sample anchors instead of all
        anchors = self.soup.find_all('a', href=True, limit=15)
        if not anchors:
            return 1
        
        suspicious_count = 0
        for anchor in anchors:
            href = anchor.get('href', '').lower().strip()
            if (href.startswith('#') or href.startswith('javascript:') or 
                href.startswith('mailto:') or href == ''):
                suspicious_count += 1
            elif href.startswith('http'):
                anchor_domain = urlparse(href).netloc.lower()
                if anchor_domain != self.domain:
                    suspicious_count += 1
        
        suspicious_percentage = (suspicious_count / len(anchors)) * 100
        return 1 if suspicious_percentage < 31 else (0 if suspicious_percentage < 67 else -1)

    def LinksInScriptTags(self):
        if not self.soup:
            return 1
        
        # Quick check for external scripts
        scripts = self.soup.find_all('script', src=True, limit=10)
        if not scripts:
            return 1
        
        external_count = sum(1 for script in scripts 
                           if script.get('src', '').startswith('http') and 
                           urlparse(script.get('src', '')).netloc.lower() != self.domain)
        
        external_percentage = (external_count / len(scripts)) * 100
        return 1 if external_percentage < 17 else (0 if external_percentage < 81 else -1)

    def ServerFormHandler(self):
        if not self.soup:
            return 1
        
        forms = self.soup.find_all('form', action=True, limit=5)
        for form in forms:
            action = form.get('action', '').lower().strip()
            if not action or action == 'about:blank':
                return -1
            if action.startswith('http') and urlparse(action).netloc.lower() != self.domain:
                return 0
        return 1

    def InfoEmail(self):
        if not self.soup:
            return 1
        
        # Quick text search
        page_text = self.soup.get_text()[:5000]  # Limit text search
        if re.search(r'mailto:|@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', page_text, re.IGNORECASE):
            return -1
        return 1

    def AbnormalURL(self):
        # Simplified check without WHOIS
        return 1 if self.domain else -1

    def WebsiteForwarding(self):
        if not hasattr(self, 'response') or not self.response:
            return -1
        
        redirect_count = len(self.response.history)
        return 1 if redirect_count <= 1 else (0 if redirect_count <= 4 else -1)

    def StatusBarCust(self):
        if not self.response:
            return 1
        
        # Quick regex search in limited content
        content_sample = self.response.text[:10000]
        if re.search(r'window\.status\s*=|onmouseover.*status', content_sample, re.IGNORECASE):
            return -1
        return 1

    def DisableRightClick(self):
        if not self.response:
            return 1
        
        content_sample = self.response.text[:10000]
        if re.search(r'contextmenu.*false|oncontextmenu.*false', content_sample, re.IGNORECASE):
            return -1
        return 1

    def UsingPopupWindow(self):
        if not self.response:
            return 1
        
        content_sample = self.response.text[:10000]
        if re.search(r'window\.open\s*\(|alert\s*\(', content_sample, re.IGNORECASE):
            return -1
        return 1

    def IframeRedirection(self):
        if not self.soup:
            return 1
        
        iframes = self.soup.find_all('iframe', limit=5)
        if not iframes:
            return 1
        
        for iframe in iframes:
            src = iframe.get('src', '')
            if src and urlparse(src).netloc.lower() != self.domain:
                return -1
            
            # Check for hidden iframes
            style = iframe.get('style', '').lower()
            width = iframe.get('width', '')
            height = iframe.get('height', '')
            if ('display:none' in style or width in ['0', '1'] or height in ['0', '1']):
                return -1
        
        return 0

    def AgeofDomain(self):
        # Simplified estimation without WHOIS
        if self.extracted_domain:
            domain_name = self.extracted_domain.domain
            # Heuristic: longer domain names tend to be older
            if len(domain_name) > 10 and self.extracted_domain.suffix in ['.com', '.org', '.net']:
                return 1
        return -1

    def DNSRecording(self):
        try:
            self._resolve_dns_cached(self.domain)
            return 1
        except:
            return -1

    def WebsiteTraffic(self):
        if not self.soup:
            return -1
        
        # Quick check for analytics
        analytics_indicators = ['google-analytics.com', 'gtag(', 'ga(']
        page_html = str(self.soup)[:15000].lower()
        
        analytics_count = sum(1 for indicator in analytics_indicators if indicator in page_html)
        return 1 if analytics_count >= 1 else -1

    def PageRank(self):
        if not self.soup:
            return -1
        
        # Quick social media check
        social_indicators = ['facebook.com', 'twitter.com', 'instagram.com']
        page_html = str(self.soup)[:15000].lower()
        
        social_count = sum(1 for indicator in social_indicators if indicator in page_html)
        return 1 if social_count >= 1 else -1

    def GoogleIndex(self):
        if not self.soup:
            return -1
        
        # Quick Google elements check
        head = self.soup.find('head')
        if head and 'google' in str(head).lower():
            return 1
        return -1

    def LinksPointingToPage(self):
        if not self.soup:
            return -1
        
        # Sample links
        all_links = self.soup.find_all('a', href=True, limit=20)
        if not all_links:
            return 1
        
        internal_links = sum(1 for link in all_links 
                           if not link.get('href', '').startswith('http') or 
                           urlparse(link.get('href', '')).netloc.lower() == self.domain)
        
        internal_ratio = internal_links / len(all_links)
        return 1 if internal_ratio >= 0.6 else (0 if internal_ratio >= 0.3 else -1)

    def StatsReport(self):
        # Quick suspicious hosting check
        suspicious_hosts = ['at.ua', 'usa.cc', '000webhost.com', 'freehosting.com']
        for host in suspicious_hosts:
            if host in self.domain.lower():
                return -1
        return 1

    def DomainRegLen(self):
        # Simplified without WHOIS
        if self.extracted_domain and self.extracted_domain.suffix in ['.com', '.org', '.net', '.edu', '.gov']:
            return 1
        return -1

    def getFeaturesList(self):
        return self.features

    def getFeatureNames(self):
        return [
            'UsingIp', 'longUrl', 'shortUrl', 'symbol', 'redirecting',
            'prefixSuffix', 'SubDomains', 'Https', 'DomainRegLen', 'Favicon',
            'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
            'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
            'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
            'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
            'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
            'StatsReport'
        ]

    def get_feature_report(self):
        features = self.getFeaturesList()
        feature_names = self.getFeatureNames()
        
        report = []
        for i, (name, value) in enumerate(zip(feature_names, features)):
            status = "Legitimate" if value == 1 else "Suspicious" if value == 0 else "Phishing"
            report.append(f"{i+1:2d}. {name:20s}: {value:2d} ({status})")
        
        return "\n".join(report)


