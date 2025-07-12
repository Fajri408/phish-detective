import pandas as pd
from pathlib import Path
import requests
from urllib.parse import urlparse

class WhitelistChecker:
    def __init__(self, whitelist_path="app/data/whitelist.csv"):
        self.whitelist_path = Path(whitelist_path)
        self.whitelist_domains = set()
        self._load_whitelist()
    
    def _load_whitelist(self):
        try:
            if self.whitelist_path.exists():
                df = pd.read_csv(self.whitelist_path)
                # Clean domains: lowercase, strip whitespace, remove trailing slashes
                cleaned_domains = df['domain'].str.lower().str.strip().str.replace(r'/*$', '', regex=True).dropna()
                self.whitelist_domains = set(cleaned_domains)
                print(f"✅ Loaded {len(self.whitelist_domains)} whitelist domains")
            else:
                print("⚠️ Whitelist file not found, creating empty whitelist")
                self._create_default_whitelist()
        except Exception as e:
            print(f"❌ Error loading whitelist: {e}")
    
    def _create_default_whitelist(self):
        """Create default whitelist dengan domain populer"""
        default_domains = [
            'google.com', 'facebook.com', 'youtube.com', 'twitter.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'amazon.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
            'linkedin.com', 'instagram.com', 'whatsapp.com', 'tiktok.com',
            'paypal.com', 'ebay.com', 'reddit.com', 'pinterest.com',
            'wordpress.com', 'blogspot.com', 'medium.com', 'quora.com',
            'shopee.com', 'tokopedia.com', 'bukalapak.com', 'lazada.com',
            'detik.com', 'kompas.com', 'tribunnews.com', 'liputan6.com',
            'cnnindonesia.com', 'kumparan.com', 'merdeka.com', 'tempo.co'
        ]
        
        # Buat direktori jika belum ada
        self.whitelist_path.parent.mkdir(parents=True, exist_ok=True)
        
        df = pd.DataFrame({
            'domain': default_domains,
            'description': ['Default trusted domain'] * len(default_domains)
        })
        df.to_csv(self.whitelist_path, index=False)
        self.whitelist_domains = set(default_domains)
        print(f"✅ Created default whitelist with {len(default_domains)} domains")
    
    def is_whitelisted(self, domain):
        """Cek apakah domain ada di whitelist"""
        return domain.lower() in self.whitelist_domains
    
    def add_domain(self, domain, description="Added manually"):
        """Tambah domain ke whitelist"""
        try:
            domain_clean = domain.lower().strip().rstrip('/')
            
            if not self.whitelist_path.exists():
                df = pd.DataFrame(columns=['domain', 'description'])
            else:
                df = pd.read_csv(self.whitelist_path)
            
            if domain_clean not in self.whitelist_domains:
                new_row = pd.DataFrame({
                    'domain': [domain_clean],
                    'description': [description]
                })
                df = pd.concat([df, new_row], ignore_index=True)
                df.to_csv(self.whitelist_path, index=False)
                self.whitelist_domains.add(domain_clean)
                print(f"✅ Added {domain_clean} to whitelist")
                return True
            else:
                print(f"⚠️ {domain_clean} already in whitelist")
                return False
        except Exception as e:
            print(f"❌ Error adding domain to whitelist: {e}")
            return False
    
    def remove_domain(self, domain):
        """Hapus domain dari whitelist"""
        try:
            domain_clean = domain.lower().strip().rstrip('/')
            if self.whitelist_path.exists():
                df = pd.read_csv(self.whitelist_path)
                df = df[df['domain'].str.lower() != domain_clean]
                df.to_csv(self.whitelist_path, index=False)
                self.whitelist_domains.discard(domain_clean)
                print(f"✅ Removed {domain_clean} from whitelist")
                return True
            return False
        except Exception as e:
            print(f"❌ Error removing domain from whitelist: {e}")
            return False
    
    def get_whitelist(self):
        """Get semua domain di whitelist"""
        try:
            if self.whitelist_path.exists():
                df = pd.read_csv(self.whitelist_path)
                return df.to_dict('records')
            return []
        except Exception as e:
            print(f"❌ Error getting whitelist: {e}")
            return []
    
    def reload_whitelist(self):
        """Reload whitelist dari file"""
        self.whitelist_domains.clear()
        self._load_whitelist() 