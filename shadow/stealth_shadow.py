#!/usr/bin/env python3
"""
ShadowFox21 - Stealth Traffic Shadow Module
==========================================
Nezavisan modul za simulaciju ljudskog ponašanja i stealth traffic
Sa H1: Whitefox980 header funkcionalnostima
"""

import requests
import json
import time
import random
import threading
from datetime import datetime
import argparse
from pathlib import Path
import base64
from urllib.parse import urlparse
import hashlib
import secrets

class StealthTrafficShadow:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.session = requests.Session()
        self.setup_session()
        
        # Stealth parametri
        self.user_agents = self.load_user_agents()
        self.behavior_patterns = self.load_behavior_patterns()
        self.proxy_pool = self.config.get('proxy_pool', [])
        self.current_proxy_index = 0
        
        # Whitefox980 specifics
        self.whitefox_mode = False
        self.whitefox_username = None
        self.whitefox_header_variants = [
            'H1: Whitefox980',
            'X-H1: Whitefox980',
            'Authorization: Whitefox980',
            'X-Whitefox: 980',
            'Custom-H1: Whitefox980'
        ]
        
        # Traffic shadow statistike
        self.requests_made = 0
        self.stealth_score = 100
        self.detection_alerts = []
        
        print(f"👤 Stealth Traffic Shadow inicijalizovan")
        print(f"🎭 User agents: {len(self.user_agents)}")
        print(f"🔄 Proxy pool: {len(self.proxy_pool)}")
        print(f"🦊 Whitefox mode: {'ENABLED' if self.whitefox_mode else 'DISABLED'}")

    def load_config(self, config_file):
        """Učitava konfiguraciju"""
        default_config = {
            'delay_range': [1.0, 5.0],
            'human_behavior': True,
            'rotate_user_agents': True,
            'rotate_proxies': False,
            'whitefox_mode': False,
            'whitefox_username': None,
            'stealth_level': 'high',
            'max_requests_per_session': 100,
            'session_cooldown': 300,
            'proxy_pool': []
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
                print(f"📂 Konfiguracija učitana iz: {config_file}")
            except Exception as e:
                print(f"⚠️  Greška pri učitavanju config: {e}")
        
        return default_config

    def load_user_agents(self):
        """Učitava realistic user agents"""
        return [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
            
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            
            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            
            # Mobile
            'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        ]

    def load_behavior_patterns(self):
        """Učitava human behavior patterns"""
        return {
            'casual_browsing': {
                'delay_range': [2.0, 8.0],
                'burst_probability': 0.1,
                'pause_probability': 0.3,
                'back_forth_probability': 0.2
            },
            'focused_research': {
                'delay_range': [0.5, 3.0],
                'burst_probability': 0.3,
                'pause_probability': 0.1,
                'back_forth_probability': 0.4
            },
            'automated_testing': {
                'delay_range': [0.1, 1.0],
                'burst_probability': 0.7,
                'pause_probability': 0.05,
                'back_forth_probability': 0.1
            }
        }

    def setup_session(self):
        """Postavlja session sa stealth parametrima"""
        # Osnovni headers
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })
        
        # Random user agent
        if self.config['rotate_user_agents']:
            self.rotate_user_agent()

    def enable_whitefox_mode(self, username=None):
        """Aktivira Whitefox980 mode"""
        self.whitefox_mode = True
        self.whitefox_username = username or f"whitefox_{secrets.token_hex(4)}"
        print(f"🦊 Whitefox980 mode AKTIVIRAN - Username: {self.whitefox_username}")

    def disable_whitefox_mode(self):
        """Deaktivira Whitefox980 mode"""
        self.whitefox_mode = False
        self.whitefox_username = None
        print(f"🦊 Whitefox980 mode DEAKTIVIRAN")

    def get_whitefox_headers(self):
        """Generiše Whitefox980 headers"""
        headers = {}
        
        if self.whitefox_mode:
            # Glavni Whitefox header
            main_header = random.choice(self.whitefox_header_variants)
            if ':' in main_header:
                key, value = main_header.split(':', 1)
                headers[key.strip()] = value.strip()
                
                # Dodaje username ako je specificiran
                if self.whitefox_username:
                    if 'Authorization' in key:
                        headers[key.strip()] = f"Whitefox980 user={self.whitefox_username}"
                    else:
                        headers[f"{key.strip()}-User"] = self.whitefox_username
            
            # Dodatni whitefox specifični headers
            whitefox_extras = random.choice([
                {'X-Test-Mode': 'whitefox980'},
                {'X-Scanner-ID': f"wf980_{secrets.token_hex(3)}"},
                {'X-Penetration-Test': 'authorized'},
                {'X-Bug-Hunter': self.whitefox_username or 'whitefox980'},
                {}  # Ponekad bez dodatnih
            ])
            
            headers.update(whitefox_extras)
        
        return headers

    def rotate_user_agent(self):
        """Rotira user agent"""
        new_ua = random.choice(self.user_agents)
        self.session.headers['User-Agent'] = new_ua
        return new_ua

    def rotate_proxy(self):
        """Rotira proxy"""
        if self.proxy_pool and self.config['rotate_proxies']:
            proxy = self.proxy_pool[self.current_proxy_index]
            self.session.proxies = {'http': proxy, 'https': proxy}
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_pool)
            return proxy
        return None

    def calculate_human_delay(self, pattern='casual_browsing'):
        """Kalkuliše human-like delay"""
        behavior = self.behavior_patterns.get(pattern, self.behavior_patterns['casual_browsing'])
        
        # Osnovno kašnjenje
        base_delay = random.uniform(*behavior['delay_range'])
        
        # Burst behavior (brže kucanje)
        if random.random() < behavior['burst_probability']:
            base_delay *= 0.3
        
        # Pause behavior (dužu pauzu)
        elif random.random() < behavior['pause_probability']:
            base_delay *= random.uniform(2.0, 5.0)
        
        return base_delay

    def simulate_human_behavior(self, url, pattern='casual_browsing'):
        """Simulira ljudsko ponašanje pre request-a"""
        behavior = self.behavior_patterns.get(pattern, self.behavior_patterns['casual_browsing'])
        
        # Možda ode nazad i napred
        if random.random() < behavior['back_forth_probability']:
            # Simulira "slučajan" referer
            fake_referers = [
                'https://www.google.com/search?q=' + urlparse(url).netloc,
                'https://duckduckgo.com/?q=' + urlparse(url).netloc,
                urlparse(url).scheme + '://' + urlparse(url).netloc,
            ]
            self.session.headers['Referer'] = random.choice(fake_referers)
        
        # Random dodatni headers
        if random.random() < 0.3:
            random_headers = random.choice([
                {'DNT': '1'},
                {'X-Requested-With': 'XMLHttpRequest'},
                {'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"},
                {}
            ])
            self.session.headers.update(random_headers)

    def make_stealth_request(self, method='GET', url=None, **kwargs):
        """Pravi stealth request sa human behavior"""
        if not url:
            raise ValueError("URL je obavezan")
        
        # Simulira human behavior
        pattern = kwargs.pop('behavior_pattern', 'casual_browsing')
        self.simulate_human_behavior(url, pattern)
        
        # Dodaje whitefox headers ako je potrebno
        request_headers = kwargs.get('headers', {})
        if self.whitefox_mode:
            whitefox_headers = self.get_whitefox_headers()
            request_headers.update(whitefox_headers)
            kwargs['headers'] = request_headers
        
        # Rotira user agent i proxy ponekad
        if random.random() < 0.1:  # 10% šanse
            self.rotate_user_agent()
        
        if random.random() < 0.05:  # 5% šanse
            self.rotate_proxy()
        
        # Human delay
        delay = self.calculate_human_delay(pattern)
        if self.requests_made > 0:  # Ne kašnji na prvi request
            time.sleep(delay)
        
        try:
            # Pravi request
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = self.session.post(url, **kwargs)
            elif method.upper() == 'PUT':
                response = self.session.put(url, **kwargs)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, **kwargs)
            else:
                response = self.session.request(method, url, **kwargs)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # Statistike
            self.requests_made += 1
            
            # Proverava detection signale
            self.check_detection_signals(response, response_time)
            
            # Request info za debug
            request_info = {
                'method': method.upper(),
                'url': url,
                'status_code': response.status_code,
                'response_time': response_time,
                'whitefox_mode': self.whitefox_mode,
                'whitefox_headers': self.get_whitefox_headers() if self.whitefox_mode else {},
                'user_agent': self.session.headers.get('User-Agent', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            # Dodaje request info u response objekat
            response.stealth_info = request_info
            
            return response
            
        except Exception as e:
            self.detection_alerts.append({
                'type': 'request_error',
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            raise

    def check_detection_signals(self, response, response_time):
        """Proverava signale detekcije"""
        # Brz response može biti bot detekcija
        if response_time < 0.1:
            self.stealth_score -= 5
            self.detection_alerts.append({
                'type': 'fast_response',
                'response_time': response_time,
                'timestamp': datetime.now().isoformat()
            })
        
        # Status kodovi koji mogu označavati detekciju
        suspicious_codes = [429, 403, 406, 418]
        if response.status_code in suspicious_codes:
            self.stealth_score -= 10
            self.detection_alerts.append({
                'type': 'suspicious_status',
                'status_code': response.status_code,
                'timestamp': datetime.now().isoformat()
            })
        
        # Captcha detekcija
        if response.text and any(keyword in response.text.lower() for keyword in ['captcha', 'cloudflare', 'bot protection']):
            self.stealth_score -= 20
            self.detection_alerts.append({
                'type': 'captcha_detected',
                'timestamp': datetime.now().isoformat()
            })

    def get_stealth_report(self):
        """Generiše stealth report"""
        return {
            'module': 'stealth_traffic_shadow',
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'requests_made': self.requests_made,
                'stealth_score': self.stealth_score,
                'detection_alerts': len(self.detection_alerts)
            },
            'whitefox_mode': {
                'enabled': self.whitefox_mode,
                'username': self.whitefox_username,
                'header_variants': self.whitefox_header_variants
            },
            'detection_alerts': self.detection_alerts,
            'configuration': self.config
        }

    def save_config(self, filename='stealth_config.json'):
        """Čuva trenutnu konfiguraciju"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
        print(f"💾 Konfiguracija sačuvana: {filename}")

# Decorator za easy import u druge module
def stealth_request(stealth_shadow=None, whitefox_mode=False, whitefox_username=None):
    """Decorator za stealth requests u drugim modulima"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Kreira stealth shadow ako nije prosleđen
            if stealth_shadow is None:
                shadow = StealthTrafficShadow()
            else:
                shadow = stealth_shadow
            
            # Aktivira whitefox ako je potrebno
            if whitefox_mode:
                shadow.enable_whitefox_mode(whitefox_username)
            
            # Zamenjuje requests sa stealth requests
            original_requests = kwargs.get('requests_session')
            kwargs['stealth_shadow'] = shadow
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Stealth Traffic Shadow Module')
    parser.add_argument('--config', help='Config JSON file')
    parser.add_argument('--test-url', help='Test URL for stealth request')
    parser.add_argument('--whitefox', action='store_true', help='Enable Whitefox980 mode')
    parser.add_argument('--username', help='Whitefox username')
    parser.add_argument('--pattern', choices=['casual_browsing', 'focused_research', 'automated_testing'], 
                       default='casual_browsing', help='Behavior pattern')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("👤 ShadowFox21 - Stealth Traffic Shadow Module")
    print("=" * 60)
    
    # Kreira stealth shadow
    shadow = StealthTrafficShadow(args.config)
    
    # Aktivira whitefox mode ako je potrebno
    if args.whitefox:
        shadow.enable_whitefox_mode(args.username)
    
    # Test request ako je URL dat
    if args.test_url:
        print(f"\n🎯 Test request na: {args.test_url}")
        try:
            response = shadow.make_stealth_request('GET', args.test_url, behavior_pattern=args.pattern)
            print(f"✅ Response: {response.status_code}")
            print(f"📊 Stealth info: {json.dumps(response.stealth_info, indent=2)}")
        except Exception as e:
            print(f"❌ Greška: {e}")
    
    # Prikazuje report
    report = shadow.get_stealth_report()
    print(f"\n📊 Stealth Report:")
    print(f"   • Requests made: {report['statistics']['requests_made']}")
    print(f"   • Stealth score: {report['statistics']['stealth_score']}/100")
    print(f"   • Detection alerts: {report['statistics']['detection_alerts']}")
    print(f"   • Whitefox mode: {'ON' if report['whitefox_mode']['enabled'] else 'OFF'}")

if __name__ == "__main__":
    main()
