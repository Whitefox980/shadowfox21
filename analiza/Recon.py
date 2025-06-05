#!/usr/bin/env python3
"""
ShadowFox21 - Stealth Recon Agent
=================================
Rekonstruisano na bazi stealth_shadow.py arhitekture
Napredni recon agent sa stealth capabilities
"""

import requests
import json
import time
import threading
import random
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import re
from queue import Queue
import argparse
from pathlib import Path
import socket
import ssl
import dns.resolver
import whois
from bs4 import BeautifulSoup
import subprocess
import os
import sys

class StealthReconAgent:
    def __init__(self, target, config=None):
        self.target = self.normalize_target(target)
        self.domain = urlparse(self.target).netloc
        self.config = config or self.default_config()
        
        # Stealth komponente
        self.session = self.create_stealth_session()
        self.user_agents = self.load_user_agents()
        self.proxies = self.config.get('proxies', [])
        self.current_proxy_index = 0
        
        # Recon state
        self.recon_data = {
            'target_info': {},
            'network_info': {},
            'web_analysis': {},
            'technology_stack': {},
            'vulnerabilities': {},
            'stealth_metrics': {}
        }
        
        # Threading
        self.thread_lock = threading.Lock()
        self.active_threads = []
        
        # Logs
        self.logs = []
        self.start_time = time.time()
        
        print(f"🕵️  ShadowFox Stealth Recon Agent initialized")
        print(f"🎯 Target: {self.target}")
        print(f"🌐 Domain: {self.domain}")

    def default_config(self):
        """Default stealth konfiguracija"""
        return {
            'stealth_mode': True,
            'max_threads': 10,
            'request_delay': (1, 3),  # random delay range
            'timeout': 15,
            'max_retries': 3,
            'rotate_user_agents': True,
            'use_proxies': False,
            'deep_scan': True,
            'save_raw_responses': True,
            'follow_redirects': True,
            'verify_ssl': False
        }

    def normalize_target(self, target):
        """Normalizuje target URL"""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        return target.rstrip('/')

    def create_stealth_session(self):
        """Kreira stealth HTTP session"""
        session = requests.Session()
        
        # Stealth headers
        session.headers.update({
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
        
        # SSL/TLS setup
        session.verify = self.config['verify_ssl']
        
        return session

    def load_user_agents(self):
        """Učitava user agent strings"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        return user_agents

    def stealth_request(self, url, method='GET', **kwargs):
        """Pravi stealth HTTP zahtev"""
        if self.config['stealth_mode']:
            # Random delay
            delay_range = self.config['request_delay']
            delay = random.uniform(delay_range[0], delay_range[1])
            time.sleep(delay)
            
            # Rotate User-Agent
            if self.config['rotate_user_agents']:
                self.session.headers['User-Agent'] = random.choice(self.user_agents)
            
            # Proxy rotation (ako su dostupni)
            if self.config['use_proxies'] and self.proxies:
                proxy = self.proxies[self.current_proxy_index % len(self.proxies)]
                kwargs['proxies'] = {'http': proxy, 'https': proxy}
                self.current_proxy_index += 1
        
        try:
            response = self.session.request(
                method, url, 
                timeout=self.config['timeout'],
                **kwargs
            )
            
            self.log_request(url, response.status_code, method)
            return response
            
        except Exception as e:
            self.log_error(f"Request failed for {url}: {str(e)}")
            return None

    def log_request(self, url, status_code, method):
        """Loguje HTTP zahtev"""
        with self.thread_lock:
            self.logs.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'request',
                'method': method,
                'url': url,
                'status_code': status_code
            })

    def log_error(self, message):
        """Loguje greške"""
        with self.thread_lock:
            self.logs.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'error',
                'message': message
            })
            print(f"❌ {message}")

    def log_info(self, message):
        """Loguje informacije"""
        with self.thread_lock:
            self.logs.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'info',
                'message': message
            })
            print(f"ℹ️  {message}")

    # ==================== RECONNAISSANCE MODULES ====================

    def dns_reconnaissance(self):
        """DNS recon modul"""
        self.log_info("Starting DNS reconnaissance...")
        dns_info = {}
        
        try:
            # A records
            try:
                a_records = dns.resolver.resolve(self.domain, 'A')
                dns_info['A'] = [str(record) for record in a_records]
            except:
                dns_info['A'] = []
            
            # AAAA records (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(self.domain, 'AAAA')
                dns_info['AAAA'] = [str(record) for record in aaaa_records]
            except:
                dns_info['AAAA'] = []
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                dns_info['MX'] = [f"{record.preference} {record.exchange}" for record in mx_records]
            except:
                dns_info['MX'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                dns_info['NS'] = [str(record) for record in ns_records]
            except:
                dns_info['NS'] = []
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(self.domain, 'TXT')
                dns_info['TXT'] = [str(record) for record in txt_records]
            except:
                dns_info['TXT'] = []
            
            # CNAME records
            try:
                cname_records = dns.resolver.resolve(self.domain, 'CNAME')
                dns_info['CNAME'] = [str(record) for record in cname_records]
            except:
                dns_info['CNAME'] = []
            
            self.recon_data['network_info']['dns'] = dns_info
            self.log_info(f"DNS records found: {len(dns_info)} types")
            
        except Exception as e:
            self.log_error(f"DNS reconnaissance failed: {str(e)}")

    def whois_reconnaissance(self):
        """WHOIS recon modul"""
        self.log_info("Starting WHOIS reconnaissance...")
        
        try:
            whois_info = whois.whois(self.domain)
            
            whois_data = {
                'domain_name': getattr(whois_info, 'domain_name', None),
                'registrar': getattr(whois_info, 'registrar', None),
                'creation_date': str(getattr(whois_info, 'creation_date', None)),
                'expiration_date': str(getattr(whois_info, 'expiration_date', None)),
                'name_servers': getattr(whois_info, 'name_servers', []),
                'emails': getattr(whois_info, 'emails', []),
                'organization': getattr(whois_info, 'org', None),
                'country': getattr(whois_info, 'country', None)
            }
            
            self.recon_data['network_info']['whois'] = whois_data
            self.log_info("WHOIS data collected")
            
        except Exception as e:
            self.log_error(f"WHOIS reconnaissance failed: {str(e)}")

    def port_scan_basic(self):
        """Basic port scan"""
        self.log_info("Starting basic port scan...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.domain, port))
                
                if result == 0:
                    open_ports.append(port)
                    self.log_info(f"Port {port} is open")
                
                sock.close()
                
            except Exception as e:
                continue
        
        self.recon_data['network_info']['open_ports'] = open_ports
        self.log_info(f"Found {len(open_ports)} open ports")

    def ssl_analysis(self):
        """SSL/TLS analiza"""
        self.log_info("Starting SSL/TLS analysis...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown')
                    }
                    
                    # Subject Alternative Names
                    if 'subjectAltName' in cert:
                        ssl_info['subject_alt_names'] = [name[1] for name in cert['subjectAltName']]
                    
                    self.recon_data['network_info']['ssl'] = ssl_info
                    self.log_info("SSL certificate analyzed")
                    
        except Exception as e:
            self.log_error(f"SSL analysis failed: {str(e)}")

    def web_reconnaissance(self):
        """Web recon modul"""
        self.log_info("Starting web reconnaissance...")
        
        # Glavni GET zahtev
        response = self.stealth_request(self.target)
        if not response:
            return
        
        web_info = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds(),
            'final_url': response.url
        }
        
        # Analiza sadržaja
        if response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta tags
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    meta_tags[name] = content
            
            web_info['meta_tags'] = meta_tags
            web_info['title'] = soup.title.string if soup.title else None
            
            # Links
            links = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(self.target, href)
                if urlparse(absolute_url).netloc == self.domain:
                    links.add(absolute_url)
            
            web_info['internal_links'] = list(links)
            
            # Forms
            forms = []
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': len(form.find_all('input'))
                }
                forms.append(form_info)
            
            web_info['forms'] = forms
            
            # Extract emails, phones
            content_text = response.text
            
            # Email regex
            emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content_text))
            web_info['emails'] = list(emails)
            
            # Phone regex
            phones = set(re.findall(r'\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', content_text))
            web_info['phones'] = list(phones)
        
        self.recon_data['web_analysis'] = web_info
        self.log_info("Web reconnaissance completed")

    def technology_detection(self):
        """Detekcija tehnologija"""
        self.log_info("Starting technology detection...")
        
        technologies = set()
        
        # Header analiza
        if 'web_analysis' in self.recon_data:
            headers = self.recon_data['web_analysis'].get('headers', {})
            
            for header, value in headers.items():
                header_lower = header.lower()
                value_lower = value.lower()
                
                # Server tech
                if header_lower == 'server':
                    technologies.add(f"Server: {value}")
                elif header_lower == 'x-powered-by':
                    technologies.add(f"X-Powered-By: {value}")
                elif 'php' in value_lower:
                    technologies.add("PHP")
                elif 'apache' in value_lower:
                    technologies.add("Apache")
                elif 'nginx' in value_lower:
                    technologies.add("Nginx")
                elif 'cloudflare' in value_lower:
                    technologies.add("Cloudflare")
        
        # Content analiza
        response = self.stealth_request(self.target)
        if response and response.text:
            content_lower = response.text.lower()
            
            tech_patterns = {
                'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
                'Drupal': [r'drupal', r'sites/default'],
                'Joomla': [r'joomla', r'components/com_'],
                'React': [r'react', r'_react'],
                'Angular': [r'angular', r'ng-'],
                'Vue.js': [r'vue\.js', r'vue-'],
                'jQuery': [r'jquery'],
                'Bootstrap': [r'bootstrap'],
                'Google Analytics': [r'google-analytics', r'gtag'],
                'Font Awesome': [r'font-awesome', r'fa-']
            }
            
            for tech_name, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower):
                        technologies.add(tech_name)
                        break
        
        self.recon_data['technology_stack'] = {
            'detected_technologies': list(technologies),
            'count': len(technologies)
        }
        
        self.log_info(f"Detected {len(technologies)} technologies")

    def subdomain_enumeration(self):
        """Subdomain enumeracija"""
        self.log_info("Starting subdomain enumeration...")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 
            'api', 'blog', 'shop', 'store', 'support', 'help',
            'cdn', 'media', 'images', 'static', 'assets',
            'secure', 'portal', 'login', 'panel', 'dashboard'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.domain}"
            
            try:
                dns.resolver.resolve(full_domain, 'A')
                found_subdomains.append(full_domain)
                self.log_info(f"Found subdomain: {full_domain}")
                
            except:
                continue
        
        self.recon_data['network_info']['subdomains'] = found_subdomains
        self.log_info(f"Found {len(found_subdomains)} subdomains")

    def directory_discovery(self):
        """Directory discovery"""
        self.log_info("Starting directory discovery...")
        
        common_dirs = [
            'admin', 'administrator', 'login', 'panel', 'dashboard',
            'wp-admin', 'wp-login', 'phpmyadmin', 'cpanel',
            'backup', 'backups', 'old', 'tmp', 'temp',
            'test', 'dev', 'staging', 'beta',
            'api', 'v1', 'v2', 'rest',
            'images', 'img', 'css', 'js', 'assets',
            'uploads', 'files', 'documents', 'download',
            'config', 'conf', 'configuration'
        ]
        
        found_directories = []
        
        for directory in common_dirs:
            url = f"{self.target}/{directory}/"
            response = self.stealth_request(url)
            
            if response and response.status_code in [200, 301, 302, 403]:
                found_directories.append({
                    'path': f"/{directory}/",
                    'status_code': response.status_code,
                    'size': len(response.content)
                })
                self.log_info(f"Found directory: /{directory}/ ({response.status_code})")
        
        self.recon_data['web_analysis']['directories'] = found_directories
        self.log_info(f"Found {len(found_directories)} directories")

    # ==================== MAIN EXECUTION ====================

    def run_full_reconnaissance(self):
        """Pokreće punu recon analizu"""
        self.log_info("🚀 Starting full stealth reconnaissance...")
        
        # Target info
        self.recon_data['target_info'] = {
            'target_url': self.target,
            'domain': self.domain,
            'scan_start': datetime.now().isoformat(),
            'agent_version': 'ShadowFox21-StealthRecon-v1.0'
        }
        
        # Recon moduli
        recon_modules = [
            ('DNS Reconnaissance', self.dns_reconnaissance),
            ('WHOIS Reconnaissance', self.whois_reconnaissance),
            ('Basic Port Scan', self.port_scan_basic),
            ('SSL Analysis', self.ssl_analysis),
            ('Web Reconnaissance', self.web_reconnaissance),
            ('Technology Detection', self.technology_detection),
            ('Subdomain Enumeration', self.subdomain_enumeration),
            ('Directory Discovery', self.directory_discovery)
        ]
        
        for module_name, module_func in recon_modules:
            try:
                print(f"\n📋 Running: {module_name}")
                module_func()
            except Exception as e:
                self.log_error(f"{module_name} failed: {str(e)}")
        
        # Finalizuj
        end_time = time.time()
        duration = end_time - self.start_time
        
        self.recon_data['target_info']['scan_end'] = datetime.now().isoformat()
        self.recon_data['target_info']['duration_seconds'] = duration
        
        # Stealth metrics
        self.recon_data['stealth_metrics'] = {
            'total_requests': len([log for log in self.logs if log['type'] == 'request']),
            'total_errors': len([log for log in self.logs if log['type'] == 'error']),
            'user_agents_rotations': self.config['rotate_user_agents'],
            'proxy_usage': self.config['use_proxies'],
            'average_delay': sum(self.config['request_delay']) / 2
        }
        
        self.log_info(f"✅ Full reconnaissance completed in {duration:.2f} seconds")
        return True

    def save_report(self, output_dir="reports/recon", filename="recon_report.json"):
        """Čuva JSON izveštaj u navedenom folderu"""

        from pathlib import Path
        import json

        Path(output_dir).mkdir(parents=True, exist_ok=True)  # Kreiraj folder ako ne postoji

        filepath = Path(output_dir) / filename

        final_report = {
            "shadowfox_recon_agent": self.recon_data,
            "execution_logs": self.logs,
            "configuration": self.config
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)

        print(f"💾 Stealth recon report saved: {filepath}")
        return str(filepath)

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Stealth Recon Agent')
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('-o', '--output', default='reports/recon', help='Output directory')
    parser.add_argument('--stealth', action='store_true', default=True, help='Enable stealth mode')
    parser.add_argument('--threads', type=int, default=10, help='Max threads')
    parser.add_argument('--delay', nargs=2, type=float, default=[1, 3], help='Request delay range')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("🕵️  ShadowFox21 - Stealth Reconnaissance Agent")
    print("=" * 80)
    
    # Konfiguracija
    config = {
        'stealth_mode': args.stealth,
        'max_threads': args.threads,
        'request_delay': tuple(args.delay),
        'timeout': 15,
        'max_retries': 3,
        'rotate_user_agents': True,
        'use_proxies': False,
        'deep_scan': True,
        'verify_ssl': False
    }
    
    # Kreira agent
    agent = StealthReconAgent(args.target, config)
    
    try:
        # Pokreće recon
        if agent.run_full_reconnaissance():
            # Čuva izveštaj
            agent.save_report(args.output)
            print(f"\n🎯 Stealth reconnaissance completed successfully!")
        else:
            print(f"\n❌ Reconnaissance failed!")
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Reconnaissance interrupted...")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
