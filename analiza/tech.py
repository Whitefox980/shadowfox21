
#!/usr/bin/env python3
"""
ShadowFox21 - Technology Analyzer Module
========================================
Duboka analiza tehnologija na osnovu recon podataka
Detektuje verzije, konfiguracije, vulnerabilities i generiše tech fingerprint
"""

import requests
import json
import time
import threading
from urllib.parse import urlparse, urljoin
from datetime import datetime
import re
import argparse
from pathlib import Path
import hashlib
import base64
from queue import Queue
import os
import glob

def get_latest_recon_json():
    """Vraća najnoviji recon JSON iz reports/recon foldera"""
    recon_folder = "reports/recon"
    json_files = glob.glob(os.path.join(recon_folder, "*.json"))
    if not json_files:
        print("❌ Nema JSON izveštaja u reports/recon folderu.")
        return None
    latest_file = max(json_files, key=os.path.getmtime)
    print(f"📂 Uzimam najnoviji Recon izveštaj: {latest_file}")
    return latest_file


class TechnologyAnalyzer:
    def __init__(self,input_json=None, threads=8, delay=0.3):
        self.threads = threads
        self.delay = delay
        self.input_json = input_json
        # Analysis state
        self.detected_technologies = {}
        self.version_fingerprints = {}
        self.security_headers = {}
        self.server_info = {}
        self.cms_details = {}
        self.framework_analysis = {}
        self.vulnerability_indicators = []
        self.tech_mutations = []
        self.errors = []
        
        # Threading
        self.analysis_queue = Queue()
        self.lock = threading.Lock()
        self.threads = threads
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; TechAnalyzer/1.0)'
        })
        
        # Load fingerprint databases
        self.fingerprints = self.load_fingerprint_database()
        self.vulnerability_db = self.load_vulnerability_patterns()
        
        print(f"🔍 Technology Analyzer inicijalizovan")


    def load_recon_data(self):
        """Učitava podatke iz poslednjeg recon JSON fajla"""
        input_path = self.input_json or get_latest_recon_json()
        if input_path is None:
            return None
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"📑 Učitani recon podaci iz: {input_path}")
            print(f"  • URLs: {len(data.get('results', {}).get('urls', []))}")
            print(f"  • Technologies: {len(data.get('results', {}).get('technology_stack', []))}")
            return data
        except Exception as e:
            print(f"❌ Greška pri učitavanju: {e}")
            return None
    def load_fingerprint_database(self):
        """Učitava fingerprint bazu za detekciju tehnologija"""
        fingerprints = {
            'cms': {
                'WordPress': {
                    'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php'],
                    'headers': ['x-pingback'],
                    'meta_tags': ['generator.*wordpress'],
                    'cookies': ['wordpress_', 'wp-'],
                    'body_patterns': ['wp-content', 'wp-includes', '/wp-json/']
                },
                'Drupal': {
                    'paths': ['/sites/default/', '/modules/', '/themes/', '/misc/drupal.js'],
                    'headers': ['x-drupal-cache', 'x-generator'],
                    'meta_tags': ['generator.*drupal'],
                    'cookies': ['SESS', 'SSESS'],
                    'body_patterns': ['Drupal.settings', '/sites/all/']
                },
                'Joomla': {
                    'paths': ['/administrator/', '/components/', '/modules/', '/templates/'],
                    'headers': [],
                    'meta_tags': ['generator.*joomla'],
                    'cookies': [],
                    'body_patterns': ['joomla', '/media/system/js/']
                },
                'Magento': {
                    'paths': ['/app/', '/skin/', '/js/mage/', '/media/'],
                    'headers': [],
                    'meta_tags': [],
                    'cookies': ['frontend'],
                    'body_patterns': ['Mage.Cookies', '/skin/frontend/']
                }
            },
            'frameworks': {
                'React': {
                    'body_patterns': ['react', '_react', 'ReactDOM', 'react-dom'],
                    'js_files': ['react.js', 'react.min.js', 'react-dom.js'],
                    'attributes': ['data-reactroot', 'data-react-helmet']
                },
                'Angular': {
                    'body_patterns': ['angular', 'ng-app', 'ng-controller', 'ng-'],
                    'js_files': ['angular.js', 'angular.min.js'],
                    'attributes': ['ng-app', 'ng-controller', 'ng-model']
                },
                'Vue.js': {
                    'body_patterns': ['vue', 'v-if', 'v-for', 'v-model'],
                    'js_files': ['vue.js', 'vue.min.js'],
                    'attributes': ['v-if', 'v-for', 'v-show']
                },
                'jQuery': {
                    'body_patterns': ['jquery', '\\$\\(', 'jQuery'],
                    'js_files': ['jquery.js', 'jquery.min.js', 'jquery-'],
                    'attributes': []
                },
                'Bootstrap': {
                    'body_patterns': ['bootstrap', 'btn-', 'col-', 'container-'],
                    'css_files': ['bootstrap.css', 'bootstrap.min.css'],
                    'attributes': ['class.*bootstrap', 'class.*btn-']
                }
            },
            'servers': {
                'Apache': {
                    'headers': ['server.*apache'],
                    'error_pages': ['Apache/.*Server at'],
                    'config_files': ['.htaccess', 'httpd.conf']
                },
                'Nginx': {
                    'headers': ['server.*nginx'],
                    'error_pages': ['nginx/'],
                    'config_files': ['nginx.conf']
                },
                'IIS': {
                    'headers': ['server.*iis', 'x-aspnet-version'],
                    'error_pages': ['Internet Information Services'],
                    'config_files': ['web.config']
                }
            },
            'languages': {
                'PHP': {
                    'extensions': ['.php', '.php3', '.php4', '.php5', '.phtml'],
                    'headers': ['x-powered-by.*php'],
                    'cookies': ['PHPSESSID'],
                    'body_patterns': ['<?php', 'php?']
                },
                'ASP.NET': {
                    'extensions': ['.aspx', '.ashx', '.asmx'],
                    'headers': ['x-aspnet-version', 'x-powered-by.*asp.net'],
                    'cookies': ['ASP.NET_SessionId'],
                    'body_patterns': ['__VIEWSTATE', '__EVENTVALIDATION']
                },
                'JSP': {
                    'extensions': ['.jsp', '.jsf', '.jspx'],
                    'headers': [],
                    'cookies': ['JSESSIONID'],
                    'body_patterns': ['<%', '%>']
                },
                'Python': {
                    'extensions': ['.py'],
                    'headers': ['server.*python', 'x-powered-by.*python'],
                    'cookies': [],
                    'body_patterns': []
                }
            }
        }
        
        return fingerprints

    def load_vulnerability_patterns(self):
        """Učitava poznate vulnerability patterns"""
        return {
            'version_disclosure': [
                r'Apache/([0-9.]+)',
                r'nginx/([0-9.]+)',
                r'WordPress ([0-9.]+)',
                r'Drupal ([0-9.]+)',
                r'jQuery ([0-9.]+)',
                r'PHP/([0-9.]+)'
            ],
            'sensitive_files': [
                '/.git/', '/admin/', '/administrator/', '/wp-admin/',
                '/phpmyadmin/', '/backup/', '/config/', '/test/',
                '/.env', '/debug/', '/staging/', '/dev/'
            ],
            'security_headers': [
                'x-frame-options', 'x-xss-protection', 'x-content-type-options',
                'strict-transport-security', 'content-security-policy',
                'x-permitted-cross-domain-policies'
            ],
            'information_disclosure': [
                'x-powered-by', 'server', 'x-aspnet-version',
                'x-generator', 'x-drupal-cache'
            ]
        }

    def analyze_headers(self, url):
        """Analizira HTTP headers za tech detection"""
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            
            tech_info = {
                'server_info': {},
                'security_headers': {},
                'framework_headers': {},
                'version_info': {}
            }
            
            # Server info
            if 'server' in headers:
                tech_info['server_info']['server'] = headers['server']
                
                # Extract server version
                for pattern in self.vulnerability_db['version_disclosure']:
                    match = re.search(pattern, headers['server'], re.IGNORECASE)
                    if match:
                        tech_info['version_info'][match.group().split('/')[0]] = match.group(1)
            
            # Security headers
            for header_name in self.vulnerability_db['security_headers']:
                if header_name in headers:
                    tech_info['security_headers'][header_name] = headers[header_name]
            
            # Information disclosure headers
            for header_name in self.vulnerability_db['information_disclosure']:
                if header_name in headers:
                    tech_info['framework_headers'][header_name] = headers[header_name]
            
            return tech_info
            
        except Exception as e:
            return {'error': str(e)}

    def analyze_content(self, url):
        """Analizira sadržaj stranice za tech detection"""
        try:
            response = self.session.get(url, timeout=15)
            content = response.text.lower()
            
            detected_tech = {
                'cms': [],
                'frameworks': [],
                'libraries': [],
                'languages': []
            }
            
            # CMS Detection
            for cms_name, cms_data in self.fingerprints['cms'].items():
                score = 0
                evidence = []
                
                # Check body patterns
                for pattern in cms_data['body_patterns']:
                    if re.search(pattern, content):
                        score += 2
                        evidence.append(f"Body pattern: {pattern}")
                
                # Check meta tags
                for pattern in cms_data['meta_tags']:
                    if re.search(pattern, content):
                        score += 3
                        evidence.append(f"Meta tag: {pattern}")
                
                if score >= 2:
                    detected_tech['cms'].append({
                        'name': cms_name,
                        'confidence': min(score * 20, 100),
                        'evidence': evidence
                    })
            
            # Framework Detection
            for fw_name, fw_data in self.fingerprints['frameworks'].items():
                score = 0
                evidence = []
                
                for pattern in fw_data['body_patterns']:
                    if re.search(pattern, content):
                        score += 1
                        evidence.append(f"Pattern: {pattern}")
                
                if score >= 1:
                    detected_tech['frameworks'].append({
                        'name': fw_name,
                        'confidence': min(score * 30, 100),
                        'evidence': evidence
                    })
            
            # Language Detection
            for lang_name, lang_data in self.fingerprints['languages'].items():
                score = 0
                evidence = []
                
                for pattern in lang_data['body_patterns']:
                    if pattern and re.search(pattern, content):
                        score += 2
                        evidence.append(f"Code pattern: {pattern}")
                
                # Check for file extensions in URLs
                for ext in lang_data['extensions']:
                    if ext in url:
                        score += 3
                        evidence.append(f"File extension: {ext}")
                
                if score >= 2:
                    detected_tech['languages'].append({
                        'name': lang_name,
                        'confidence': min(score * 25, 100),
                        'evidence': evidence
                    })
            
            return detected_tech
            
        except Exception as e:
            return {'error': str(e)}

    def probe_technology_files(self, base_url, tech_name):
        """Proverava postojanje specifičnih tech fajlova"""
        probes = {
            'WordPress': [
                '/wp-admin/admin-ajax.php',
                '/wp-json/wp/v2/',
                '/wp-content/themes/',
                '/wp-includes/js/jquery/',
                '/readme.html',
                '/wp-config.php.bak'
            ],
            'Drupal': [
                '/sites/default/files/',
                '/misc/drupal.js',
                '/CHANGELOG.txt',
                '/modules/system/',
                '/core/misc/drupal.js'
            ],
            'Joomla': [
                '/administrator/manifests/',
                '/media/system/js/',
                '/language/en-GB/',
                '/templates/system/',
                '/configuration.php.bak'
            ]
        }
        
        found_files = []
        
        if tech_name in probes:
            for probe_path in probes[tech_name]:
                try:
                    probe_url = urljoin(base_url, probe_path)
                    response = self.session.head(probe_url, timeout=5)
                    
                    if response.status_code == 200:
                        found_files.append({
                            'path': probe_path,
                            'url': probe_url,
                            'status': response.status_code,
                            'size': response.headers.get('content-length', 'unknown')
                        })
                except:
                    continue
        
        return found_files

    def extract_version_info(self, content, tech_name):
        """Izvlači informacije o verziji"""
        version_patterns = {
            'WordPress': [
                r'wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)',
                r'content="WordPress ([0-9.]+)"',
                r'/wp-content/themes/[^/]+/style\.css\?ver=([0-9.]+)'
            ],
            'jQuery': [
                r'jQuery v([0-9.]+)',
                r'jquery-([0-9.]+)\.min\.js',
                r'jQuery JavaScript Library v([0-9.]+)'
            ],
            'Bootstrap': [
                r'Bootstrap v([0-9.]+)',
                r'bootstrap-([0-9.]+)\.min\.css'
            ]
        }
        
        versions = []
        
        if tech_name in version_patterns:
            for pattern in version_patterns[tech_name]:
                matches = re.findall(pattern, content, re.IGNORECASE)
                versions.extend(matches)
        
        return list(set(versions))  # Remove duplicates

    def analyze_security_posture(self, headers, content):
        """Analizira sigurnosnu konfiguraciju"""
        security_issues = []
        security_score = 100
        
        # Missing security headers
        required_headers = {
            'x-frame-options': 'Missing X-Frame-Options header (Clickjacking protection)',
            'x-xss-protection': 'Missing X-XSS-Protection header',
            'x-content-type-options': 'Missing X-Content-Type-Options header',
            'strict-transport-security': 'Missing HSTS header',
            'content-security-policy': 'Missing CSP header'
        }
        
        for header, description in required_headers.items():
            if header not in headers:
                security_issues.append({
                    'type': 'missing_header',
                    'severity': 'medium',
                    'description': description
                })
                security_score -= 10
        
        # Information disclosure
        disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version']
        for header in disclosure_headers:
            if header in headers:
                security_issues.append({
                    'type': 'information_disclosure',
                    'severity': 'low',
                    'description': f'Server information disclosed: {header}: {headers[header]}'
                })
                security_score -= 5
        
        # Sensitive files/paths in content
        sensitive_patterns = [
            r'\.git/', r'\.env', r'config\.php', r'wp-config\.php',
            r'database\.yml', r'settings\.php', r'\.htaccess'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                security_issues.append({
                    'type': 'sensitive_file_reference',
                    'severity': 'high',
                    'description': f'Reference to sensitive file: {pattern}'
                })
                security_score -= 15
        
        return {
            'security_score': max(security_score, 0),
            'issues': security_issues
        }

    def generate_tech_mutations(self, detected_tech, security_analysis):
        """Generiše podatke za tech-specific napade"""
        mutations = []
        
        for category, techs in detected_tech.items():
            for tech in techs:
                if tech['confidence'] >= 70:
                    mutation = {
                        'technology': tech['name'],
                        'category': category,
                        'confidence': tech['confidence'],
                        'attack_vectors': [],
                        'exploitation_paths': [],
                        'priority': 'high' if tech['confidence'] >= 90 else 'medium'
                    }
                    
                    # Tech-specific attack vectors
                    if tech['name'] == 'WordPress':
                        mutation['attack_vectors'] = [
                            'wp-admin brute force',
                            'plugin enumeration',
                            'theme vulnerabilities',
                            'wp-json api abuse',
                            'xmlrpc attacks'
                        ]
                        mutation['exploitation_paths'] = [
                            '/wp-admin/',
                            '/wp-json/wp/v2/users',
                            '/xmlrpc.php',
                            '/wp-content/plugins/'
                        ]
                    
                    elif tech['name'] == 'Drupal':
                        mutation['attack_vectors'] = [
                            'admin interface attacks',
                            'module vulnerabilities',
                            'cache poisoning',
                            'user enumeration'
                        ]
                    
                    elif tech['name'] == 'PHP':
                        mutation['attack_vectors'] = [
                            'LFI/RFI attacks',
                            'code injection',
                            'session hijacking',
                            'file upload attacks'
                        ]
                    
                    mutations.append(mutation)
        
        return mutations

    def analyze_url_worker(self):
        """Worker thread za analizu URL-ova"""
        while True:
            try:
                url = self.analysis_queue.get(timeout=5)
                self.analyze_single_url(url)
                self.analysis_queue.task_done()
                time.sleep(self.delay)
            except:
                break

    def analyze_single_url(self, url):
        """Analizira jedan URL"""
        try:
            print(f"🔍 Analyzing: {url}")
            
            # Header analysis
            header_info = self.analyze_headers(url)
            
            # Content analysis
            content_info = self.analyze_content(url)
            
            # Security analysis
            headers = header_info.get('security_headers', {})
            headers.update(header_info.get('framework_headers', {}))
            
            # Get content for security analysis
            try:
                response = self.session.get(url, timeout=10)
                security_info = self.analyze_security_posture(headers, response.text)
            except:
                security_info = {'security_score': 0, 'issues': []}
            
            # Generate mutations
            mutations = self.generate_tech_mutations(content_info, security_info)
            
            with self.lock:
                self.detected_technologies[url] = content_info
                self.server_info[url] = header_info
                self.security_headers[url] = security_info
                self.tech_mutations.extend(mutations)
                
        except Exception as e:
            with self.lock:
                self.errors.append({
                    'url': url,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

    def run_analysis(self):
        """Pokreće technology analysis"""
        print(f"\n🚀 Početak technology analysis...")
        
        # Učitava recon podatke
        recon_data = self.load_recon_data()
        if not recon_data:
            return False
        
        # Izvlači URL-ove za analizu
        urls = recon_data.get('results', {}).get('urls', [])
        if not urls:
            print("❌ Nema URL-ova za analizu!")
            return False
        
        # Ograničava na razumnu količinu URL-ova
        analysis_urls = urls[:50]  # Prvih 50 URL-ova
        
        start_time = time.time()
        
        # Puni queue
        for url in analysis_urls:
            self.analysis_queue.put(url)
        
        print(f"📊 Analizira se {len(analysis_urls)} URL-ova")
        
        # Kreira worker threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.analyze_url_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Čeka da se završi
        self.analysis_queue.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n✅ Technology analysis završen za {duration:.2f} sekundi")
        print(f"📊 Rezultati:")
        print(f"   • Analizirano URL-ova: {len(self.detected_technologies)}")
        print(f"   • Tech mutations: {len(self.tech_mutations)}")
        print(f"   • Greške: {len(self.errors)}")
        
        return True

    def generate_analysis_report(self):
        """Generiše JSON izveštaj analize"""
        # Agregira tehnologije
        tech_summary = {}
        security_summary = {'total_score': 0, 'issues_count': 0}
        
        for url, tech_data in self.detected_technologies.items():
            for category, techs in tech_data.items():
                if category not in tech_summary:
                    tech_summary[category] = {}
                
                for tech in techs:
                    tech_name = tech['name']
                    if tech_name not in tech_summary[category]:
                        tech_summary[category][tech_name] = {
                            'count': 0,
                            'max_confidence': 0,
                            'urls': []
                        }
                    
                    tech_summary[category][tech_name]['count'] += 1
                    tech_summary[category][tech_name]['max_confidence'] = max(
                        tech_summary[category][tech_name]['max_confidence'],
                        tech['confidence']
                    )
                    tech_summary[category][tech_name]['urls'].append(url)
        
        # Security summary
        for url, sec_data in self.security_headers.items():
            security_summary['total_score'] += sec_data.get('security_score', 0)
            security_summary['issues_count'] += len(sec_data.get('issues', []))
        
        if len(self.security_headers) > 0:
            security_summary['average_score'] = security_summary['total_score'] / len(self.security_headers)
        else:
            security_summary['average_score'] = 0
        
        report = {
            'module': 'technology_analyzer',
            'analysis_info': {
                'timestamp': datetime.now().isoformat(),
                'input_file': self.input_json,
                'threads': self.threads,
                'delay': self.delay
            },
            'statistics': {
                'urls_analyzed': len(self.detected_technologies),
                'technologies_detected': sum(len(techs) for tech_data in self.detected_technologies.values() for techs in tech_data.values()),
                'mutations_generated': len(self.tech_mutations),
                'security_issues_found': security_summary['issues_count'],
                'average_security_score': round(security_summary['average_score'], 2)
            },
            'technology_summary': tech_summary,
            'security_analysis': {
                'summary': security_summary,
                'details': self.security_headers
            },
            'detected_technologies': self.detected_technologies,
            'server_information': self.server_info,
            'tech_mutations': self.tech_mutations,
            'errors': self.errors
        }
        
        return report

    def save_report(self, data):
        from datetime import datetime
        import os, json

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/tech/tech_analysis_{timestamp}.json"
        os.makedirs("reports/tech", exist_ok=True)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Technology analysis izveštaj sačuvan: {filename}")

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Technology Analyzer Module')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Number of threads (default: 8)')
    parser.add_argument('--delay', type=float, default=0.3, help='Delay between requests (default: 0.3)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔍 ShadowFox21 - Technology Analyzer Module")
    print("=" * 60)
    
    # Provera da li input fajl postoji
    
    # Kreira analyzer
    analyzer = TechnologyAnalyzer(
        threads=args.threads,
        delay=args.delay
    )
    
    try:
        # Pokreće analizu
        if analyzer.run_analysis():
            # Čuva izveštaj
            analyzer.save_report(args.output)
            print(f"\n🎯 Technology analysis završen uspešno!")
        else:
            print(f"\n❌ Analiza neuspešna!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Analiza prekinuta...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()

