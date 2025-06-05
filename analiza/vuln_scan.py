
#!/usr/bin/env python3
"""
ShadowFox21 - Vulnerability Scanner Module
==========================================
Skenira poznate ranjivosti na bazi recon podataka
Učitava JSON iz prethodnih modula i generiše vulnerability report
"""

import requests
import json
import time
import threading
from urllib.parse import urlparse, urljoin
from datetime import datetime
import re
from queue import Queue
import argparse
from pathlib import Path
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityScanner:
    def __init__(self, input_json, threads=15, timeout=10):
        self.input_json = input_json
        self.threads = threads
        self.timeout = timeout
        
        # Scan state
        self.vulnerabilities = []
        self.tested_endpoints = []
        self.high_risk_findings = []
        self.medium_risk_findings = []
        self.low_risk_findings = []
        self.info_findings = []
        self.errors = []
        
        # Threading
        self.scan_queue = Queue()
        self.lock = threading.Lock()
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Load vulnerability database
        self.vuln_db = self.load_vulnerability_database()
        
        print(f"🔍 Vulnerability Scanner inicijalizovan")
        print(f"📊 Threads: {threads}, Timeout: {timeout}s")
        print(f"🎯 Vulnerability checks loaded: {len(self.vuln_db)}")

    def load_vulnerability_database(self):
        """Učitava bazu poznatih ranjivosti"""
        vuln_db = {
            'web_technologies': [
                {
                    'name': 'WordPress Outdated',
                    'check_type': 'version_check',
                    'paths': ['/wp-includes/version.php', '/readme.html'],
                    'indicators': ['wordpress', 'wp-content'],
                    'severity': 'medium',
                    'cve': 'Multiple CVE-s',
                    'description': 'Outdated WordPress installation detected'
                },
                {
                    'name': 'phpMyAdmin',
                    'check_type': 'path_check',
                    'paths': ['/phpmyadmin/', '/pma/', '/phpMyAdmin/', '/mysql/'],
                    'indicators': ['phpmyadmin', 'pma_username'],
                    'severity': 'high',
                    'cve': 'CVE-2020-26934',
                    'description': 'phpMyAdmin interface exposed'
                },
                {
                    'name': 'Apache Server Status',
                    'check_type': 'path_check',
                    'paths': ['/server-status', '/server-info'],
                    'indicators': ['apache server status', 'server information'],
                    'severity': 'medium',
                    'cve': 'N/A',
                    'description': 'Apache server status page exposed'
                }
            ],
            'sensitive_files': [
                {
                    'name': 'Configuration Files',
                    'check_type': 'file_check',
                    'paths': [
                        '/config.php', '/configuration.php', '/wp-config.php',
                        '/.env', '/database.yml', '/config.yml', '/settings.py',
                        '/web.config', '/app.config', '/.htaccess'
                    ],
                    'indicators': ['password', 'database', 'secret', 'key'],
                    'severity': 'high',
                    'cve': 'N/A',
                    'description': 'Sensitive configuration files exposed'
                },
                {
                    'name': 'Backup Files',
                    'check_type': 'file_check',
                    'paths': [
                        '/backup.sql', '/backup.zip', '/backup.tar.gz',
                        '/database.sql', '/dump.sql', '/site.zip',
                        '/backup/', '/backups/', '/old/'
                    ],
                    'indicators': ['sql', 'backup', 'dump'],
                    'severity': 'high',
                    'cve': 'N/A',
                    'description': 'Backup files exposed'
                },
                {
                    'name': 'Version Control',
                    'check_type': 'path_check',
                    'paths': ['/.git/', '/.svn/', '/.hg/', '/.bzr/'],
                    'indicators': ['index', 'refs', 'objects'],
                    'severity': 'medium',
                    'cve': 'N/A',
                    'description': 'Version control directories exposed'
                }
            ],
            'authentication_bypass': [
                {
                    'name': 'Default Credentials',
                    'check_type': 'credential_check',
                    'paths': ['/admin/', '/login/', '/wp-admin/', '/administrator/'],
                    'credentials': [
                        ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
                        ('administrator', 'administrator'), ('admin', ''), ('root', ''),
                        ('guest', 'guest'), ('test', 'test')
                    ],
                    'severity': 'critical',
                    'cve': 'N/A',
                    'description': 'Default credentials accepted'
                },
                {
                    'name': 'SQL Injection Login Bypass',
                    'check_type': 'sqli_bypass',
                    'paths': ['/login.php', '/admin/login.php', '/user/login.php'],
                    'payloads': [
                        "admin' OR '1'='1'--",
                        "admin' OR 1=1#",
                        "' OR ''='",
                        "admin'/**/OR/**/1=1--"
                    ],
                    'severity': 'critical',
                    'cve': 'N/A',
                    'description': 'SQL injection login bypass possible'
                }
            ],
            'information_disclosure': [
                {
                    'name': 'Directory Listing',
                    'check_type': 'directory_listing',
                    'paths': [
                        '/images/', '/uploads/', '/files/', '/documents/',
                        '/backup/', '/logs/', '/temp/', '/tmp/'
                    ],
                    'indicators': ['index of', 'parent directory'],
                    'severity': 'medium',
                    'cve': 'N/A',
                    'description': 'Directory listing enabled'
                },
                {
                    'name': 'Error Pages',
                    'check_type': 'error_check',
                    'paths': ['/nonexistent', '/error', '/404'],
                    'indicators': ['stack trace', 'mysql', 'php', 'apache', 'path'],
                    'severity': 'low',
                    'cve': 'N/A',
                    'description': 'Verbose error messages detected'
                },
                {
                    'name': 'PHP Info',
                    'check_type': 'path_check',
                    'paths': ['/phpinfo.php', '/info.php', '/test.php', '/php.php'],
                    'indicators': ['phpinfo()', 'php version', 'configuration'],
                    'severity': 'medium',
                    'cve': 'N/A',
                    'description': 'PHP info page exposed'
                }
            ],
            'security_headers': [
                {
                    'name': 'Missing Security Headers',
                    'check_type': 'header_check',
                    'required_headers': [
                        'x-frame-options', 'x-xss-protection', 'x-content-type-options',
                        'strict-transport-security', 'content-security-policy'
                    ],
                    'severity': 'low',
                    'cve': 'N/A',
                    'description': 'Missing security headers'
                }
            ],
            'ssl_tls': [
                {
                    'name': 'SSL/TLS Configuration',
                    'check_type': 'ssl_check',
                    'tests': ['certificate', 'protocols', 'ciphers'],
                    'severity': 'medium',
                    'cve': 'Multiple CVE-s',
                    'description': 'SSL/TLS configuration issues'
                }
            ]
        }
        
        # Flatten vulnerability database
        all_vulns = []
        for category, vulns in vuln_db.items():
            for vuln in vulns:
                vuln['category'] = category
                all_vulns.append(vuln)
        
        return all_vulns

    def load_input_data(self):
        """Učitava podatke iz input JSON fajla"""
        try:
            with open(self.input_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"📂 Učitani podaci iz: {self.input_json}")
            
            # Može biti recon ili attack modul
            if 'module' in data:
                print(f"   • Modul: {data['module']}")
            
            return data
        except Exception as e:
            print(f"❌ Greška pri učitavanju: {e}")
            return None

    def extract_scan_targets(self, input_data):
        """Izvlači mete za skeniranje"""
        targets = set()
        
        # Iz recon modula
        if input_data.get('module') == 'recon_spider':
            urls = input_data.get('results', {}).get('urls', [])
            for url in urls:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                targets.add(base_url)
        
        # Iz attack modula
        elif input_data.get('module') == 'sqli_attack':
            results = input_data.get('all_test_results', [])
            for result in results:
                url = result.get('target', {}).get('url', '')
                if url:
                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    targets.add(base_url)
        
        # Generički pristup
        else:
            # Traži sve URL-ove u JSON-u
            def find_urls(obj, urls_found):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if isinstance(value, str) and value.startswith('http'):
                            urls_found.add(value)
                        else:
                            find_urls(value, urls_found)
                elif isinstance(obj, list):
                    for item in obj:
                        find_urls(item, urls_found)
            
            urls_found = set()
            find_urls(input_data, urls_found)
            
            for url in urls_found:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                targets.add(base_url)
        
        print(f"🎯 Pronađeno {len(targets)} osnovnih meta za skeniranje")
        return list(targets)

    def check_path_vulnerability(self, base_url, vuln_info):
        """Proverava path-based vulnerabilities"""
        findings = []
        
        for path in vuln_info.get('paths', []):
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Proverava indicators
                    for indicator in vuln_info.get('indicators', []):
                        if indicator.lower() in content_lower:
                            findings.append({
                                'vulnerability': vuln_info['name'],
                                'category': vuln_info['category'],
                                'severity': vuln_info['severity'],
                                'cve': vuln_info['cve'],
                                'description': vuln_info['description'],
                                'url': test_url,
                                'evidence': f"Found indicator: {indicator}",
                                'response_code': response.status_code,
                                'response_length': len(response.text)
                            })
                            break
                
            except Exception as e:
                continue
        
        return findings

    def check_file_vulnerability(self, base_url, vuln_info):
        """Proverava file-based vulnerabilities"""
        findings = []
        
        for path in vuln_info.get('paths', []):
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Proverava da li je fajl dostupan
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Proverava da li sadrži osetljive informacije
                    sensitive_found = False
                    for indicator in vuln_info.get('indicators', []):
                        if indicator.lower() in content_lower:
                            sensitive_found = True
                            break
                    
                    findings.append({
                        'vulnerability': vuln_info['name'],
                        'category': vuln_info['category'],
                        'severity': vuln_info['severity'] if sensitive_found else 'low',
                        'cve': vuln_info['cve'],
                        'description': vuln_info['description'],
                        'url': test_url,
                        'evidence': f"File accessible, sensitive content: {sensitive_found}",
                        'response_code': response.status_code,
                        'response_length': len(response.text)
                    })
                
            except Exception as e:
                continue
        
        return findings

    def check_credential_vulnerability(self, base_url, vuln_info):
        """Proverava default credentials"""
        findings = []
        
        for path in vuln_info.get('paths', []):
            try:
                test_url = urljoin(base_url, path)
                
                # Prvo proverava da li login stranica postoji
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code != 200:
                    continue
                
                # Testira default credentials
                for username, password in vuln_info.get('credentials', []):
                    try:
                        login_data = {
                            'username': username,
                            'password': password,
                            'user': username,
                            'pass': password,
                            'login': 'Login'
                        }
                        
                        login_response = self.session.post(
                            test_url, 
                            data=login_data, 
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                        
                        # Proverava uspešnu prijavu
                        success_indicators = [
                            login_response.status_code in [302, 301],  # Redirect
                            'welcome' in login_response.text.lower(),
                            'dashboard' in login_response.text.lower(),
                            'logout' in login_response.text.lower()
                        ]
                        
                        if any(success_indicators):
                            findings.append({
                                'vulnerability': vuln_info['name'],
                                'category': vuln_info['category'],
                                'severity': vuln_info['severity'],
                                'cve': vuln_info['cve'],
                                'description': vuln_info['description'],
                                'url': test_url,
                                'evidence': f"Default credentials work: {username}/{password}",
                                'credentials': f"{username}:{password}",
                                'response_code': login_response.status_code
                            })
                            break
                        
                    except Exception as e:
                        continue
                
            except Exception as e:
                continue
        
        return findings

    def check_header_vulnerability(self, base_url, vuln_info):
        """Proverava security headers"""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=self.timeout)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            missing_headers = []
            for required_header in vuln_info.get('required_headers', []):
                if required_header not in headers:
                    missing_headers.append(required_header)
            
            if missing_headers:
                findings.append({
                    'vulnerability': vuln_info['name'],
                    'category': vuln_info['category'],
                    'severity': vuln_info['severity'],
                    'cve': vuln_info['cve'],
                    'description': vuln_info['description'],
                    'url': base_url,
                    'evidence': f"Missing headers: {', '.join(missing_headers)}",
                    'missing_headers': missing_headers
                })
                
        except Exception as e:
            pass
        
        return findings

    def check_directory_listing(self, base_url, vuln_info):
        """Proverava directory listing"""
        findings = []
        
        for path in vuln_info.get('paths', []):
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Proverava da li je directory listing
                    for indicator in vuln_info.get('indicators', []):
                        if indicator.lower() in content_lower:
                            findings.append({
                                'vulnerability': vuln_info['name'],
                                'category': vuln_info['category'],
                                'severity': vuln_info['severity'],
                                'cve': vuln_info['cve'],
                                'description': vuln_info['description'],
                                'url': test_url,
                                'evidence': f"Directory listing detected: {indicator}",
                                'response_code': response.status_code
                            })
                            break
                
            except Exception as e:
                continue
        
        return findings

    def run_vulnerability_check(self, target_url, vuln_info):
        """Pokreće specifičnu vulnerability proveru"""
        findings = []
        
        try:
            check_type = vuln_info.get('check_type')
            
            if check_type == 'path_check':
                findings.extend(self.check_path_vulnerability(target_url, vuln_info))
            elif check_type == 'file_check':
                findings.extend(self.check_file_vulnerability(target_url, vuln_info))
            elif check_type == 'credential_check':
                findings.extend(self.check_credential_vulnerability(target_url, vuln_info))
            elif check_type == 'header_check':
                findings.extend(self.check_header_vulnerability(target_url, vuln_info))
            elif check_type == 'directory_listing':
                findings.extend(self.check_directory_listing(target_url, vuln_info))
            elif check_type in ['version_check', 'error_check']:
                findings.extend(self.check_path_vulnerability(target_url, vuln_info))
            
            with self.lock:
                self.vulnerabilities.extend(findings)
                self.tested_endpoints.append(f"{target_url}_{vuln_info['name']}")
                
                # Kategorisanje po severity
                for finding in findings:
                    severity = finding['severity']
                    if severity == 'critical':
                        self.high_risk_findings.append(finding)
                        print(f"🚨 CRITICAL: {finding['vulnerability']} - {finding['url']}")
                    elif severity == 'high':
                        self.high_risk_findings.append(finding)
                        print(f"🔴 HIGH: {finding['vulnerability']} - {finding['url']}")
                    elif severity == 'medium':
                        self.medium_risk_findings.append(finding)
                        print(f"🟡 MEDIUM: {finding['vulnerability']} - {finding['url']}")
                    else:
                        self.low_risk_findings.append(finding)
                        print(f"🟢 LOW: {finding['vulnerability']} - {finding['url']}")
        
        except Exception as e:
            with self.lock:
                self.errors.append({
                    'target': target_url,
                    'vulnerability': vuln_info['name'],
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

    def scan_worker(self):
        """Worker thread za skeniranje"""
        while True:
            try:
                target_url, vuln_info = self.scan_queue.get(timeout=5)
                self.run_vulnerability_check(target_url, vuln_info)
                self.scan_queue.task_done()
                time.sleep(0.1)  # Kratka pauza
            except:
                break

    def run_scan(self):
        """Pokreće vulnerability scan"""
        print(f"\n🔍 Početak vulnerability scan-a...")
        
        # Učitava input podatke
        input_data = self.load_input_data()
        if not input_data:
            return False
        
        # Izvlači mete
        targets = self.extract_scan_targets(input_data)
        if not targets:
            print("❌ Nema meta za skeniranje!")
            return False
        
        start_time = time.time()
        
        # Puni queue sa zadacima
        for target in targets:
            for vuln_info in self.vuln_db:
                self.scan_queue.put((target, vuln_info))
        
        total_checks = len(targets) * len(self.vuln_db)
        print(f"📊 Ukupno provera: {total_checks}")
        
        # Kreira worker threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Čeka da se završi
        self.scan_queue.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n✅ Vulnerability scan završen za {duration:.2f} sekundi")
        print(f"📊 Rezultati:")
        print(f"   • Ukupno ranjivosti: {len(self.vulnerabilities)}")
        print(f"   • Critical/High: {len(self.high_risk_findings)}")
        print(f"   • Medium: {len(self.medium_risk_findings)}")
        print(f"   • Low/Info: {len(self.low_risk_findings)}")
        print(f"   • Greške: {len(self.errors)}")
        
        return True

    def generate_vulnerability_report(self):
        """Generiše vulnerability report"""
        # Kalkuliše CVSS score
        total_score = 0
        if self.high_risk_findings:
            total_score += len(self.high_risk_findings) * 8
        if self.medium_risk_findings:
            total_score += len(self.medium_risk_findings) * 5
        if self.low_risk_findings:
            total_score += len(self.low_risk_findings) * 2
        
        risk_level = "LOW"
        if total_score > 50:
            risk_level = "CRITICAL"
        elif total_score > 30:
            risk_level = "HIGH"
        elif total_score > 15:
            risk_level = "MEDIUM"
        
        report = {
            'module': 'vulnerability_scanner',
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'input_file': self.input_json,
                'threads': self.threads,
                'timeout': self.timeout,
                'checks_performed': len(self.vuln_db)
            },
            'risk_assessment': {
                'overall_risk_level': risk_level,
                'total_risk_score': total_score,
                'critical_high_count': len(self.high_risk_findings),
                'medium_count': len(self.medium_risk_findings),
                'low_info_count': len(self.low_risk_findings)
            },
            'statistics': {
                'total_vulnerabilities_found': len(self.vulnerabilities),
                'checks_performed': len(self.tested_endpoints),
                'errors_encountered': len(self.errors)
            },
            'vulnerabilities_by_severity': {
                'critical_high': self.high_risk_findings,
                'medium': self.medium_risk_findings,
                'low_info': self.low_risk_findings
            },
            'all_vulnerabilities': self.vulnerabilities,
            'errors': self.errors,
            'recommendations': self.generate_recommendations()
        }
        
        return report

    def generate_recommendations(self):
        """Generiše preporuke za remediation"""
        recommendations = []
        
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vtype = vuln['vulnerability']
            if vtype not in vuln_types:
                vuln_types[vtype] = 0
            vuln_types[vtype] += 1
        
        # Preporuke na bazi pronađenih ranjivosti
        for vuln_type, count in vuln_types.items():
            if 'Default Credentials' in vuln_type:
                recommendations.append({
                    'issue': vuln_type,
                    'count': count,
                    'recommendation': 'Change all default credentials immediately',
                    'priority': 'CRITICAL'
                })
            elif 'Configuration Files' in vuln_type:
                recommendations.append({
                    'issue': vuln_type,
                    'count': count,
                    'recommendation': 'Remove or protect configuration files from web access',
                    'priority': 'HIGH'
                })
            elif 'Directory Listing' in vuln_type:
                recommendations.append({
                    'issue': vuln_type,
                    'count': count,
                    'recommendation': 'Disable directory listing in web server configuration',
                    'priority': 'MEDIUM'
                })
            elif 'Security Headers' in vuln_type:
                recommendations.append({
                    'issue': vuln_type,
                    'count': count,
                    'recommendation': 'Implement proper security headers',
                    'priority': 'MEDIUM'
                })
        
        return recommendations

    def save_report(self, filename=None):
        """Čuva vulnerability report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowfox_vulnerability_scan_{timestamp}.json"
        
        report = self.generate_vulnerability_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Vulnerability report sačuvan: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Vulnerability Scanner Module')
    parser.add_argument('input_json', help='Input JSON file from previous modules')
    parser.add_argument('-t', '--threads', type=int, default=15, help='Number of threads (default: 15)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔍 ShadowFox21 - Vulnerability Scanner Module")
    print("=" * 60)
    
    # Provera da li input fajl postoji
    if not Path(args.input_json).exists():
        print(f"❌ Input fajl ne postoji: {args.input_json}")
        return
    
    # Kreira scanner
    scanner = VulnerabilityScanner(
        input_json=args.input_json,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        # Pokreće scan
        if scanner.run_scan():
            # Čuva report
            scanner.save_report(args.output)
            print(f"\n🎯 Vulnerability scan završen uspešno!")
        else:
            print(f"\n❌ Scan neuspešan!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Scan prekinut...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()

