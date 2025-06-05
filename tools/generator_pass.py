
#!/usr/bin/env python3
"""
ShadowFox21 - Credentials Archive Generator
==========================================
Generiše obimnu arhivu credentials-a za brute force napade
"""

import json
import itertools
from datetime import datetime
import argparse
from pathlib import Path

class CredentialsGenerator:
    def __init__(self):
        self.usernames = set()
        self.passwords = set()
        self.combinations = []
        
        print("🔐 ShadowFox21 Credentials Generator")
        print("🎯 Generiše obimnu arhivu za brute force")

    def load_default_usernames(self):
        """Učitava default username listu"""
        usernames = [
            # Admin accounts
            'admin', 'administrator', 'root', 'sa', 'sysadmin', 'system',
            'superuser', 'super', 'supervisor', 'manager', 'guest',
            
            # Common service accounts
            'mysql', 'postgres', 'oracle', 'mssql', 'mongodb', 'redis',
            'elasticsearch', 'jenkins', 'gitlab', 'jenkins', 'tomcat',
            'apache', 'nginx', 'www', 'www-data', 'httpd', 'ftp', 'sftp',
            
            # Default users
            'user', 'test', 'demo', 'sample', 'temp', 'backup', 'service',
            'support', 'help', 'info', 'mail', 'email', 'web', 'api',
            
            # Company related
            'ceo', 'cto', 'cfo', 'hr', 'it', 'tech', 'dev', 'developer',
            'webmaster', 'postmaster', 'hostmaster', 'admin1', 'admin2',
            
            # Database defaults
            'db', 'database', 'dbadmin', 'dbuser', 'dba', 'data',
            'report', 'reports', 'analytics', 'stats', 'monitor',
            
            # Application defaults
            'app', 'application', 'portal', 'dashboard', 'panel',
            'control', 'console', 'interface', 'ui', 'api',
            
            # Regional/Language variants
            'administrador', 'usuario', 'utilisateur', 'benutzer',
            'utente', 'gebruiker', 'uzytkownik', 'пользователь',
            
            # Numbers combinations
            'admin123', 'user123', 'test123', 'admin1', 'user1',
            'admin01', 'user01', 'test01', 'guest1', 'guest123',
            
            # Special characters
            'admin!', 'admin@', 'admin#', 'user!', 'user@', 'user#',
            'admin_1', 'admin-1', 'user_1', 'user-1', 'test_1',
            
            # Common names
            'john', 'jane', 'mike', 'mary', 'david', 'sarah', 'chris',
            'alex', 'sam', 'pat', 'kim', 'bob', 'alice', 'eve',
            
            # Service specific
            'elastic', 'kibana', 'logstash', 'grafana', 'prometheus',
            'docker', 'kubernetes', 'k8s', 'openshift', 'ansible',
            
            # IoT/Embedded defaults
            'pi', 'raspberry', 'arduino', 'esp32', 'admin', 'ubnt',
            'mikrotik', 'cisco', 'netgear', 'linksys', 'dlink',
            
            # Cloud/SaaS
            'aws', 'azure', 'gcp', 'cloud', 'saas', 'paas', 'iaas',
            'serverless', 'lambda', 'function', 'container', 'pod'
        ]
        
        return set(usernames)

    def load_default_passwords(self):
        """Učitava default password listu"""
        passwords = [
            # Most common passwords
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', '1234567890', 'welcome', 'admin', 'letmein',
            
            # Admin defaults
            'admin', 'administrator', 'root', 'toor', 'pass', 'passwd',
            'secret', 'changeme', 'default', 'guest', 'test', 'demo',
            
            # Empty passwords
            '', ' ', 'null', 'none', 'empty',
            
            # Keyboard patterns
            'qwerty', 'asdf', 'zxcv', 'qazwsx', 'wsxedc', 'rfvtgb',
            '1qaz2wsx', 'qwer1234', 'asdf1234', 'zxcv1234',
            
            # Number sequences
            '123456', '1234567', '12345678', '123456789', '1234567890',
            '654321', '987654321', '0123456789', '1111', '2222',
            '1234', '4321', '0000', '9999', '1212', '2121',
            
            # Date patterns
            '2024', '2023', '2022', '2021', '2020', '2019', '2018',
            '01012024', '31122023', '12345678', '20240101', '20231231',
            
            # Common words
            'welcome', 'hello', 'world', 'computer', 'internet',
            'system', 'server', 'network', 'database', 'secure',
            'login', 'access', 'control', 'master', 'super',
            
            # Service defaults
            'mysql', 'postgres', 'oracle', 'mssql', 'mongodb',
            'redis', 'elasticsearch', 'jenkins', 'tomcat', 'apache',
            
            # Variations with numbers
            'password1', 'password123', 'admin123', 'test123',
            'welcome123', 'hello123', 'computer1', 'system1',
            'admin1', 'admin01', 'user1', 'user123', 'guest1',
            
            # Special characters
            'password!', 'admin!', 'test!', 'welcome!', 'hello!',
            'password@', 'admin@', 'test@', 'welcome@', 'hello@',
            'password#', 'admin#', 'test#', 'welcome#', 'hello#',
            'password$', 'admin$', 'test$', 'welcome$', 'hello$',
            
            # Complex but common
            'Password1', 'Password123', 'Admin123', 'Welcome1',
            'Password!', 'Admin!@#', 'Welcome123!', 'Test123!',
            'P@ssw0rd', 'P@ssword', 'Adm1n', 'W3lcome', 'T3st',
            
            # Company/Brand related
            'company', 'company123', 'enterprise', 'business',
            'corporate', 'office', 'work', 'job', 'team', 'staff',
            
            # Seasonal/Temporal
            'spring', 'summer', 'autumn', 'winter', 'january',
            'february', 'march', 'april', 'may', 'june', 'july',
            'august', 'september', 'october', 'november', 'december',
            
            # Regional variants
            'senha', 'contraseña', 'mot2passe', 'passwort',
            'wachtwoord', 'hasło', 'пароль', 'パスワード',
            
            # IoT/Router defaults
            'admin', 'password', '12345', 'admin123', 'root',
            'ubnt', 'mikrotik', 'cisco', 'netgear', 'linksys',
            'default', 'public', 'private', 'community', 'monitor',
            
            # Database defaults
            'sa', 'root', 'mysql', 'postgres', 'oracle', 'admin',
            'dbadmin', 'database', 'db', 'data', 'sql', 'nosql',
            
            # Weak passwords
            'trustno1', 'iloveyou', 'monkey', 'dragon', 'sunshine',
            'princess', 'football', 'baseball', 'superman', 'batman',
            
            # Application specific
            'changeme', 'pleasechange', 'temp', 'temporary', 'install',
            'setup', 'config', 'configure', 'settings', 'options',
            
            # Combinations
            'admin/admin', 'user/user', 'test/test', 'guest/guest',
            'root/root', 'sa/sa', 'demo/demo', 'sample/sample'
        ]
        
        return set(passwords)

    def generate_username_variants(self, base_usernames):
        """Generiše varijante usernames-a"""
        variants = set(base_usernames)
        
        for username in base_usernames:
            # Case variations
            variants.add(username.upper())
            variants.add(username.lower())
            variants.add(username.capitalize())
            
            # Number suffixes
            for i in range(0, 10):
                variants.add(f"{username}{i}")
                variants.add(f"{username}0{i}")
            
            # Common suffixes
            suffixes = ['1', '01', '123', '2024', '2023', 'admin', 'user', 'test']
            for suffix in suffixes:
                variants.add(f"{username}{suffix}")
                variants.add(f"{username}_{suffix}")
                variants.add(f"{username}-{suffix}")
            
            # Special characters
            variants.add(f"{username}!")
            variants.add(f"{username}@")
            variants.add(f"{username}#")
            variants.add(f"{username}_")
            variants.add(f"{username}-")
        
        return variants

    def generate_password_variants(self, base_passwords):
        """Generiše varijante passwords-a"""
        variants = set(base_passwords)
        
        for password in base_passwords:
            if len(password) == 0:  # Skip empty passwords for variants
                continue
                
            # Case variations
            variants.add(password.upper())
            variants.add(password.lower())
            variants.add(password.capitalize())
            
            # Number suffixes
            for i in range(0, 10):
                variants.add(f"{password}{i}")
                variants.add(f"{password}0{i}")
            
            # Year suffixes
            years = ['2024', '2023', '2022', '2021', '2020']
            for year in years:
                variants.add(f"{password}{year}")
            
            # Special character suffixes
            specials = ['!', '@', '#', '$', '%', '^', '&', '*']
            for special in specials:
                variants.add(f"{password}{special}")
            
            # Number + special combinations
            for i in range(1, 10):
                variants.add(f"{password}{i}!")
                variants.add(f"{password}{i}@")
                variants.add(f"{password}{i}#")
            
            # Leet speak variations
            leet_map = {
                'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
            }
            leet_password = password.lower()
            for char, leet in leet_map.items():
                leet_password = leet_password.replace(char, leet)
            if leet_password != password.lower():
                variants.add(leet_password)
                variants.add(leet_password.capitalize())
        
        return variants

    def generate_contextual_credentials(self, domain=None):
        """Generiše credentials na osnovu konteksta (domena)"""
        contextual = {'usernames': set(), 'passwords': set()}
        
        if domain:
            # Extract company name from domain
            domain_parts = domain.replace('www.', '').split('.')
            company = domain_parts[0] if domain_parts else 'company'
            
            # Company-based usernames
            contextual['usernames'].update([
                company, f"{company}admin", f"{company}user",
                f"admin{company}", f"user{company}", f"{company}123",
                f"{company}_admin", f"{company}-admin"
            ])
            
            # Company-based passwords
            contextual['passwords'].update([
                company, f"{company}123", f"{company}2024",
                f"{company}!", f"{company}@123", company.capitalize(),
                f"{company.upper()}123", f"Welcome{company}",
                f"{company}Pass", f"{company}Login"
            ])
        
        return contextual

    def load_leaked_credentials(self):
        """Simulira učitavanje iz poznate leak baze"""
        # Top leaked credentials from various breaches
        leaked = {
            'usernames': [
                'admin', 'administrator', 'user', 'test', 'guest',
                'root', 'demo', 'service', 'support', 'manager',
                'john.doe', 'jane.smith', 'admin@company.com',
                'user@domain.com', 'test@test.com', 'info@company.com'
            ],
            'passwords': [
                '123456', 'password', '12345678', 'qwerty', 'abc123',
                'monkey', 'letmein', 'dragon', 'password123', 'welcome',
                'trustno1', 'iloveyou', 'password1', 'qwerty123',
                'admin123', 'password!', 'welcome123', 'changeme'
            ]
        }
        return leaked

    def generate_smart_combinations(self):
        """Generiše pametne kombinacije credentials-a"""
        combinations = []
        
        # Same username/password
        common_same = ['admin', 'test', 'guest', 'demo', 'user', 'root']
        for cred in common_same:
            combinations.append({'username': cred, 'password': cred})
            combinations.append({'username': cred, 'password': f"{cred}123"})
            combinations.append({'username': f"{cred}123", 'password': cred})
        
        # Service specific combinations
        service_combos = {
            'mysql': ['mysql', 'root', '', 'password', 'admin'],
            'postgres': ['postgres', 'postgresql', 'admin', 'password'],
            'oracle': ['oracle', 'system', 'sys', 'scott', 'tiger'],
            'mssql': ['sa', 'admin', 'mssql', 'sql', 'password'],
            'mongodb': ['admin', 'mongo', 'mongodb', 'root', 'user'],
            'redis': ['redis', 'default', '', 'admin', 'password'],
            'elasticsearch': ['elastic', 'elasticsearch', 'admin', 'changeme'],
            'jenkins': ['jenkins', 'admin', 'user', 'password', 'jenkins123'],
            'tomcat': ['tomcat', 'admin', 'manager', 'password', 'tomcat123'],
            'apache': ['apache', 'admin', 'www', 'password', 'apache123']
        }
        
        for service, passwords in service_combos.items():
            for password in passwords:
                combinations.append({'username': service, 'password': password})
        
        return combinations

    def generate_full_archive(self, domain=None, include_contextual=True):
        """Generiše kompletnu arhivu credentials-a"""
        print("🔄 Generišem credentials arhivu...")
        
        # Load base lists
        base_usernames = self.load_default_usernames()
        base_passwords = self.load_default_passwords()
        
        print(f"📋 Base usernames: {len(base_usernames)}")
        print(f"📋 Base passwords: {len(base_passwords)}")
        
        # Generate variants
        print("🔄 Generiše variants...")
        all_usernames = self.generate_username_variants(base_usernames)
        all_passwords = self.generate_password_variants(base_passwords)
        
        # Add contextual if domain provided
        if domain and include_contextual:
            print(f"🔄 Dodaje contextual credentials za: {domain}")
            contextual = self.generate_contextual_credentials(domain)
            all_usernames.update(contextual['usernames'])
            all_passwords.update(contextual['passwords'])
        
        # Add leaked credentials
        leaked = self.load_leaked_credentials()
        all_usernames.update(leaked['usernames'])
        all_passwords.update(leaked['passwords'])
        
        # Generate smart combinations
        smart_combos = self.generate_smart_combinations()
        
        print(f"📊 Final counts:")
        print(f"   • Usernames: {len(all_usernames)}")
        print(f"   • Passwords: {len(all_passwords)}")
        print(f"   • Smart combinations: {len(smart_combos)}")
        print(f"   • Total possible combinations: {len(all_usernames) * len(all_passwords):,}")
        
        self.usernames = all_usernames
        self.passwords = all_passwords
        self.combinations = smart_combos
        
        return {
            'usernames': sorted(list(all_usernames)),
            'passwords': sorted(list(all_passwords)),
            'smart_combinations': smart_combos,
            'statistics': {
                'total_usernames': len(all_usernames),
                'total_passwords': len(all_passwords),
                'smart_combinations': len(smart_combos),
                'possible_combinations': len(all_usernames) * len(all_passwords)
            }
        }

    def save_credentials_archive(self, credentials_data, output_file):
        """Čuva credentials arhivu u JSON format"""
        archive = {
            'generator': 'ShadowFox21 Credentials Generator',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0',
            'data': credentials_data
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(archive, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Credentials arhiva sačuvana: {output_file}")
        return output_file

    def save_separate_files(self, credentials_data, prefix="shadowfox"):
        """Čuva zasebne fajlove za usernames i passwords"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Usernames file
        usernames_file = f"{prefix}_usernames_{timestamp}.txt"
        with open(usernames_file, 'w', encoding='utf-8') as f:
            for username in credentials_data['usernames']:
                f.write(f"{username}\n")
        
        # Passwords file
        passwords_file = f"{prefix}_passwords_{timestamp}.txt"
        with open(passwords_file, 'w', encoding='utf-8') as f:
            for password in credentials_data['passwords']:
                f.write(f"{password}\n")
        
        # Combinations file
        combos_file = f"{prefix}_combinations_{timestamp}.txt"
        with open(combos_file, 'w', encoding='utf-8') as f:
            for combo in credentials_data['smart_combinations']:
                f.write(f"{combo['username']}:{combo['password']}\n")
        
        print(f"📁 Zasebni fajlovi sačuvani:")
        print(f"   • {usernames_file}")
        print(f"   • {passwords_file}")
        print(f"   • {combos_file}")
        
        return {
            'usernames': usernames_file,
            'passwords': passwords_file,
            'combinations': combos_file
        }

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Credentials Archive Generator')
    parser.add_argument('-d', '--domain', help='Target domain for contextual credentials')
    parser.add_argument('-o', '--output', default='shadowfox_credentials.json', help='Output JSON file')
    parser.add_argument('--separate', action='store_true', help='Save separate .txt files')
    parser.add_argument('--no-contextual', action='store_true', help='Skip contextual generation')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔐 ShadowFox21 - Credentials Archive Generator")
    print("=" * 60)
    
    generator = CredentialsGenerator()
    
    try:
        # Generate credentials archive
        credentials_data = generator.generate_full_archive(
            domain=args.domain,
            include_contextual=not args.no_contextual
        )
        
        # Save JSON archive
        generator.save_credentials_archive(credentials_data, args.output)
        
        # Save separate files if requested
        if args.separate:
            generator.save_separate_files(credentials_data)
        
        print(f"\n🎯 Credentials archive generiša završena!")
        print(f"📊 Ready for brute force attacks!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Generation prekinut...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()

