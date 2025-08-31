#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attack Surface Management Module for Sayer7
Automated attack surface discovery and management
Author: SayerLinux
"""

import socket
import requests
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import dns.resolver
import subprocess
import logging
from typing import Dict, List, Set, Optional
import xml.etree.ElementTree as ET

class AttackSurfaceManager:
    """
    Advanced attack surface management system for automated discovery
    and continuous monitoring of attack vectors
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Attack surface components
        self.domains: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.ips: Set[str] = set()
        self.ports: Set[int] = set()
        self.services: Dict[str, Dict] = {}
        self.endpoints: Set[str] = set()
        self.technologies: Dict[str, List[str]] = {}
        
        # Discovery results
        self.discovery_results = {
            'domains': [],
            'subdomains': [],
            'ips': [],
            'open_ports': [],
            'services': [],
            'endpoints': [],
            'technologies': [],
            'vulnerabilities': [],
            'risk_score': 0
        }
        
        # Configuration
        self.max_threads = self.config.get('max_threads', 50)
        self.timeout = self.config.get('timeout', 10)
        self.port_range = self.config.get('port_range', '1-10000')
        self.wordlist_path = self.config.get('wordlist', 'wordlists/subdomains.txt')
        
    def discover_attack_surface(self) -> Dict:
        """
        Comprehensive attack surface discovery
        """
        self.logger.info("Starting attack surface discovery...")
        
        try:
            # Phase 1: Domain and subdomain enumeration
            self._discover_domains()
            
            # Phase 2: IP address discovery
            self._discover_ips()
            
            # Phase 3: Port scanning and service discovery
            self._discover_services()
            
            # Phase 4: Web endpoint discovery
            self._discover_endpoints()
            
            # Phase 5: Technology stack identification
            self._identify_technologies()
            
            # Phase 6: Vulnerability correlation
            self._correlate_vulnerabilities()
            
            # Calculate risk score
            self._calculate_risk_score()
            
            return self.discovery_results
            
        except Exception as e:
            self.logger.error(f"Error in attack surface discovery: {str(e)}")
            return self.discovery_results
    
    def _discover_domains(self):
        """Discover domains and subdomains"""
        self.logger.info("Discovering domains and subdomains...")
        
        # Add main domain
        self.domains.add(self.target)
        
        # Subdomain enumeration
        self._enumerate_subdomains()
        
        # Certificate transparency logs
        self._check_certificate_transparency()
        
        # DNS zone transfer
        self._check_dns_zone_transfer()
        
        self.discovery_results['domains'] = list(self.domains)
        self.discovery_results['subdomains'] = list(self.subdomains)
    
    def _enumerate_subdomains(self):
        """Enumerate subdomains using various techniques"""
        subdomain_techniques = [
            self._bruteforce_subdomains,
            self._search_engines_subdomains,
            self._dns_subdomain_enum,
            self._crawler_subdomains
        ]
        
        for technique in subdomain_techniques:
            try:
                technique()
            except Exception as e:
                self.logger.warning(f"Subdomain technique failed: {str(e)}")
    
    def _bruteforce_subdomains(self):
        """Brute force subdomain discovery"""
        try:
            with open(self.wordlist_path, 'r') as f:
                subdomains = f.read().splitlines()
            
            target_domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for sub in subdomains:
                    subdomain = f"{sub}.{target_domain}"
                    futures.append(executor.submit(self._check_subdomain, subdomain))
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.subdomains.add(result)
                        
        except FileNotFoundError:
            self.logger.warning("Subdomain wordlist not found, skipping brute force")
    
    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            return subdomain
        except:
            return None
    
    def _search_engines_subdomains(self):
        """Find subdomains using search engines"""
        search_engines = [
            f"https://www.google.com/search?q=site:*.{self.target}",
            f"https://duckduckgo.com/?q=site:*.{self.target}",
            f"https://bing.com/search?q=site:*.{self.target}"
        ]
        
        for engine in search_engines:
            try:
                response = requests.get(engine, timeout=self.timeout)
                # Extract subdomains from response (simplified)
                # In real implementation, use proper regex and parsing
            except:
                continue
    
    def _check_certificate_transparency(self):
        """Check Certificate Transparency logs"""
        try:
            domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    subdomain = entry.get('name_value', '').strip()
                    if subdomain and '*' not in subdomain:
                        self.subdomains.add(subdomain)
                        
        except Exception as e:
            self.logger.warning(f"CT logs check failed: {str(e)}")
    
    def _check_dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        try:
            domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            
            # Get NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        self.subdomains.add(subdomain)
                except:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Zone transfer failed: {str(e)}")
    
    def _discover_ips(self):
        """Discover IP addresses"""
        self.logger.info("Discovering IP addresses...")
        
        all_domains = list(self.domains) + list(self.subdomains)
        
        for domain in all_domains:
            try:
                ip = socket.gethostbyname(domain)
                self.ips.add(ip)
            except:
                continue
        
        self.discovery_results['ips'] = list(self.ips)
    
    def _discover_services(self):
        """Discover services through port scanning"""
        self.logger.info("Discovering services...")
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for ip in self.ips:
                for port in common_ports:
                    futures.append(executor.submit(self._scan_port, ip, port))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.services[f"{result['ip']}:{result['port']}"] = result
                    self.ports.add(result['port'])
        
        self.discovery_results['open_ports'] = list(self.ports)
        self.discovery_results['services'] = list(self.services.values())
    
    def _scan_port(self, ip: str, port: int) -> Optional[Dict]:
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service_info = {
                    'ip': ip,
                    'port': port,
                    'service': self._get_service_name(port),
                    'banner': self._get_banner(ip, port)
                }
                sock.close()
                return service_info
            
            sock.close()
            return None
            
        except Exception:
            return None
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return common_services.get(port, 'unknown')
    
    def _get_banner(self, ip: str, port: int) -> str:
        """Get service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
            
        except Exception:
            return ""
    
    def _discover_endpoints(self):
        """Discover web endpoints"""
        self.logger.info("Discovering web endpoints...")
        
        web_services = [svc for svc in self.services.values() if svc['service'] in ['http', 'https']]
        
        for service in web_services:
            base_url = f"http://{service['ip']}:{service['port']}"
            if service['port'] == 443:
                base_url = f"https://{service['ip']}:{service['port']}"
            
            self._crawl_endpoints(base_url)
        
        self.discovery_results['endpoints'] = list(self.endpoints)
    
    def _crawl_endpoints(self, base_url: str):
        """Crawl endpoints from web service"""
        common_paths = [
            '/robots.txt', '/sitemap.xml', '/admin', '/login', '/wp-admin',
            '/phpmyadmin', '/.git', '/.env', '/config.php', '/backup',
            '/api', '/api/v1', '/graphql', '/swagger', '/docs'
        ]
        
        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                response = requests.head(url, timeout=self.timeout)
                if response.status_code < 400:
                    self.endpoints.add(url)
            except:
                continue
    
    def _identify_technologies(self):
        """Identify technology stack"""
        self.logger.info("Identifying technology stack...")
        
        for endpoint in self.endpoints:
            try:
                response = requests.get(endpoint, timeout=self.timeout)
                headers = response.headers
                
                technologies = []
                
                # Server identification
                if 'server' in headers:
                    technologies.append(f"Server: {headers['server']}")
                
                # Framework detection
                if 'x-powered-by' in headers:
                    technologies.append(f"Framework: {headers['x-powered-by']}")
                
                # Technology stack from response
                content = response.text.lower()
                tech_indicators = {
                    'wordpress': 'wp-content',
                    'drupal': 'drupal.js',
                    'joomla': 'joomla',
                    'php': '.php',
                    'asp.net': 'asp.net',
                    'node.js': 'node.js',
                    'react': 'react',
                    'angular': 'angular',
                    'vue': 'vue.js'
                }
                
                for tech, indicator in tech_indicators.items():
                    if indicator in content:
                        technologies.append(tech)
                
                self.technologies[endpoint] = technologies
                
            except Exception as e:
                self.logger.warning(f"Technology identification failed for {endpoint}: {str(e)}")
        
        self.discovery_results['technologies'] = [
            {'endpoint': ep, 'technologies': techs} 
            for ep, techs in self.technologies.items()
        ]
    
    def _correlate_vulnerabilities(self):
        """Correlate discovered services with known vulnerabilities"""
        self.logger.info("Correlating vulnerabilities...")
        
        vulnerabilities = []
        
        for service_key, service_info in self.services.items():
            # Check for common vulnerabilities
            if service_info['service'] == 'ssh' and service_info['port'] == 22:
                vulnerabilities.append({
                    'service': 'ssh',
                    'port': 22,
                    'vulnerability': 'SSH brute force possible',
                    'severity': 'medium'
                })
            
            if service_info['service'] == 'ftp' and service_info['port'] == 21:
                vulnerabilities.append({
                    'service': 'ftp',
                    'port': 21,
                    'vulnerability': 'FTP anonymous access possible',
                    'severity': 'medium'
                })
            
            if service_info['service'] == 'mysql' and service_info['port'] == 3306:
                vulnerabilities.append({
                    'service': 'mysql',
                    'port': 3306,
                    'vulnerability': 'MySQL exposed to internet',
                    'severity': 'high'
                })
        
        self.discovery_results['vulnerabilities'] = vulnerabilities
    
    def _calculate_risk_score(self):
        """Calculate overall risk score based on discovered components"""
        score = 0
        
        # Risk factors
        risk_factors = {
            'domains': len(self.domains) * 1,
            'subdomains': len(self.subdomains) * 2,
            'ips': len(self.ips) * 1,
            'ports': len(self.ports) * 3,
            'services': len(self.discovery_results['services']) * 2,
            'vulnerabilities': len(self.discovery_results['vulnerabilities']) * 10
        }
        
        # Calculate total score (max 100)
        score = sum(risk_factors.values())
        
        # Cap at 100
        score = min(score, 100)
        
        # Adjust based on critical ports
        critical_ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443]
        for service in self.discovery_results['services']:
            if service['port'] in critical_ports:
                score += 5
        
        # Final cap
        score = min(score, 100)
        
        self.discovery_results['risk_score'] = score
    
    def generate_attack_surface_report(self) -> str:
        """Generate comprehensive attack surface report in Arabic"""
        report = f"""# تقرير تحليل سطح الهجوم

## معلومات أساسية
- **الهدف**: {self.target}
- **تاريخ الفحص**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **إجمالي النطاقات**: {len(self.domains)}
- **إجمالي النطاقات الفرعية**: {len(self.subdomains)}
- **إجمالي عناوين IP**: {len(self.ips)}
- **إجمالي المنافذ المفتوحة**: {len(self.ports)}

## النطاقات المكتشفة
{chr(10).join(f"- {domain}" for domain in self.domains)}

## النطاقات الفرعية المكتشفة
{chr(10).join(f"- {subdomain}" for subdomain in self.subdomains)}

## عناوين IP
{chr(10).join(f"- {ip}" for ip in self.ips)}

## المنافذ المفتوحة والخدمات
"""
        
        for service in self.discovery_results['services']:
            report += f"- **{service['ip']}:{service['port']}** - {service['service']} - {service['banner'][:50]}...\n"
        
        report += f"""
## النقاط النهائية للويب
{chr(10).join(f"- {endpoint}" for endpoint in self.endpoints)}

## التكنولوجيا المستخدمة
"""
        
        for tech_info in self.discovery_results['technologies']:
            report += f"- **{tech_info['endpoint']}**: {', '.join(tech_info['technologies'])}\n"
        
        report += f"""
## الثغرات الأمنية المحتملة
"""
        
        for vuln in self.discovery_results['vulnerabilities']:
            severity_emoji = "🔴" if vuln['severity'] == 'high' else "🟡" if vuln['severity'] == 'medium' else "🟢"
            report += f"{severity_emoji} **{vuln['service']}:{vuln['port']}** - {vuln['vulnerability']}\n"
        
        report += f"""
## تقييم المخاطر
**درجة الخطورة**: {self.discovery_results['risk_score']}/100

## التوصيات
1. **فورية**: إغلاق المنافذ غير الضرورية
2. **قصيرة المدى**: تحديث البرامج القديمة
3. **طويلة المدى**: تنفيذ مراقبة مستمرة

---
*تم إنشاء هذا التقرير بواسطة Sayer7 - أداة الاستطلاع المتقدمة*
"""
        return report

    def continuous_monitoring(self, interval_hours: int = 1):
        """Continuous monitoring of attack surface changes"""
        print(f"[*] Starting continuous monitoring every {interval_hours} hours...")
        
        last_results = self.discovery_results.copy()
        
        while True:
            try:
                print(f"[*] Running scheduled scan at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Run new discovery
                new_results = self.discover_attack_surface()
                
                # Check for changes
                changes = self._detect_changes(last_results, new_results)
                
                if changes:
                    print(f"[!] Changes detected:")
                    for change in changes:
                        print(f"  - {change}")
                    
                    # Save changes report
                    changes_report = self._generate_changes_report(changes)
                    changes_file = f"changes_{int(time.time())}.md"
                    with open(changes_file, 'w', encoding='utf-8') as f:
                        f.write(changes_report)
                    print(f"[+] Changes report saved to: {changes_file}")
                
                last_results = new_results.copy()
                time.sleep(interval_hours * 3600)  # Convert hours to seconds
                
            except KeyboardInterrupt:
                print("[+] Continuous monitoring stopped by user")
                break
            except Exception as e:
                print(f"[!] Error in continuous monitoring: {str(e)}")
                time.sleep(60)  # Wait 1 minute before retry

    def _detect_changes(self, old_results: Dict, new_results: Dict) -> List[str]:
        """Detect changes between old and new results"""
        changes = []
        
        # Check new subdomains
        old_subdomains = set(old_results.get('subdomains', []))
        new_subdomains = set(new_results.get('subdomains', []))
        new_discovered = new_subdomains - old_subdomains
        if new_discovered:
            changes.append(f"New subdomains discovered: {', '.join(new_discovered)}")
        
        # Check new open ports
        old_ports = set(old_results.get('open_ports', []))
        new_ports = set(new_results.get('open_ports', []))
        new_open_ports = new_ports - old_ports
        if new_open_ports:
            changes.append(f"New open ports discovered: {', '.join(map(str, new_open_ports))}")
        
        # Check new services
        old_services = {f"{s['ip']}:{s['port']}" for s in old_results.get('services', [])}
        new_services = {f"{s['ip']}:{s['port']}" for s in new_results.get('services', [])}
        new_service_list = new_services - old_services
        if new_service_list:
            changes.append(f"New services discovered: {', '.join(new_service_list)}")
        
        return changes

    def _generate_changes_report(self, changes: List[str]) -> str:
        """Generate report for detected changes"""
        report = f"""# تقرير التغييرات في سطح الهجوم

**تاريخ الكشف**: {time.strftime('%Y-%m-%d %H:%M:%S')}
**الهدف**: {self.target}

## التغييرات المكتشفة
"""
        
        for change in changes:
            report += f"- {change}\n"
        
        report += """
## الإجراءات المطلوبة
يرجى مراجعة هذه التغييرات واتخاذ الإجراءات المناسبة حسب الخطورة.

---
*تقرير تلقائي من Sayer7*
"""
        return report


class AttackSurfaceVisualizer:
    """Visualize attack surface data with network diagrams and heatmaps"""
    
    def __init__(self, attack_surface_data: Dict):
        self.data = attack_surface_data
    
    def generate_network_map(self) -> str:
        """Generate Mermaid network diagram for attack surface"""
        mermaid_code = """graph TD
    subgraph "Internet"
        Target[Target: %s]
    end
    
    subgraph "Attack Surface"
""" % self.data.get('target', 'unknown')
        
        # Add domains
        for i, domain in enumerate(self.data.get('domains', [])[:5]):
            mermaid_code += f'        Domain{i}["{domain}"]\n'
            mermaid_code += f'        Target --> Domain{i}\n'
        
        # Add subdomains
        for i, subdomain in enumerate(self.data.get('subdomains', [])[:10]):
            mermaid_code += f'        Sub{i}["{subdomain}"]\n'
            mermaid_code += f'        Target --> Sub{i}\n'
        
        # Add IP addresses
        for i, ip in enumerate(self.data.get('ips', [])[:5]):
            mermaid_code += f'        IP{i}["{ip}"]\n'
            mermaid_code += f'        Target --> IP{i}\n'
        
        # Add services
        for i, service in enumerate(self.data.get('services', [])[:8]):
            mermaid_code += f'        Service{i}["{service["ip"]}:{service["port"]} - {service["service"]}"]\n'
            mermaid_code += f'        Target --> Service{i}\n'
        
        mermaid_code += """    end
    
    classDef critical fill:#ff6666,stroke:#ff0000
    classDef high fill:#ffcc66,stroke:#ff9900
    classDef medium fill:#ffff66,stroke:#ffcc00
    classDef low fill:#66ff66,stroke:#00cc00
"""
        
        return mermaid_code
    
    def generate_risk_heatmap(self) -> str:
        """Generate risk heatmap based on discovered vulnerabilities"""
        vulnerabilities = self.data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return "No vulnerabilities found for heatmap generation."
        
        # Create risk matrix
        risk_matrix = {
            'critical': {'count': 0, 'services': []},
            'high': {'count': 0, 'services': []},
            'medium': {'count': 0, 'services': []},
            'low': {'count': 0, 'services': []}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            service = f"{vuln.get('service', 'unknown')}:{vuln.get('port', 'unknown')}"
            
            if severity in risk_matrix:
                risk_matrix[severity]['count'] += 1
                if service not in risk_matrix[severity]['services']:
                    risk_matrix[severity]['services'].append(service)
        
        heatmap = """# Risk Heatmap

## Risk Distribution
"""
        
        for severity, data in risk_matrix.items():
            if data['count'] > 0:
                emoji = "🔴" if severity == 'critical' else "🟡" if severity == 'high' else "🟠" if severity == 'medium' else "🟢"
                heatmap += f"{emoji} **{severity.upper()}**: {data['count']} vulnerabilities\n"
                heatmap += f"**Affected Services**: {', '.join(data['services'][:5])}\n\n"
        
        # Create ASCII heatmap
        heatmap += "\n## ASCII Risk Heatmap\n\n"
        heatmap += "```\n"
        heatmap += "Risk Level    | Services\n"
        heatmap += "-------------|-----------------\n"
        
        for severity, data in risk_matrix.items():
            if data['count'] > 0:
                bar_length = min(data['count'], 20)
                bar = "█" * bar_length
                heatmap += f"{severity.capitalize():<12} | {bar} ({data['count']})\n"
        
        heatmap += "```\n"
        
        return heatmap


if __name__ == "__main__":
    # Test the attack surface manager
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "example.com"
    
    manager = AttackSurfaceManager(target)
    results = manager.discover_attack_surface()
    
    print(json.dumps(results, indent=2))
    print("\n" + manager.generate_attack_surface_report())