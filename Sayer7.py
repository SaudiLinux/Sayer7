#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sayer7 - Advanced Web Reconnaissance Tool
Author: SayerLinux
GitHub: https://github.com/SaudiLinux
Email: SayerLinux1@gmail.com

A comprehensive web reconnaissance tool designed to make web application reconnaissance simple.
Features include URL analysis, search engine compatibility, vulnerability assessments, and more.
"""

import argparse
import sys
import os
import time
import requests
from colorama import init, Fore, Style

# Import core modules
from core.url_parser import URLAnalyzer
from core.request_handler import RequestHandler
from modules.search_engines import SearchEngine
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.proxy_manager import ProxyManager
from modules.ssl_dns_scanner import SSLDNSScanner
from modules.web_crawler import WebCrawler
from modules.waf_detector import WAFDetector
from modules.network_recon import NetworkRecon
from modules.exploitation_engine import ExploitationEngine
from modules.attack_surface_manager import AttackSurfaceManager, AttackSurfaceVisualizer
from utils.helpers import Logger, ConfigManager

init(autoreset=True)

class Sayer7:
    def __init__(self):
        self.banner = f"""
{Fore.CYAN}  ███████╗ █████╗ ███████╗██╗  ██╗███████╗██████╗ ███████╗███████╗
  ██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██╔════╝██╔════╝
  ███████╗███████║███████╗███████║█████╗  ██████╔╝███████╗█████╗  
  ╚════██║██╔══██║╚════██║██╔══██║██╔══╝  ██╔═══╝ ╚════██║██╔══╝  
  ███████║██║  ██║███████║██║  ██║███████╗██║     ███████║███████╗
  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.GREEN}  Advanced Web Reconnaissance Tool - Sayer7 v1.0{Style.RESET_ALL}
  {Fore.YELLOW}Author: SayerLinux | GitHub: https://github.com/SaudiLinux{Style.RESET_ALL}
  {Fore.YELLOW}Email: SayerLinux1@gmail.com{Style.RESET_ALL}
        """
        self.parser = self.setup_argparse()
        self.logger = Logger()
        self.config = ConfigManager()
        
    def setup_argparse(self):
        parser = argparse.ArgumentParser(
            description="Sayer7 - Advanced Web Reconnaissance Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python Sayer7.py -u https://example.com --full-scan
  python Sayer7.py -d example.com --dns-enum
  python Sayer7.py -u https://example.com --xss-scan
  python Sayer7.py -q "site:example.com" --search-engine google
            """
        )
        
        # Target options
        target_group = parser.add_argument_group('Target Options')
        target_group.add_argument('-u', '--url', help='Target URL to scan')
        target_group.add_argument('-d', '--domain', help='Target domain to scan')
        target_group.add_argument('-q', '--query', help='Search query for search engines')
        
        # Scan types
        scan_group = parser.add_argument_group('Scan Types')
        scan_group.add_argument('--full-scan', action='store_true', help='Perform full reconnaissance scan including exploitation testing')
        scan_group.add_argument('--xss-scan', action='store_true', help='Scan for XSS vulnerabilities')
        scan_group.add_argument('--sqli-scan', action='store_true', help='Scan for SQL injection vulnerabilities')
        scan_group.add_argument('--clickjacking', action='store_true', help='Check for clickjacking vulnerability')
        scan_group.add_argument('--port-scan', action='store_true', help='Scan common open ports')
        scan_group.add_argument('--admin-panel', action='store_true', help='Search for admin panels')
        scan_group.add_argument('--dns-enum', action='store_true', help='Perform DNS enumeration')
        scan_group.add_argument('--ssl-check', action='store_true', help='Check SSL vulnerabilities')
        scan_group.add_argument('--waf-detect', action='store_true', help='Detect WAF/IDS/IPS protection')
        scan_group.add_argument('--web-crawl', action='store_true', help='Crawl website and extract all links')
        scan_group.add_argument('--network-recon', action='store_true', help='Perform comprehensive network reconnaissance')
        scan_group.add_argument('--os-detect', action='store_true', help='Detect operating system')
        scan_group.add_argument('--service-scan', action='store_true', help='Detailed service version scanning')
        scan_group.add_argument('--exploit-test', action='store_true', help='Test exploitation of discovered vulnerabilities')
        scan_group.add_argument('--attack-surface', action='store_true', help='Discover and analyze attack surface')
        scan_group.add_argument('--continuous-monitoring', action='store_true', help='Enable continuous attack surface monitoring')

        # Search engines
        search_group = parser.add_argument_group('Search Engine Options')
        search_group.add_argument('--search-engine', choices=['google', 'duckduckgo', 'bing', 'aol'], 
                                default='google', help='Search engine to use (default: google)')
        search_group.add_argument('--pages', type=int, default=5, help='Number of pages to search')
        
        # Proxy options
        proxy_group = parser.add_argument_group('Proxy Options')
        proxy_group.add_argument('--proxy', help='Proxy to use (format: http://host:port)')
        proxy_group.add_argument('--proxy-type', choices=['http', 'https', 'socks4', 'socks5'], 
                               default='http', help='Proxy type')
        proxy_group.add_argument('--tor', action='store_true', help='Use Tor proxy')
        proxy_group.add_argument('--random-ua', action='store_true', help='Use random user agent')
        proxy_group.add_argument('--custom-ua', help='Use custom user agent')
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('-o', '--output', help='Output file path')
        output_group.add_argument('--format', choices=['txt', 'json', 'csv'], default='txt', help='Output format')
        output_group.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        
        return parser
    
    def print_banner(self):
        print(self.banner)
    
    def validate_target(self, args):
        if not any([args.url, args.domain, args.query]):
            print(f"{Fore.RED}[!] Error: You must specify a target (-u, -d, or -q){Style.RESET_ALL}")
            return False
        return True
    
    def run_full_scan(self, target):
        print(f"{Fore.GREEN}[+] Starting full reconnaissance scan on: {target}{Style.RESET_ALL}")
        
        # Initialize modules
        url_analyzer = URLAnalyzer()
        vuln_scanner = VulnerabilityScanner()
        ssl_dns_scanner = SSLDNSScanner()
        waf_detector = WAFDetector(requests.Session())
        web_crawler = WebCrawler()
        network_recon = NetworkRecon()
        
        results = {}
        
        # URL Analysis
        print(f"{Fore.YELLOW}[*] Analyzing URL structure...{Style.RESET_ALL}")
        results['url_analysis'] = url_analyzer.analyze(target)
        
        # SSL and DNS Check
        print(f"{Fore.YELLOW}[*] Checking SSL and DNS vulnerabilities...{Style.RESET_ALL}")
        hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
        results['ssl_dns_info'] = ssl_dns_scanner.scan_ssl_vulnerabilities(hostname)
        
        # WAF Detection
        print(f"{Fore.YELLOW}[*] Detecting WAF/IDS protection...{Style.RESET_ALL}")
        results['waf_detection'] = waf_detector.detect_waf(target)
        
        # Web Crawling
        print(f"{Fore.YELLOW}[*] Crawling website for links...{Style.RESET_ALL}")
        results['crawled_links'] = web_crawler.recursive_crawl(target)
        
        # Network Reconnaissance
        print(f"{Fore.YELLOW}[*] Performing comprehensive network reconnaissance...{Style.RESET_ALL}")
        results['network_recon'] = network_recon.network_discovery(hostname)
        
        # Vulnerability Scanning
        print(f"{Fore.YELLOW}[*] Scanning for vulnerabilities...{Style.RESET_ALL}")
        vulnerabilities = {}
        vulnerabilities['xss'] = vuln_scanner.scan_xss(target)
        vulnerabilities['sqli'] = vuln_scanner.scan_sqli(target)
        vulnerabilities['clickjacking'] = vuln_scanner.scan_clickjacking(target)
        vulnerabilities['admin_panels'] = vuln_scanner.scan_admin_panels(target)
        results['vulnerabilities'] = vulnerabilities
        
        # Exploitation Testing
        print(f"{Fore.YELLOW}[*] Testing exploitation of discovered vulnerabilities...{Style.RESET_ALL}")
        exploitation_engine = ExploitationEngine(target)
        
        # Prepare vulnerability data for exploitation
        vuln_data = []
        for vuln_type, vuln_results in vulnerabilities.items():
            if vuln_results:
                for vuln in vuln_results:
                    vuln_data.append({
                        'type': vuln_type,
                        'name': vuln.get('parameter', 'unknown'),
                        'url': vuln.get('url', target)
                    })
        
        if vuln_data:
            results['exploitation_test'] = exploitation_engine.run_comprehensive_exploitation(vuln_data)
        else:
            results['exploitation_test'] = {'message': 'No vulnerabilities found for exploitation testing'}
        
        return results
    
    def run_specific_scan(self, target, scan_type):
        print(f"{Fore.GREEN}[+] Starting {scan_type} scan on: {target}{Style.RESET_ALL}")
        
        if scan_type == 'xss':
            scanner = VulnerabilityScanner()
            return scanner.scan_xss(target)
        elif scan_type == 'sqli':
            scanner = VulnerabilityScanner()
            return scanner.scan_sqli(target)
        elif scan_type == 'clickjacking':
            scanner = VulnerabilityScanner()
            return scanner.scan_clickjacking(target)
        elif scan_type == 'port_scan':
            scanner = VulnerabilityScanner()
            return scanner.scan_ports(target)
        elif scan_type == 'admin_panel':
            scanner = VulnerabilityScanner()
            return scanner.scan_admin_panels(target)
        elif scan_type == 'dns_enum' or scan_type == 'ssl_check':
            scanner = SSLDNSScanner()
            hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
            return scanner.scan_ssl_vulnerabilities(hostname)
        elif scan_type == 'waf_detect':
            detector = WAFDetector(requests.Session())
            return detector.detect_waf(target)
        elif scan_type == 'web_crawl':
            crawler = WebCrawler()
            return crawler.recursive_crawl(target)
        elif scan_type == 'network_recon':
            network_recon = NetworkRecon()
            hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
            return network_recon.network_discovery(hostname)
        elif scan_type == 'os_detect':
            network_recon = NetworkRecon()
            hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
            return network_recon.os_detection(hostname)
        elif scan_type == 'service_scan':
            network_recon = NetworkRecon()
            hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
            return network_recon.nmap_scan(hostname, 'comprehensive')
        elif scan_type == 'exploit_test':
            exploitation_engine = ExploitationEngine(target)
            # First run vulnerability scan to get vulnerabilities
            vuln_scanner = VulnerabilityScanner()
            vulnerabilities = []
            
            # Scan for various vulnerabilities
            xss_results = vuln_scanner.scan_xss(target)
            sqli_results = vuln_scanner.scan_sqli(target)
            
            # Convert results to exploitation format
            for vuln_type, results in [('xss', xss_results), ('sqli', sqli_results)]:
                if results:
                    for result in results:
                        vulnerabilities.append({
                            'type': vuln_type,
                            'name': result.get('parameter', 'unknown'),
                            'url': result.get('url', target)
                        })
            
            return exploitation_engine.run_comprehensive_exploitation(vulnerabilities)
    
    def run_search(self, query, engine, pages):
        print(f"{Fore.GREEN}[+] Searching for: {query} using {engine}{Style.RESET_ALL}")
        
        search_engine = SearchEngine()
        return search_engine.search(query, engine, pages)
    
    def save_results(self, results, output_file, format_type):
        if not output_file:
            output_file = f"results_{int(time.time())}.{format_type}"
        
        self.logger.save_results(results, output_file, format_type)
        print(f"{Fore.GREEN}[+] Results saved to: {output_file}{Style.RESET_ALL}")
    
    def main(self):
        args = self.parser.parse_args()
        
        self.print_banner()
        
        if not self.validate_target(args):
            sys.exit(1)
        
        try:
            results = {}
            
            # Configure proxy and user agent
            if args.proxy:
                proxy_manager = ProxyManager()
                proxy_manager.set_proxy(args.proxy, args.proxy_type)
            
            if args.tor:
                proxy_manager = ProxyManager()
                proxy_manager.set_tor_proxy()
            
            if args.random_ua:
                ua_manager = UserAgentManager()
                ua_manager.set_random_ua()
            elif args.custom_ua:
                ua_manager = UserAgentManager()
                ua_manager.set_custom_ua(args.custom_ua)
            
            # Determine target
            target = args.url or args.domain or args.query
            
            # Run scans based on arguments
            if args.full_scan:
                results = self.run_full_scan(target)
            elif args.xss_scan:
                results = self.run_specific_scan(target, 'xss')
            elif args.sqli_scan:
                results = self.run_specific_scan(target, 'sqli')
            elif args.clickjacking:
                results = self.run_specific_scan(target, 'clickjacking')
            elif args.port_scan:
                results = self.run_specific_scan(target, 'port_scan')
            elif args.admin_panel:
                results = self.run_specific_scan(target, 'admin_panel')
            elif args.dns_enum:
                results = self.run_specific_scan(target, 'dns_enum')
            elif args.ssl_check:
                results = self.run_specific_scan(target, 'ssl_check')
            elif args.waf_detect:
                results = self.run_specific_scan(target, 'waf_detect')
            elif args.web_crawl:
                results = self.run_specific_scan(target, 'web_crawl')
            elif args.network_recon:
                results = self.run_specific_scan(target, 'network_recon')
            elif args.os_detect:
                results = self.run_specific_scan(target, 'os_detect')
            elif args.service_scan:
                results = self.run_specific_scan(target, 'service_scan')
            elif args.exploit_test:
                results = self.run_specific_scan(target, 'exploit_test')
            elif args.attack_surface:
                print(f"{Fore.GREEN}[+] Starting attack surface discovery on: {target}{Style.RESET_ALL}")
                attack_manager = AttackSurfaceManager(target)
                
                # Discover attack surface
                results = attack_manager.discover_attack_surface()
                
                # Generate visual report
                visualizer = AttackSurfaceVisualizer()
                network_map = visualizer.generate_network_map(results)
                
                # Generate comprehensive report
                report = attack_manager.generate_attack_surface_report()
                
                # Save results
                timestamp = int(time.time())
                attack_results_file = f"attack_surface_{timestamp}.json"
                report_file = f"attack_surface_report_{timestamp}.md"
                map_file = f"network_map_{timestamp}.mmd"
                
                self.save_results(results, attack_results_file, 'json')
                
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"{Fore.GREEN}[+] Attack surface report saved to: {report_file}{Style.RESET_ALL}")
                
                with open(map_file, 'w') as f:
                    f.write(network_map)
                print(f"{Fore.GREEN}[+] Network map saved to: {map_file}{Style.RESET_ALL}")
                
                if args.continuous_monitoring:
                    print(f"{Fore.YELLOW}[*] Starting continuous monitoring...{Style.RESET_ALL}")
                    attack_manager.continuous_monitoring(1)  # Default 1 hour interval
            elif args.query:
                results = self.run_search(args.query, args.search_engine, args.pages)
            
            # Save results
            if args.output:
                self.save_results(results, args.output, args.format)
            else:
                print(f"{Fore.CYAN}[+] Scan Results:{Style.RESET_ALL}")
                print(results)
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

if __name__ == "__main__":
    sayer7 = Sayer7()
    sayer7.main()