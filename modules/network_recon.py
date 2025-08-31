#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Reconnaissance Module for Sayer7
Comprehensive network scanning using Nmap for target information gathering
including IP addresses, open services, OS detection, and version identification
"""

import subprocess
import json
import re
import socket
import requests
from typing import Dict, List, Optional, Tuple
import concurrent.futures
import time

class NetworkRecon:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sayer7 Network Recon/1.0'
        })
        
    def check_nmap_availability(self) -> bool:
        """Check if Nmap is available on the system"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            ips = socket.gethostbyname_ex(domain)
            return list(set(ips[2]))  # Remove duplicates
        except socket.gaierror:
            return []
    
    def reverse_dns_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup"""
        try:
            hostnames = socket.gethostbyaddr(ip)
            return [hostnames[0]] + list(hostnames[1])
        except socket.herror:
            return []
    
    def get_ip_geolocation(self, ip: str) -> Dict:
        """Get IP geolocation information"""
        try:
            response = self.session.get(f'https://ipapi.co/{ip}/json/', timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        # Fallback service
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {'ip': ip, 'error': 'Location data unavailable'}
    
    def nmap_scan(self, target: str, scan_type: str = 'comprehensive') -> Dict:
        """
        Perform comprehensive Nmap scan
        
        Args:
            target: IP address or domain
            scan_type: 'fast', 'comprehensive', 'intense'
        """
        if not self.check_nmap_availability():
            return {'error': 'Nmap not available. Please install Nmap.'}
        
        scan_configs = {
            'fast': ['-T4', '-F'],
            'comprehensive': ['-sS', '-sV', '-O', '-sC', '--top-ports', '1000'],
            'intense': ['-sS', '-sU', '-sV', '-O', '-A', '-p-', '-T4']
        }
        
        nmap_args = scan_configs.get(scan_type, scan_configs['comprehensive'])
        
        try:
            cmd = ['nmap'] + nmap_args + [target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                return {'error': f'Nmap scan failed: {result.stderr}'}
            
            return self.parse_nmap_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def nmap_xml_scan(self, target: str, scan_type: str = 'comprehensive') -> Dict:
        """Perform Nmap scan with XML output for better parsing"""
        if not self.check_nmap_availability():
            return {'error': 'Nmap not available. Please install Nmap.'}
        
        scan_configs = {
            'fast': ['-T4', '-F'],
            'comprehensive': ['-sS', '-sV', '-O', '-sC', '--top-ports', '1000'],
            'intense': ['-sS', '-sU', '-sV', '-O', '-A', '-p-', '-T4']
        }
        
        nmap_args = scan_configs.get(scan_type, scan_configs['comprehensive'])
        
        try:
            cmd = ['nmap', '-oX', '-'] + nmap_args + [target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                return {'error': f'Nmap scan failed: {result.stderr}'}
            
            return self.parse_nmap_xml(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def parse_nmap_output(self, output: str) -> Dict:
        """Parse Nmap text output"""
        result = {
            'scan_type': 'nmap',
            'target': '',
            'host_status': '',
            'os_detection': {},
            'open_ports': [],
            'services': [],
            'raw_output': output
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Target
            if line.startswith('Nmap scan report for'):
                result['target'] = line.split('for')[1].strip()
            
            # Host status
            elif 'Host is up' in line:
                result['host_status'] = 'up'
            elif 'Host seems down' in line or '0 hosts up' in line:
                result['host_status'] = 'down'
            
            # OS Detection
            elif 'OS details:' in line:
                result['os_detection']['os_details'] = line.split('OS details:')[1].strip()
            elif 'Aggressive OS guesses:' in line:
                result['os_detection']['os_guesses'] = line.split('Aggressive OS guesses:')[1].strip()
            elif 'Running:' in line and 'JUST GUESSING' not in line:
                result['os_detection']['running'] = line.split('Running:')[1].strip()
            
            # Port information
            elif re.match(r'^\d+/\w+\s+\w+\s+\w+\s+.*$', line):
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        'port': parts[0].split('/')[0],
                        'protocol': parts[0].split('/')[1],
                        'state': parts[1],
                        'service': parts[2],
                        'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                    }
                    result['open_ports'].append(port_info)
                    
                    service_info = {
                        'port': parts[0].split('/')[0],
                        'service': parts[2],
                        'version': ' '.join(parts[3:]) if len(parts) > 3 else 'Unknown'
                    }
                    result['services'].append(service_info)
        
        return result
    
    def parse_nmap_xml(self, xml_output: str) -> Dict:
        """Parse Nmap XML output"""
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(xml_output)
            result = {
                'scan_type': 'nmap_xml',
                'target': '',
                'host_status': '',
                'os_detection': {},
                'open_ports': [],
                'services': [],
                'raw_xml': xml_output
            }
            
            # Find host information
            host = root.find('.//host')
            if host is not None:
                # Target
                address = host.find('.//address[@addrtype="ipv4"]')
                if address is not None:
                    result['target'] = address.get('addr')
                
                # Host status
                status = host.find('.//status')
                if status is not None:
                    result['host_status'] = status.get('state')
                
                # OS Detection
                os_elem = host.find('.//os/osmatch')
                if os_elem is not None:
                    result['os_detection']['name'] = os_elem.get('name')
                    result['os_detection']['accuracy'] = os_elem.get('accuracy')
                    
                    os_class = host.find('.//os/osclass')
                    if os_class is not None:
                        result['os_detection']['type'] = os_class.get('type')
                        result['os_detection']['vendor'] = os_class.get('vendor')
                        result['os_detection']['family'] = os_class.get('osfamily')
                        result['os_detection']['version'] = os_class.get('osgen')
                
                # Ports and services
                ports = host.findall('.//port')
                for port in ports:
                    port_info = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('.//state').get('state') if port.find('.//state') is not None else 'unknown',
                        'service': '',
                        'version': ''
                    }
                    
                    service = port.find('.//service')
                    if service is not None:
                        port_info['service'] = service.get('name', '')
                        port_info['version'] = f"{service.get('product', '')} {service.get('version', '')}".strip()
                    
                    result['open_ports'].append(port_info)
                    
                    service_info = {
                        'port': port.get('portid'),
                        'service': port_info['service'],
                        'version': port_info['version']
                    }
                    result['services'].append(service_info)
            
            return result
            
        except ET.ParseError as e:
            return {'error': f'Failed to parse Nmap XML: {str(e)}'}
    
    def network_discovery(self, target: str) -> Dict:
        """
        Perform comprehensive network discovery
        
        Args:
            target: IP address, domain, or network range (e.g., 192.168.1.0/24)
        """
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_addresses': [],
            'hostnames': [],
            'geolocation': {},
            'network_scan': {},
            'dns_info': {},
            'summary': {}
        }

        # Determine if target is IP or domain
        try:
            socket.inet_aton(target.split('/')[0])
            is_ip = True
            ip_list = [target] if '/' not in target else []
        except socket.error:
            is_ip = False
            ip_list = self.resolve_domain(target)

        # Resolve IPs if domain
        if not is_ip:
            results['dns_info']['resolved_ips'] = ip_list
            results['dns_info']['domain'] = target
            
            # Reverse DNS for each IP
            for ip in ip_list:
                hostnames = self.reverse_dns_lookup(ip)
                results['hostnames'].extend(hostnames)

        # Use target as-is if it's an IP
        scan_target = target if is_ip else (ip_list[0] if ip_list else target)

        if scan_target:
            # IP geolocation
            if not '/' in scan_target:
                actual_ip = scan_target.split('/')[0] if '/' in scan_target else scan_target
                results['geolocation'] = self.get_ip_geolocation(actual_ip)

            # Nmap scan with error handling
            print(f"Starting comprehensive network scan for {scan_target}...")
            try:
                nmap_results = self.nmap_xml_scan(scan_target, 'comprehensive')
                results['network_scan'] = nmap_results
            except Exception as e:
                results['network_scan'] = {'error': f'Nmap scan failed: {str(e)}'}
                print(f"[!] Nmap scan unavailable - using fallback methods")

            # Additional IP info
            if not '/' in scan_target:
                results['ip_addresses'] = [actual_ip]

        # Generate summary
        open_ports = results['network_scan'].get('open_ports', [])
        services = results['network_scan'].get('services', [])
        os_info = results['network_scan'].get('os_detection', {})
        has_error = 'error' in results['network_scan']

        results['summary'] = {
            'total_open_ports': len(open_ports) if not has_error else 0,
            'services_found': [s['service'] for s in services] if not has_error else [],
            'detected_os': os_info.get('name', 'Unknown') if not has_error else 'Unknown',
            'ip_addresses': results['ip_addresses'],
            'hostnames': list(set(results['hostnames']))
        }

        return results
    
    def service_version_detection(self, target: str, port: int) -> Dict:
        """Get detailed service version information"""
        if not self.check_nmap_availability():
            return {'error': 'Nmap not available'}
        
        try:
            cmd = ['nmap', '-sV', '-p', str(port), '--version-intensity', '9', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                return {'error': f'Service scan failed: {result.stderr}'}
            
            return self.parse_nmap_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {'error': 'Service scan timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def os_detection(self, target: str) -> Dict:
        """Perform OS detection"""
        if not self.check_nmap_availability():
            return {'error': 'Nmap not available'}
        
        try:
            cmd = ['nmap', '-O', '--osscan-guess', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                return {'error': f'OS detection failed: {result.stderr}'}
            
            return self.parse_nmap_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            return {'error': 'OS detection timed out'}
        except Exception as e:
            return {'error': str(e)}