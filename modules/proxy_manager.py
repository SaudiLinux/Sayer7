#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy Manager for Sayer7
Comprehensive proxy support including HTTP, HTTPS, SOCKS4, SOCKS5, and Tor
Features proxy rotation, validation, and automatic failover
"""

import requests
import socket
import socks
import time
import random
import threading
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
import json
import os

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.working_proxies = []
        self.failed_proxies = []
        self.current_proxy_index = 0
        self.lock = threading.Lock()
        
        # Tor configuration
        self.tor_host = '127.0.0.1'
        self.tor_port = 9050
        self.tor_control_port = 9051
        self.tor_password = None
        
        # Proxy types
        self.proxy_types = {
            'http': self.validate_http_proxy,
            'https': self.validate_https_proxy,
            'socks4': self.validate_socks4_proxy,
            'socks5': self.validate_socks5_proxy,
            'tor': self.validate_tor_proxy
        }
    
    def add_proxy(self, proxy_url: str, proxy_type: str = 'http') -> bool:
        """Add a proxy to the pool"""
        try:
            proxy_data = {
                'url': proxy_url,
                'type': proxy_type.lower(),
                'status': 'unknown',
                'response_time': None,
                'last_check': None,
                'fail_count': 0
            }
            
            self.proxies.append(proxy_data)
            return True
        except Exception as e:
            print(f"Error adding proxy {proxy_url}: {str(e)}")
            return False
    
    def load_proxies_from_file(self, file_path: str) -> int:
        """Load proxies from file (format: type://host:port or host:port)"""
        try:
            loaded_count = 0
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse proxy format
                        if '://' in line:
                            proxy_type, proxy_url = line.split('://', 1)
                        else:
                            proxy_type = 'http'
                            proxy_url = line
                        
                        if self.add_proxy(proxy_url, proxy_type):
                            loaded_count += 1
            
            print(f"Loaded {loaded_count} proxies from {file_path}")
            return loaded_count
            
        except FileNotFoundError:
            print(f"Proxy file {file_path} not found")
            return 0
        except Exception as e:
            print(f"Error loading proxies: {str(e)}")
            return 0
    
    def load_proxies_from_list(self, proxy_list: List[str]) -> int:
        """Load proxies from a list of strings"""
        loaded_count = 0
        for proxy_str in proxy_list:
            try:
                if '://' in proxy_str:
                    proxy_type, proxy_url = proxy_str.split('://', 1)
                else:
                    proxy_type = 'http'
                    proxy_url = proxy_str
                
                if self.add_proxy(proxy_url, proxy_type):
                    loaded_count += 1
            except:
                continue
        
        return loaded_count
    
    def validate_http_proxy(self, proxy_url: str, timeout: int = 5) -> Tuple[bool, float]:
        """Validate HTTP proxy"""
        try:
            start_time = time.time()
            
            proxy_dict = {
                'http': f'http://{proxy_url}',
                'https': f'http://{proxy_url}'
            }
            
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxy_dict,
                timeout=timeout,
                headers={'User-Agent': 'Sayer7/1.0'}
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                return True, response_time
            else:
                return False, response_time
                
        except Exception as e:
            return False, 0.0
    
    def validate_https_proxy(self, proxy_url: str, timeout: int = 5) -> Tuple[bool, float]:
        """Validate HTTPS proxy"""
        try:
            start_time = time.time()
            
            proxy_dict = {
                'http': f'https://{proxy_url}',
                'https': f'https://{proxy_url}'
            }
            
            response = requests.get(
                'https://httpbin.org/ip',
                proxies=proxy_dict,
                timeout=timeout,
                headers={'User-Agent': 'Sayer7/1.0'},
                verify=False
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                return True, response_time
            else:
                return False, response_time
                
        except Exception as e:
            return False, 0.0
    
    def validate_socks4_proxy(self, proxy_url: str, timeout: int = 5) -> Tuple[bool, float]:
        """Validate SOCKS4 proxy"""
        try:
            host, port = proxy_url.split(':')
            port = int(port)
            
            start_time = time.time()
            
            # Test SOCKS4 connection
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, host, port)
            socket.socket = socks.socksocket
            
            # Try to connect to a test server
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(timeout)
            test_socket.connect(('httpbin.org', 80))
            test_socket.close()
            
            response_time = time.time() - start_time
            return True, response_time
            
        except Exception as e:
            return False, 0.0
    
    def validate_socks5_proxy(self, proxy_url: str, timeout: int = 5) -> Tuple[bool, float]:
        """Validate SOCKS5 proxy"""
        try:
            host, port = proxy_url.split(':')
            port = int(port)
            
            start_time = time.time()
            
            # Test SOCKS5 connection
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port)
            socket.socket = socks.socksocket
            
            # Try to connect to a test server
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(timeout)
            test_socket.connect(('httpbin.org', 80))
            test_socket.close()
            
            response_time = time.time() - start_time
            return True, response_time
            
        except Exception as e:
            return False, 0.0
    
    def validate_tor_proxy(self, proxy_url: str = None, timeout: int = 5) -> Tuple[bool, float]:
        """Validate Tor proxy connection"""
        try:
            if proxy_url:
                host, port = proxy_url.split(':')
                self.tor_host = host
                self.tor_port = int(port)
            
            start_time = time.time()
            
            # Configure SOCKS5 for Tor
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, self.tor_host, self.tor_port)
            socket.socket = socks.socksocket
            
            # Test Tor connection
            response = requests.get(
                'http://check.torproject.org',
                timeout=timeout,
                headers={'User-Agent': 'Sayer7/1.0'}
            )
            
            response_time = time.time() - start_time
            
            if 'Congratulations. This browser is configured to use Tor' in response.text:
                return True, response_time
            else:
                return False, response_time
                
        except Exception as e:
            return False, 0.0
    
    def validate_all_proxies(self, timeout: int = 5) -> Dict[str, int]:
        """Validate all proxies and categorize them"""
        results = {
            'total': len(self.proxies),
            'working': 0,
            'failed': 0,
            'by_type': {}
        }
        
        for proxy in self.proxies:
            proxy_type = proxy['type']
            proxy_url = proxy['url']
            
            if proxy_type in self.proxy_types:
                validator = self.proxy_types[proxy_type]
                is_working, response_time = validator(proxy_url, timeout)
                
                proxy['status'] = 'working' if is_working else 'failed'
                proxy['response_time'] = response_time
                proxy['last_check'] = time.time()
                
                if is_working:
                    self.working_proxies.append(proxy)
                    results['working'] += 1
                    
                    if proxy_type not in results['by_type']:
                        results['by_type'][proxy_type] = 0
                    results['by_type'][proxy_type] += 1
                else:
                    self.failed_proxies.append(proxy)
                    proxy['fail_count'] += 1
                    results['failed'] += 1
        
        return results
    
    def get_proxy(self, rotate: bool = True) -> Optional[Dict]:
        """Get a working proxy (with rotation)"""
        if not self.working_proxies:
            return None
        
        with self.lock:
            if rotate:
                proxy = self.working_proxies[self.current_proxy_index]
                self.current_proxy_index = (self.current_proxy_index + 1) % len(self.working_proxies)
            else:
                proxy = self.working_proxies[0]
        
        return proxy
    
    def get_proxy_dict(self, proxy: Dict) -> Dict[str, str]:
        """Convert proxy dict to requests-compatible format"""
        proxy_url = proxy['url']
        proxy_type = proxy['type']
        
        if proxy_type == 'http':
            return {
                'http': f'http://{proxy_url}',
                'https': f'http://{proxy_url}'
            }
        elif proxy_type == 'https':
            return {
                'http': f'https://{proxy_url}',
                'https': f'https://{proxy_url}'
            }
        elif proxy_type == 'socks4':
            return {
                'http': f'socks4://{proxy_url}',
                'https': f'socks4://{proxy_url}'
            }
        elif proxy_type == 'socks5':
            return {
                'http': f'socks5://{proxy_url}',
                'https': f'socks5://{proxy_url}'
            }
        elif proxy_type == 'tor':
            return {
                'http': f'socks5://{proxy_url}',
                'https': f'socks5://{proxy_url}'
            }
        
        return {}
    
    def setup_tor_proxy(self, host: str = '127.0.0.1', port: int = 9050, 
                       control_port: int = 9051, password: str = None) -> bool:
        """Setup Tor proxy configuration"""
        try:
            self.tor_host = host
            self.tor_port = port
            self.tor_control_port = control_port
            self.tor_password = password
            
            # Add Tor as a proxy
            tor_proxy = {
                'url': f'{host}:{port}',
                'type': 'tor',
                'status': 'unknown',
                'response_time': None,
                'last_check': None,
                'fail_count': 0
            }
            
            self.proxies.append(tor_proxy)
            return True
            
        except Exception as e:
            print(f"Error setting up Tor proxy: {str(e)}")
            return False
    
    def renew_tor_identity(self) -> bool:
        """Renew Tor identity (requires Tor control port)"""
        try:
            import stem.control
            
            with stem.control.Controller.from_port(port=self.tor_control_port) as controller:
                if self.tor_password:
                    controller.authenticate(password=self.tor_password)
                else:
                    controller.authenticate()
                
                controller.signal(stem.Signal.NEWNYM)
                return True
                
        except Exception as e:
            print(f"Error renewing Tor identity: {str(e)}")
            return False
    
    def get_proxy_stats(self) -> Dict:
        """Get proxy statistics"""
        stats = {
            'total_proxies': len(self.proxies),
            'working_proxies': len(self.working_proxies),
            'failed_proxies': len(self.failed_proxies),
            'proxy_types': {},
            'response_times': []
        }
        
        # Count by type
        for proxy in self.proxies:
            proxy_type = proxy['type']
            if proxy_type not in stats['proxy_types']:
                stats['proxy_types'][proxy_type] = {'total': 0, 'working': 0}
            
            stats['proxy_types'][proxy_type]['total'] += 1
            if proxy['status'] == 'working':
                stats['proxy_types'][proxy_type]['working'] += 1
        
        # Response times
        for proxy in self.working_proxies:
            if proxy['response_time']:
                stats['response_times'].append(proxy['response_time'])
        
        return stats
    
    def save_working_proxies(self, file_path: str) -> bool:
        """Save working proxies to file"""
        try:
            with open(file_path, 'w') as f:
                for proxy in self.working_proxies:
                    f.write(f"{proxy['type']}://{proxy['url']}\n")
            
            return True
            
        except Exception as e:
            print(f"Error saving proxies: {str(e)}")
            return False
    
    def load_default_proxy_lists(self):
        """Load default proxy lists from common sources"""
        # Common free proxy sources (for educational purposes)
        default_proxies = [
            # HTTP/HTTPS proxies (example format)
            'http://proxy1.example.com:8080',
            'https://proxy2.example.com:443',
            'socks4://proxy3.example.com:1080',
            'socks5://proxy4.example.com:1080'
        ]
        
        # These would typically be loaded from actual proxy lists
        # For now, we'll just set up the structure
        return 0