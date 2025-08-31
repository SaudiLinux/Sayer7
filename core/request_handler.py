#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Request Handler for Sayer7
Manages HTTP requests with proxy support, user agent rotation, and error handling
"""

import requests
import random
import time
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socket
import socks

class RequestHandler:
    def __init__(self, timeout=10, retries=3):
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def set_proxy(self, proxy_url, proxy_type='http'):
        """Set proxy for requests"""
        if proxy_type.lower() == 'http':
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
        elif proxy_type.lower() == 'socks4':
            socks.setdefaultproxy(socks.SOCKS4, *self.parse_proxy_url(proxy_url))
            socket.socket = socks.socksocket
        elif proxy_type.lower() == 'socks5':
            socks.setdefaultproxy(socks.SOCKS5, *self.parse_proxy_url(proxy_url))
            socket.socket = socks.socksocket
    
    def set_tor_proxy(self, host='127.0.0.1', port=9050):
        """Set Tor proxy"""
        socks.setdefaultproxy(socks.SOCKS5, host, port)
        socket.socket = socks.socksocket
    
    def parse_proxy_url(self, proxy_url):
        """Parse proxy URL into components"""
        from urllib.parse import urlparse
        parsed = urlparse(proxy_url)
        return parsed.hostname, parsed.port
    
    def set_user_agent(self, user_agent):
        """Set custom user agent"""
        self.session.headers.update({'User-Agent': user_agent})
    
    def get(self, url, headers=None, params=None, allow_redirects=True):
        """Perform GET request"""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            response = self.session.get(
                url,
                headers=request_headers,
                params=params,
                timeout=self.timeout,
                allow_redirects=allow_redirects
            )
            
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'url': response.url,
                'encoding': response.encoding,
                'cookies': dict(response.cookies)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'status_code': None,
                'headers': {},
                'content': '',
                'url': url,
                'encoding': None,
                'cookies': {}
            }
    
    def post(self, url, data=None, json_data=None, headers=None):
        """Perform POST request"""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            if json_data:
                response = self.session.post(
                    url,
                    json=json_data,
                    headers=request_headers,
                    timeout=self.timeout
                )
            else:
                response = self.session.post(
                    url,
                    data=data,
                    headers=request_headers,
                    timeout=self.timeout
                )
            
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'url': response.url,
                'encoding': response.encoding,
                'cookies': dict(response.cookies)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'status_code': None,
                'headers': {},
                'content': '',
                'url': url,
                'encoding': None,
                'cookies': {}
            }
    
    def head(self, url, headers=None):
        """Perform HEAD request"""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            response = self.session.head(
                url,
                headers=request_headers,
                timeout=self.timeout
            )
            
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'url': response.url
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'status_code': None,
                'headers': {},
                'url': url
            }
    
    def check_connection(self, url):
        """Check if URL is accessible"""
        result = self.head(url)
        return result['success'] and result['status_code'] < 400
    
    def get_response_time(self, url):
        """Measure response time for URL"""
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=self.timeout)
            end_time = time.time()
            
            return {
                'success': True,
                'response_time': round(end_time - start_time, 3),
                'status_code': response.status_code
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'response_time': None
            }
    
    def follow_redirects(self, url, max_redirects=10):
        """Follow redirects and return final URL"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            redirect_chain = []
            if response.history:
                for resp in response.history:
                    redirect_chain.append({
                        'status_code': resp.status_code,
                        'url': resp.url
                    })
            
            return {
                'success': True,
                'final_url': response.url,
                'status_code': response.status_code,
                'redirect_chain': redirect_chain,
                'total_redirects': len(redirect_chain)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'final_url': url,
                'status_code': None,
                'redirect_chain': [],
                'total_redirects': 0
            }
    
    def download_file(self, url, local_path):
        """Download file from URL"""
        try:
            response = self.session.get(url, stream=True, timeout=self.timeout)
            response.raise_for_status()
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return {
                'success': True,
                'file_size': os.path.getsize(local_path),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'file_size': 0,
                'content_type': None
            }