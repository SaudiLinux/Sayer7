#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL Analysis Engine for Sayer7
Advanced URL parsing and analysis capabilities
"""

import re
import urllib.parse
import tldextract
import ipaddress
from urllib.parse import urlparse, parse_qs, urljoin
import requests
from bs4 import BeautifulSoup
import json

class URLAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, url):
        """Comprehensive URL analysis"""
        results = {
            'original_url': url,
            'parsed_url': self.parse_url(url),
            'domain_info': self.extract_domain_info(url),
            'parameters': self.extract_parameters(url),
            'google_cache': self.get_google_cache(url),
            'robots_txt': self.check_robots_txt(url),
            'sitemap_xml': self.check_sitemap_xml(url),
            'subdomains': self.extract_subdomains(url),
            'ip_info': self.get_ip_info(url),
            'technologies': self.detect_technologies(url),
            'directories': self.extract_directories(url)
        }
        return results
    
    def parse_url(self, url):
        """Parse URL into components"""
        try:
            parsed = urlparse(url)
            return {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'username': parsed.username,
                'password': parsed.password
            }
        except Exception as e:
            return {'error': str(e)}
    
    def extract_domain_info(self, url):
        """Extract detailed domain information"""
        try:
            extracted = tldextract.extract(url)
            return {
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix,
                'registered_domain': extracted.registered_domain,
                'fqdn': extracted.fqdn
            }
        except Exception as e:
            return {'error': str(e)}
    
    def extract_parameters(self, url):
        """Extract and analyze URL parameters"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            param_analysis = {}
            for key, values in params.items():
                param_analysis[key] = {
                    'values': values,
                    'potential_vulnerable': self.is_potential_vulnerable_param(key),
                    'data_type': self.infer_data_type(values[0]) if values else 'empty'
                }
            
            return param_analysis
        except Exception as e:
            return {'error': str(e)}
    
    def is_potential_vulnerable_param(self, param_name):
        """Check if parameter name suggests vulnerability potential"""
        vuln_keywords = [
            'id', 'page', 'file', 'path', 'url', 'redirect', 'return', 'next',
            'callback', 'template', 'view', 'content', 'data', 'input',
            'cmd', 'command', 'system', 'exec', 'shell', 'php', 'asp', 'jsp'
        ]
        
        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in vuln_keywords)
    
    def infer_data_type(self, value):
        """Infer the data type of a parameter value"""
        if value.isdigit():
            return 'integer'
        elif value.replace('.', '', 1).isdigit():
            return 'float'
        elif value.lower() in ['true', 'false']:
            return 'boolean'
        elif len(value) == 32 and re.match(r'^[a-f0-9]+$', value.lower()):
            return 'md5_hash'
        elif len(value) == 40 and re.match(r'^[a-f0-9]+$', value.lower()):
            return 'sha1_hash'
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return 'email'
        elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
            return 'ip_address'
        elif re.match(r'https?://', value):
            return 'url'
        else:
            return 'string'
    
    def get_google_cache(self, url):
        """Extract URL from Google cache"""
        try:
            cache_url = f"http://webcache.googleusercontent.com/search?q=cache:{url}"
            response = self.session.get(cache_url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                cache_info = {
                    'cached': True,
                    'cache_url': cache_url,
                    'cache_date': self.extract_cache_date(soup),
                    'original_url': url
                }
                return cache_info
            else:
                return {'cached': False, 'error': 'Not found in cache'}
        except Exception as e:
            return {'cached': False, 'error': str(e)}
    
    def extract_cache_date(self, soup):
        """Extract cache date from Google cache page"""
        try:
            # Look for cache date in the cache header
            cache_header = soup.find('div', {'id': 'cache_info'})
            if cache_header:
                text = cache_header.get_text()
                date_match = re.search(r'(\d{1,2}\s+\w+\s+\d{4})', text)
                if date_match:
                    return date_match.group(1)
            return 'Unknown'
        except:
            return 'Unknown'
    
    def check_robots_txt(self, url):
        """Check robots.txt file"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                return {
                    'exists': True,
                    'url': robots_url,
                    'content': response.text,
                    'disallowed_paths': self.parse_robots_txt(response.text)
                }
            else:
                return {'exists': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'exists': False, 'error': str(e)}
    
    def parse_robots_txt(self, content):
        """Parse robots.txt to extract disallowed paths"""
        disallowed = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    disallowed.append(path)
        
        return disallowed
    
    def check_sitemap_xml(self, url):
        """Check sitemap.xml file"""
        try:
            parsed = urlparse(url)
            sitemap_urls = [
                f"{parsed.scheme}://{parsed.netloc}/sitemap.xml",
                f"{parsed.scheme}://{parsed.netloc}/sitemap_index.xml"
            ]
            
            for sitemap_url in sitemap_urls:
                try:
                    response = self.session.get(sitemap_url, timeout=10)
                    if response.status_code == 200:
                        return {
                            'exists': True,
                            'url': sitemap_url,
                            'content': response.text,
                            'urls': self.parse_sitemap_xml(response.text)
                        }
                except:
                    continue
            
            return {'exists': False, 'error': 'Sitemap not found'}
        except Exception as e:
            return {'exists': False, 'error': str(e)}
    
    def parse_sitemap_xml(self, content):
        """Parse sitemap.xml to extract URLs"""
        try:
            soup = BeautifulSoup(content, 'xml')
            urls = []
            
            # Look for <url> tags in standard sitemap
            url_tags = soup.find_all('url')
            for url_tag in url_tags:
                loc = url_tag.find('loc')
                if loc:
                    urls.append(loc.text)
            
            # Look for <sitemap> tags in sitemap index
            sitemap_tags = soup.find_all('sitemap')
            for sitemap_tag in sitemap_tags:
                loc = sitemap_tag.find('loc')
                if loc:
                    urls.append(loc.text)
            
            return urls
        except:
            return []
    
    def extract_subdomains(self, url):
        """Extract potential subdomains"""
        try:
            extracted = tldextract.extract(url)
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Common subdomains to test
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                'blog', 'shop', 'support', 'help', 'docs', 'wiki', 'forum',
                'news', 'media', 'cdn', 'static', 'assets', 'images', 'css',
                'js', 'api', 'secure', 'login', 'account', 'user', 'app',
                'mobile', 'm', 'beta', 'alpha', 'demo', 'sandbox', 'backup'
            ]
            
            return {
                'base_domain': base_domain,
                'current_subdomain': extracted.subdomain,
                'potential_subdomains': [f"{sub}.{base_domain}" for sub in common_subdomains]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_ip_info(self, url):
        """Get IP address information"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return {'error': 'No hostname found'}
            
            ip = self.resolve_hostname(hostname)
            
            return {
                'hostname': hostname,
                'ip_address': ip,
                'is_private': ipaddress.ip_address(ip).is_private if ip else None,
                'is_loopback': ipaddress.ip_address(ip).is_loopback if ip else None
            }
        except Exception as e:
            return {'error': str(e)}
    
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP address"""
        try:
            import socket
            return socket.gethostbyname(hostname)
        except:
            return None
    
    def detect_technologies(self, url):
        """Detect web technologies used by the target"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            technologies = {
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'frameworks': self.detect_frameworks(soup, response.text),
                'cms': self.detect_cms(soup, response.text),
                'javascript': self.detect_javascript(soup),
                'css_frameworks': self.detect_css_frameworks(soup)
            }
            
            return technologies
        except Exception as e:
            return {'error': str(e)}
    
    def detect_frameworks(self, soup, html_content):
        """Detect web frameworks"""
        frameworks = []
        
        # Check for common framework signatures
        if 'django' in str(soup).lower():
            frameworks.append('Django')
        if 'flask' in str(soup).lower():
            frameworks.append('Flask')
        if 'rails' in str(soup).lower():
            frameworks.append('Ruby on Rails')
        if 'laravel' in str(soup).lower():
            frameworks.append('Laravel')
        if 'spring' in str(soup).lower():
            frameworks.append('Spring')
        if 'express' in str(soup).lower():
            frameworks.append('Express.js')
        
        return frameworks
    
    def detect_cms(self, soup, html_content):
        """Detect Content Management Systems"""
        cms = []
        
        # WordPress signatures
        if 'wp-content' in str(soup) or 'wordpress' in str(soup).lower():
            cms.append('WordPress')
        
        # Drupal signatures
        if 'drupal' in str(soup).lower():
            cms.append('Drupal')
        
        # Joomla signatures
        if 'joomla' in str(soup).lower():
            cms.append('Joomla')
        
        return cms
    
    def detect_javascript(self, soup):
        """Detect JavaScript libraries and frameworks"""
        js_libraries = []
        
        # Check script sources
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            if 'jquery' in src:
                js_libraries.append('jQuery')
            if 'angular' in src:
                js_libraries.append('Angular')
            if 'react' in src:
                js_libraries.append('React')
            if 'vue' in src:
                js_libraries.append('Vue.js')
            if 'bootstrap' in src:
                js_libraries.append('Bootstrap')
        
        return js_libraries
    
    def detect_css_frameworks(self, soup):
        """Detect CSS frameworks"""
        css_frameworks = []
        
        # Check link tags for CSS
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '').lower()
            if 'bootstrap' in href:
                css_frameworks.append('Bootstrap')
            if 'tailwind' in href:
                css_frameworks.append('Tailwind CSS')
            if 'bulma' in href:
                css_frameworks.append('Bulma')
            if 'foundation' in href:
                css_frameworks.append('Foundation')
        
        return css_frameworks
    
    def extract_directories(self, url):
        """Extract directory structure from URL"""
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            directories = []
            parts = path.strip('/').split('/')
            
            current_path = ''
            for part in parts:
                if part:
                    current_path = f"{current_path}/{part}"
                    directories.append({
                        'directory': part,
                        'full_path': current_path,
                        'url': f"{parsed.scheme}://{parsed.netloc}{current_path}"
                    })
            
            return directories
        except Exception as e:
            return {'error': str(e)}
    
    def normalize_url(self, url):
        """Normalize URL for consistent processing"""
        try:
            # Remove default ports
            url = re.sub(r':80(?=/|$)', '', url)
            url = re.sub(r':443(?=/|$)', '', url)
            
            # Remove trailing slash
            url = url.rstrip('/')
            
            # Convert to lowercase domain
            parsed = urlparse(url)
            normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
            
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized
        except:
            return url
    
    def is_valid_url(self, url):
        """Validate if URL is properly formatted"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def extract_urls_from_text(self, text):
        """Extract URLs from text content"""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)