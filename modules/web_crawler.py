#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Crawler for Sayer7
Comprehensive web crawling with link extraction, robots.txt analysis,
sitemap parsing, and recursive crawling capabilities
"""

import requests
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Set, Tuple
from bs4 import BeautifulSoup
import json
import threading
from collections import deque
import concurrent.futures
import os
from urllib.robotparser import RobotFileParser

class WebCrawler:
    def __init__(self, max_depth: int = 3, max_pages: int = 100, delay: float = 1.0):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Sayer7 Web Crawler/1.0 (Educational purposes)'
        })
        
        # Crawling state
        self.visited_urls = set()
        self.found_urls = set()
        self.external_urls = set()
        self.internal_urls = set()
        self.robots_content = {}
        self.sitemap_urls = []
        self.forms = []
        self.comments = []
        self.emails = []
        self.phones = []
        
        # File extensions to ignore
        self.ignore_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.mp3', '.mp4', '.avi',
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2'
        }
    
    def can_fetch(self, url: str, user_agent: str = '*') -> bool:
        """Check if URL can be fetched according to robots.txt"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            if robots_url not in self.robots_content:
                rp = RobotFileParser()
                rp.set_url(robots_url)
                try:
                    rp.read()
                    self.robots_content[robots_url] = rp
                except:
                    # If robots.txt doesn't exist, allow all
                    return True
            
            rp = self.robots_content[robots_url]
            return rp.can_fetch(user_agent, url)
            
        except Exception:
            return True
    
    def fetch_robots_txt(self, base_url: str) -> Dict:
        """Fetch and parse robots.txt"""
        try:
            parsed_url = urllib.parse.urlparse(base_url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            response = self.session.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                content = response.text
                
                # Parse robots.txt
                robots_data = {
                    'url': robots_url,
                    'content': content,
                    'sitemaps': [],
                    'disallowed': [],
                    'allowed': []
                }
                
                lines = content.split('\n')
                current_user_agent = None
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Sitemap:'):
                        sitemap_url = line.replace('Sitemap:', '').strip()
                        robots_data['sitemaps'].append(sitemap_url)
                        self.sitemap_urls.append(sitemap_url)
                    elif line.lower().startswith('user-agent:'):
                        current_user_agent = line.split(':', 1)[1].strip()
                    elif line.lower().startswith('disallow:'):
                        disallow_path = line.split(':', 1)[1].strip()
                        if disallow_path:
                            robots_data['disallowed'].append({
                                'user_agent': current_user_agent,
                                'path': disallow_path
                            })
                    elif line.lower().startswith('allow:'):
                        allow_path = line.split(':', 1)[1].strip()
                        if allow_path:
                            robots_data['allowed'].append({
                                'user_agent': current_user_agent,
                                'path': allow_path
                            })
                
                return robots_data
            else:
                return {'url': robots_url, 'error': 'robots.txt not found'}
                
        except Exception as e:
            return {'url': robots_url, 'error': str(e)}
    
    def fetch_sitemap(self, sitemap_url: str) -> List[str]:
        """Fetch and parse sitemap.xml"""
        urls = []
        
        try:
            response = self.session.get(sitemap_url, timeout=10)
            
            if response.status_code == 200:
                content = response.text
                
                # Parse XML sitemap
                try:
                    root = ET.fromstring(content)
                    
                    # Handle sitemap index
                    if root.tag.endswith('sitemapindex'):
                        for sitemap in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                            loc = sitemap.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc is not None:
                                sub_sitemap_url = loc.text
                                urls.extend(self.fetch_sitemap(sub_sitemap_url))
                    
                    # Handle URL set
                    elif root.tag.endswith('urlset'):
                        for url in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                            loc = url.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc is not None:
                                urls.append(loc.text)
                
                except ET.ParseError:
                    # Fallback to regex parsing
                    urls = re.findall(r'<loc>(.*?)</loc>', content)
            
        except Exception as e:
            print(f"Error fetching sitemap {sitemap_url}: {str(e)}")
        
        return urls
    
    def extract_links(self, html: str, base_url: str) -> Tuple[Set[str], Set[str], List[Dict]]:
        """Extract all links from HTML"""
        internal_links = set()
        external_links = set()
        forms = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            parsed_base = urllib.parse.urlparse(base_url)
            base_domain = parsed_base.netloc
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href:
                    absolute_url = urllib.parse.urljoin(base_url, href)
                    parsed_url = urllib.parse.urlparse(absolute_url)
                    
                    # Skip javascript: and mailto: links
                    if parsed_url.scheme in ['javascript', 'mailto', 'tel']:
                        continue
                    
                    # Skip file downloads
                    path_lower = parsed_url.path.lower()
                    if any(path_lower.endswith(ext) for ext in self.ignore_extensions):
                        continue
                    
                    if parsed_url.netloc == base_domain:
                        internal_links.add(absolute_url)
                    else:
                        external_links.add(absolute_url)
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Get absolute action URL
                if form_data['action']:
                    form_data['action'] = urllib.parse.urljoin(base_url, form_data['action'])
                else:
                    form_data['action'] = base_url
                
                # Extract form inputs
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name', ''),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
            
        except Exception as e:
            print(f"Error extracting links: {str(e)}")
        
        return internal_links, external_links, forms
    
    def extract_metadata(self, html: str) -> Dict:
        """Extract metadata from HTML"""
        metadata = {
            'title': '',
            'description': '',
            'keywords': '',
            'author': '',
            'charset': '',
            'viewport': '',
            'og_tags': {},
            'twitter_tags': {}
        }
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = title.get_text().strip()
            
            # Meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                
                if name == 'description':
                    metadata['description'] = content
                elif name == 'keywords':
                    metadata['keywords'] = content
                elif name == 'author':
                    metadata['author'] = content
                elif name == 'viewport':
                    metadata['viewport'] = content
                elif meta.get('charset'):
                    metadata['charset'] = meta.get('charset')
            
            # Open Graph tags
            og_tags = soup.find_all('meta', property=re.compile(r'^og:'))
            for og in og_tags:
                prop = og.get('property', '').replace('og:', '')
                content = og.get('content', '')
                metadata['og_tags'][prop] = content
            
            # Twitter tags
            twitter_tags = soup.find_all('meta', attrs={'name': re.compile(r'^twitter:')})
            for twitter in twitter_tags:
                name = twitter.get('name', '').replace('twitter:', '')
                content = twitter.get('content', '')
                metadata['twitter_tags'][name] = content
            
        except Exception as e:
            print(f"Error extracting metadata: {str(e)}")
        
        return metadata
    
    def extract_emails_and_phones(self, text: str) -> Tuple[List[str], List[str]]:
        """Extract emails and phone numbers from text"""
        emails = []
        phones = []
        
        try:
            # Email regex
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, text)
            
            # Phone regex (various formats)
            phone_patterns = [
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US format
                r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
                r'\b\d{3}\s\d{3}\s\d{4}\b',
                r'\(\d{3}\)\s?\d{3}-\d{4}'
            ]
            
            for pattern in phone_patterns:
                phones.extend(re.findall(pattern, text))
            
            # Clean and deduplicate
            emails = list(set(emails))
            phones = list(set(phones))
            
        except Exception as e:
            print(f"Error extracting emails/phones: {str(e)}")
        
        return emails, phones
    
    def crawl_page(self, url: str, depth: int = 0) -> Dict:
        """Crawl a single page and extract information"""
        result = {
            'url': url,
            'status_code': None,
            'title': '',
            'links': [],
            'forms': [],
            'metadata': {},
            'emails': [],
            'phones': [],
            'error': None
        }
        
        try:
            if not self.can_fetch(url):
                result['error'] = 'Blocked by robots.txt'
                return result
            
            if url in self.visited_urls:
                return result
            
            self.visited_urls.add(url)
            
            response = self.session.get(url, timeout=10)
            result['status_code'] = response.status_code
            
            if response.status_code == 200:
                html = response.text
                
                # Extract all information
                internal_links, external_links, forms = self.extract_links(html, url)
                metadata = self.extract_metadata(html)
                emails, phones = self.extract_emails_and_phones(html)
                
                result.update({
                    'title': metadata.get('title', ''),
                    'links': list(internal_links),
                    'forms': forms,
                    'metadata': metadata,
                    'emails': emails,
                    'phones': phones
                })
                
                # Add to found URLs
                self.found_urls.update(internal_links)
                self.external_urls.update(external_links)
                self.forms.extend(forms)
                self.emails.extend(emails)
                self.phones.extend(phones)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def recursive_crawl(self, start_url: str) -> Dict:
        """Recursively crawl website"""
        results = {
            'start_url': start_url,
            'pages_crawled': 0,
            'pages': [],
            'summary': {
                'total_urls': 0,
                'internal_urls': 0,
                'external_urls': 0,
                'forms_found': 0,
                'emails_found': 0,
                'phones_found': 0,
                'errors': 0
            }
        }
        
        try:
            # Reset state
            self.visited_urls.clear()
            self.found_urls.clear()
            self.external_urls.clear()
            self.forms.clear()
            self.emails.clear()
            self.phones.clear()
            
            # Get robots.txt and sitemap
            robots_info = self.fetch_robots_txt(start_url)
            results['robots_txt'] = robots_info
            
            # Fetch sitemap URLs
            all_sitemap_urls = []
            for sitemap_url in self.sitemap_urls:
                sitemap_urls = self.fetch_sitemap(sitemap_url)
                all_sitemap_urls.extend(sitemap_urls)
            
            # Initialize crawl queue
            crawl_queue = deque()
            crawl_queue.append((start_url, 0))
            
            # Add sitemap URLs to queue
            for url in all_sitemap_urls[:50]:  # Limit to prevent overload
                if url not in self.visited_urls:
                    crawl_queue.append((url, 0))
            
            # Crawl pages
            while crawl_queue and len(self.visited_urls) < self.max_pages:
                url, depth = crawl_queue.popleft()
                
                if depth > self.max_depth:
                    continue
                
                page_result = self.crawl_page(url, depth)
                results['pages'].append(page_result)
                results['pages_crawled'] += 1
                
                # Add new links to queue
                if page_result.get('links'):
                    for link in page_result['links']:
                        if link not in self.visited_urls:
                            crawl_queue.append((link, depth + 1))
                
                time.sleep(self.delay)
            
            # Generate summary
            results['summary'] = {
                'total_urls': len(self.visited_urls),
                'internal_urls': len(self.found_urls),
                'external_urls': len(self.external_urls),
                'forms_found': len(self.forms),
                'emails_found': len(self.emails),
                'phones_found': len(self.phones),
                'errors': len([p for p in results['pages'] if p.get('error')])
            }
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def crawl_single_page(self, url: str) -> Dict:
        """Crawl only a single page"""
        # Reset state for single page
        self.visited_urls.clear()
        self.found_urls.clear()
        self.external_urls.clear()
        self.forms.clear()
        self.emails.clear()
        self.phones.clear()
        
        return self.crawl_page(url)
    
    def save_crawl_results(self, results: Dict, output_file: str) -> bool:
        """Save crawl results to file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving results: {str(e)}")
            return False