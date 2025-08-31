#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Search Engine Module for Sayer7
Multi-engine search capabilities with Google, DuckDuckGo, Bing, and AOL
Includes bypass techniques for IP restrictions and Google cache extraction
"""

import requests
import re
import time
import random
from urllib.parse import quote_plus, urljoin, urlparse
from bs4 import BeautifulSoup
import json

class SearchEngine:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Search engine configurations
        self.engines = {
            'google': {
                'base_url': 'https://www.google.com/search',
                'param': 'q',
                'results_selector': 'div.g',
                'title_selector': 'h3',
                'url_selector': 'a',
                'description_selector': 'span.aCOpRe, div.VwiC3b'
            },
            'duckduckgo': {
                'base_url': 'https://duckduckgo.com/html',
                'param': 'q',
                'results_selector': 'div.result',
                'title_selector': 'a.result__a',
                'url_selector': 'a.result__a',
                'description_selector': 'a.result__snippet'
            },
            'bing': {
                'base_url': 'https://www.bing.com/search',
                'param': 'q',
                'results_selector': 'li.b_algo',
                'title_selector': 'h2 a',
                'url_selector': 'h2 a',
                'description_selector': 'div.b_caption p'
            },
            'aol': {
                'base_url': 'https://search.aol.com/aol/search',
                'param': 'q',
                'results_selector': 'div.algo',
                'title_selector': 'h3.title',
                'url_selector': 'h3.title a',
                'description_selector': 'div.compText'
            }
        }
    
    def search(self, query, engine='google', pages=5, delay=1):
        """Main search function supporting multiple engines"""
        if engine not in self.engines:
            raise ValueError(f"Unsupported engine: {engine}")
        
        results = []
        
        for page in range(pages):
            try:
                if engine == 'google':
                    page_results = self.search_google(query, page + 1)
                elif engine == 'duckduckgo':
                    page_results = self.search_duckduckgo(query, page + 1)
                elif engine == 'bing':
                    page_results = self.search_bing(query, page + 1)
                elif engine == 'aol':
                    page_results = self.search_aol(query, page + 1)
                
                results.extend(page_results)
                
                # Add delay to avoid rate limiting
                if delay > 0:
                    time.sleep(delay)
                    
            except Exception as e:
                print(f"Error searching page {page + 1}: {str(e)}")
                continue
        
        # Remove duplicates while preserving order
        seen = set()
        unique_results = []
        for result in results:
            url = result.get('url', '')
            if url and url not in seen:
                seen.add(url)
                unique_results.append(result)
        
        return unique_results
    
    def search_google(self, query, page=1, country='us', language='en'):
        """Search Google with bypass techniques"""
        try:
            start = (page - 1) * 10
            params = {
                'q': query,
                'start': start,
                'hl': language,
                'gl': country,
                'num': 10
            }
            
            # Rotate user agents and headers
            headers = self.get_random_headers()
            
            response = self.session.get(
                'https://www.google.com/search',
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 429:
                # Rate limited, try alternative methods
                return self.search_google_alternative(query, page)
            
            return self.parse_google_results(response.text)
            
        except Exception as e:
            print(f"Google search error: {str(e)}")
            return []
    
    def search_google_alternative(self, query, page=1):
        """Alternative Google search methods"""
        methods = [
            self.search_google_cache,
            self.search_google_scholar,
            self.search_google_custom_api
        ]
        
        for method in methods:
            try:
                results = method(query, page)
                if results:
                    return results
            except:
                continue
        
        return []
    
    def search_google_cache(self, query, page=1):
        """Search using Google cache"""
        try:
            cache_url = f"http://webcache.googleusercontent.com/search?q=cache:{quote_plus(query)}"
            response = self.session.get(cache_url, timeout=10)
            
            if response.status_code == 200:
                return self.parse_google_results(response.text)
            
            return []
        except:
            return []
    
    def search_google_scholar(self, query, page=1):
        """Search using Google Scholar"""
        try:
            start = (page - 1) * 10
            params = {
                'q': query,
                'start': start
            }
            
            response = self.session.get(
                'https://scholar.google.com/scholar',
                params=params,
                timeout=10
            )
            
            return self.parse_google_results(response.text)
        except:
            return []
    
    def search_google_custom_api(self, query, page=1):
        """Search using Google Custom Search API"""
        # This would require API key configuration
        return []
    
    def parse_google_results(self, html):
        """Parse Google search results"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            
            # Find search result containers
            result_divs = soup.find_all('div', class_='g')
            
            for div in result_divs:
                try:
                    title_elem = div.find('h3')
                    if not title_elem:
                        continue
                    
                    link_elem = title_elem.find('a')
                    if not link_elem:
                        continue
                    
                    title = title_elem.get_text(strip=True)
                    url = link_elem.get('href', '')
                    
                    # Clean Google redirect URLs
                    if url.startswith('/url?'):
                        url = self.clean_google_url(url)
                    
                    description_elem = div.find('span', class_='aCOpRe') or div.find('div', class_='VwiC3b')
                    description = description_elem.get_text(strip=True) if description_elem else ''
                    
                    if url and title:
                        results.append({
                            'title': title,
                            'url': url,
                            'description': description,
                            'source': 'google'
                        })
                
                except Exception as e:
                    continue
            
            return results
            
        except Exception as e:
            print(f"Error parsing Google results: {str(e)}")
            return []
    
    def clean_google_url(self, url):
        """Clean Google redirect URLs"""
        try:
            if '/url?' in url:
                # Extract actual URL from Google redirect
                match = re.search(r'[?&]url=([^&]+)', url)
                if match:
                    from urllib.parse import unquote
                    return unquote(match.group(1))
            
            return url
        except:
            return url
    
    def search_duckduckgo(self, query, page=1):
        """Search DuckDuckGo"""
        try:
            params = {
                'q': query,
                's': (page - 1) * 30,
                'dc': (page - 1) * 30 + 1,
                'v': 'l',
                'o': 'json',
                'api': 'd.js'
            }
            
            headers = self.get_random_headers()
            
            response = self.session.post(
                'https://duckduckgo.com/html',
                params=params,
                headers=headers,
                timeout=10
            )
            
            return self.parse_duckduckgo_results(response.text)
            
        except Exception as e:
            print(f"DuckDuckGo search error: {str(e)}")
            return []
    
    def parse_duckduckgo_results(self, html):
        """Parse DuckDuckGo search results"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            
            # Find result containers
            result_divs = soup.find_all('div', class_='result')
            
            for div in result_divs:
                try:
                    title_elem = div.find('a', class_='result__a')
                    if not title_elem:
                        continue
                    
                    title = title_elem.get_text(strip=True)
                    url = title_elem.get('href', '')
                    
                    description_elem = div.find('a', class_='result__snippet')
                    description = description_elem.get_text(strip=True) if description_elem else ''
                    
                    if url and title:
                        results.append({
                            'title': title,
                            'url': url,
                            'description': description,
                            'source': 'duckduckgo'
                        })
                
                except Exception as e:
                    continue
            
            return results
            
        except Exception as e:
            print(f"Error parsing DuckDuckGo results: {str(e)}")
            return []
    
    def search_bing(self, query, page=1):
        """Search Bing"""
        try:
            first = (page - 1) * 10 + 1
            params = {
                'q': query,
                'first': first,
                'count': 10,
                'format': 'html'
            }
            
            headers = self.get_random_headers()
            
            response = self.session.get(
                'https://www.bing.com/search',
                params=params,
                headers=headers,
                timeout=10
            )
            
            return self.parse_bing_results(response.text)
            
        except Exception as e:
            print(f"Bing search error: {str(e)}")
            return []
    
    def parse_bing_results(self, html):
        """Parse Bing search results"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            
            # Find result containers
            result_lis = soup.find_all('li', class_='b_algo')
            
            for li in result_lis:
                try:
                    title_elem = li.find('h2')
                    if not title_elem:
                        continue
                    
                    link_elem = title_elem.find('a')
                    if not link_elem:
                        continue
                    
                    title = title_elem.get_text(strip=True)
                    url = link_elem.get('href', '')
                    
                    description_elem = li.find('div', class_='b_caption')
                    if description_elem:
                        description = description_elem.find('p')
                        description = description.get_text(strip=True) if description else ''
                    else:
                        description = ''
                    
                    if url and title:
                        results.append({
                            'title': title,
                            'url': url,
                            'description': description,
                            'source': 'bing'
                        })
                
                except Exception as e:
                    continue
            
            return results
            
        except Exception as e:
            print(f"Error parsing Bing results: {str(e)}")
            return []
    
    def search_aol(self, query, page=1):
        """Search AOL"""
        try:
            params = {
                'q': query,
                'page': page,
                'count': 10
            }
            
            headers = self.get_random_headers()
            
            response = self.session.get(
                'https://search.aol.com/aol/search',
                params=params,
                headers=headers,
                timeout=10
            )
            
            return self.parse_aol_results(response.text)
            
        except Exception as e:
            print(f"AOL search error: {str(e)}")
            return []
    
    def parse_aol_results(self, html):
        """Parse AOL search results"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            
            # Find result containers
            result_divs = soup.find_all('div', class_='algo')
            
            for div in result_divs:
                try:
                    title_elem = div.find('h3', class_='title')
                    if not title_elem:
                        continue
                    
                    link_elem = title_elem.find('a')
                    if not link_elem:
                        continue
                    
                    title = title_elem.get_text(strip=True)
                    url = link_elem.get('href', '')
                    
                    description_elem = div.find('div', class_='compText')
                    description = description_elem.get_text(strip=True) if description_elem else ''
                    
                    if url and title:
                        results.append({
                            'title': title,
                            'url': url,
                            'description': description,
                            'source': 'aol'
                        })
                
                except Exception as e:
                    continue
            
            return results
            
        except Exception as e:
            print(f"Error parsing AOL results: {str(e)}")
            return []
    
    def get_random_headers(self):
        """Get random headers to avoid detection"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59'
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }
    
    def search_dork(self, dork, engine='google', pages=5):
        """Search using Google dorks"""
        return self.search(dork, engine, pages)
    
    def search_site(self, site, keywords, engine='google', pages=5):
        """Search within specific site"""
        query = f"site:{site} {keywords}"
        return self.search(query, engine, pages)
    
    def search_filetype(self, filetype, keywords, engine='google', pages=5):
        """Search for specific file types"""
        query = f"filetype:{filetype} {keywords}"
        return self.search(query, engine, pages)
    
    def search_inurl(self, inurl, keywords, engine='google', pages=5):
        """Search for URLs containing specific text"""
        query = f"inurl:{inurl} {keywords}"
        return self.search(query, engine, pages)
    
    def search_intitle(self, intitle, keywords, engine='google', pages=5):
        """Search for pages with specific text in title"""
        query = f"intitle:{intitle} {keywords}"
        return self.search(query, engine, pages)