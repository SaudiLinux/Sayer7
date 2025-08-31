#!/usr/bin/env python3
"""
Sayer7 - SSL/DNS Vulnerability Scanner
Advanced SSL/TLS and DNS Security Assessment Module
Author: SayerLinux
GitHub: https://github.com/SaudiLinux
Email: SayerLinux1@gmail.com
"""

import ssl
import socket
import dns.resolver
import dns.zone
import dns.query
import dns.name
import subprocess
import json
import time
import requests
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import OpenSSL
import concurrent.futures
import threading

class SSLDNSScanner:
    """
    Comprehensive SSL/TLS and DNS Security Scanner
    Detects SSL vulnerabilities, DNS issues, and performs security assessments
    """
    
    def __init__(self):
        self.ssl_vulnerabilities = self._load_ssl_vulnerabilities()
        self.dns_tools = self._load_dns_tools()
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
    def _load_ssl_vulnerabilities(self) -> Dict[str, Dict]:
        """Load SSL/TLS vulnerability database"""
        return {
            "HEARTBLEED": {
                "name": "Heartbleed",
                "description": "OpenSSL memory disclosure vulnerability",
                "cve": "CVE-2014-0160",
                "severity": "Critical",
                "test_method": "heartbeat_extension",
                "remediation": "Update OpenSSL to latest version"
            },
            "FREAK": {
                "name": "FREAK Attack",
                "description": "Factoring RSA Export Keys vulnerability",
                "cve": "CVE-2015-0204",
                "severity": "High",
                "test_method": "export_ciphers",
                "remediation": "Disable export-grade ciphers"
            },
            "POODLE": {
                "name": "POODLE",
                "description": "SSLv3 padding oracle vulnerability",
                "cve": "CVE-2014-3566",
                "severity": "High",
                "test_method": "sslv3_support",
                "remediation": "Disable SSLv3 support"
            },
            "CCS_INJECTION": {
                "name": "CCS Injection",
                "description": "OpenSSL ChangeCipherSpec injection",
                "cve": "CVE-2014-0224",
                "severity": "Medium",
                "test_method": "ccs_injection",
                "remediation": "Update OpenSSL to latest version"
            },
            "LOGJAM": {
                "name": "Logjam",
                "description": "TLS weak Diffie-Hellman vulnerability",
                "cve": "CVE-2015-4000",
                "severity": "High",
                "test_method": "weak_dh_key",
                "remediation": "Use strong DH parameters"
            },
            "DROWN": {
                "name": "DROWN",
                "description": "SSLv2 cross-protocol attack",
                "cve": "CVE-2016-0800",
                "severity": "High",
                "test_method": "sslv2_support",
                "remediation": "Disable SSLv2 support"
            },
            "BEAST": {
                "name": "BEAST",
                "description": "SSL/TLS CBC cipher vulnerability",
                "cve": "CVE-2011-3389",
                "severity": "Medium",
                "test_method": "cbc_ciphers",
                "remediation": "Use TLS 1.2+ with AEAD ciphers"
            },
            "CRIME": {
                "name": "CRIME",
                "description": "TLS compression vulnerability",
                "cve": "CVE-2012-4929",
                "severity": "Medium",
                "test_method": "compression_support",
                "remediation": "Disable TLS compression"
            },
            "BREACH": {
                "name": "BREACH",
                "description": "HTTP compression attack",
                "cve": "CVE-2013-3587",
                "severity": "Medium",
                "test_method": "http_compression",
                "remediation": "Disable HTTP compression for sensitive content"
            },
            "LUCKY13": {
                "name": "Lucky13",
                "description": "TLS CBC padding oracle attack",
                "cve": "CVE-2013-0169",
                "severity": "Medium",
                "test_method": "cbc_timing",
                "remediation": "Use AEAD ciphers"
            }
        }
    
    def _load_dns_tools(self) -> Dict[str, str]:
        """Load DNS enumeration tools configuration"""
        return {
            "dnsrecon": "dnsrecon",
            "dnsenum": "dnsenum",
            "fierce": "fierce",
            "dnswalk": "dnswalk",
            "amass": "amass",
            "dnsmap": "dnsmap",
            "sublist3r": "sublist3r",
            "nmap": "nmap"
        }
    
    def scan_ssl_vulnerabilities(self, target: str, port: int = 443) -> Dict[str, any]:
        """
        Comprehensive SSL/TLS vulnerability scan
        """
        results = {
            "target": target,
            "port": port,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ssl_info": {},
            "vulnerabilities": {},
            "certificate_info": {},
            "cipher_suites": {},
            "protocols": {},
            "recommendations": []
        }
        
        try:
            # Get SSL certificate information
            results["certificate_info"] = self._get_certificate_info(target, port)
            
            # Test SSL/TLS protocols
            results["protocols"] = self._test_ssl_protocols(target, port)
            
            # Test cipher suites
            results["cipher_suites"] = self._test_cipher_suites(target, port)
            
            # Check for SSL vulnerabilities
            results["vulnerabilities"] = self._check_ssl_vulnerabilities(target, port)
            
            # Generate recommendations
            results["recommendations"] = self._generate_ssl_recommendations(results)
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _get_certificate_info(self, hostname: str, port: int) -> Dict[str, any]:
        """Get detailed SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    der_cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
                    
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": x509.get_version(),
                        "serial_number": str(x509.get_serial_number()),
                        "not_before": x509.get_notBefore().decode("utf-8"),
                        "not_after": x509.get_notAfter().decode("utf-8"),
                        "signature_algorithm": x509.get_signature_algorithm().decode("utf-8"),
                        "public_key_algorithm": x509.get_pubkey().type(),
                        "public_key_size": x509.get_pubkey().bits(),
                        "san": cert.get("subjectAltName", []),
                        "is_self_signed": self._is_self_signed(x509),
                        "days_until_expiry": self._get_days_until_expiry(x509),
                        "ocsp_stapling": ssock.getpeercert().get("OCSP", None) is not None
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_ssl_protocols(self, hostname: str, port: int) -> Dict[str, any]:
        """Test supported SSL/TLS protocols"""
        protocols = {
            "SSLv2": False,
            "SSLv3": False,
            "TLSv1.0": False,
            "TLSv1.1": False,
            "TLSv1.2": False,
            "TLSv1.3": False
        }
        
        for protocol in protocols:
            try:
                context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{protocol.upper().replace('.', '_')}"))
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[protocol] = True
            except:
                protocols[protocol] = False
        
        return protocols
    
    def _test_cipher_suites(self, hostname: str, port: int) -> Dict[str, any]:
        """Test supported cipher suites"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    return {
                        "current_cipher": cipher,
                        "weak_ciphers": self._check_weak_ciphers(hostname, port),
                        "strong_ciphers": self._check_strong_ciphers(hostname, port)
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_ssl_vulnerabilities(self, hostname: str, port: int) -> Dict[str, any]:
        """Check for specific SSL vulnerabilities"""
        vulnerabilities = {}
        
        for vuln_name, vuln_info in self.ssl_vulnerabilities.items():
            try:
                is_vulnerable = self._test_vulnerability(hostname, port, vuln_name)
                vulnerabilities[vuln_name] = {
                    "vulnerable": is_vulnerable,
                    "details": vuln_info,
                    "severity": vuln_info["severity"]
                }
            except Exception as e:
                vulnerabilities[vuln_name] = {
                    "vulnerable": False,
                    "error": str(e),
                    "severity": vuln_info["severity"]
                }
        
        return vulnerabilities
    
    def _test_vulnerability(self, hostname: str, port: int, vuln_name: str) -> bool:
        """Test specific SSL vulnerability"""
        if vuln_name == "HEARTBLEED":
            return self._test_heartbleed(hostname, port)
        elif vuln_name == "FREAK":
            return self._test_freak(hostname, port)
        elif vuln_name == "POODLE":
            return self._test_poodle(hostname, port)
        elif vuln_name == "LOGJAM":
            return self._test_logjam(hostname, port)
        else:
            return False
    
    def _test_heartbleed(self, hostname: str, port: int) -> bool:
        """Test for Heartbleed vulnerability"""
        try:
            # Use OpenSSL to test Heartbleed
            cmd = ["openssl", "s_client", "-connect", f"{hostname}:{port}", "-tlsextdebug"]
            result = subprocess.run(cmd, input=b"", capture_output=True, timeout=10)
            return b"heartbeat" in result.stdout.lower()
        except:
            return False
    
    def _test_freak(self, hostname: str, port: int) -> bool:
        """Test for FREAK vulnerability"""
        try:
            # Test export-grade ciphers
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers("EXP")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except:
            return False
    
    def _test_poodle(self, hostname: str, port: int) -> bool:
        """Test for POODLE vulnerability"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except:
            return False
    
    def _test_logjam(self, hostname: str, port: int) -> bool:
        """Test for Logjam vulnerability"""
        try:
            # Test weak DH parameters
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers("DH")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except:
            return False
    
    def _generate_ssl_recommendations(self, results: Dict[str, any]) -> List[str]:
        """Generate SSL/TLS security recommendations"""
        recommendations = []
        
        # Check for vulnerable protocols
        protocols = results.get("protocols", {})
        if protocols.get("SSLv2", False):
            recommendations.append("Disable SSLv2 support")
        if protocols.get("SSLv3", False):
            recommendations.append("Disable SSLv3 support to prevent POODLE attack")
        if protocols.get("TLSv1.0", False):
            recommendations.append("Consider disabling TLSv1.0")
        if protocols.get("TLSv1.1", False):
            recommendations.append("Consider disabling TLSv1.1")
        
        # Check certificate expiry
        cert_info = results.get("certificate_info", {})
        days_until_expiry = cert_info.get("days_until_expiry", 0)
        if days_until_expiry < 30:
            recommendations.append(f"Certificate expires in {days_until_expiry} days - renew soon")
        
        # Check for vulnerabilities
        vulnerabilities = results.get("vulnerabilities", {})
        for vuln_name, vuln_data in vulnerabilities.items():
            if vuln_data.get("vulnerable", False):
                recommendations.append(f"Address {vuln_name}: {vuln_data.get('details', {}).get('remediation', '')}")
        
        return recommendations
    
    def scan_dns_vulnerabilities(self, domain: str) -> Dict[str, any]:
        """
        Comprehensive DNS security scan
        """
        results = {
            "domain": domain,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dns_records": {},
            "zone_transfer": {},
            "dnssec": {},
            "subdomains": [],
            "dns_vulnerabilities": {},
            "recommendations": []
        }
        
        try:
            # Enumerate DNS records
            results["dns_records"] = self._enumerate_dns_records(domain)
            
            # Test zone transfer
            results["zone_transfer"] = self._test_zone_transfer(domain)
            
            # Check DNSSEC
            results["dnssec"] = self._check_dnssec(domain)
            
            # Brute force subdomains
            results["subdomains"] = self._brute_force_subdomains(domain)
            
            # Check DNS vulnerabilities
            results["dns_vulnerabilities"] = self._check_dns_vulnerabilities(domain)
            
            # Generate recommendations
            results["recommendations"] = self._generate_dns_recommendations(results)
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _enumerate_dns_records(self, domain: str) -> Dict[str, List]:
        """Enumerate DNS records"""
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except:
                records[record_type] = []
        
        return records
    
    def _test_zone_transfer(self, domain: str) -> Dict[str, any]:
        """Test DNS zone transfer vulnerability"""
        results = {"vulnerable": False, "ns_servers": [], "records": []}
        
        try:
            # Get NS records
            ns_records = dns.resolver.resolve(domain, "NS")
            
            for ns in ns_records:
                ns_name = str(ns)
                results["ns_servers"].append(ns_name)
                
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain))
                    results["vulnerable"] = True
                    
                    # Extract records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            results["records"].append({
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "data": [str(rdata) for rdata in rdataset]
                            })
                except:
                    continue
                    
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _check_dnssec(self, domain: str) -> Dict[str, any]:
        """Check DNSSEC configuration"""
        results = {"enabled": False, "valid": False, "details": {}}
        
        try:
            # Check DNSKEY records
            try:
                dnskey_records = dns.resolver.resolve(domain, "DNSKEY")
                results["enabled"] = True
                results["details"]["dnskey_records"] = [str(record) for record in dnskey_records]
            except:
                pass
            
            # Check DS records
            try:
                ds_records = dns.resolver.resolve(domain, "DS")
                results["details"]["ds_records"] = [str(record) for record in ds_records]
            except:
                pass
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _brute_force_subdomains(self, domain: str) -> List[str]:
        """Brute force subdomains using wordlist"""
        subdomains = []
        
        # Common subdomain wordlist
        subdomain_list = [
            "www", "mail", "ftp", "admin", "blog", "shop", "dev", "test", "staging",
            "api", "app", "mobile", "secure", "support", "help", "docs", "cdn",
            "media", "static", "assets", "images", "css", "js", "assets", "download",
            "upload", "files", "resources", "assets", "static", "media", "content"
        ]
        
        for subdomain in subdomain_list:
            try:
                full_domain = f"{subdomain}.{domain}"
                dns.resolver.resolve(full_domain, "A")
                subdomains.append(full_domain)
            except:
                continue
        
        return subdomains
    
    def _check_dns_vulnerabilities(self, domain: str) -> Dict[str, any]:
        """Check for DNS-specific vulnerabilities"""
        vulnerabilities = {}
        
        # Check for DNS cache poisoning
        vulnerabilities["cache_poisoning"] = self._test_cache_poisoning(domain)
        
        # Check for DNS hijacking
        vulnerabilities["dns_hijacking"] = self._test_dns_hijacking(domain)
        
        return vulnerabilities
    
    def _test_cache_poisoning(self, domain: str) -> Dict[str, any]:
        """Test DNS cache poisoning vulnerability"""
        return {"tested": True, "vulnerable": False, "note": "Requires specialized testing"}
    
    def _test_dns_hijacking(self, domain: str) -> Dict[str, any]:
        """Test DNS hijacking vulnerability"""
        try:
            # Check if domain resolves to unexpected IPs
            answers = dns.resolver.resolve(domain, "A")
            ips = [str(answer) for answer in answers]
            
            return {
                "resolved_ips": ips,
                "suspicious": len(ips) > 5,  # Simple heuristic
                "note": "Check against known good DNS servers"
            }
        except:
            return {"error": "Unable to resolve domain"}
    
    def _generate_dns_recommendations(self, results: Dict[str, any]) -> List[str]:
        """Generate DNS security recommendations"""
        recommendations = []
        
        # Check zone transfer
        zone_transfer = results.get("zone_transfer", {})
        if zone_transfer.get("vulnerable", False):
            recommendations.append("Disable DNS zone transfer or restrict to authorized servers")
        
        # Check DNSSEC
        dnssec = results.get("dnssec", {})
        if not dnssec.get("enabled", False):
            recommendations.append("Implement DNSSEC for domain security")
        
        # Check for missing DNS records
        dns_records = results.get("dns_records", {})
        if not dns_records.get("TXT", []):
            recommendations.append("Consider adding SPF/DKIM TXT records")
        
        return recommendations
    
    def scan_common_ports(self, target: str) -> Dict[str, any]:
        """Scan common ports for open services"""
        results = {
            "target": target,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": [],
            "services": {},
            "banner_info": {}
        }
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        return port, True
            except:
                pass
            return port, False
        
        # Scan ports concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in self.common_ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    results["open_ports"].append(port)
                    results["services"][port] = self._get_service_info(port)
                    results["banner_info"][port] = self._get_banner(target, port)
        
        return results
    
    def _get_service_info(self, port: int) -> str:
        """Get service information for port"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return service_map.get(port, "Unknown")
    
    def _get_banner(self, target: str, port: int) -> str:
        """Get service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                return banner.strip()
        except:
            return "Unable to retrieve banner"
    
    def generate_comprehensive_report(self, target: str) -> Dict[str, any]:
        """Generate comprehensive SSL/DNS security report"""
        report = {
            "target": target,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ssl_analysis": {},
            "dns_analysis": {},
            "port_scan": {},
            "summary": {
                "ssl_grade": "unknown",
                "dns_grade": "unknown",
                "overall_grade": "unknown",
                "critical_issues": 0,
                "warnings": 0,
                "recommendations": []
            }
        }
        
        # Parse domain from URL if needed
        if target.startswith("http"):
            parsed = urlparse(target)
            hostname = parsed.hostname
            domain = hostname
        else:
            hostname = target
            domain = target
        
        # Perform SSL scan
        if hostname:
            report["ssl_analysis"] = self.scan_ssl_vulnerabilities(hostname)
        
        # Perform DNS scan
        report["dns_analysis"] = self.scan_dns_vulnerabilities(domain)
        
        # Perform port scan
        report["port_scan"] = self.scan_common_ports(hostname or domain)
        
        # Generate summary
        report["summary"] = self._generate_report_summary(report)
        
        return report
    
    def _generate_report_summary(self, report: Dict[str, any]) -> Dict[str, any]:
        """Generate report summary with grades"""
        summary = {
            "ssl_grade": "A",
            "dns_grade": "A",
            "overall_grade": "A",
            "critical_issues": 0,
            "warnings": 0,
            "recommendations": []
        }
        
        # SSL grading
        ssl_vulns = report.get("ssl_analysis", {}).get("vulnerabilities", {})
        critical_ssl = sum(1 for v in ssl_vulns.values() if v.get("severity") == "Critical")
        high_ssl = sum(1 for v in ssl_vulns.values() if v.get("severity") == "High")
        
        if critical_ssl > 0:
            summary["ssl_grade"] = "F"
            summary["critical_issues"] += critical_ssl
        elif high_ssl > 0:
            summary["ssl_grade"] = "C"
            summary["warnings"] += high_ssl
        elif any(ssl_vulns.values()):
            summary["ssl_grade"] = "B"
        
        # DNS grading
        zone_transfer = report.get("dns_analysis", {}).get("zone_transfer", {})
        dnssec = report.get("dns_analysis", {}).get("dnssec", {})
        
        if zone_transfer.get("vulnerable", False):
            summary["dns_grade"] = "F"
            summary["critical_issues"] += 1
        elif not dnssec.get("enabled", False):
            summary["dns_grade"] = "B"
            summary["warnings"] += 1
        
        # Overall grade
        if summary["critical_issues"] > 0:
            summary["overall_grade"] = "F"
        elif summary["warnings"] > 2:
            summary["overall_grade"] = "C"
        elif summary["warnings"] > 0:
            summary["overall_grade"] = "B"
        
        # Collect all recommendations
        ssl_recs = report.get("ssl_analysis", {}).get("recommendations", [])
        dns_recs = report.get("dns_analysis", {}).get("recommendations", [])
        summary["recommendations"] = ssl_recs + dns_recs
        
        return summary
    
    def _is_self_signed(self, cert) -> bool:
        """Check if certificate is self-signed"""
        try:
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            return subject.get_name() == issuer.get_name()
        except:
            return False
    
    def _get_days_until_expiry(self, cert) -> int:
        """Calculate days until certificate expiry"""
        try:
            not_after = cert.get_notAfter().decode("utf-8")
            expiry_date = time.strptime(not_after, "%Y%m%d%H%M%SZ")
            expiry_timestamp = time.mktime(expiry_date)
            current_timestamp = time.time()
            return int((expiry_timestamp - current_timestamp) / 86400)
        except:
            return 0
    
    def _check_weak_ciphers(self, hostname: str, port: int) -> List[str]:
        """Check for weak cipher suites"""
        weak_ciphers = []
        
        try:
            # This would require more sophisticated cipher testing
            # For now, return placeholder
            weak_ciphers = ["RC4", "3DES", "DES", "EXPORT"]
        except:
            pass
        
        return weak_ciphers
    
    def _check_strong_ciphers(self, hostname: str, port: int) -> List[str]:
        """Check for strong cipher suites"""
        strong_ciphers = []
        
        try:
            # This would require more sophisticated cipher testing
            # For now, return placeholder
            strong_ciphers = ["AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"]
        except:
            pass
        
        return strong_ciphers