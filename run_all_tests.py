#!/usr/bin/env python3
"""
WordPress Security Testing Suite - Main Runner
Execute all security tests with a single command
"""

import sys
import time
from datetime import datetime

# Import all test modules
try:
    from advanced_wordpress_scanner import AdvancedWordPressScanner
    from wordpress_plugin_exploiter import WordPressPluginExploiter
    from advanced_credential_tester import AdvancedCredentialTester
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure all script files are in the same directory")
    sys.exit(1)

# Configuration
import json
import os

# Configuration
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
        TARGET = config.get('target', {}).get('url', "https://lead.se")
except Exception as e:
    print(f"Warning: Could not load config.json: {e}")
    TARGET = "https://lead.se"

def print_banner():
    """Print main banner"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        WordPress Security Testing Suite - Automated Runner          ║
║        All Tests Execution                                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    print(f"🎯 Target: {TARGET}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

def print_module_header(module_name, module_number, total_modules):
    """Print module execution header"""
    print(f"\n{'='*70}")
    print(f"MODULE {module_number}/{total_modules}: {module_name}")
    print(f"{'='*70}\n")

def run_advanced_scanner():
    """Run advanced WordPress scanner"""
    print_module_header("Advanced WordPress Scanner", 1, 3)
    print("🔍 Testing for: SQL Injection, XSS, CSRF, File Upload, Security Headers")
    print("⏱️  Estimated time: 10-15 minutes\n")
    
    try:
        scanner = AdvancedWordPressScanner(TARGET)
        scanner.run_full_scan()
        print("\n✅ Advanced scanner completed successfully")
        return True
    except Exception as e:
        print(f"\n❌ Advanced scanner failed: {str(e)}")
        return False

def run_plugin_exploiter():
    """Run plugin vulnerability exploiter"""
    print_module_header("WordPress Plugin Exploiter", 2, 3)
    print("🔌 Testing for: Known plugin CVEs and vulnerabilities")
    print("⏱️  Estimated time: 5-10 minutes\n")
    
    try:
        exploiter = WordPressPluginExploiter(TARGET)
        exploiter.run_full_scan()
        print("\n✅ Plugin exploiter completed successfully")
        return True
    except Exception as e:
        print(f"\n❌ Plugin exploiter failed: {str(e)}")
        return False

def run_credential_tester():
    """Run credential testing"""
    print_module_header("Advanced Credential Tester", 3, 3)
    print("🔐 Testing for: User enumeration and authentication security")
    print("⏱️  Estimated time: 5-10 minutes")
    print("⚠️  Limited to 20 password attempts per user for safety\n")
    
    try:
        tester = AdvancedCredentialTester(TARGET)
        # Run with limited attempts for safety
        tester.run_attack(mode="smart", max_attempts=20)
        print("\n✅ Credential tester completed successfully")
        return True
    except Exception as e:
        print(f"\n❌ Credential tester failed: {str(e)}")
        return False

def print_summary(results, start_time):
    """Print execution summary"""
    elapsed = time.time() - start_time
    
    print(f"\n{'='*70}")
    print("EXECUTION SUMMARY")
    print(f"{'='*70}\n")
    
    print(f"⏱️  Total execution time: {elapsed/60:.1f} minutes")
    print(f"🎯 Target: {TARGET}")
    print(f"📅 Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print("Module Results:")
    total = len(results)
    successful = sum(1 for r in results.values() if r)
    failed = total - successful
    
    for module, success in results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"  {status} - {module}")
    
    print(f"\n📊 Summary: {successful}/{total} modules completed successfully")
    
    if failed > 0:
        print(f"⚠️  {failed} module(s) failed - check output above for details")
    
    print(f"\n{'='*70}")
    print("📄 Check generated report files for detailed findings:")
    print("   - security_report_*.json")
    print("   - plugin_exploit_report_*.json")
    print("   - valid_credentials_*.json (if credentials found)")
    print(f"{'='*70}\n")

def main():
    """Main execution function"""
    print_banner()
    
    # Confirm execution
    print("⚠️  This will run ALL security tests against the target.")
    print("⏱️  Total estimated time: 20-35 minutes")
    print(f"🎯 Target: {TARGET}\n")
    
    response = input("Do you want to continue? (y/n): ").strip().lower()
    if response != 'y':
        print("\n❌ Execution cancelled by user")
        return
    
    print("\n🚀 Starting automated security testing...\n")
    start_time = time.time()
    
    # Track results
    results = {}
    
    # Module 1: Advanced Scanner
    results['Advanced Scanner'] = run_advanced_scanner()
    time.sleep(2)  # Brief pause between modules
    
    # Module 2: Plugin Exploiter
    results['Plugin Exploiter'] = run_plugin_exploiter()
    time.sleep(2)
    
    # Module 3: Credential Tester
    results['Credential Tester'] = run_credential_tester()
    
    # Print summary
    print_summary(results, start_time)
    
    # Exit code based on results
    if all(results.values()):
        print("✅ All tests completed successfully!")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed - review output above")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Execution interrupted by user (Ctrl+C)")
        print("Partial results may be available in generated report files")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
