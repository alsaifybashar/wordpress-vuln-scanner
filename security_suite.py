#!/usr/bin/env python3
"""
WordPress Security Testing Suite - Master Controller
Orchestrates comprehensive security assessment
"""

import subprocess
import sys
import json
import time
from datetime import datetime
from typing import Dict, List
import os

class WordPressSecuritySuite:
    def __init__(self, target: str):
        self.target = target
        
        # Load output_dir from config
        self.output_dir = "."
        try:
            with open('config.json', 'r') as f:
                self.output_dir = json.load(f).get('reporting', {}).get('output_directory', '.')
        except:
            pass
            
        self.results = {
            'target': target,
            'scan_start': datetime.now().isoformat(),
            'scan_end': None,
            'modules': {}
        }
        
        # Available test modules
        self.modules = {
            '1': {
                'name': 'Advanced Scanner',
                'script': 'advanced_wordpress_scanner.py',
                'description': 'SQL injection, XSS, CSRF, file upload, security headers',
                'severity': 'CRITICAL'
            },
            '2': {
                'name': 'Plugin Exploiter',
                'script': 'wordpress_plugin_exploiter.py',
                'description': 'Known CVE exploitation for popular plugins',
                'severity': 'HIGH'
            },
            '3': {
                'name': 'Credential Tester',
                'script': 'advanced_credential_tester.py',
                'description': 'User enumeration and intelligent password testing',
                'severity': 'HIGH'
            },
            '4': {
                'name': 'Basic Scanner',
                'script': 'wordpress_advanced_scan.py',
                'description': 'File exposure, directory listing, version disclosure',
                'severity': 'MEDIUM'
            },
            '5': {
                'name': 'User Enumeration',
                'script': 'exploit_user_enum.py',
                'description': 'Focused user enumeration and basic auth testing',
                'severity': 'MEDIUM'
            }
        }
    
    def print_banner(self):
        """Print suite banner"""
        print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        WordPress Security Testing Suite v2.0                        ║
║        Comprehensive Vulnerability Assessment Platform              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """)
        print(f"Target: {self.target}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
    
    def print_menu(self):
        """Print interactive menu"""
        print("\n" + "="*70)
        print("AVAILABLE TEST MODULES")
        print("="*70)
        
        for key, module in self.modules.items():
            severity_colors = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }
            icon = severity_colors.get(module['severity'], '⚪')
            
            print(f"\n{icon} [{key}] {module['name']}")
            print(f"    Script: {module['script']}")
            print(f"    Tests: {module['description']}")
            print(f"    Severity: {module['severity']}")
        
        print("\n" + "="*70)
        print("[A] Run ALL modules (comprehensive scan)")
        print("[Q] Quick scan (modules 1, 4)")
        print("[C] Custom selection")
        print("[X] Exit")
        print("="*70)
    
    def run_module(self, script_name: str, module_name: str) -> Dict:
        """Run a single test module"""
        print(f"\n{'='*70}")
        print(f"EXECUTING: {module_name}")
        print(f"Script: {script_name}")
        print(f"{'='*70}\n")
        
        start_time = time.time()
        
        try:
            # Run the script
            result = subprocess.run(
                [sys.executable, script_name],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            elapsed = time.time() - start_time
            
            # Parse output
            output = result.stdout
            errors = result.stderr
            
            print(output)
            
            if errors:
                print(f"\n⚠️  Errors/Warnings:\n{errors}")
            
            # Try to find JSON report
            report_data = None
            try:
                # Look for JSON files created by the script in output_dir
                if os.path.exists(self.output_dir):
                    json_files = [os.path.join(self.output_dir, f) for f in os.listdir(self.output_dir) 
                                if f.endswith('.json') and 
                                os.path.getmtime(os.path.join(self.output_dir, f)) > start_time]
                    if json_files:
                        latest_report = max(json_files, key=os.path.getmtime)
                        with open(latest_report, 'r') as f:
                            report_data = json.load(f)
            except:
                pass
            
            return {
                'status': 'completed',
                'exit_code': result.returncode,
                'duration': elapsed,
                'output_lines': len(output.split('\n')),
                'report_data': report_data
            }
            
        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'error': 'Module exceeded 10 minute timeout'
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def run_selected_modules(self, module_keys: List[str]):
        """Run selected modules"""
        print(f"\n{'='*70}")
        print(f"STARTING SCAN - {len(module_keys)} modules selected")
        print(f"{'='*70}")
        
        for key in module_keys:
            if key in self.modules:
                module = self.modules[key]
                result = self.run_module(module['script'], module['name'])
                self.results['modules'][module['name']] = result
                
                # Brief pause between modules
                time.sleep(2)
        
        self.results['scan_end'] = datetime.now().isoformat()
    
    def generate_master_report(self):
        """Generate comprehensive master report"""
        print("\n" + "="*70)
        print("GENERATING MASTER REPORT")
        print("="*70)
        
        # Calculate statistics
        total_modules = len(self.results['modules'])
        completed = sum(1 for r in self.results['modules'].values() if r['status'] == 'completed')
        failed = sum(1 for r in self.results['modules'].values() if r['status'] == 'error')
        
        # Create master report
        report = {
            'scan_summary': {
                'target': self.target,
                'scan_start': self.results['scan_start'],
                'scan_end': self.results['scan_end'],
                'total_modules': total_modules,
                'completed': completed,
                'failed': failed
            },
            'module_results': self.results['modules'],
            'aggregated_findings': self.aggregate_findings()
        }
        
        # Save master report
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        filename = f"MASTER_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        full_path = os.path.join(self.output_dir, filename)
        
        with open(full_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n📊 SCAN SUMMARY")
        print(f"   Total Modules: {total_modules}")
        print(f"   Completed: {completed}")
        print(f"   Failed: {failed}")
        
        # Print findings summary
        findings = self.aggregate_findings()
        if findings:
            print(f"\n🔍 AGGREGATED FINDINGS")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = findings.get(severity, 0)
                if count > 0:
                    icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}
                    print(f"   {icons[severity]} {severity}: {count}")
        
        print(f"\n📄 Master report saved to: {full_path}")
        
        # Generate human-readable report
        self.generate_html_report(report, full_path.replace('.json', '.html'))
    
    def aggregate_findings(self) -> Dict[str, int]:
        """Aggregate findings from all modules"""
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for module_name, result in self.results['modules'].items():
            if result.get('report_data') and 'vulnerabilities' in result['report_data']:
                for vuln in result['report_data']['vulnerabilities']:
                    severity = vuln.get('severity', 'INFO')
                    if severity in severity_count:
                        severity_count[severity] += 1
        
        return severity_count
    
    def generate_html_report(self, report_data: Dict, filename: str):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WordPress Security Assessment - {self.target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        .module {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WordPress Security Assessment Report</h1>
        <p><strong>Target:</strong> {self.target}</p>
        <p><strong>Scan Date:</strong> {report_data['scan_summary']['scan_start']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Modules Executed:</strong> {report_data['scan_summary']['total_modules']}</p>
        <p><strong>Completed:</strong> {report_data['scan_summary']['completed']}</p>
        <p><strong>Failed:</strong> {report_data['scan_summary']['failed']}</p>
        
        <h3>Findings by Severity</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
"""
        
        findings = report_data['aggregated_findings']
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = findings.get(severity, 0)
            html += f"""
            <tr>
                <td class="severity-{severity.lower()}">{severity}</td>
                <td>{count}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
    
    <h2>Module Results</h2>
"""
        
        for module_name, result in report_data['module_results'].items():
            status_color = 'green' if result['status'] == 'completed' else 'red'
            html += f"""
    <div class="module">
        <h3>{module_name}</h3>
        <p><strong>Status:</strong> <span style="color: {status_color}">{result['status']}</span></p>
"""
            if 'duration' in result:
                html += f"<p><strong>Duration:</strong> {result['duration']:.2f} seconds</p>"
            
            html += "</div>"
        
        html += """
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html)
        
        print(f"📄 HTML report saved to: {filename}")
    
    def interactive_mode(self):
        """Run in interactive mode"""
        self.print_banner()
        
        while True:
            self.print_menu()
            choice = input("\nSelect option: ").strip().upper()
            
            if choice == 'X':
                print("\nExiting...")
                break
            
            elif choice == 'A':
                # Run all modules
                print("\n⚠️  Running ALL modules - this may take 30+ minutes")
                confirm = input("Continue? (y/n): ").strip().lower()
                if confirm == 'y':
                    self.run_selected_modules(list(self.modules.keys()))
                    self.generate_master_report()
                    break
            
            elif choice == 'Q':
                # Quick scan
                print("\n🚀 Running quick scan (modules 1, 4)")
                self.run_selected_modules(['1', '4'])
                self.generate_master_report()
                break
            
            elif choice == 'C':
                # Custom selection
                print("\nEnter module numbers separated by commas (e.g., 1,2,3):")
                selection = input("Modules: ").strip()
                module_keys = [k.strip() for k in selection.split(',') if k.strip() in self.modules]
                
                if module_keys:
                    self.run_selected_modules(module_keys)
                    self.generate_master_report()
                    break
                else:
                    print("❌ Invalid selection")
            
            elif choice in self.modules:
                # Run single module
                self.run_selected_modules([choice])
                self.generate_master_report()
                break
            
            else:
                print("❌ Invalid option")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='WordPress Security Testing Suite')
    # Load default target from config
    default_target = "https://lead.se"
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            default_target = config.get('target', {}).get('url', default_target)
    except:
        pass

    parser.add_argument('--target', default=default_target, help='Target WordPress site')
    parser.add_argument('--auto', action='store_true', help='Run all tests automatically')
    parser.add_argument('--quick', action='store_true', help='Run quick scan only')
    parser.add_argument('--modules', help='Comma-separated module numbers to run')
    
    args = parser.parse_args()
    
    suite = WordPressSecuritySuite(args.target)
    
    if args.auto:
        suite.print_banner()
        print("\n🤖 Running in automatic mode - ALL modules")
        suite.run_selected_modules(list(suite.modules.keys()))
        suite.generate_master_report()
    
    elif args.quick:
        suite.print_banner()
        print("\n🚀 Running quick scan")
        suite.run_selected_modules(['1', '4'])
        suite.generate_master_report()
    
    elif args.modules:
        suite.print_banner()
        module_keys = [k.strip() for k in args.modules.split(',')]
        suite.run_selected_modules(module_keys)
        suite.generate_master_report()
    
    else:
        # Interactive mode
        suite.interactive_mode()

if __name__ == "__main__":
    main()
