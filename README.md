# WordPress Security Testing Suite - Project Manual

## 1. Project Purpose & Overview
This suite is a comprehensive, professional-grade security assessment toolkit designed for WordPress websites. It allows security researchers and authorized administrators to:
- Detect vulnerabilities (SQL Injection, XSS, CSRF, etc.)
- Test authentication strength (User enumeration, Brute-force protection)
- Verify plugin security against known CVEs
- Analyze server security headers and configurations

**⚠️ Disclaimer:** This tool is for **authorized security testing and educational purposes only**. Always obtain written permission before scanning any target.

## 2. File Structure & Explanations

Here is a breakdown of the essential files in this project:

### 🎯 Core Scripts
| File | Purpose |
|------|---------|
| **`security_suite.py`** | **Master Controller**. The main entry point. Provides an interactive menu to run all other modules. Use this to start. |
| **`advanced_wordpress_scanner.py`** | **Vulnerability Scanner**. Deep scans for SQLi, XSS, File Upload flaws, and more. |
| **`wordpress_plugin_exploiter.py`** | **Plugin Exploiter**. Checks installed plugins against a database of known vulnerabilities (CVEs). |
| **`advanced_credential_tester.py`** | **Auth Tester**. Smart password guessing, user enumeration, and login page analysis. |
| **`run_all_tests.py`** | **Automated Runner**. A headless script to run all tests sequentially (useful for CI/CD or cron jobs). |

### ⚙️ Configuration
| File | Purpose |
|------|---------|
| **`config.json`** | **Central Configuration**. Define your target URL, timeouts, thread counts, and user agents here. **Change `target.url` before running!** |

### ℹ️ Other
| File | Purpose |
|------|---------|
| **`reports/`** | (Directory) Where scan reports (JSON/HTML) are saved. |

## 3. How to Use

### Step 1: Configuration
Open `config.json` and set your target website:
```json
"target": {
    "url": "https://your-target-site.com",
    ...
}
```

### Step 2: Running the Suite
The easiest way is to use the Master Controller:
```bash
python security_suite.py
```
This will open an interactive menu where you can:
- **[A]** Run ALL modules (Full Scan)
- **[Q]** Quick scan
- **[1-5]** Run specific modules

### Alternative: Running Individual Scripts
You can also run any script independently. They will automatically load settings from `config.json`.
```bash
python advanced_wordpress_scanner.py
python wordpress_plugin_exploiter.py
```

## 4. Understanding Results
The suite generates two types of reports in the root directory (or configured output dir):
1.  **Console Output**: Real-time progress with color-coded severity (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low).
2.  **JSON/HTML Reports**: Detailed files saved as `security_report_<timestamp>.json` and `MASTER_REPORT_<timestamp>.html`.

## 5. Cleaning Up
To keep the directory clean, move old `*.json` and `*.html` reports to a `reports/` folder or delete them after analysis.
