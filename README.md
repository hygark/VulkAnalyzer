# **VulkAnalyzer**

just a test, beginner

Author: Hygark

## **Features**

* **Port Scanning:** Scans TCP/UDP ports within a configurable range with multi-thread support.
* **Web Testing:** Checks for vulnerabilities such as SQL Injection, XSS, CSRF, SSRF, LFI/RFI.
* **CMS Detection:** Identifies systems like WordPress, Joomla, and Drupal.
* **OS Fingerprinting:** Estimates the operating system based on TTL.
* **Subdomain Scanning:** Discovers subdomains via DNS.
* **API Testing:** Supports scanning REST, GraphQL, and WebSocket APIs, including weak authentication and injections.
* **Cloud Misconfigurations:** Detects public buckets (AWS S3, Azure Blob, Google Cloud Storage).
* **Integrations:** Supports XSStrike, Nikto, Burp Suite, Wfuzz, OWASP ZAP, Metasploit, and Nuclei.
* **Report Exporting:** Generates reports in JSON, PDF, CSV, and interactive HTML with charts.
* **Logs:** Supports logging to file, webhook, email, and Syslog (Splunk/ELK).
* **GUI:** Tkinter interface with tabs for Settings, Dashboard (charts), Results, and interactive Reports.

## **Requirements**

* **Python:** 3.11 or higher.
* **Python Dependencies:**

  ```bash
  pip install requests beautifulsoup4 scapy reportlab matplotlib msfrpc websocket-client tkinterweb dnspython
  ```

## **External Tools:**

* XSStrike: `git clone https://github.com/s0md3v/XSStrike.git`
* Nikto: `sudo apt install nikto` (Linux) or equivalent.
* Wfuzz: `pip install wfuzz`
* Nuclei: `go install -v github.com/projectdiscovery/nuclei/v3@latest`
* OWASP ZAP: Install and configure the API.
* Burp Suite: Configure the REST API.
* Metasploit: Install and configure the RPC.

## **Operating System**

* Compatible with Windows and Linux.
* **Permissions:** Some features (like port scanning) may require administrator privileges.

## **Installation**

Clone the repository:

```bash
git clone https://github.com/hygark/VulkAnalyzer.git
cd VulkAnalyzer
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install external tools as described above.
Configure paths and API keys in the script (in **Settings** or via the GUI).

Create directories for logs and reports:

```bash
mkdir logs reports
```

## **Usage**

Run the script:

```bash
python3 VulnerabilityAnalyzer.py
```

### **In the GUI:**

* **Settings:** Input targets (URLs or IPs), port ranges, tool paths, API keys, etc.
* **Dashboard:** View vulnerability charts in real time.
* **Results:** Inspect detailed scan results.
* **Reports:** Export reports in JSON, PDF, CSV, or interactive HTML.
* **Buttons:** Start/stop scans, save settings, view charts, or export reports.

Configure logs (file, webhook, email, Syslog) and exports as needed.

### **Example Settings:**

```python
Settings = {
    'Targets': ['http://testphp.vulnweb.com', '127.0.0.1'],
    'PortRange': (1, 1000),
    'Threads': 200,
    'XSStrikePath': './XSStrike/xsstrike.py',
    'NiktoPath': 'nikto',
    'SyslogServer': 'localhost',
    'SyslogPort': 514,
    'ExportJSON': True,
    'ExportPDF': True,
    'ExportCSV': True,
    'ExportHTML': True
}
```

## **Legal Compliance**

⚠️ **Disclaimer:** This tool is intended **exclusively** for ethical testing with explicit authorization from system owners. Unauthorized use may violate local laws, such as Brazil’s **LGPD (General Data Protection Law)** or international regulations (e.g., GDPR).
**Responsibility:** The author (Hygark) is not responsible for any misuse of this tool. Always obtain permission before performing scans.

## **Contributions**

Contributions are welcome! Submit pull requests or open issues in the GitHub repository.

## **License**

MIT License. See the LICENSE file for more details.

**Contact**
For questions or suggestions, reach out to Hygark via GitHub.
