# Vulnerability / CVE Scanner

## Overview

A lightweight Python scanner for Kali Linux that detects TCP services, collects service banners, identifies recognizable software versions, and queries the NIST National Vulnerability Database (NVD) for potential CVE matches.

## Features

- TCP port scanning using Python sockets
- Service banner grabbing
- Basic product and version fingerprinting
- HTTP response-header collection
- NVD CVE API 2.0 integration
- CVSS score and severity extraction
- JSON scan reports
- Interactive terminal menu
- Initial vulnerability triage notes

## Project Structure

```text
vulnerability-cve-scanner/
├── scanner.py
├── requirements.txt
├── README.md
└── reports/
```

## Requirements

- Kali Linux
- Python 3
- Network connectivity to the target
- Internet access for live NVD lookups
- A reachable DVWA VM

## Installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv

mkdir -p ~/vulnerability-cve-scanner/reports
cd ~/vulnerability-cve-scanner

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Save the scanner implementation as `scanner.py`.

## Usage

```bash
source .venv/bin/activate
python3 scanner.py
```

1. Select option 1 to set the DVWA target IP.
2. Select option 2 to scan TCP ports and query CVEs.
3. Enter a comma-separated port list, or press Enter to use the defaults.
4. Select option 3 to review the latest findings.
5. Inspect the generated JSON report in `reports/`.

## DVWA Network Setup

On the DVWA VM:

```bash
ip -br addr
```

On Kali:

```bash
ip -br addr
ping -c 3 <DVWA_IP>
curl -I --connect-timeout 3 http://<DVWA_IP>/
```

Use the DVWA address on the host-only network.

## CVE Matching

The scanner queries the NVD CVE API 2.0 using detected product/version keywords. Returned records include CVE identifiers, descriptions, CVSS scores where available, severity, publication dates and NVD links.

Keyword matches are preliminary leads. They do not confirm that the installed version or configuration is vulnerable.

## Report Output

Reports are written to `reports/` in JSON format and include target information, detected services, potential CVEs, severity, confidence and limitations.

## Limitations

- Only specified TCP ports are scanned.
- Banner identification depends on the information exposed by services.
- Some services do not disclose versions.
- CVE matching is keyword-based rather than full CPE affected-version validation.
- Missing CVSS scores are reported as UNKNOWN.
- No exploit or destructive validation is performed.
- NVD results require internet access.

## Triage Workflow

1. Confirm the service and product identity.
2. Establish the exact installed version and vendor.
3. Compare it with the affected versions in the CVE record.
4. Review severity, exploitability, exposure and business impact.
5. Verify vendor advisories and available patches.
6. Record evidence, confidence and remediation.
7. Retest after remediation.

## Responsible Disclosure

Document reproducible evidence, affected versions, potential impact and remediation recommendations. Report confirmed issues privately to the system owner or vendor through their published security contact or vulnerability disclosure process. Avoid publishing sensitive information before coordinated disclosure.

## Data Sources

- NIST National Vulnerability Database: https://nvd.nist.gov/
- NVD Vulnerabilities API documentation: https://nvd.nist.gov/developers/vulnerabilities
