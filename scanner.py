
#!/usr/bin/env python3
"""
Vulnerability / CVE Scanner
Target platform: Kali Linux
Purpose: Non-destructive TCP service detection and CVE triage.
"""

import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 3306, 3389, 5432, 5900, 8000,
    8080, 8443, 9000
]

SOCKET_TIMEOUT = 1.2
MAX_WORKERS = 40


class ServiceScanner:
    """Discover TCP services and collect non-destructive banners."""

    def __init__(self, target, ports=None, timeout=SOCKET_TIMEOUT):
        self.target = target
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.results = []

    @staticmethod
    def validate_target(target):
        """Accept an IP address or a syntactically valid hostname."""
        try:
            socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            return True
        except socket.gaierror:
            return False

    def identify_service(self, port, banner):
        text = banner.lower()

        signatures = [
            ("OpenSSH", r"openssh[_ /-]?([\d.p]+)", "ssh"),
            ("Apache HTTP Server", r"apache/([\d.]+)", "http"),
            ("nginx", r"nginx/([\d.]+)", "http"),
            ("OpenSSL", r"openssl/([\d.]+)", "tls"),
            ("ProFTPD", r"proftpd[ /]?([\d.]+)", "ftp"),
            ("vsFTPd", r"vsftpd[ /]?([\d.]+)", "ftp"),
            ("MySQL", r"mysql(?:\s+|/)([\d.]+)", "database"),
            ("MariaDB", r"mariadb[ /-]?([\d.]+)", "database"),
            ("PostgreSQL", r"postgresql[ /]?([\d.]+)", "database"),
            ("Microsoft IIS", r"microsoft-iis/([\d.]+)", "http"),
        ]

        for product, pattern, service in signatures:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return {
                    "service": service,
                    "product": product,
                    "version": match.group(1).rstrip("."),
                }

        common = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 3306: "mysql",
            5432: "postgresql", 5900: "vnc", 8080: "http",
            8443: "https",
        }

        return {
            "service": common.get(port, "unknown"),
            "product": None,
            "version": None,
        }

    def grab_banner(self, sock, port):
        """Use protocol-appropriate, low-impact probes."""
        try:
            if port in (80, 8080, 8000, 9000):
                request = (
                    f"HEAD / HTTP/1.0\r\n"
                    f"Host: {self.target}\r\n"
                    "User-Agent: Local-CVE-Scanner/1.0\r\n\r\n"
                )
                sock.sendall(request.encode("ascii", errors="ignore"))

            elif port == 443 or port == 8443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(
                    sock, server_hostname=self.target
                ) as tls_sock:
                    tls_sock.settimeout(self.timeout)
                    tls_sock.sendall(
                        f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n"
                        .encode()
                    )
                    return tls_sock.recv(2048).decode(
                        "utf-8", errors="replace"
                    ).strip()

            elif port in (21, 22, 25, 110, 143, 3306):
                # These services commonly send a greeting immediately.
                pass

            else:
                return ""

            return sock.recv(2048).decode(
                "utf-8", errors="replace"
            ).strip()

        except (socket.timeout, OSError, ssl.SSLError):
            return ""

    def scan_port(self, port):
        result = {
            "port": port,
            "state": "closed_or_filtered",
            "banner": "",
            "service": "unknown",
            "product": None,
            "version": None,
            "http_headers": {},
        }

        try:
            with socket.create_connection(
                (self.target, port), timeout=self.timeout
            ) as sock:
                result["state"] = "open"
                sock.settimeout(self.timeout)

                banner = self.grab_banner(sock, port)
                result["banner"] = banner[:2000]

                info = self.identify_service(port, banner)
                result.update(info)

            # Query HTTP headers separately after closing the TCP socket.
            if port in (80, 8000, 8080, 9000, 443, 8443):
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{self.target}:{port}/"

                try:
                    response = requests.get(
                        url,
                        timeout=3,
                        allow_redirects=False,
                        verify=False,
                        headers={
                            "User-Agent": "Local-CVE-Scanner/1.0"
                        },
                    )
                    result["http_status"] = response.status_code
                    result["http_headers"] = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() in (
                            "server", "x-powered-by",
                            "content-type", "www-authenticate"
                        )
                    }

                    server = response.headers.get("Server", "")
                    if server:
                        result["banner"] += (
                            "\nHTTP Server: " + server
                        )
                        info = self.identify_service(port, server)
                        if info["product"] and not result["product"]:
                            result.update(info)

                except requests.RequestException:
                    pass

        except (socket.timeout, OSError):
            pass

        return result

    def scan(self):
        print(f"\n[*] Target: {self.target}")
        print(f"[*] Scanning {len(self.ports)} TCP ports...")

        self.results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self.scan_port, port): port
                for port in self.ports
            }

            for future in as_completed(futures):
                result = future.result()
                if result["state"] == "open":
                    self.results.append(result)
                    service = result["service"]
                    version = result["version"] or "unknown version"
                    print(
                        f"[OPEN] {result['port']:5}  "
                        f"{service:12} {version}"
                    )

        self.results.sort(key=lambda item: item["port"])
        print(f"\n[+] Open TCP ports: {len(self.results)}")
        return self.results


class CVELookup:
    """Query NVD API 2.0 using detected product/version keywords."""

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Local-CVE-Scanner/1.0"
        })
        if api_key:
            self.session.headers["apiKey"] = api_key

    @staticmethod
    def severity_from_score(score):
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"

    @staticmethod
    def extract_cvss(metrics):
        for key in (
            "cvssMetricV40", "cvssMetricV31",
            "cvssMetricV30", "cvssMetricV2"
        ):
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                severity = data.get("baseSeverity")
                if score is not None:
                    return float(score), (
                        severity or CVELookup.severity_from_score(
                            float(score)
                        )
                    )
        return None, "UNKNOWN"

    def search(self, keyword):
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10,
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = self.session.get(
                NVD_API,
                params=params,
                headers=headers,
                timeout=20,
            )

            if response.status_code == 429:
                print("[!] NVD rate limit reached; skipping this query.")
                return []

            response.raise_for_status()
            data = response.json()

        except (requests.RequestException, ValueError) as exc:
            print(f"[!] NVD lookup failed for {keyword!r}: {exc}")
            return []

        findings = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions", [])
            description = next(
                (
                    entry.get("value", "")
                    for entry in descriptions
                    if entry.get("lang") == "en"
                ),
                "No English description available.",
            )

            score, severity = self.extract_cvss(
                cve.get("metrics", {})
            )

            findings.append({
                "cve_id": cve.get("id", "UNKNOWN"),
                "description": description[:1500],
                "cvss_score": score,
                "severity": severity,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "url": (
                    "https://nvd.nist.gov/vuln/detail/"
                    + cve.get("id", "")
                ),
                "match_type": "keyword search; not verified",
            })

        return findings


class ReportManager:
    """Create machine-readable JSON reports."""

    def __init__(self, report_dir=REPORT_DIR):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def save(self, target, services, findings):
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        safe_target = re.sub(r"[^a-zA-Z0-9.-]", "_", target)
        path = self.report_dir / f"scan_{safe_target}_{timestamp}.json"

        report = {
            "scanner": "Vulnerability-CVE-Scanner",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "scope": "TCP ports specified by the operator",
            "services": services,
            "cve_findings": findings,
            "limitations": [
                "Banner and keyword matches do not prove vulnerability.",
                "Some services hide or falsify version information.",
                "CVE search results may describe other product versions.",
                "No exploit verification was performed.",
                "Only the scanned TCP ports were checked.",
            ],
        }

        path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path


class VulnerabilityScannerApp:
    """Menu-driven application."""

    def __init__(self):
        self.target = None
        self.services = []
        self.findings = []
        self.report_manager = ReportManager()
        self.cve_lookup = CVELookup()

    def set_target(self):
        target = input("DVWA target IP/hostname: ").strip()
        if not target or not ServiceScanner.validate_target(target):
            print("[!] Target is invalid or cannot be resolved.")
            return

        self.target = target
        print(f"[+] Target set to {target}")

    def run_scan(self):
        if not self.target:
            print("[!] Set the target first.")
            return

        raw = input(
            "TCP ports (comma-separated, Enter for defaults): "
        ).strip()

        try:
            if raw:
                ports = sorted(set(int(p.strip()) for p in raw.split(",")))
                if not ports or any(p < 1 or p > 65535 for p in ports):
                    raise ValueError
            else:
                ports = DEFAULT_PORTS.copy()
        except ValueError:
            print("[!] Invalid port list.")
            return

        scanner = ServiceScanner(self.target, ports)
        self.services = scanner.scan()
        self.findings = []

        products = []
        for service in self.services:
            if service.get("product"):
                name = service["product"]
                version = service.get("version")
                keyword = f"{name} {version}" if version else name
                products.append((service["port"], keyword))

        if not products:
            print(
                "[!] No recognizable product/version banners found. "
                "CVE lookup skipped."
            )
        else:
            print("\n[*] Querying NVD; results are potential matches.")
            seen = set()

            for port, keyword in products:
                print(f"[*] Searching: {keyword}")
                matches = self.cve_lookup.search(keyword)

                for finding in matches:
                    key = (port, finding["cve_id"])
                    if key in seen:
                        continue
                    seen.add(key)

                    finding["port"] = port
                    finding["detected_product"] = keyword
                    finding["confidence"] = "LOW"
                    finding["triage"] = (
                        "Verify product identity, exact affected "
                        "version, configuration and vendor advisory."
                    )
                    self.findings.append(finding)

                # Reduce request rate when querying multiple products.
                time.sleep(1.0)

        path = self.report_manager.save(
            self.target, self.services, self.findings
        )
        print(f"\n[+] Report saved: {path}")

    def show_findings(self):
        if not self.services:
            print("[!] Run a scan first.")
            return

        print("\n=== DETECTED SERVICES ===")
        for service in self.services:
            print(
                f"{service['port']}/tcp | "
                f"{service['service']} | "
                f"{service.get('product') or 'Unknown'} | "
                f"{service.get('version') or 'Unknown version'}"
            )

        print("\n=== POTENTIAL CVE MATCHES ===")
        if not self.findings:
            print("No CVE matches returned.")
            return

        for item in sorted(
            self.findings,
            key=lambda x: (
                x["cvss_score"] is not None,
                x["cvss_score"] or 0
            ),
            reverse=True,
        ):
            print(
                f"\n{item['cve_id']} | {item['severity']} | "
                f"CVSS: {item['cvss_score']}"
            )
            print(f"Port: {item['port']}/tcp")
            print(item["description"][:300])
            print(item["url"])
            print("Confidence: LOW — validate before reporting.")

    def menu(self):
        while True:
            print("""
====================================
     VULNERABILITY / CVE SCANNER
====================================
1. Set DVWA target
2. Scan TCP services and query CVEs
3. Display latest findings
4. Exit
""")
            choice = input("Select: ").strip()

            if choice == "1":
                self.set_target()
            elif choice == "2":
                self.run_scan()
            elif choice == "3":
                self.show_findings()
            elif choice == "4":
                print("Exiting.")
                break
            else:
                print("[!] Invalid option.")


if __name__ == "__main__":
    try:
        VulnerabilityScannerApp().menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
