import os
import time
from datetime import datetime

# Load CVE keywords for detection
CVE_SIGNATURES = [
    "CVE-2023-23397", "CVE-2024-3094", "unauthorized access", "exploit attempt", "buffer overflow"
]

MALWARE_SIGNATURES = [
    "malicious.exe", "trojan_found", "worm_behavior", "unauthorized_upload", "ransomware_detected"
]

def scan_log_for_cves(log_content):
    findings = []
    for line in log_content.splitlines():
        for sig in CVE_SIGNATURES:
            if sig in line:
                findings.append(f"[CVE] {sig} found in line: {line.strip()}")
    return findings or ["✅ No known CVE indicators found."]

def scan_for_malware_signatures(log_content):
    results = []
    for line in log_content.splitlines():
        for sig in MALWARE_SIGNATURES:
            if sig in line:
                results.append(f"[MALWARE] Signature '{sig}' matched: {line.strip()}")
    return results or ["✅ No known malware signatures detected."]

def monitor_log_file(filepath, callback):
    seen = set()
    while True:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if line not in seen:
                        seen.add(line)
                        callback(line.strip())
        except Exception as e:
            print(f"[Monitor Error] {e}")
        time.sleep(2)
