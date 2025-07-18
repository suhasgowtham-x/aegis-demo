import os
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_file_hash(file_hash):
    """Check a file hash on VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    try:
        return response.json()
    except Exception as e:
        return {"error": f"Invalid VirusTotal response: {str(e)}"}

def check_ip_address(ip):
    """Check IP reputation using AbuseIPDB"""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }
    response = requests.get(url, headers=headers, params=params)
    try:
        return response.json()
    except Exception as e:
        return {"error": f"Invalid AbuseIPDB response: {str(e)}"}
