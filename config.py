import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
ALIENVAULT_KEY = os.getenv("ALIENVAULT_KEY", "")

# Delay entre requests para respetar rate limits (segundos)
RATE_LIMITS = {
    "virustotal": 15,    # 4 req/min en plan gratuito
    "abuseipdb": 1.5,
    "alienvault": 1,
    "urlhaus": 1,
    "malwarebazaar": 1,
    "threatfox": 1,
}

REQUEST_TIMEOUT = 20
MAX_RETRIES = 2
