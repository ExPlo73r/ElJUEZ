from .virustotal import VirusTotalAPI
from .abuseipdb import AbuseIPDBAPI
from .alienvault import AlienVaultAPI
from .urlhaus import URLhausAPI
from .malwarebazaar import MalwareBazaarAPI
from .threatfox import ThreatFoxAPI

ALL_APIS = [
    VirusTotalAPI,
    AbuseIPDBAPI,
    AlienVaultAPI,
    URLhausAPI,
    MalwareBazaarAPI,
    ThreatFoxAPI,
]
