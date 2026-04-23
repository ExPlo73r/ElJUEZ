import aiohttp
from .base import BaseAPI
from config import ABUSEIPDB_KEY

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBAPI(BaseAPI):
    name = "abuseipdb"
    supported_types = {"ip"}

    async def query(self, session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
        result = self._base_result(ioc, ioc_type)
        if not ABUSEIPDB_KEY:
            result["error"] = "API key no configurada"
            return result

        params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""}
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        data = await self._get(session, f"{ABUSE_BASE}/check", headers=headers, params=params)

        if "error" in data and "data" not in data:
            result["error"] = data.get("error")
            return result

        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)

        result.update({
            "malicious": score > 0,
            "score": score,
            "detections": d.get("totalReports", 0),
            "total_engines": None,
            "tags": d.get("usageType", "").split(",") if d.get("usageType") else [],
            "country": d.get("countryCode"),
            "raw": {
                "abuse_score": score,
                "total_reports": d.get("totalReports"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "is_whitelisted": d.get("isWhitelisted"),
            },
        })
        return result
