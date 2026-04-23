import aiohttp
from .base import BaseAPI
from config import VIRUSTOTAL_KEY

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalAPI(BaseAPI):
    name = "virustotal"
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}

    def _headers(self) -> dict:
        return {"x-apikey": VIRUSTOTAL_KEY}

    def _endpoint(self, ioc: str, ioc_type: str) -> str | None:
        if ioc_type == "ip":
            return f"{VT_BASE}/ip_addresses/{ioc}"
        if ioc_type == "domain":
            return f"{VT_BASE}/domains/{ioc}"
        if ioc_type in ("md5", "sha1", "sha256"):
            return f"{VT_BASE}/files/{ioc}"
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            return f"{VT_BASE}/urls/{url_id}"
        return None

    async def query(self, session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
        result = self._base_result(ioc, ioc_type)
        if not VIRUSTOTAL_KEY:
            result["error"] = "API key no configurada"
            return result

        endpoint = self._endpoint(ioc, ioc_type)
        if not endpoint:
            result["error"] = "Tipo no soportado"
            return result

        data = await self._get(session, endpoint, headers=self._headers())

        if "error" in data and "attributes" not in data:
            result["error"] = data.get("error")
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        result.update({
            "malicious": malicious > 0 or suspicious > 0,
            "score": malicious + suspicious,
            "detections": malicious + suspicious,
            "total_engines": total,
            "tags": attrs.get("tags", []),
            "country": attrs.get("country"),
            "raw": stats,
        })
        return result
