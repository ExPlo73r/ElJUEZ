import aiohttp
from .base import BaseAPI
from config import ALIENVAULT_KEY

OTX_BASE = "https://otx.alienvault.com/api/v1"


class AlienVaultAPI(BaseAPI):
    name = "alienvault"
    supported_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}

    def _headers(self) -> dict:
        if ALIENVAULT_KEY:
            return {"X-OTX-API-KEY": ALIENVAULT_KEY}
        return {}

    def _endpoint(self, ioc: str, ioc_type: str) -> str | None:
        if ioc_type == "ip":
            return f"{OTX_BASE}/indicators/IPv4/{ioc}/general"
        if ioc_type == "domain":
            return f"{OTX_BASE}/indicators/domain/{ioc}/general"
        if ioc_type == "url":
            return f"{OTX_BASE}/indicators/url/{ioc}/general"
        if ioc_type in ("md5", "sha1", "sha256"):
            return f"{OTX_BASE}/indicators/file/{ioc}/general"
        return None

    async def query(self, session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
        result = self._base_result(ioc, ioc_type)
        endpoint = self._endpoint(ioc, ioc_type)
        if not endpoint:
            result["error"] = "Tipo no soportado"
            return result

        data = await self._get(session, endpoint, headers=self._headers())

        if "error" in data and "pulse_info" not in data:
            result["error"] = data.get("error")
            return result

        pulses = data.get("pulse_info", {}).get("count", 0)
        tags_raw = data.get("pulse_info", {}).get("related", {}).get("other", {}).get("tag_list", [])

        result.update({
            "malicious": pulses > 0,
            "score": pulses,
            "detections": pulses,
            "total_engines": None,
            "tags": [t.get("name", "") for t in tags_raw] if isinstance(tags_raw, list) else [],
            "country": data.get("country_code"),
            "raw": {
                "pulse_count": pulses,
                "reputation": data.get("reputation", 0),
                "asn": data.get("asn"),
            },
        })
        return result
