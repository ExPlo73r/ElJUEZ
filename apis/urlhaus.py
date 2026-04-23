import aiohttp
from .base import BaseAPI

URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausAPI(BaseAPI):
    name = "urlhaus"
    # No key requerida
    supported_types = {"url", "domain", "md5", "sha256"}

    async def query(self, session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
        result = self._base_result(ioc, ioc_type)

        if ioc_type == "url":
            endpoint = f"{URLHAUS_BASE}/url/"
            payload = {"url": ioc}
        elif ioc_type == "domain":
            endpoint = f"{URLHAUS_BASE}/host/"
            payload = {"host": ioc}
        elif ioc_type in ("md5", "sha256"):
            endpoint = f"{URLHAUS_BASE}/payload/"
            key = "md5_hash" if ioc_type == "md5" else "sha256_hash"
            payload = {key: ioc}
        else:
            result["error"] = "Tipo no soportado"
            return result

        data = await self._post(session, endpoint, data=payload)

        if "error" in data and "query_status" not in data:
            result["error"] = data.get("error")
            return result

        status = data.get("query_status", "")
        is_malicious = status in ("is_host", "is_url", "ok") and data.get("urls_count", 0) > 0

        urls_count = data.get("urls_count", 0)
        tags = data.get("tags") or []

        result.update({
            "malicious": is_malicious or status == "online",
            "score": urls_count,
            "detections": urls_count,
            "total_engines": None,
            "tags": tags if isinstance(tags, list) else [tags],
            "raw": {"query_status": status, "urls_count": urls_count},
        })
        return result
