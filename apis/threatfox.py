import aiohttp
from .base import BaseAPI

TF_BASE = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxAPI(BaseAPI):
    name = "threatfox"
    supported_types = {"ip", "domain", "url", "md5", "sha256", "sha1"}

    async def query(self, session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
        result = self._base_result(ioc, ioc_type)

        if ioc_type == "ip":
            search_term = ioc
        elif ioc_type == "domain":
            search_term = ioc
        elif ioc_type in ("md5", "sha1", "sha256"):
            search_term = ioc
        elif ioc_type == "url":
            search_term = ioc
        else:
            result["error"] = "Tipo no soportado"
            return result

        payload = {"query": "search_ioc", "search_term": search_term}
        data = await self._post(session, TF_BASE, json=payload)

        if "error" in data and "query_status" not in data:
            result["error"] = data.get("error")
            return result

        status = data.get("query_status", "")
        found = status == "ok"
        entries = data.get("data", []) or []
        entry = entries[0] if entries else {}

        tags = entry.get("tags") or []
        result.update({
            "malicious": found,
            "score": len(entries),
            "detections": len(entries),
            "total_engines": None,
            "tags": tags if isinstance(tags, list) else [tags],
            "raw": {
                "malware": entry.get("malware"),
                "threat_type": entry.get("threat_type"),
                "confidence": entry.get("confidence_level"),
                "reporter": entry.get("reporter"),
            },
        })
        return result
