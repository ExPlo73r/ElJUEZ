import asyncio
import aiohttp
from config import REQUEST_TIMEOUT, MAX_RETRIES, RATE_LIMITS


class BaseAPI:
    name: str = "base"
    supported_types: set[str] = set()

    def __init__(self):
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types

    async def _wait_rate_limit(self):
        delay = RATE_LIMITS.get(self.name, 1)
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = self._last_call + delay - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = asyncio.get_event_loop().time()

    async def _get(self, session: aiohttp.ClientSession, url: str, **kwargs) -> dict:
        await self._wait_rate_limit()
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT), **kwargs
                ) as resp:
                    if resp.status == 429:
                        await asyncio.sleep(60)
                        continue
                    resp.raise_for_status()
                    return await resp.json()
            except Exception as exc:
                if attempt == MAX_RETRIES:
                    return {"error": str(exc)}
                await asyncio.sleep(2 ** attempt)
        return {"error": "max retries exceeded"}

    async def _post(self, session: aiohttp.ClientSession, url: str, **kwargs) -> dict:
        await self._wait_rate_limit()
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with session.post(
                    url, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT), **kwargs
                ) as resp:
                    if resp.status == 429:
                        await asyncio.sleep(60)
                        continue
                    resp.raise_for_status()
                    return await resp.json(content_type=None)
            except Exception as exc:
                if attempt == MAX_RETRIES:
                    return {"error": str(exc)}
                await asyncio.sleep(2 ** attempt)
        return {"error": "max retries exceeded"}

    async def query(self, session: aiohttp.ClientSession, ioc: str, ioc_type: str) -> dict:
        """Implementar en cada subclase. Debe devolver un dict con claves estandarizadas."""
        raise NotImplementedError

    def _base_result(self, ioc: str, ioc_type: str) -> dict:
        return {
            "source": self.name,
            "ioc": ioc,
            "type": ioc_type,
            "malicious": None,
            "score": None,
            "detections": None,
            "total_engines": None,
            "tags": [],
            "country": None,
            "raw": {},
            "error": None,
        }
