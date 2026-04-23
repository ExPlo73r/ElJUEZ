import asyncio
import aiohttp
from apis import ALL_APIS
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn


async def query_ioc(session: aiohttp.ClientSession, api_instance, ioc: str, ioc_type: str) -> dict:
    try:
        return await api_instance.query(session, ioc, ioc_type)
    except Exception as exc:
        r = api_instance._base_result(ioc, ioc_type)
        r["error"] = str(exc)
        return r


async def process_iocs(iocs: list[dict], selected_apis: list[str] | None = None) -> list[dict]:
    """
    Consulta todos los IOCs contra todas las APIs habilitadas.
    Devuelve lista plana de resultados: un dict por (ioc, api).
    """
    api_instances = [
        cls() for cls in ALL_APIS
        if selected_apis is None or cls.name in selected_apis
    ]

    results = []
    total = len(iocs)

    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Procesando IOCs...", total=total)

            for item in iocs:
                ioc = item["ioc"]
                ioc_type = item["type"]

                if ioc_type == "unknown":
                    progress.advance(task)
                    continue

                applicable = [a for a in api_instances if a.supports(ioc_type)]
                tasks = [query_ioc(session, api, ioc, ioc_type) for api in applicable]
                batch = await asyncio.gather(*tasks)
                results.extend(batch)
                progress.advance(task)

    return results


def summarize(results: list[dict]) -> list[dict]:
    """Agrupa por IOC y genera resumen consolidado."""
    from collections import defaultdict

    grouped: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        grouped[r["ioc"]].append(r)

    summary = []
    for ioc, entries in grouped.items():
        valid = [e for e in entries if not e.get("error")]
        malicious_count = sum(1 for e in valid if e.get("malicious"))
        total_sources = len(valid)

        all_tags = []
        for e in valid:
            all_tags.extend(e.get("tags") or [])

        verdict = "limpio"
        if malicious_count > 0:
            ratio = malicious_count / total_sources if total_sources else 0
            verdict = "malicioso" if ratio >= 0.5 else "sospechoso"

        summary.append({
            "ioc": ioc,
            "type": entries[0]["type"],
            "verdict": verdict,
            "malicious_sources": malicious_count,
            "total_sources": total_sources,
            "tags": list(set(filter(None, all_tags))),
            "per_source": {
                e["source"]: {
                    "malicious": e.get("malicious"),
                    "score": e.get("score"),
                    "detections": e.get("detections"),
                    "total_engines": e.get("total_engines"),
                    "country": e.get("country"),
                    "tags": e.get("tags"),
                    "error": e.get("error"),
                }
                for e in entries
            },
        })

    return sorted(summary, key=lambda x: (x["verdict"] != "malicioso", x["verdict"] != "sospechoso"))
