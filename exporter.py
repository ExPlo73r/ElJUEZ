import csv
import json
import os
from datetime import datetime


def _ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None


def export_csv(summary: list[dict], output_name: str) -> str:
    """Genera CSV con una fila por IOC y columna por fuente."""
    path = f"{output_name}.csv"
    _ensure_dir(path)

    sources = sorted({src for row in summary for src in row["per_source"]})
    fieldnames = ["ioc", "type", "verdict", "malicious_sources", "total_sources", "tags"] + [
        f"{s}_{field}"
        for s in sources
        for field in ("malicious", "score", "detections", "total_engines", "country", "error")
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in summary:
            flat = {
                "ioc": row["ioc"],
                "type": row["type"],
                "verdict": row["verdict"],
                "malicious_sources": row["malicious_sources"],
                "total_sources": row["total_sources"],
                "tags": "|".join(row.get("tags") or []),
            }
            for src, data in row["per_source"].items():
                for field in ("malicious", "score", "detections", "total_engines", "country", "error"):
                    flat[f"{src}_{field}"] = data.get(field, "")
            writer.writerow(flat)
    return path


def export_json(summary: list[dict], output_name: str) -> str:
    path = f"{output_name}.json"
    _ensure_dir(path)
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total": len(summary),
        "results": summary,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def export_txt(summary: list[dict], output_name: str) -> dict[str, str]:
    """Genera tres archivos .txt separados: maliciosos, sospechosos, limpios."""
    groups = {"malicioso": [], "sospechoso": [], "limpio": []}
    for row in summary:
        groups[row["verdict"]].append(row["ioc"])

    paths = {}
    for verdict, iocs in groups.items():
        if not iocs:
            continue
        path = f"{output_name}_{verdict}.txt"
        _ensure_dir(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(iocs) + "\n")
        paths[verdict] = path
    return paths
