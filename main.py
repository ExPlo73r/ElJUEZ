#!/usr/bin/env python3
"""
ElJuezPY - Herramienta de reputación de IOCs (IPs, dominios, hashes, URLs)
Consulta múltiples APIs gratuitas y genera reportes consolidados.
"""

import asyncio
import argparse
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_banner():
    from banner import show_banner
    show_banner()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eljuez",
        description="Consulta IOCs contra múltiples APIs de reputación gratuitas.",
    )
    p.add_argument("input", help="Archivo con IOCs (uno por línea)")
    p.add_argument("-o", "--output", required=True,
                   help="Nombre base para los archivos de salida (ej: reporte_2024)")
    p.add_argument("--apis", nargs="*",
                   choices=["virustotal", "abuseipdb", "alienvault", "urlhaus", "malwarebazaar", "threatfox"],
                   help="APIs a usar (por defecto todas)")
    p.add_argument("--format", nargs="*", default=["csv", "json", "txt"],
                   choices=["csv", "json", "txt"],
                   help="Formatos de salida (por defecto: csv json txt)")
    p.add_argument("--no-banner", action="store_true", help="Omitir banner")
    return p


def print_summary_table(summary: list[dict]):
    table = Table(
        title="Resumen de resultados",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold magenta",
    )
    table.add_column("IOC", style="white", max_width=45)
    table.add_column("Tipo", style="cyan", justify="center")
    table.add_column("Veredicto", justify="center")
    table.add_column("Fuentes malic.", justify="center")
    table.add_column("Tags", style="dim", max_width=35)

    VERDICT_STYLE = {
        "malicioso": "[bold red]MALICIOSO[/bold red]",
        "sospechoso": "[bold yellow]SOSPECHOSO[/bold yellow]",
        "limpio": "[bold green]LIMPIO[/bold green]",
    }

    for row in summary:
        tags_str = ", ".join((row.get("tags") or [])[:5])
        table.add_row(
            row["ioc"],
            row["type"],
            VERDICT_STYLE.get(row["verdict"], row["verdict"]),
            f"{row['malicious_sources']}/{row['total_sources']}",
            tags_str,
        )
    console.print(table)


def check_env():
    missing = []
    from config import VIRUSTOTAL_KEY, ABUSEIPDB_KEY
    if not VIRUSTOTAL_KEY:
        missing.append("VIRUSTOTAL_KEY")
    if not ABUSEIPDB_KEY:
        missing.append("ABUSEIPDB_KEY")
    if missing:
        console.print(
            f"[yellow]Advertencia:[/yellow] Las siguientes API keys no están configuradas "
            f"en .env y serán omitidas: {', '.join(missing)}"
        )


async def run(args):
    from detector import load_iocs
    from processor import process_iocs, summarize
    from exporter import export_csv, export_json, export_txt

    if not os.path.isfile(args.input):
        console.print(f"[red]Error:[/red] Archivo no encontrado: {args.input}")
        sys.exit(1)

    check_env()

    iocs = load_iocs(args.input)
    if not iocs:
        console.print("[red]Error:[/red] El archivo está vacío o no contiene IOCs válidos.")
        sys.exit(1)

    # Estadísticas de entrada
    from collections import Counter
    type_counts = Counter(i["type"] for i in iocs)
    console.print(f"\n[bold]IOCs cargados:[/bold] {len(iocs)}")
    for t, c in type_counts.items():
        color = "red" if t == "unknown" else "cyan"
        console.print(f"  [{color}]{t}[/{color}]: {c}")

    unknown = [i for i in iocs if i["type"] == "unknown"]
    if unknown:
        console.print(f"[yellow]  {len(unknown)} IOC(s) no reconocidos serán ignorados.[/yellow]")

    console.print()
    results = await process_iocs(iocs, selected_apis=args.apis)

    if not results:
        console.print("[red]No se obtuvieron resultados. Verifica tus API keys.[/red]")
        sys.exit(1)

    summary = summarize(results)

    print_summary_table(summary)

    generated = []
    fmt = args.format

    if "csv" in fmt:
        path = export_csv(summary, args.output)
        generated.append(f"  CSV  → {path}")
    if "json" in fmt:
        path = export_json(summary, args.output)
        generated.append(f"  JSON → {path}")
    if "txt" in fmt:
        paths = export_txt(summary, args.output)
        for verdict, path in paths.items():
            generated.append(f"  TXT  → {path}  [{verdict}]")

    console.print("\n[bold green]Archivos generados:[/bold green]")
    for g in generated:
        console.print(g)
    console.print()


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
