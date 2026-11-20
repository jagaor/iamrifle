import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from src.loader import JSONLoader
from src.auditors import WildcardAuditor, MFAAuditor, StaleKeyAuditor, FindingAggregator
from src.reporters import RichReporter, JSONReporter
from src.mock_builder import MockIAMBuilder

# Versión del proyecto
VERSION = "1.0.0"

# Consola rich compartida por toda la CLI
console = Console()

# Aplicación typer con metadatos de ayuda
app = typer.Typer(
    name="iamrifle",
    help="Audita permisos IAM en AWS desde un JSON exportado.",
    add_completion=False,
)


def _print_banner() -> None:
    """Muestra el banner de bienvenida al inicio de la ejecución."""
    console.print(f"[bold cyan]IAMRifle v{VERSION}[/bold cyan]", justify="left")
    console.print("[dim]Auditoría de permisos IAM en AWS[/dim]", justify="left")


@app.command("audit")
def audit(
    input: Path = typer.Option(
        ...,
        "--input",
        "-i",
        help="Ruta al fichero JSON con la exportación IAM.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("report.json"),
        "--output",
        "-o",
        help="Ruta donde se guardará el informe JSON.",
    ),
    max_key_age: int = typer.Option(
        90,
        "--max-key-age",
        help="Antigüedad máxima (en días) permitida para access keys.",
        min=1,
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Formato de salida por consola: 'table' o 'json'.",
    ),
) -> None:
    """Ejecuta la auditoría completa sobre un fichero de exportación IAM."""
    _print_banner()

    # Validación temprana del formato solicitado
    formato = format.lower().strip()
    if formato not in ("table", "json"):
        console.print(f"[bold red]Error:[/bold red] formato '{format}' no soportado. Usa 'table' o 'json'.")
        raise typer.Exit(code=2)

    # 1. Cargar y validar el JSON de entrada
    console.print(f"[cyan]Cargando exportación IAM desde:[/cyan] {input}")
    try:
        loader = JSONLoader(input)
        export = loader.load()
    except Exception as exc:  # noqa: BLE001 - mostramos cualquier error de carga
        console.print(f"[bold red]Error al cargar el JSON:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # 2. Ejecutar los tres auditores en orden
    console.print("[cyan]Ejecutando auditores...[/cyan]")
    findings = []
    findings.extend(WildcardAuditor(export).run())
    findings.extend(MFAAuditor(export).run())
    findings.extend(StaleKeyAuditor(export, max_key_age_days=max_key_age).run())

    # 3. Consolidar, deduplicar y ordenar por severidad
    aggregator = FindingAggregator()
    consolidated = aggregator.aggregate(findings)

    # 4. Renderizar por consola según el formato elegido
    if formato == "table":
        RichReporter(console).report(consolidated)
    else:
        # Volcado JSON a stdout para integraciones
        json.dump([f.model_dump() for f in consolidated], sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")

    # 5. Guardar siempre el informe JSON en disco
    metadata = {
        "tool": "IAMRifle",
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "max_key_age_days": max_key_age,
        "input_file": str(input),
        "total_findings": len(consolidated),
    }
    try:
        JSONReporter(output).report(consolidated, metadata=metadata)
        console.print(f"[green]Informe guardado en:[/green] {output}")
    except OSError as exc:
        console.print(f"[bold red]Error al guardar el informe:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command("mock-generate")
def mock_generate(
    output: Path = typer.Option(
        Path("data/sample_iam_export.json"),
        "--output",
        "-o",
        help="Ruta donde se guardará la exportación IAM sintética.",
    ),
    seed: int = typer.Option(
        42,
        "--seed",
        help="Semilla para la generación determinista de datos mock.",
    ),
) -> None:
    """Genera una exportación IAM sintética para probar sin cuenta AWS."""
    _print_banner()
    console.print(f"[cyan]Generando exportación mock (seed={seed})...[/cyan]")

    try:
        builder = MockIAMBuilder(seed=seed)
        data = builder.generate()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Error generando datos mock:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # Aseguramos que el directorio destino existe
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        console.print(f"[bold red]Error al escribir el fichero:[/bold red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]Exportación mock guardada en:[/green] {output}")


@app.command("version")
def version() -> None:
    """Muestra la versión actual de IAMRifle."""
    console.print(f"IAMRifle v{VERSION}")


if __name__ == "__main__":
    app()
