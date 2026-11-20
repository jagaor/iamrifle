import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from src.auditors import Finding, Severity


class RichReporter:
    """Reporter que imprime hallazgos en terminal usando rich."""

    def __init__(self) -> None:
        self.console = Console()

    def report(self, findings: List[Finding]) -> None:
        """Renderiza una tabla con los hallazgos y un panel de resumen."""
        table = Table(title="IAMRifle - Hallazgos de auditoría")
        table.add_column("ID", style="dim")
        table.add_column("Severidad")
        table.add_column("Recurso")
        table.add_column("Título")
        table.add_column("Detalle")

        # Mapa de colores por severidad
        color_map = {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
        }

        for f in findings:
            sev_text = Text(f.severity.value, style=color_map.get(f.severity, "white"))
            table.add_row(
                f.id,
                sev_text,
                f.resource,
                f.title,
                f.detail,
            )

        self.console.print(table)

        # Contadores por severidad
        counts: Dict[Severity, int] = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        resumen = "\n".join(
            f"{s.value}: {counts[s]}" for s in Severity
        )
        self.console.print(Panel(resumen, title="Resumen por severidad", expand=False))


class JSONReporter:
    """Reporter que serializa los hallazgos a un fichero JSON."""

    def report(self, findings: List[Finding], output_path: Path, meta: dict) -> None:
        """Escribe los hallazgos y metadatos en un fichero JSON."""
        # Convertir hallazgos a dicts serializables
        findings_dicts = []
        for f in findings:
            d = asdict(f)
            # Convertir enums y fechas a strings
            d["severity"] = f.severity.value
            if isinstance(d.get("detected_at"), datetime):
                d["detected_at"] = d["detected_at"].isoformat()
            findings_dicts.append(d)

        # Metadatos obligatorios
        meta_completa = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "iamrifle_version": "1.0.0",
            "total_findings": len(findings),
            "max_key_age_days": meta.get("max_key_age_days", 90),
        }
        # Incluir cualquier otro metadato adicional
        for key, value in meta.items():
            if key not in meta_completa:
                meta_completa[key] = value

        output = {
            "meta": meta_completa,
            "findings": findings_dicts,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2, ensure_ascii=False)
