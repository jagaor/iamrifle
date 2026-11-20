from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from enum import IntEnum
from typing import Literal, List

from src.loader import IAMExport


class Severity(IntEnum):
    """Niveles de severidad ordenables de menor a mayor gravedad."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    """Hallazgo estandarizado emitido por cualquier auditor."""

    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_name: str
    detail: str
    mitre_technique: str


class WildcardAuditor:
    """Detecta comodines peligrosos en los Statements de las políticas."""

    def audit(self, export: IAMExport) -> List[Finding]:
        findings: List[Finding] = []
        for policy in export.policies:
            for statement in policy.statements:
                actions = statement.actions
                resources = statement.resources
                action_wild = any("*" in a for a in actions)
                resource_wild = any(r == "*" for r in resources)
                if not action_wild and not resource_wild:
                    continue

                if action_wild and resource_wild:
                    findings.append(
                        Finding(
                            rule_id="WILD-001",
                            title="Acción y recurso comodín en la misma política",
                            severity=Severity.CRITICAL,
                            resource_type="policy",
                            resource_name=policy.name,
                            detail=(
                                f"La política '{policy.name}' combina Action con comodín "
                                f"({', '.join(actions)}) y Resource '*'."
                            ),
                            mitre_technique="T1078.004",
                        )
                    )
                elif any(a.endswith(":*") for a in actions) and resource_wild:
                    findings.append(
                        Finding(
                            rule_id="WILD-002",
                            title="Servicio completo con comodín sobre todos los recursos",
                            severity=Severity.HIGH,
                            resource_type="policy",
                            resource_name=policy.name,
                            detail=(
                                f"La política '{policy.name}' concede todos los permisos de "
                                f"servicio ({', '.join(actions)}) sobre Resource '*'."
                            ),
                            mitre_technique="T1078.004",
                        )
                    )
                elif resource_wild:
                    findings.append(
                        Finding(
                            rule_id="WILD-003",
                            title="Recurso comodín con acciones acotadas",
                            severity=Severity.MEDIUM,
                            resource_type="policy",
                            resource_name=policy.name,
                            detail=(
                                f"La política '{policy.name}' aplica acciones acotadas sobre "
                                f"Resource '*', ampliando el alcance efectivo."
                            ),
                            mitre_technique="T1078.004",
                        )
                    )
        return findings


class MFAAuditor:
    """Detecta usuarios IAM sin dispositivos MFA activos."""

    def audit(self, export: IAMExport) -> List[Finding]:
        findings: List[Finding] = []
        for user in export.users:
            if user.mfa_devices:
                continue
            last_login = (
                user.last_login.strftime("%Y-%m-%d %H:%M UTC")
                if user.last_login
                else "nunca registrado"
            )
            findings.append(
                Finding(
                    rule_id="MFA-001",
                    title="Usuario sin MFA habilitado",
                    severity=Severity.HIGH,
                    resource_type="user",
                    resource_name=user.name,
                    detail=(
                        f"El usuario '{user.name}' no tiene dispositivos MFA. "
                        f"Último login: {last_login}."
                    ),
                    mitre_technique="T1098",
                )
            )
        return findings


class StaleKeyAuditor:
    """Detecta access keys activas que superan el umbral de antigüedad."""

    def audit(self, export: IAMExport, max_age_days: int = 90) -> List[Finding]:
        findings: List[Finding] = []
        now = datetime.now(UTC)
        for user in export.users:
            for key in user.access_keys:
                if key.status != "Active":
                    continue
                created = key.created_date
                if created.tzinfo is None:
                    created = created.replace(tzinfo=UTC)
                age_days = (now - created).days
                if age_days <= max_age_days:
                    continue
                findings.append(
                    Finding(
                        rule_id="KEY-001",
                        title="Access key activa demasiado antigua",
                        severity=Severity.HIGH,
                        resource_type="access_key",
                        resource_name=f"{user.name}/{key.access_key_id}",
                        detail=(
                            f"La access key '{key.access_key_id}' del usuario "
                            f"'{user.name}' tiene {age_days} días de antigüedad "
                            f"(umbral: {max_age_days})."
                        ),
                        mitre_technique="T1552.005",
                    )
                )
        return findings


class FindingAggregator:
    """Consolida, deduplica y ordena los hallazgos de todos los auditores."""

    def aggregate(self, findings: List[Finding]) -> List[Finding]:
        unique: dict[tuple[str, str], Finding] = {}
        for finding in findings:
            key = (finding.rule_id, finding.resource_name)
            existing = unique.get(key)
            if existing is None or finding.severity > existing.severity:
                unique[key] = finding
        ordered = sorted(
            unique.values(),
            key=lambda f: (int(f.severity), f.rule_id, f.resource_name),
            reverse=True,
        )
        return ordered
