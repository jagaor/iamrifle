import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from pydantic import BaseModel, Field, ValidationError, field_validator


class IAMRifleLoadError(Exception):
    """Error lanzado cuando la carga o validación del export IAM falla."""


class AccessKey(BaseModel):
    """Clave de acceso de un usuario IAM."""

    key_id: str
    created_date: datetime
    status: str


class MFADevice(BaseModel):
    """Dispositivo MFA asociado a un usuario IAM."""

    serial_number: str
    enable_date: datetime


class IAMUser(BaseModel):
    """Usuario IAM con sus credenciales y políticas asociadas."""

    user_name: str
    user_id: str
    arn: str
    create_date: datetime
    password_last_used: Optional[datetime] = None
    mfa_devices: List[MFADevice] = Field(default_factory=list)
    access_keys: List[AccessKey] = Field(default_factory=list)
    attached_policies: List[str] = Field(default_factory=list)
    inline_policies: List[dict] = Field(default_factory=list)


class PolicyStatement(BaseModel):
    """Sentencia individual de una política IAM."""

    effect: str
    action: Union[str, List[str]]
    resource: Union[str, List[str]]

    @field_validator("effect")
    @classmethod
    def efecto_valido(cls, v: str) -> str:
        """Valida que el efecto sea Allow o Deny."""
        if v not in ("Allow", "Deny"):
            raise ValueError(f"Efecto no válido: {v}. Debe ser 'Allow' o 'Deny'.")
        return v


class IAMPolicy(BaseModel):
    """Política IAM compuesta por una o varias sentencias."""

    policy_name: str
    policy_id: str
    arn: str
    statements: List[PolicyStatement]


class IAMExport(BaseModel):
    """Export completo de IAM con usuarios y políticas."""

    users: List[IAMUser] = Field(default_factory=list)
    policies: List[IAMPolicy] = Field(default_factory=list)
    exported_at: datetime


def load_export(path: Path) -> IAMExport:
    """Carga y valida un fichero JSON de export IAM.

    Args:
        path: Ruta al fichero JSON de export.

    Returns:
        Instancia de IAMExport con los datos validados.

    Raises:
        IAMRifleLoadError: Si el fichero no existe, no es JSON válido o no
            cumple el esquema esperado.
    """
    ruta = Path(path)
    if not ruta.is_file():
        raise IAMRifleLoadError(f"El fichero no existe o no es accesible: {ruta}")

    try:
        contenido = ruta.read_text(encoding="utf-8")
    except OSError as exc:
        raise IAMRifleLoadError(f"No se pudo leer el fichero {ruta}: {exc}") from exc

    try:
        json.loads(contenido)
    except json.JSONDecodeError as exc:
        raise IAMRifleLoadError(f"JSON inválido en {ruta}: {exc}") from exc

    try:
        return IAMExport.model_validate_json(contenido)
    except ValidationError as exc:
        raise IAMRifleLoadError(
            f"El export IAM no cumple el esquema esperado: {exc}"
        ) from exc
