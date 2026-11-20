import json
from pathlib import Path

import pytest

from src.loader import IAMExport, IAMRifleLoadError, load_export


SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_iam_export.json"


def test_load_sample_export():
    """Carga la exportación de ejemplo y valida el número de usuarios y políticas."""
    export = load_export(SAMPLE_PATH)

    assert isinstance(export, IAMExport)
    assert len(export.users) == 14
    assert len(export.policies) == 22


def test_load_invalid_json(tmp_path):
    """Un fichero con JSON malformado debe provocar IAMRifleLoadError."""
    bad_file = tmp_path / "invalid.json"
    bad_file.write_text("{ esto no es json valido ,,, }", encoding="utf-8")

    with pytest.raises(IAMRifleLoadError):
        load_export(bad_file)


def test_load_missing_file(tmp_path):
    """Un path inexistente debe provocar IAMRifleLoadError."""
    missing = tmp_path / "no_existe.json"

    with pytest.raises(IAMRifleLoadError):
        load_export(missing)


def test_user_model_fields():
    """El modelo de usuario expone user_name, access_keys y mfa_devices."""
    export = load_export(SAMPLE_PATH)
    user = export.users[0]

    assert hasattr(user, "user_name")
    assert hasattr(user, "access_keys")
    assert hasattr(user, "mfa_devices")
    assert isinstance(user.user_name, str) and user.user_name


def test_policy_model_fields():
    """La primera política debe contener al menos un statement parseado."""
    export = load_export(SAMPLE_PATH)
    policy = export.policies[0]

    assert hasattr(policy, "statements")
    assert len(policy.statements) >= 1
    assert hasattr(policy.statements[0], "action")
    assert hasattr(policy.statements[0], "resource")
