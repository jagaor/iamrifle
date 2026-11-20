import pytest
from datetime import datetime, timedelta, timezone
from src.loader import IAMExport, IAMUser, IAMPolicy, IAMAccessKey, IAMStatement
from src.auditors import WildcardAuditor, MFAAuditor, StaleKeyAuditor, FindingAggregator, Severity


@pytest.fixture
def minimal_export() -> IAMExport:
    """Exportación IAM mínima con dos usuarios y tres políticas."""
    now = datetime.now(timezone.utc)
    # Usuario 1: sin MFA, con clave antigua
    user1 = IAMUser(
        name="alice",
        arn="arn:aws:iam::123456789012:user/alice",
        create_date=now - timedelta(days=300),
        mfa_devices=[],
        access_keys=[
            IAMAccessKey(
                access_key_id="AKIAALICEOLD",
                create_date=now - timedelta(days=200),
                status="Active"
            )
        ],
        inline_policies=[],
        attached_policies=[]
    )
    # Usuario 2: con MFA, clave reciente
    user2 = IAMUser(
        name="bob",
        arn="arn:aws:iam::123456789012:user/bob",
        create_date=now - timedelta(days=100),
        mfa_devices=["arn:aws:iam::123456789012:mfa/bob"],
        access_keys=[
            IAMAccessKey(
                access_key_id="AKIABOBNEW",
                create_date=now - timedelta(days=10),
                status="Active"
            )
        ],
        inline_policies=[],
        attached_policies=[]
    )
    # Política con comodines peligrosos
    wildcard_policy = IAMPolicy(
        name="WildcardPolicy",
        arn="arn:aws:iam::123456789012:policy/WildcardPolicy",
        statements=[
            IAMStatement(
                effect="Allow",
                action=["*"],
                resource=["*"]
            )
        ]
    )
    # Política segura
    safe_policy = IAMPolicy(
        name="SafePolicy",
        arn="arn:aws:iam::123456789012:policy/SafePolicy",
        statements=[
            IAMStatement(
                effect="Allow",
                action=["s3:GetObject"],
                resource=["arn:aws:s3:::mybucket/*"]
            )
        ]
    )
    # Política con comodín solo en acción
    action_wildcard_policy = IAMPolicy(
        name="ActionWildcard",
        arn="arn:aws:iam::123456789012:policy/ActionWildcard",
        statements=[
            IAMStatement(
                effect="Allow",
                action=["s3:*"],
                resource=["arn:aws:s3:::mybucket"]
            )
        ]
    )
    return IAMExport(
        users=[user1, user2],
        policies=[wildcard_policy, safe_policy, action_wildcard_policy],
        roles=[]
    )


@pytest.fixture
def wildcard_policy() -> IAMPolicy:
    """Política con statement action='*', resource='*'."""
    return IAMPolicy(
        name="FullWildcard",
        arn="arn:aws:iam::123456789012:policy/FullWildcard",
        statements=[
            IAMStatement(
                effect="Allow",
                action=["*"],
                resource=["*"]
            )
        ]
    )


def test_wildcard_critical(wildcard_policy):
    """WildcardAuditor debe detectar comodines peligrosos como CRITICAL con rule_id WILD-001."""
    auditor = WildcardAuditor()
    findings = auditor.audit([wildcard_policy])
    assert len(findings) >= 1
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1
    assert any(f.rule_id == "WILD-001" for f in critical_findings)


def test_mfa_missing(minimal_export):
    """MFAAuditor debe detectar usuario sin MFA como HIGH con rule_id MFA-001."""
    auditor = MFAAuditor()
    findings = auditor.audit(minimal_export.users)
    assert len(findings) >= 1
    alice_findings = [f for f in findings if f.resource_name == "alice"]
    assert len(alice_findings) == 1
    assert alice_findings[0].severity == Severity.HIGH
    assert alice_findings[0].rule_id == "MFA-001"
    # Bob tiene MFA, no debe aparecer
    bob_findings = [f for f in findings if f.resource_name == "bob"]
    assert len(bob_findings) == 0


def test_stale_key(minimal_export):
    """StaleKeyAuditor con max_age_days=90 debe detectar clave de 200 días como HIGH con rule_id KEY-001."""
    auditor = StaleKeyAuditor(max_age_days=90)
    findings = auditor.audit(minimal_export.users)
    assert len(findings) >= 1
    alice_key_findings = [f for f in findings if f.resource_name == "alice"]
    assert len(alice_key_findings) == 1
    assert alice_key_findings[0].severity == Severity.HIGH
    assert alice_key_findings[0].rule_id == "KEY-001"
    # Bob tiene clave reciente, no debe aparecer
    bob_key_findings = [f for f in findings if f.resource_name == "bob"]
    assert len(bob_key_findings) == 0


def test_no_stale_key(minimal_export):
    """Clave creada hace 10 días no debe generar findings con umbral de 90 días."""
    auditor = StaleKeyAuditor(max_age_days=90)
    findings = auditor.audit(minimal_export.users)
    # Solo alice tiene clave antigua, bob no debe aparecer
    bob_findings = [f for f in findings if f.resource_name == "bob"]
    assert len(bob_findings) == 0
    # Verificar que el hallazgo de alice es por la clave antigua
    alice_findings = [f for f in findings if f.resource_name == "alice"]
    assert len(alice_findings) == 1
    assert alice_findings[0].rule_id == "KEY-001"


def test_aggregator_dedup():
    """El agregador debe deduplicar findings por (rule_id, resource_name)."""
    from src.auditors import Finding
    f1 = Finding(
        rule_id="WILD-001",
        resource_name="policy1",
        severity=Severity.CRITICAL,
        message="Wildcard detectado"
    )
    f2 = Finding(
        rule_id="WILD-001",
        resource_name="policy1",
        severity=Severity.CRITICAL,
        message="Wildcard detectado (duplicado)"
    )
    f3 = Finding(
        rule_id="MFA-001",
        resource_name="user1",
        severity=Severity.HIGH,
        message="Sin MFA"
    )
    aggregator = FindingAggregator()
    result = aggregator.aggregate([f1, f2, f3])
    assert len(result) == 2
    # Verificar que se mantiene uno de los duplicados
    wildcard_findings = [f for f in result if f.rule_id == "WILD-001"]
    assert len(wildcard_findings) == 1


def test_aggregator_order():
    """El agregador debe ordenar findings de mayor a menor severidad."""
    from src.auditors import Finding
    f_low = Finding(
        rule_id="LOW-001",
        resource_name="res1",
        severity=Severity.LOW,
        message="Bajo"
    )
    f_critical = Finding(
        rule_id="CRIT-001",
        resource_name="res2",
        severity=Severity.CRITICAL,
        message="Crítico"
    )
    f_medium = Finding(
        rule_id="MED-001",
        resource_name="res3",
        severity=Severity.MEDIUM,
        message="Medio"
    )
    f_high = Finding(
        rule_id="HIGH-001",
        resource_name="res4",
        severity=Severity.HIGH,
        message="Alto"
    )
    aggregator = FindingAggregator()
    result = aggregator.aggregate([f_low, f_critical, f_medium, f_high])
    assert len(result) == 4
    assert result[0].severity == Severity.CRITICAL
    assert result[1].severity == Severity.HIGH
    assert result[2].severity == Severity.MEDIUM
    assert result[3].severity == Severity.LOW