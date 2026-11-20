import random
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


class MockIAMBuilder:
    """Genera exportaciones IAM sintéticas realistas para pruebas y demos."""

    @staticmethod
    def generate(seed: int = 42, num_users: int = 14, num_policies: int = 22) -> dict:
        """Construye un diccionario compatible con el esquema IAMExport de loader.py.

        Args:
            seed: Semilla para reproducibilidad.
            num_users: Número de usuarios a generar.
            num_policies: Número de políticas a generar.

        Returns:
            Diccionario con las claves 'exported_at', 'users' y 'policies'.
        """
        random.seed(seed)
        now = datetime.now(timezone.utc)

        # Nombres ficticios de usuario (sin empresas reales)
        first_names = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan", "judy", "mallory", "oscar", "peggy", "trent"]
        last_names = ["johnson", "smith", "garcia", "lee", "patel", "kim", "muller", "rossi", "tanaka", "dubois", "silva", "novak", "haddad", "olsen"]
        service_prefixes = ["svc-deploy", "svc-backup", "svc-monitor", "svc-ci", "svc-data", "svc-proxy", "svc-cache", "svc-queue"]

        users = []
        for i in range(num_users):
            # Alternar entre usuarios humanos y de servicio
            if i % 3 == 0:
                username = f"{random.choice(service_prefixes)}-{random.choice(['prod', 'staging', 'dev', 'test'])}"
            else:
                username = f"{random.choice(first_names)}.{random.choice(last_names)}"

            # Access keys: 0 a 2 claves por usuario con antigüedad aleatoria
            num_keys = random.choices([0, 1, 2], weights=[0.2, 0.6, 0.2])[0]
            access_keys = []
            for _ in range(num_keys):
                days_ago = random.randint(1, 400)
                created = (now - timedelta(days=days_ago)).isoformat()
                access_keys.append({
                    "access_key_id": f"AKIA{random.randrange(16**16):016X}",
                    "status": random.choice(["Active", "Active", "Inactive"]),
                    "create_date": created,
                })

            # MFA: algunos usuarios sin MFA (especialmente servicios)
            has_mfa = random.random() > 0.35 if i % 3 != 0 else random.random() > 0.7
            mfa_devices = []
            if has_mfa:
                mfa_devices.append({
                    "serial_number": f"arn:aws:iam::123456789012:mfa/{username}",
                    "enable_date": (now - timedelta(days=random.randint(1, 300))).isoformat(),
                })

            # Último login (puede ser None)
            last_login = None
            if random.random() > 0.4:
                last_login = (now - timedelta(days=random.randint(0, 200))).isoformat()

            users.append({
                "username": username,
                "user_id": str(uuid.uuid4()),
                "arn": f"arn:aws:iam::123456789012:user/{username}",
                "create_date": (now - timedelta(days=random.randint(10, 800))).isoformat(),
                "mfa_devices": mfa_devices,
                "access_keys": access_keys,
                "last_login": last_login,
                "attached_policies": [],  # Se rellenará después
            })

        # Políticas
        policies = []
        for i in range(num_policies):
            policy_name = f"Policy-{i:03d}-{random.choice(['ReadOnly', 'Admin', 'S3', 'EC2', 'Lambda', 'Custom'])}"
            statements = []

            # Aseguramos al menos una política con Action:* y Resource:*
            if i == 0:
                statements.append({
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                })
            elif i in (1, 2):
                # Políticas con comodines en servicios específicos
                service = random.choice(["s3", "ec2"])
                statements.append({
                    "Effect": "Allow",
                    "Action": f"{service}:*",
                    "Resource": "*",
                })
            else:
                # Políticas acotadas
                actions = random.sample([
                    "s3:GetObject", "s3:PutObject", "s3:ListBucket",
                    "ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances",
                    "lambda:InvokeFunction", "dynamodb:GetItem", "dynamodb:PutItem",
                    "sqs:SendMessage", "sns:Publish", "logs:CreateLogGroup",
                ], k=random.randint(1, 3))
                resources = random.sample([
                    "arn:aws:s3:::my-bucket/*",
                    "arn:aws:ec2:us-east-1:123456789012:instance/*",
                    "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                    "arn:aws:dynamodb:us-east-1:123456789012:table/my-table",
                    "arn:aws:sqs:us-east-1:123456789012:my-queue",
                ], k=random.randint(1, 2))
                statements.append({
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": resources,
                })

            policies.append({
                "policy_name": policy_name,
                "policy_id": str(uuid.uuid4()),
                "arn": f"arn:aws:iam::123456789012:policy/{policy_name}",
                "create_date": (now - timedelta(days=random.randint(1, 500))).isoformat(),
                "document": {
                    "Version": "2012-10-17",
                    "Statement": statements,
                },
            })

        # Asignar políticas a usuarios de forma aleatoria (al menos una por usuario)
        for user in users:
            num_attached = random.randint(1, min(3, len(policies)))
            user["attached_policies"] = random.sample([p["policy_name"] for p in policies], k=num_attached)

        return {
            "exported_at": now.isoformat(),
            "users": users,
            "policies": policies,
        }


def build_and_save(output_path: Path, seed: int = 42) -> None:
    """Genera datos mock y los escribe en un fichero JSON con indentación."""
    data = MockIAMBuilder.generate(seed=seed)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
