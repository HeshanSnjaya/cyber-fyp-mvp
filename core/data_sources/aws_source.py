"""Live AWS data source.

Enumerates real EC2 instances, IAM roles/policies and S3 buckets using boto3 and
normalizes them into the shared schema. Credentials are always passed
**explicitly** to the boto3 Session, so the ambient credential chain
(environment variables, ~/.aws) is bypassed by design.

Read-only APIs used (a read-only policy such as ``SecurityAudit`` or
``ReadOnlyAccess`` is sufficient):

* EC2:  DescribeInstances, DescribeSecurityGroups
* IAM:  ListRoles, ListAttachedRolePolicies, ListRolePolicies,
        GetPolicy, GetPolicyVersion, GetRolePolicy
* S3:   ListBuckets, GetBucketLocation, GetBucketEncryption,
        GetPublicAccessBlock, GetBucketPolicyStatus
* STS:  GetCallerIdentity (connection test)

Every call is defensively wrapped: partial permissions degrade gracefully into
"unknown" fields rather than crashing the scan.
"""

from __future__ import annotations

import fnmatch

from .base import DataSource, DataSourceError

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

    _HAS_BOTO3 = True
except Exception:  # pragma: no cover
    _HAS_BOTO3 = False


# Substrings that suggest a bucket holds sensitive data (used as one heuristic
# signal among several).
_SENSITIVE_KEYWORDS = [
    "customer", "pii", "personal", "user", "backup", "db", "database",
    "secret", "credential", "private", "confidential", "finance", "payment",
    "card", "invoice", "health", "medical", "prod", "production",
]

# Managed policy ARNs that grant broad/administrative access.
_ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


class AWSDataSource(DataSource):
    name = "aws"
    label = "Live AWS Account"

    def __init__(
        self,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        region="us-east-1",
        aws_session_token=None,
        **_ignored,
    ):
        if not _HAS_BOTO3:
            raise DataSourceError(
                "boto3 is not installed. Run: pip install boto3"
            )
        if not aws_access_key_id or not aws_secret_access_key:
            raise DataSourceError(
                "AWS access key and secret are required for live mode."
            )
        self.region = region or "us-east-1"
        # Build a session with EXPLICIT credentials only.
        self._session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token or None,
            region_name=self.region,
        )
        self.account_id = None

    # ------------------------------------------------------------------ #
    # Connection test
    # ------------------------------------------------------------------ #
    def test_connection(self):
        """Verify credentials via STS. Returns (ok, message)."""
        try:
            sts = self._session.client("sts")
            ident = sts.get_caller_identity()
            self.account_id = ident.get("Account")
            return True, (
                f"Connected to AWS account {ident.get('Account')} "
                f"as {ident.get('Arn')}"
            )
        except (ClientError, BotoCoreError, NoCredentialsError) as exc:
            return False, f"Connection failed: {exc}"

    # ------------------------------------------------------------------ #
    # Main fetch
    # ------------------------------------------------------------------ #
    def fetch(self, progress=None):
        ok, message = self.test_connection()
        if not ok:
            raise DataSourceError(message)

        self._report(progress, 0.15, "Scanning S3 buckets")
        s3 = self._scan_s3()

        self._report(progress, 0.45, "Scanning IAM roles & policies")
        bucket_names = [b["id"] for b in s3]
        iam_roles = self._scan_iam(bucket_names)

        self._report(progress, 0.8, "Scanning EC2 instances")
        ec2 = self._scan_ec2()

        self._report(progress, 1.0, "AWS scan complete")
        return {"ec2": ec2, "iam_roles": iam_roles, "s3": s3}

    # ------------------------------------------------------------------ #
    # S3
    # ------------------------------------------------------------------ #
    def _scan_s3(self):
        client = self._session.client("s3")
        buckets = []
        try:
            resp = client.list_buckets()
        except (ClientError, BotoCoreError) as exc:
            raise DataSourceError(f"Unable to list S3 buckets: {exc}") from exc

        for b in resp.get("Buckets", []):
            name = b["Name"]
            encrypted = self._bucket_encrypted(client, name)
            public_blocked = self._bucket_public_blocked(client, name)
            public_policy = self._bucket_public_by_policy(client, name)
            region = self._bucket_region(client, name)
            sensitive = self._is_sensitive(name, encrypted, public_blocked, public_policy)
            buckets.append(
                {
                    "id": name,
                    "sensitive": sensitive,
                    "encrypted": encrypted,
                    "public_access_blocked": public_blocked,
                    "public_by_policy": public_policy,
                    "region": region,
                    "description": _s3_description(
                        name, encrypted, public_blocked, sensitive
                    ),
                    "source": "aws",
                }
            )
        return buckets

    def _bucket_encrypted(self, client, name):
        try:
            client.get_bucket_encryption(Bucket=name)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "ServerSideEncryptionConfigurationNotFoundError",
            ):
                return False
            return None  # unknown (access denied, etc.)
        except BotoCoreError:
            return None

    def _bucket_public_blocked(self, client, name):
        try:
            resp = client.get_public_access_block(Bucket=name)
            cfg = resp.get("PublicAccessBlockConfiguration", {})
            return all(
                cfg.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return False
            return None
        except BotoCoreError:
            return None

    def _bucket_public_by_policy(self, client, name):
        try:
            resp = client.get_bucket_policy_status(Bucket=name)
            return bool(resp.get("PolicyStatus", {}).get("IsPublic"))
        except ClientError:
            return False
        except BotoCoreError:
            return None

    def _bucket_region(self, client, name):
        try:
            resp = client.get_bucket_location(Bucket=name)
            return resp.get("LocationConstraint") or "us-east-1"
        except (ClientError, BotoCoreError):
            return self.region

    def _is_sensitive(self, name, encrypted, public_blocked, public_policy):
        lname = name.lower()
        keyword_hit = any(k in lname for k in _SENSITIVE_KEYWORDS)
        risky_posture = (encrypted is False) or (public_blocked is False) or public_policy
        # Flag as sensitive if the name suggests sensitive data, OR the bucket
        # has a risky posture (unencrypted / publicly reachable).
        return bool(keyword_hit or risky_posture)

    # ------------------------------------------------------------------ #
    # IAM
    # ------------------------------------------------------------------ #
    def _scan_iam(self, bucket_names):
        client = self._session.client("iam")
        roles = []
        try:
            paginator = client.get_paginator("list_roles")
            role_iter = paginator.paginate()
        except (ClientError, BotoCoreError) as exc:
            raise DataSourceError(f"Unable to list IAM roles: {exc}") from exc

        for page in role_iter:
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                # Skip AWS service-linked roles (not attacker-usable pivots).
                if role.get("Path", "/").startswith("/aws-service-role/"):
                    continue
                statements, is_admin = self._collect_role_statements(client, role_name)
                s3_access = self._resolve_s3_access(statements, bucket_names, is_admin)
                roles.append(
                    {
                        "id": role_name,
                        "s3_access": s3_access,
                        "admin": is_admin,
                        "description": (
                            f"IAM role granting access to {len(s3_access)} bucket(s)"
                            + (" [ADMIN]" if is_admin else "")
                        ),
                        "source": "aws",
                    }
                )
        return roles

    def _collect_role_statements(self, client, role_name):
        """Return (list_of_statements, is_admin) for a role's policies."""
        statements = []
        is_admin = False

        # Attached managed policies.
        try:
            attached = client.list_attached_role_policies(RoleName=role_name)
            for pol in attached.get("AttachedPolicies", []):
                arn = pol["PolicyArn"]
                if arn in _ADMIN_POLICY_ARNS:
                    is_admin = True
                statements.extend(self._managed_policy_statements(client, arn))
        except (ClientError, BotoCoreError):
            pass

        # Inline policies.
        try:
            inline = client.list_role_policies(RoleName=role_name)
            for pol_name in inline.get("PolicyNames", []):
                doc = client.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                statements.extend(_as_statements(doc.get("PolicyDocument", {})))
        except (ClientError, BotoCoreError):
            pass

        if _statements_grant_admin(statements):
            is_admin = True
        return statements, is_admin

    def _managed_policy_statements(self, client, arn):
        try:
            pol = client.get_policy(PolicyArn=arn)
            version = pol["Policy"]["DefaultVersionId"]
            doc = client.get_policy_version(PolicyArn=arn, VersionId=version)
            return _as_statements(doc["PolicyVersion"]["Document"])
        except (ClientError, BotoCoreError, KeyError):
            return []

    def _resolve_s3_access(self, statements, bucket_names, is_admin):
        """Determine which buckets a role can touch, from its policy statements."""
        if is_admin:
            return list(bucket_names)

        accessible = set()
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = _as_list(stmt.get("Action", []))
            if not _has_s3_read(actions):
                continue
            resources = _as_list(stmt.get("Resource", []))
            for res in resources:
                if res == "*":
                    accessible.update(bucket_names)
                    continue
                # arn:aws:s3:::bucket or arn:aws:s3:::bucket/*
                bucket = _bucket_from_arn(res)
                if bucket is None:
                    continue
                if "*" in bucket or "?" in bucket:
                    for name in bucket_names:
                        if fnmatch.fnmatch(name, bucket):
                            accessible.add(name)
                elif bucket in bucket_names:
                    accessible.add(bucket)
        return sorted(accessible)

    # ------------------------------------------------------------------ #
    # EC2
    # ------------------------------------------------------------------ #
    def _scan_ec2(self):
        client = self._session.client("ec2")
        instances = []
        try:
            open_sgs = self._open_security_groups(client)
            paginator = client.get_paginator("describe_instances")
            pages = paginator.paginate()
        except (ClientError, BotoCoreError) as exc:
            raise DataSourceError(f"Unable to describe EC2 instances: {exc}") from exc

        for page in pages:
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                        continue
                    instances.append(self._normalize_instance(inst, open_sgs))
        return instances

    def _open_security_groups(self, client):
        """Return the set of SG ids that allow inbound from 0.0.0.0/0 or ::/0."""
        open_ids = set()
        try:
            paginator = client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    for perm in sg.get("IpPermissions", []):
                        ranges = perm.get("IpRanges", [])
                        v6 = perm.get("Ipv6Ranges", [])
                        if any(r.get("CidrIp") == "0.0.0.0/0" for r in ranges) or any(
                            r.get("CidrIpv6") == "::/0" for r in v6
                        ):
                            open_ids.add(sg["GroupId"])
        except (ClientError, BotoCoreError):
            pass
        return open_ids

    def _normalize_instance(self, inst, open_sgs):
        instance_id = inst["InstanceId"]
        name = _tag(inst, "Name") or instance_id
        public_ip = inst.get("PublicIpAddress")
        sg_ids = {g["GroupId"] for g in inst.get("SecurityGroups", [])}
        has_open_sg = bool(sg_ids & open_sgs)
        public = bool(public_ip) and has_open_sg

        role_name = None
        profile = inst.get("IamInstanceProfile")
        if profile and profile.get("Arn"):
            # arn:aws:iam::acct:instance-profile/RoleName -> best-effort role name
            role_name = profile["Arn"].rsplit("/", 1)[-1]

        return {
            "id": name,
            "instance_id": instance_id,
            "public": public,
            "public_ip": public_ip,
            "iam_role": role_name,
            "region": self.region,
            "description": (
                f"EC2 instance {instance_id}"
                + (f" (public IP {public_ip}, open security group)" if public else " (private)")
            ),
            "source": "aws",
        }


# ---------------------------------------------------------------------- #
# Module-level helpers
# ---------------------------------------------------------------------- #
def _as_statements(document):
    if not document:
        return []
    stmt = document.get("Statement", [])
    return stmt if isinstance(stmt, list) else [stmt]


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _has_s3_read(actions):
    for a in actions:
        a = a.lower()
        if a in ("*", "s3:*") or a.startswith("s3:get") or a.startswith("s3:list") or a == "s3:*":
            return True
    return False


def _statements_grant_admin(statements):
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = [a.lower() for a in _as_list(stmt.get("Action", []))]
        resources = _as_list(stmt.get("Resource", []))
        if ("*" in actions or "s3:*" in actions) and "*" in resources:
            return True
    return False


def _bucket_from_arn(arn):
    if not isinstance(arn, str) or not arn.startswith("arn:aws:s3:::"):
        return None
    remainder = arn[len("arn:aws:s3:::"):]
    return remainder.split("/", 1)[0]


def _tag(inst, key):
    for tag in inst.get("Tags", []):
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _s3_description(name, encrypted, public_blocked, sensitive):
    bits = []
    bits.append("SENSITIVE" if sensitive else "standard")
    if encrypted is False:
        bits.append("unencrypted")
    elif encrypted is True:
        bits.append("encrypted")
    if public_blocked is False:
        bits.append("public access NOT fully blocked")
    return f"S3 bucket ({', '.join(bits)})"
