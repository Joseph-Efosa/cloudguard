"""AWS Connector — queries AWS APIs via boto3 for each GDPR control check."""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from cloudguard.models import CheckResult, ControlDefinition, Status

logger = logging.getLogger(__name__)


class AWSConnector:
    """Executes all AWS-side GDPR control checks using boto3."""

    def __init__(self, region: str = "eu-west-1"):
        self.region = region
        self._s3 = None
        self._iam = None
        self._cloudtrail = None
        self._rds = None
        self._kms = None
        self._ec2 = None
        self._config = None

    # ── lazy clients ──────────────────────────────────────────────────────────

    def _client(self, service: str):
        return boto3.client(service, region_name=self.region)

    @property
    def s3(self):
        if not self._s3:
            self._s3 = boto3.client("s3")
        return self._s3

    @property
    def iam(self):
        if not self._iam:
            self._iam = boto3.client("iam")
        return self._iam

    @property
    def cloudtrail(self):
        if not self._cloudtrail:
            self._cloudtrail = self._client("cloudtrail")
        return self._cloudtrail

    @property
    def rds(self):
        if not self._rds:
            self._rds = self._client("rds")
        return self._rds

    @property
    def kms(self):
        if not self._kms:
            self._kms = self._client("kms")
        return self._kms

    @property
    def ec2(self):
        if not self._ec2:
            self._ec2 = self._client("ec2")
        return self._ec2

    @property
    def config_svc(self):
        if not self._config:
            self._config = self._client("config")
        return self._config

    # ── dispatcher ────────────────────────────────────────────────────────────

    def run(self, control: ControlDefinition) -> CheckResult:
        handler = getattr(self, control.check, None)
        if handler is None:
            return self._error(control, f"No handler for check '{control.check}'")
        try:
            return handler(control)
        except NoCredentialsError:
            return self._error(control, "AWS credentials not configured")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            return self._error(control, f"AWS ClientError [{code}]: {exc.response['Error']['Message']}")
        except Exception as exc:  # noqa: BLE001
            return self._error(control, f"Unexpected error: {exc}")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _pass(self, ctrl: ControlDefinition, detail: str, raw: Any = None) -> CheckResult:
        return CheckResult(ctrl.id, ctrl.title, ctrl.article, ctrl.gdpr_clause,
                           ctrl.csp, ctrl.service, Status.PASS, detail, ctrl.remediation, raw)

    def _fail(self, ctrl: ControlDefinition, detail: str, raw: Any = None) -> CheckResult:
        return CheckResult(ctrl.id, ctrl.title, ctrl.article, ctrl.gdpr_clause,
                           ctrl.csp, ctrl.service, Status.FAIL, detail, ctrl.remediation, raw)

    def _error(self, ctrl: ControlDefinition, detail: str) -> CheckResult:
        return CheckResult(ctrl.id, ctrl.title, ctrl.article, ctrl.gdpr_clause,
                           ctrl.csp, ctrl.service, Status.ERROR, detail, ctrl.remediation)

    def _list_all_buckets(self) -> list[str]:
        resp = self.s3.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    # ── C-01: S3 default encryption ───────────────────────────────────────────

    def s3_encryption_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No S3 buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            try:
                self.s3.get_bucket_encryption(Bucket=bucket)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    failing.append(bucket)
                else:
                    raise

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) lack default encryption: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have default encryption enabled.")

    # ── C-02: S3 public access block ─────────────────────────────────────────

    def s3_public_access_blocked(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No S3 buckets found — control vacuously satisfied.")

        required_keys = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        failing = []
        for bucket in buckets:
            try:
                resp = self.s3.get_public_access_block(Bucket=bucket)
                cfg = resp["PublicAccessBlockConfiguration"]
                if not all(cfg.get(k, False) for k in required_keys):
                    failing.append(bucket)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    failing.append(bucket)
                else:
                    raise

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) do not fully block public access: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have all public access block settings enabled.")

    # ── C-03: CloudTrail multi-region ─────────────────────────────────────────

    def cloudtrail_multiregion_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.cloudtrail.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        if not trails:
            return self._fail(ctrl, "No CloudTrail trails found in this region.")

        multi_region_active = []
        for trail in trails:
            if trail.get("IsMultiRegionTrail"):
                status_resp = self.cloudtrail.get_trail_status(Name=trail["TrailARN"])
                if status_resp.get("IsLogging"):
                    multi_region_active.append(trail["Name"])

        if multi_region_active:
            return self._pass(ctrl, f"Multi-region active trail(s): {multi_region_active}")
        return self._fail(ctrl, "No active multi-region CloudTrail trail found.")

    # ── C-04: CloudTrail log file validation ──────────────────────────────────

    def cloudtrail_log_validation_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.cloudtrail.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        if not trails:
            return self._fail(ctrl, "No CloudTrail trails found.")

        failing = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
        if failing:
            return self._fail(ctrl, f"Trail(s) without log file validation: {failing}")
        return self._pass(ctrl, f"All {len(trails)} trail(s) have log file validation enabled.")

    # ── C-05: RDS storage encryption ──────────────────────────────────────────

    def rds_encryption_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        paginator = self.rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])

        if not instances:
            return self._pass(ctrl, "No RDS instances found — control vacuously satisfied.")

        failing = [i["DBInstanceIdentifier"] for i in instances if not i.get("StorageEncrypted")]
        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} RDS instance(s) not encrypted: {failing}")
        return self._pass(ctrl, f"All {len(instances)} RDS instance(s) have storage encryption enabled.")

    # ── C-06: KMS key rotation ────────────────────────────────────────────────

    def kms_key_rotation_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        paginator = self.kms.get_paginator("list_keys")
        all_keys = []
        for page in paginator.paginate():
            all_keys.extend(page["Keys"])

        customer_keys = []
        for key in all_keys:
            meta = self.kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                customer_keys.append(key["KeyId"])

        if not customer_keys:
            return self._pass(ctrl, "No customer-managed KMS keys found — control vacuously satisfied.")

        failing = []
        for key_id in customer_keys:
            resp = self.kms.get_key_rotation_status(KeyId=key_id)
            if not resp.get("KeyRotationEnabled"):
                failing.append(key_id)

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(customer_keys)} CMK(s) do not have rotation enabled: {failing}")
        return self._pass(ctrl, f"All {len(customer_keys)} customer-managed KMS key(s) have rotation enabled.")

    # ── C-07: IAM root MFA ────────────────────────────────────────────────────

    def iam_root_mfa_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        summary = self.iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 1:
            return self._pass(ctrl, "MFA is enabled on the AWS root account.")
        return self._fail(ctrl, "MFA is NOT enabled on the AWS root account.")

    # ── C-08: S3 versioning ───────────────────────────────────────────────────

    def s3_versioning_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No S3 buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            resp = self.s3.get_bucket_versioning(Bucket=bucket)
            if resp.get("Status") != "Enabled":
                failing.append(bucket)

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) do not have versioning enabled: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have versioning enabled.")

    # ── C-09: EBS default encryption ──────────────────────────────────────────

    def ebs_default_encryption_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.ec2.get_ebs_encryption_by_default()
        if resp.get("EbsEncryptionByDefault"):
            return self._pass(ctrl, f"EBS default encryption is enabled in region {self.region}.")
        return self._fail(ctrl, f"EBS default encryption is DISABLED in region {self.region}.")

    # ── C-10: AWS Config recorder ─────────────────────────────────────────────

    def config_recorder_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        recorders = self.config_svc.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            return self._fail(ctrl, "No AWS Config configuration recorder found.")

        statuses = self.config_svc.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        active = [s for s in statuses if s.get("recording")]
        if active:
            return self._pass(ctrl, f"AWS Config recorder is active: {[s['name'] for s in active]}")
        return self._fail(ctrl, "AWS Config recorder exists but is not currently recording.")
