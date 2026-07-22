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
        self._logs = None
        self._guardduty = None
        self._sns = None
        self._sqs = None
        self._secretsmanager = None
        self._accessanalyzer = None

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

    @property
    def logs(self):
        if not self._logs:
            self._logs = self._client("logs")
        return self._logs

    @property
    def guardduty(self):
        if not self._guardduty:
            self._guardduty = self._client("guardduty")
        return self._guardduty

    @property
    def sns(self):
        if not self._sns:
            self._sns = self._client("sns")
        return self._sns

    @property
    def sqs(self):
        if not self._sqs:
            self._sqs = self._client("sqs")
        return self._sqs

    @property
    def secretsmanager(self):
        if not self._secretsmanager:
            self._secretsmanager = self._client("secretsmanager")
        return self._secretsmanager

    @property
    def accessanalyzer(self):
        if not self._accessanalyzer:
            self._accessanalyzer = self._client("accessanalyzer")
        return self._accessanalyzer

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

    def _get_password_policy(self):
        """Returns the IAM password policy dict, or None if none is set."""
        try:
            return self.iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return None
            raise

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

    # ── C-11: IAM password policy — minimum length ────────────────────────────

    def iam_password_min_length(self, ctrl: ControlDefinition) -> CheckResult:
        policy = self._get_password_policy()
        if policy is None:
            return self._fail(ctrl, "No IAM account password policy is set.")
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len >= 14:
            return self._pass(ctrl, f"Password policy minimum length is {min_len} (≥ 14).")
        return self._fail(ctrl, f"Password policy minimum length is {min_len} (required: ≥ 14).")

    # ── C-12: IAM password policy — maximum age ───────────────────────────────

    def iam_password_max_age(self, ctrl: ControlDefinition) -> CheckResult:
        policy = self._get_password_policy()
        if policy is None:
            return self._fail(ctrl, "No IAM account password policy is set.")
        max_age = policy.get("MaxPasswordAge")
        if max_age is not None and max_age <= 90:
            return self._pass(ctrl, f"Password policy maximum age is {max_age} days (≤ 90).")
        desc = "not set (passwords never expire)" if max_age is None else f"{max_age} days"
        return self._fail(ctrl, f"Password policy maximum age is {desc} (required: ≤ 90 days).")

    # ── C-13: IAM password policy — prevent reuse ─────────────────────────────

    def iam_password_reuse(self, ctrl: ControlDefinition) -> CheckResult:
        policy = self._get_password_policy()
        if policy is None:
            return self._fail(ctrl, "No IAM account password policy is set.")
        reuse = policy.get("PasswordReusePrevention", 0)
        if reuse >= 24:
            return self._pass(ctrl, f"Password policy prevents reuse of last {reuse} passwords (≥ 24).")
        return self._fail(ctrl, f"Password reuse prevention is {reuse} (required: ≥ 24).")

    # ── C-14: VPC default SG — no open rules ─────────────────────────────────

    def vpc_default_sg_no_open_rules(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )
        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            return self._pass(ctrl, "No default security groups found — control vacuously satisfied.")

        violations = []
        for sg in sgs:
            inbound = len(sg.get("IpPermissions", []))
            outbound = len(sg.get("IpPermissionsEgress", []))
            if inbound > 0 or outbound > 0:
                violations.append(
                    f"{sg['GroupId']} (vpc {sg['VpcId']}): {inbound} inbound, {outbound} outbound rule(s)"
                )

        if violations:
            return self._fail(ctrl, f"Default security group(s) have open rules: {violations}")
        return self._pass(ctrl, f"All {len(sgs)} default security group(s) have no inbound/outbound rules.")

    # ── C-15: EC2 IMDSv2 required ─────────────────────────────────────────────

    def ec2_imdsv2_required(self, ctrl: ControlDefinition) -> CheckResult:
        paginator = self.ec2.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))

        if not instances:
            return self._pass(ctrl, "No EC2 instances found — control vacuously satisfied.")

        failing = [
            i["InstanceId"]
            for i in instances
            if i.get("MetadataOptions", {}).get("HttpTokens") != "required"
        ]
        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} instance(s) do not require IMDSv2: {failing}")
        return self._pass(ctrl, f"All {len(instances)} EC2 instance(s) require IMDSv2 (HttpTokens=required).")

    # ── C-16: CloudWatch log group encryption ────────────────────────────────

    def cloudwatch_log_group_encrypted(self, ctrl: ControlDefinition) -> CheckResult:
        paginator = self.logs.get_paginator("describe_log_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page.get("logGroups", []))

        if not groups:
            return self._pass(ctrl, "No CloudWatch log groups found — control vacuously satisfied.")

        failing = [g["logGroupName"] for g in groups if not g.get("kmsKeyId")]
        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(groups)} log group(s) have no KMS encryption: {failing}")
        return self._pass(ctrl, f"All {len(groups)} CloudWatch log group(s) are encrypted with KMS.")

    # ── C-17: S3 access logging ───────────────────────────────────────────────

    def s3_access_logging_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No S3 buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            try:
                resp = self.s3.get_bucket_logging(Bucket=bucket)
                if "LoggingEnabled" not in resp:
                    failing.append(bucket)
            except ClientError:
                failing.append(bucket)

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) do not have access logging enabled: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have access logging enabled.")

    # ── C-18: GuardDuty detector active ──────────────────────────────────────

    def guardduty_detector_active(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.guardduty.list_detectors()
        detector_ids = resp.get("DetectorIds", [])
        if not detector_ids:
            return self._fail(ctrl, f"No GuardDuty detectors found in region {self.region}.")

        active = []
        for det_id in detector_ids:
            det = self.guardduty.get_detector(DetectorId=det_id)
            if det.get("Status") == "ENABLED":
                active.append(det_id)

        if active:
            return self._pass(ctrl, f"GuardDuty is active: {len(active)} ENABLED detector(s) in {self.region}.")
        return self._fail(ctrl, f"GuardDuty detector(s) found but none are ENABLED: {detector_ids}")

    # ── C-19: SNS topics encrypted ────────────────────────────────────────────

    def sns_topics_encrypted(self, ctrl: ControlDefinition) -> CheckResult:
        topics = []
        resp = self.sns.list_topics()
        topics.extend(t["TopicArn"] for t in resp.get("Topics", []))
        while "NextToken" in resp:
            resp = self.sns.list_topics(NextToken=resp["NextToken"])
            topics.extend(t["TopicArn"] for t in resp.get("Topics", []))

        if not topics:
            return self._pass(ctrl, "No SNS topics found — control vacuously satisfied.")

        failing = []
        for arn in topics:
            attrs = self.sns.get_topic_attributes(TopicArn=arn)["Attributes"]
            if not attrs.get("KmsMasterKeyId"):
                failing.append(arn.split(":")[-1])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(topics)} SNS topic(s) have no KMS encryption: {failing}")
        return self._pass(ctrl, f"All {len(topics)} SNS topic(s) are encrypted with KMS.")

    # ── C-20: SQS queues encrypted ────────────────────────────────────────────

    def sqs_queues_encrypted(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.sqs.list_queues()
        queue_urls = resp.get("QueueUrls", [])

        if not queue_urls:
            return self._pass(ctrl, "No SQS queues found — control vacuously satisfied.")

        failing = []
        for url in queue_urls:
            attrs = self.sqs.get_queue_attributes(
                QueueUrl=url,
                AttributeNames=["KmsMasterKeyId", "SqsManagedSseEnabled"],
            )["Attributes"]
            has_kms = bool(attrs.get("KmsMasterKeyId"))
            has_sse = attrs.get("SqsManagedSseEnabled", "false").lower() == "true"
            if not (has_kms or has_sse):
                failing.append(url.split("/")[-1])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(queue_urls)} SQS queue(s) have no encryption: {failing}")
        return self._pass(ctrl, f"All {len(queue_urls)} SQS queue(s) are encrypted.")

    # ── C-21: Secrets Manager in use ─────────────────────────────────────────

    def secrets_manager_in_use(self, ctrl: ControlDefinition) -> CheckResult:
        paginator = self.secretsmanager.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))

        if secrets:
            return self._pass(ctrl, f"AWS Secrets Manager is in use: {len(secrets)} secret(s) found.")
        return self._fail(ctrl, "No secrets found in AWS Secrets Manager — plaintext credential storage may be in use.")

    # ── C-22: CloudTrail S3 bucket not public ────────────────────────────────

    def cloudtrail_s3_not_public(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.cloudtrail.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        if not trails:
            return self._fail(ctrl, "No CloudTrail trails found.")

        required_keys = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        failing = []
        for trail in trails:
            bucket = trail.get("S3BucketName")
            if not bucket:
                continue
            try:
                block_resp = self.s3.get_public_access_block(Bucket=bucket)
                cfg = block_resp["PublicAccessBlockConfiguration"]
                if not all(cfg.get(k, False) for k in required_keys):
                    failing.append(f"trail '{trail['Name']}' → bucket '{bucket}'")
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    failing.append(f"trail '{trail['Name']}' → bucket '{bucket}' (no public access block)")
                else:
                    raise

        if failing:
            return self._fail(ctrl, f"CloudTrail S3 bucket(s) are not fully blocking public access: {failing}")
        return self._pass(ctrl, "All CloudTrail S3 bucket(s) have public access fully blocked.")

    # ── C-23: RDS Multi-AZ ───────────────────────────────────────────────────

    def rds_multi_az_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        paginator = self.rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])

        if not instances:
            return self._pass(ctrl, "No RDS instances found — control vacuously satisfied.")

        failing = [i["DBInstanceIdentifier"] for i in instances if not i.get("MultiAZ")]
        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} RDS instance(s) do not have Multi-AZ enabled: {failing}")
        return self._pass(ctrl, f"All {len(instances)} RDS instance(s) have Multi-AZ deployment enabled.")

    # ── C-24: IAM Access Analyser active ─────────────────────────────────────

    def iam_access_analyser_active(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.accessanalyzer.list_analyzers(type="ACCOUNT")
        analyzers = resp.get("analyzers", [])

        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        if active:
            return self._pass(ctrl, f"IAM Access Analyzer is active: {[a['name'] for a in active]}")
        if analyzers:
            return self._fail(ctrl, f"IAM Access Analyzer found but not ACTIVE: {[a['name'] for a in analyzers]}")
        return self._fail(ctrl, f"No IAM Access Analyzer found in region {self.region}.")

    # ── C-25: CloudTrail KMS encryption ──────────────────────────────────────

    def cloudtrail_kms_encrypted(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.cloudtrail.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        if not trails:
            return self._fail(ctrl, "No CloudTrail trails found.")

        failing = [t["Name"] for t in trails if not t.get("KMSKeyId")]
        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(trails)} trail(s) have no KMS encryption: {failing}")
        return self._pass(ctrl, f"All {len(trails)} CloudTrail trail(s) use KMS encryption.")
