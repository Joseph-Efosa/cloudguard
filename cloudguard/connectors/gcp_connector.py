"""GCP Connector — queries GCP APIs via Google Cloud SDK for each GDPR control check."""

import logging
from typing import Any

from cloudguard.models import CheckResult, ControlDefinition, Status

logger = logging.getLogger(__name__)


class GCPConnector:
    """Executes all GCP-side GDPR control checks using the Google Cloud SDK."""

    def __init__(self, project_id: str):
        if not project_id:
            raise ValueError("GCP project_id is required")
        self.project_id = project_id
        self._storage_client = None
        self._iam_client = None
        self._sqladmin_client = None
        self._compute_client = None
        self._logging_client = None
        self._secretmanager_client = None
        self._crm_client = None

    # ── lazy clients ──────────────────────────────────────────────────────────

    @property
    def storage_client(self):
        if not self._storage_client:
            from google.cloud import storage
            self._storage_client = storage.Client(project=self.project_id)
        return self._storage_client

    @property
    def sqladmin_client(self):
        if not self._sqladmin_client:
            import googleapiclient.discovery
            self._sqladmin_client = googleapiclient.discovery.build("sqladmin", "v1")
        return self._sqladmin_client

    @property
    def compute_client(self):
        if not self._compute_client:
            import googleapiclient.discovery
            self._compute_client = googleapiclient.discovery.build("compute", "v1")
        return self._compute_client

    @property
    def crm_client(self):
        """Cloud Resource Manager — used for IAM policy and audit log checks."""
        if not self._crm_client:
            import googleapiclient.discovery
            self._crm_client = googleapiclient.discovery.build("cloudresourcemanager", "v1")
        return self._crm_client

    @property
    def secretmanager_client(self):
        if not self._secretmanager_client:
            from google.cloud import secretmanager
            self._secretmanager_client = secretmanager.SecretManagerServiceClient()
        return self._secretmanager_client

    # ── dispatcher ────────────────────────────────────────────────────────────

    def run(self, control: ControlDefinition) -> CheckResult:
        handler = getattr(self, control.check, None)
        if handler is None:
            return self._error(control, f"No handler for check '{control.check}'")
        try:
            return handler(control)
        except Exception as exc:  # noqa: BLE001
            logger.debug("GCP check %s raised: %s", control.id, exc, exc_info=True)
            return self._error(control, f"Error during check: {exc}")

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

    def _list_all_buckets(self) -> list:
        return list(self.storage_client.list_buckets())

    def _get_project_iam_policy(self) -> dict:
        return self.crm_client.projects().getIamPolicy(
            resource=self.project_id, body={}
        ).execute()

    def _get_audit_log_configs(self) -> list[dict]:
        """Returns the auditConfigs from the project IAM policy."""
        policy = self._get_project_iam_policy()
        return policy.get("auditConfigs", [])

    def _audit_log_type_enabled(self, log_type: str) -> bool:
        """Check whether a given auditLogConfig logType is enabled for allServices."""
        audit_configs = self._get_audit_log_configs()
        for cfg in audit_configs:
            service = cfg.get("service", "")
            if service in ("allServices", ""):
                for log_cfg in cfg.get("auditLogConfigs", []):
                    if log_cfg.get("logType") == log_type:
                        return True
        return False

    # ── C-11: GCS CMEK ───────────────────────────────────────────────────────

    def gcs_cmek_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No Cloud Storage buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            bucket.reload()
            if not bucket.default_kms_key_name:
                failing.append(bucket.name)

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) have no CMEK: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) use a customer-managed encryption key.")

    # ── C-12: GCS public access prevention ───────────────────────────────────

    def gcs_public_access_prevention(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No Cloud Storage buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            bucket.reload()
            iam_cfg = bucket.iam_configuration
            pap = getattr(iam_cfg, "public_access_prevention", None)
            if pap != "enforced":
                failing.append(f"{bucket.name} (pap={pap})")

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) do not enforce public access prevention: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have publicAccessPrevention=enforced.")

    # ── C-13: Audit log DATA_READ ─────────────────────────────────────────────

    def audit_log_data_read_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        if self._audit_log_type_enabled("DATA_READ"):
            return self._pass(ctrl, "DATA_READ audit log type is enabled for allServices.")
        return self._fail(ctrl, "DATA_READ audit log type is NOT enabled at the project level.")

    # ── C-14: Audit log DATA_WRITE ────────────────────────────────────────────

    def audit_log_data_write_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        if self._audit_log_type_enabled("DATA_WRITE"):
            return self._pass(ctrl, "DATA_WRITE audit log type is enabled for allServices.")
        return self._fail(ctrl, "DATA_WRITE audit log type is NOT enabled at the project level.")

    # ── C-15: Audit log ADMIN_READ ────────────────────────────────────────────

    def audit_log_admin_read_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        if self._audit_log_type_enabled("ADMIN_READ"):
            return self._pass(ctrl, "ADMIN_READ audit log type is enabled for allServices.")
        return self._fail(ctrl, "ADMIN_READ audit log type is NOT enabled at the project level.")

    # ── C-16: Cloud SQL SSL ───────────────────────────────────────────────────

    def cloudsql_ssl_required(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.sqladmin_client.instances().list(project=self.project_id).execute()
        instances = resp.get("items", [])
        if not instances:
            return self._pass(ctrl, "No Cloud SQL instances found — control vacuously satisfied.")

        failing = []
        for inst in instances:
            require_ssl = (
                inst.get("settings", {})
                    .get("ipConfiguration", {})
                    .get("requireSsl", False)
            )
            if not require_ssl:
                failing.append(inst["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} Cloud SQL instance(s) do not require SSL: {failing}")
        return self._pass(ctrl, f"All {len(instances)} Cloud SQL instance(s) require SSL.")

    # ── C-17: Cloud SQL backup ────────────────────────────────────────────────

    def cloudsql_backup_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.sqladmin_client.instances().list(project=self.project_id).execute()
        instances = resp.get("items", [])
        if not instances:
            return self._pass(ctrl, "No Cloud SQL instances found — control vacuously satisfied.")

        failing = []
        for inst in instances:
            backup_enabled = (
                inst.get("settings", {})
                    .get("backupConfiguration", {})
                    .get("enabled", False)
            )
            if not backup_enabled:
                failing.append(inst["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} Cloud SQL instance(s) do not have backups enabled: {failing}")
        return self._pass(ctrl, f"All {len(instances)} Cloud SQL instance(s) have automated backups enabled.")

    # ── C-18: IAM no public bindings ─────────────────────────────────────────

    def iam_no_public_bindings(self, ctrl: ControlDefinition) -> CheckResult:
        public_members = {"allUsers", "allAuthenticatedUsers"}
        violations = []

        # Check project-level IAM policy
        policy = self._get_project_iam_policy()
        for binding in policy.get("bindings", []):
            for member in binding.get("members", []):
                if member in public_members:
                    violations.append(f"project: {member} → {binding['role']}")

        # Check GCS bucket-level IAM policies
        buckets = self._list_all_buckets()
        for bucket in buckets:
            try:
                bucket_policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in bucket_policy.bindings:
                    members = set(binding.get("members", []))
                    for pm in public_members:
                        if pm in members:
                            violations.append(f"bucket/{bucket.name}: {pm} → {binding['role']}")
            except Exception:
                pass

        if violations:
            return self._fail(ctrl, f"Public IAM bindings found: {violations}")
        return self._pass(ctrl, "No public (allUsers / allAuthenticatedUsers) IAM bindings found.")

    # ── C-19: Compute disk CMEK ───────────────────────────────────────────────

    def compute_disk_cmek_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.compute_client.disks().aggregatedList(project=self.project_id).execute()
        items = resp.get("items", {})

        all_disks = []
        for zone_data in items.values():
            all_disks.extend(zone_data.get("disks", []))

        if not all_disks:
            return self._pass(ctrl, "No Compute Engine disks found — control vacuously satisfied.")

        failing = []
        for disk in all_disks:
            enc = disk.get("diskEncryptionKey", {})
            if not enc.get("kmsKeyName"):
                failing.append(disk["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(all_disks)} disk(s) do not use CMEK: {failing}")
        return self._pass(ctrl, f"All {len(all_disks)} disk(s) use customer-managed encryption keys.")

    # ── C-20: Secret Manager secrets ─────────────────────────────────────────

    def secret_manager_secrets_exist(self, ctrl: ControlDefinition) -> CheckResult:
        from google.cloud.secretmanager_v1.types import SecretVersion

        parent = f"projects/{self.project_id}"
        secrets = list(self.secretmanager_client.list_secrets(request={"parent": parent}))

        if not secrets:
            return self._fail(ctrl, "No secrets found in Secret Manager. Plaintext credential storage may be in use.")

        unversioned = []
        for secret in secrets:
            all_versions = list(self.secretmanager_client.list_secret_versions(
                request={"parent": secret.name}
            ))
            # Only count ENABLED or DISABLED versions — DESTROYED versions are inert
            active_versions = [
                v for v in all_versions
                if v.state != SecretVersion.State.DESTROYED
            ]
            if not active_versions:
                unversioned.append(secret.name.split("/")[-1])

        if unversioned:
            return self._fail(ctrl, f"{len(unversioned)} secret(s) have no active versions: {unversioned}")

        return self._pass(ctrl, f"{len(secrets)} secret(s) found in Secret Manager, all versioned.")
