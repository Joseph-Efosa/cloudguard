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
        self._iam_client = None       # IAM v1 API (googleapiclient)
        self._sqladmin_client = None
        self._compute_client = None
        self._logging_client = None   # Cloud Logging v2 API (googleapiclient)
        self._kms_client = None       # Cloud KMS v1 API (googleapiclient)
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
    def iam_api_client(self):
        """IAM v1 API — used for service account and key checks."""
        if not self._iam_client:
            import googleapiclient.discovery
            self._iam_client = googleapiclient.discovery.build("iam", "v1")
        return self._iam_client

    @property
    def logging_api_client(self):
        """Cloud Logging v2 API — used for log sink checks."""
        if not self._logging_client:
            import googleapiclient.discovery
            self._logging_client = googleapiclient.discovery.build("logging", "v2")
        return self._logging_client

    @property
    def kms_client(self):
        """Cloud KMS v1 API — used for key destruction schedule checks."""
        if not self._kms_client:
            import googleapiclient.discovery
            self._kms_client = googleapiclient.discovery.build("cloudkms", "v1")
        return self._kms_client

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

    @staticmethod
    def _port_allowed(ports: list[str], target: int) -> bool:
        """Returns True if target port falls within any entry in the ports list."""
        if not ports:
            return True  # no restriction means all ports
        for p in ports:
            if "-" in p:
                lo, hi = p.split("-", 1)
                if int(lo) <= target <= int(hi):
                    return True
            elif p == str(target):
                return True
        return False

    # ── C-26: GCS CMEK ───────────────────────────────────────────────────────

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

    # ── C-27: GCS public access prevention ───────────────────────────────────

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

    # ── C-28: Audit log DATA_READ ─────────────────────────────────────────────

    def audit_log_data_read_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        if self._audit_log_type_enabled("DATA_READ"):
            return self._pass(ctrl, "DATA_READ audit log type is enabled for allServices.")
        return self._fail(ctrl, "DATA_READ audit log type is NOT enabled at the project level.")

    # ── C-29: Audit log DATA_WRITE ────────────────────────────────────────────

    def audit_log_data_write_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        if self._audit_log_type_enabled("DATA_WRITE"):
            return self._pass(ctrl, "DATA_WRITE audit log type is enabled for allServices.")
        return self._fail(ctrl, "DATA_WRITE audit log type is NOT enabled at the project level.")

    # ── C-30: Audit log ADMIN_READ ────────────────────────────────────────────

    def audit_log_admin_read_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        if self._audit_log_type_enabled("ADMIN_READ"):
            return self._pass(ctrl, "ADMIN_READ audit log type is enabled for allServices.")
        return self._fail(ctrl, "ADMIN_READ audit log type is NOT enabled at the project level.")

    # ── C-31: Cloud SQL SSL ───────────────────────────────────────────────────

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

    # ── C-32: Cloud SQL backup ────────────────────────────────────────────────

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

    # ── C-33: IAM no public bindings ─────────────────────────────────────────

    def iam_no_public_bindings(self, ctrl: ControlDefinition) -> CheckResult:
        public_members = {"allUsers", "allAuthenticatedUsers"}
        violations = []

        policy = self._get_project_iam_policy()
        for binding in policy.get("bindings", []):
            for member in binding.get("members", []):
                if member in public_members:
                    violations.append(f"project: {member} → {binding['role']}")

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

    # ── C-34: Compute disk CMEK ───────────────────────────────────────────────

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

    # ── C-35: Secret Manager secrets ─────────────────────────────────────────

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
            active_versions = [
                v for v in all_versions
                if v.state != SecretVersion.State.DESTROYED
            ]
            if not active_versions:
                unversioned.append(secret.name.split("/")[-1])

        if unversioned:
            return self._fail(ctrl, f"{len(unversioned)} secret(s) have no active versions: {unversioned}")

        return self._pass(ctrl, f"{len(secrets)} secret(s) found in Secret Manager, all versioned.")

    # ── C-36: KMS key destruction schedule ───────────────────────────────────

    def kms_key_destruction_delay(self, ctrl: ControlDefinition) -> CheckResult:
        locations_resp = self.kms_client.projects().locations().list(
            name=f"projects/{self.project_id}"
        ).execute()
        locations = locations_resp.get("locations", [])

        all_keys = []
        failing = []
        for loc in locations:
            kr_resp = self.kms_client.projects().locations().keyRings().list(
                parent=loc["name"]
            ).execute()
            for kr in kr_resp.get("keyRings", []):
                keys_resp = self.kms_client.projects().locations().keyRings().cryptoKeys().list(
                    parent=kr["name"]
                ).execute()
                for key in keys_resp.get("cryptoKeys", []):
                    all_keys.append(key["name"])
                    duration_str = key.get("destroyScheduledDuration", "86400s")
                    seconds = int(duration_str.rstrip("s"))
                    if seconds < 604800:  # 7 days in seconds
                        days = seconds // 86400
                        failing.append(f"{key['name'].split('/')[-1]} ({days}d schedule)")

        if not all_keys:
            return self._pass(ctrl, "No Cloud KMS keys found — control vacuously satisfied.")
        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(all_keys)} KMS key(s) have destruction schedule < 7 days: {failing}")
        return self._pass(ctrl, f"All {len(all_keys)} KMS key(s) have a destruction schedule ≥ 7 days.")

    # ── C-37: Firewall — no open SSH ─────────────────────────────────────────

    def firewall_no_open_ssh(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.compute_client.firewalls().list(project=self.project_id).execute()
        rules = resp.get("items", [])
        open_ranges = {"0.0.0.0/0", "::/0"}
        violations = []

        for rule in rules:
            if rule.get("direction", "INGRESS") != "INGRESS":
                continue
            if rule.get("disabled", False):
                continue
            if not (set(rule.get("sourceRanges", [])) & open_ranges):
                continue
            for allowed in rule.get("allowed", []):
                proto = allowed.get("IPProtocol", "")
                ports = allowed.get("ports", [])
                if proto == "all" or (proto == "tcp" and self._port_allowed(ports, 22)):
                    violations.append(rule["name"])
                    break

        if violations:
            return self._fail(ctrl, f"{len(violations)} firewall rule(s) allow unrestricted SSH (port 22): {violations}")
        return self._pass(ctrl, "No firewall rules allow unrestricted SSH access from 0.0.0.0/0.")

    # ── C-38: Firewall — no open RDP ─────────────────────────────────────────

    def firewall_no_open_rdp(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.compute_client.firewalls().list(project=self.project_id).execute()
        rules = resp.get("items", [])
        open_ranges = {"0.0.0.0/0", "::/0"}
        violations = []

        for rule in rules:
            if rule.get("direction", "INGRESS") != "INGRESS":
                continue
            if rule.get("disabled", False):
                continue
            if not (set(rule.get("sourceRanges", [])) & open_ranges):
                continue
            for allowed in rule.get("allowed", []):
                proto = allowed.get("IPProtocol", "")
                ports = allowed.get("ports", [])
                if proto == "all" or (proto == "tcp" and self._port_allowed(ports, 3389)):
                    violations.append(rule["name"])
                    break

        if violations:
            return self._fail(ctrl, f"{len(violations)} firewall rule(s) allow unrestricted RDP (port 3389): {violations}")
        return self._pass(ctrl, "No firewall rules allow unrestricted RDP access from 0.0.0.0/0.")

    # ── C-39: GCS uniform bucket-level access ────────────────────────────────

    def gcs_uniform_bucket_access(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No Cloud Storage buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            bucket.reload()
            iam_cfg = bucket.iam_configuration
            if not getattr(iam_cfg, "uniform_bucket_level_access_enabled", False):
                failing.append(bucket.name)

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) do not have uniform bucket-level access: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have uniform bucket-level access enabled.")

    # ── C-40: Cloud SQL — no public IP ───────────────────────────────────────

    def cloudsql_no_public_ip(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.sqladmin_client.instances().list(project=self.project_id).execute()
        instances = resp.get("items", [])
        if not instances:
            return self._pass(ctrl, "No Cloud SQL instances found — control vacuously satisfied.")

        failing = []
        for inst in instances:
            ip_cfg = inst.get("settings", {}).get("ipConfiguration", {})
            has_public_ip = ip_cfg.get("ipv4Enabled", False)
            has_auth_networks = bool(ip_cfg.get("authorizedNetworks", []))
            if has_public_ip or has_auth_networks:
                failing.append(inst["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} Cloud SQL instance(s) have a public IP or authorised networks: {failing}")
        return self._pass(ctrl, f"All {len(instances)} Cloud SQL instance(s) have no public IP or authorised networks.")

    # ── C-41: Compute Engine — serial port disabled ───────────────────────────

    def compute_serial_port_disabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.compute_client.instances().aggregatedList(project=self.project_id).execute()
        items = resp.get("items", {})

        all_instances = []
        for zone_data in items.values():
            all_instances.extend(zone_data.get("instances", []))

        if not all_instances:
            return self._pass(ctrl, "No Compute Engine instances found — control vacuously satisfied.")

        failing = []
        for inst in all_instances:
            metadata_items = inst.get("metadata", {}).get("items", [])
            for item in metadata_items:
                if item.get("key") == "serial-port-enable" and item.get("value", "").lower() in ("1", "true"):
                    failing.append(inst["name"])
                    break

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(all_instances)} instance(s) have serial port access enabled: {failing}")
        return self._pass(ctrl, f"All {len(all_instances)} Compute Engine instance(s) have serial port access disabled.")

    # ── C-42: Cloud Logging — log sink exists ────────────────────────────────

    def logging_sink_exists(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.logging_api_client.projects().sinks().list(
            parent=f"projects/{self.project_id}"
        ).execute()
        sinks = resp.get("sinks", [])

        if sinks:
            names = [s["name"].split("/")[-1] for s in sinks]
            return self._pass(ctrl, f"{len(sinks)} log export sink(s) configured: {names}")
        return self._fail(ctrl, f"No log export sinks configured in project '{self.project_id}'.")

    # ── C-43: Compute Engine — OS Login enabled ───────────────────────────────

    def compute_oslogin_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        project_info = self.compute_client.projects().get(project=self.project_id).execute()
        metadata_items = project_info.get("commonInstanceMetadata", {}).get("items", [])

        for item in metadata_items:
            if item.get("key") == "enable-oslogin" and item.get("value", "").upper() in ("TRUE", "1"):
                return self._pass(ctrl, "OS Login is enabled at the project level (enable-oslogin=TRUE).")

        return self._fail(ctrl, "OS Login is NOT enabled at the project level (enable-oslogin metadata key absent or not TRUE).")

    # ── C-44: Cloud SQL — deletion protection ────────────────────────────────

    def cloudsql_deletion_protection(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.sqladmin_client.instances().list(project=self.project_id).execute()
        instances = resp.get("items", [])
        if not instances:
            return self._pass(ctrl, "No Cloud SQL instances found — control vacuously satisfied.")

        failing = []
        for inst in instances:
            if not inst.get("settings", {}).get("deletionProtectionEnabled", False):
                failing.append(inst["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} Cloud SQL instance(s) do not have deletion protection enabled: {failing}")
        return self._pass(ctrl, f"All {len(instances)} Cloud SQL instance(s) have deletion protection enabled.")

    # ── C-45: IAM — no service account with admin roles ──────────────────────

    def iam_no_service_account_admin(self, ctrl: ControlDefinition) -> CheckResult:
        admin_roles = {
            "roles/owner",
            "roles/editor",
            "roles/iam.securityAdmin",
            "roles/iam.roleAdmin",
            "roles/resourcemanager.projectIamAdmin",
        }
        policy = self._get_project_iam_policy()
        violations = []

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            if role not in admin_roles:
                continue
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:"):
                    violations.append(f"{member} → {role}")

        if violations:
            return self._fail(ctrl, f"Service account(s) with admin/owner roles found: {violations}")
        return self._pass(ctrl, "No service accounts are assigned admin-level roles at the project level.")

    # ── C-46: Compute Engine — Shielded VM enabled ───────────────────────────

    def compute_shielded_vm_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.compute_client.instances().aggregatedList(project=self.project_id).execute()
        items = resp.get("items", {})

        all_instances = []
        for zone_data in items.values():
            all_instances.extend(zone_data.get("instances", []))

        if not all_instances:
            return self._pass(ctrl, "No Compute Engine instances found — control vacuously satisfied.")

        failing = []
        for inst in all_instances:
            shielded = inst.get("shieldedInstanceConfig", {})
            vtpm = shielded.get("enableVtpm", False)
            integrity = shielded.get("enableIntegrityMonitoring", False)
            if not (vtpm and integrity):
                failing.append(inst["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(all_instances)} instance(s) do not have Shielded VM fully enabled: {failing}")
        return self._pass(ctrl, f"All {len(all_instances)} instance(s) have Shielded VM (vTPM + Integrity Monitoring) enabled.")

    # ── C-47: GCS versioning enabled ─────────────────────────────────────────

    def gcs_versioning_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        buckets = self._list_all_buckets()
        if not buckets:
            return self._pass(ctrl, "No Cloud Storage buckets found — control vacuously satisfied.")

        failing = []
        for bucket in buckets:
            bucket.reload()
            if not bucket.versioning_enabled:
                failing.append(bucket.name)

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(buckets)} bucket(s) do not have versioning enabled: {failing}")
        return self._pass(ctrl, f"All {len(buckets)} bucket(s) have versioning enabled.")

    # ── C-48: IAM service account key rotation ───────────────────────────────

    def iam_service_account_key_rotation(self, ctrl: ControlDefinition) -> CheckResult:
        from datetime import datetime, timezone, timedelta

        parent = f"projects/{self.project_id}"
        sa_resp = self.iam_api_client.projects().serviceAccounts().list(name=parent).execute()
        service_accounts = sa_resp.get("accounts", [])

        if not service_accounts:
            return self._pass(ctrl, "No service accounts found — control vacuously satisfied.")

        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        stale_keys = []

        for sa in service_accounts:
            keys_resp = self.iam_api_client.projects().serviceAccounts().keys().list(
                name=sa["name"], keyTypes=["USER_MANAGED"]
            ).execute()
            for key in keys_resp.get("keys", []):
                created_str = key.get("validAfterTime", "")
                if not created_str:
                    continue
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                if created < cutoff:
                    age_days = (datetime.now(timezone.utc) - created).days
                    key_short = key["name"].split("/")[-1][:12]
                    stale_keys.append(f"{sa['email']} (key {key_short}…, {age_days}d old)")

        if stale_keys:
            return self._fail(ctrl, f"{len(stale_keys)} service account key(s) older than 90 days: {stale_keys}")
        return self._pass(ctrl, "All user-managed service account keys were created within the last 90 days.")

    # ── C-49: Cloud SQL — PITR enabled ───────────────────────────────────────

    def cloudsql_pitr_enabled(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.sqladmin_client.instances().list(project=self.project_id).execute()
        instances = resp.get("items", [])
        if not instances:
            return self._pass(ctrl, "No Cloud SQL instances found — control vacuously satisfied.")

        failing = []
        for inst in instances:
            pitr = (
                inst.get("settings", {})
                    .get("backupConfiguration", {})
                    .get("pointInTimeRecoveryEnabled", False)
            )
            if not pitr:
                failing.append(inst["name"])

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(instances)} Cloud SQL instance(s) do not have PITR enabled: {failing}")
        return self._pass(ctrl, f"All {len(instances)} Cloud SQL instance(s) have point-in-time recovery enabled.")

    # ── C-50: Compute Engine — no default service account ────────────────────

    def compute_no_default_service_account(self, ctrl: ControlDefinition) -> CheckResult:
        resp = self.compute_client.instances().aggregatedList(project=self.project_id).execute()
        items = resp.get("items", {})

        all_instances = []
        for zone_data in items.values():
            all_instances.extend(zone_data.get("instances", []))

        if not all_instances:
            return self._pass(ctrl, "No Compute Engine instances found — control vacuously satisfied.")

        failing = []
        for inst in all_instances:
            for sa in inst.get("serviceAccounts", []):
                if sa.get("email", "").endswith("-compute@developer.gserviceaccount.com"):
                    failing.append(f"{inst['name']} ({sa['email']})")
                    break

        if failing:
            return self._fail(ctrl, f"{len(failing)}/{len(all_instances)} instance(s) use the default compute service account: {failing}")
        return self._pass(ctrl, f"All {len(all_instances)} instance(s) use custom service accounts (not the default compute SA).")
