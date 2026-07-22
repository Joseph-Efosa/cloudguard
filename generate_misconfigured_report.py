"""
Generates report.html for a fully-misconfigured scenario (0 PASS / 50 FAIL / 0 ERROR)
by synthesising CheckResult objects directly from the controls YAML — no live cloud calls.

Run from the repo root:
    python generate_misconfigured_report.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import yaml
from cloudguard.models import CheckResult, ControlDefinition, Status
from cloudguard.evaluator import EvaluationSummary
from cloudguard.llm_reporter import LLMReporter

# ── Realistic FAIL details for each of the 50 controls ───────────────────────

FAIL_DETAILS = {
    # ── AWS Controls (C-01 – C-25) ──────────────────────────────────────────
    "C-01": "1/1 bucket(s) have no default encryption: ['cloudguard-test-bucket']",
    "C-02": "1/1 bucket(s) have public access enabled: ['cloudguard-test-bucket'] (BlockPublicAcls=False)",
    "C-03": "No active multi-region CloudTrail trail found.",
    "C-04": "Trail 'cloudguard-test-trail' has log file validation DISABLED.",
    "C-05": "1/1 RDS instance(s) have storage encryption disabled: ['cloudguard-test-rds']",
    "C-06": "1/1 customer-managed KMS key(s) do not have automatic rotation enabled.",
    "C-07": "Root account MFA is NOT enabled.",
    "C-08": "1/1 bucket(s) do not have versioning enabled: ['cloudguard-test-bucket']",
    "C-09": "EBS default encryption is DISABLED for this account/region.",
    "C-10": "No active AWS Config configuration recorder found.",
    "C-11": "Password policy minimum length is 8 (required: ≥ 14).",
    "C-12": "Password policy maximum age is not set (passwords never expire) (required: ≤ 90 days).",
    "C-13": "Password reuse prevention is 0 (required: ≥ 24).",
    "C-14": "Default security group(s) have open rules: ['sg-0abc1234 (vpc vpc-00112233): 1 inbound, 1 outbound rule(s)']",
    "C-15": "2/2 instance(s) do not require IMDSv2: ['i-0aaaa111111111111', 'i-0bbbb222222222222']",
    "C-16": "3/3 log group(s) have no KMS encryption: ['/aws/lambda/cloudguard-fn', '/aws/rds/cloudguard-test-rds', '/cloudguard/trail-logs']",
    "C-17": "1/1 bucket(s) do not have access logging enabled: ['cloudguard-test-bucket']",
    "C-18": "No GuardDuty detectors found in region eu-west-1.",
    "C-19": "1/1 SNS topic(s) have no KMS encryption: ['cloudguard-test-topic']",
    "C-20": "1/1 SQS queue(s) have no encryption: ['cloudguard-test-queue']",
    "C-21": "No secrets found in AWS Secrets Manager — plaintext credential storage may be in use.",
    "C-22": "CloudTrail S3 bucket(s) are not fully blocking public access: [\"trail 'cloudguard-test-trail' → bucket 'cloudguard-test-trail-bucket' (no public access block)\"]",
    "C-23": "1/1 RDS instance(s) do not have Multi-AZ enabled: ['cloudguard-test-rds']",
    "C-24": "No IAM Access Analyzer found in region eu-west-1.",
    "C-25": "1/1 trail(s) have no KMS encryption: ['cloudguard-test-trail']",
    # ── GCP Controls (C-26 – C-50) ──────────────────────────────────────────
    "C-26": "1/1 bucket(s) have no CMEK: ['cloudguard-gdpr-2026-bucket']",
    "C-27": "1/1 bucket(s) do not enforce public access prevention: ['cloudguard-gdpr-2026-bucket (pap=inherited)']",
    "C-28": "DATA_READ audit log type is NOT enabled at the project level.",
    "C-29": "DATA_WRITE audit log type is NOT enabled at the project level.",
    "C-30": "ADMIN_READ audit log type is NOT enabled at the project level.",
    "C-31": "1/1 Cloud SQL instance(s) do not require SSL: ['cloudguard-test-sql']",
    "C-32": "1/1 Cloud SQL instance(s) do not have backups enabled: ['cloudguard-test-sql']",
    "C-33": "Public IAM bindings found: [\"bucket/cloudguard-gdpr-2026-bucket: allUsers → roles/storage.objectViewer\"]",
    "C-34": "1/1 disk(s) do not use CMEK: ['cloudguard-test-disk']",
    "C-35": "1 secret(s) have no active versions: ['cloudguard-test-secret']",
    "C-36": "1/1 KMS key(s) have destruction schedule < 7 days: ['cloudguard-key (1d schedule)']",
    "C-37": "2 firewall rule(s) allow unrestricted SSH (port 22): ['default-allow-ssh', 'cloudguard-allow-ssh']",
    "C-38": "1 firewall rule(s) allow unrestricted RDP (port 3389): ['default-allow-rdp']",
    "C-39": "1/1 bucket(s) do not have uniform bucket-level access: ['cloudguard-gdpr-2026-bucket']",
    "C-40": "1/1 Cloud SQL instance(s) have a public IP or authorised networks: ['cloudguard-test-sql']",
    "C-41": "1/1 instance(s) have serial port access enabled: ['cloudguard-test-vm']",
    "C-42": "No log export sinks configured in project 'cloudguard-gdpr-2026'.",
    "C-43": "OS Login is NOT enabled at the project level (enable-oslogin metadata key absent or not TRUE).",
    "C-44": "1/1 Cloud SQL instance(s) do not have deletion protection enabled: ['cloudguard-test-sql']",
    "C-45": "Service account(s) with admin/owner roles found: ['serviceAccount:cloudguard-sa@cloudguard-gdpr-2026.iam.gserviceaccount.com → roles/owner']",
    "C-46": "1/1 instance(s) do not have Shielded VM fully enabled: ['cloudguard-test-vm']",
    "C-47": "1/1 bucket(s) do not have versioning enabled: ['cloudguard-gdpr-2026-bucket']",
    "C-48": "1 service account key(s) older than 90 days: ['cloudguard-sa@cloudguard-gdpr-2026.iam.gserviceaccount.com (key AbCdEfGhIjKl…, 120d old)']",
    "C-49": "1/1 Cloud SQL instance(s) do not have PITR enabled: ['cloudguard-test-sql']",
    "C-50": "1/1 instance(s) use the default compute service account: ['cloudguard-test-vm (12345678901-compute@developer.gserviceaccount.com)']",
}

# ── Load controls from YAML ───────────────────────────────────────────────────

controls_path = Path(__file__).parent / "controls" / "gdpr_controls.yaml"
with controls_path.open() as f:
    data = yaml.safe_load(f)

control_defs = [ControlDefinition(**c) for c in data["controls"]]

# ── Build synthetic FAIL results for all 50 controls ─────────────────────────

results: list[CheckResult] = [
    CheckResult(
        control_id=ctrl.id,
        title=ctrl.title,
        article=ctrl.article,
        gdpr_clause=ctrl.gdpr_clause,
        csp=ctrl.csp,
        service=ctrl.service,
        status=Status.FAIL,
        detail=FAIL_DETAILS[ctrl.id],
        remediation=ctrl.remediation,
    )
    for ctrl in control_defs
]

# ── Build EvaluationSummary (0 PASS, 50 FAIL, 0 ERROR) ───────────────────────

summary = EvaluationSummary(
    total=50,
    passed=0,
    failed=50,
    errored=0,
    precision=1.0,   # 50 TP / (50 TP + 0 FP)
    recall=1.0,      # 50 TP / (50 TP + 0 FN)
    f1=1.0,
    false_positive_rate=0.0,
    elapsed_seconds=0.0,
    true_positives=50,
    false_positives=0,
    true_negatives=0,
    false_negatives=0,
)

# ── Generate LLM HTML report ──────────────────────────────────────────────────

output_path = Path(__file__).parent / "cloudguard" / "reports" / "report_misconfigured_all_fail.html"
reporter = LLMReporter(timeout=300)

print("Calling Ollama LLM for explanations (five batches of 10) …")
t0 = time.monotonic()
reporter.write_html(results, summary, output_path)
elapsed = time.monotonic() - t0

print(f"Done in {elapsed:.1f}s  →  {output_path}")
