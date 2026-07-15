"""
Generates report.html for a fully-misconfigured scenario (0 PASS / 20 FAIL / 0 ERROR)
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

# ── Realistic FAIL details for each control ───────────────────────────────────

FAIL_DETAILS = {
    "C-01": "1/1 bucket(s) have no default encryption: ['cloudguard-test-bucket']",
    "C-02": "1/1 bucket(s) have public access enabled: ['cloudguard-test-bucket'] (BlockPublicAcls=False)",
    "C-03": "No multi-region CloudTrail trail with logging active found.",
    "C-04": "Trail 'cloudguard-test-trail' has log file validation DISABLED.",
    "C-05": "1/1 RDS instance(s) have storage encryption disabled: ['cloudguard-test-rds']",
    "C-06": "1/1 customer-managed KMS key(s) do not have automatic rotation enabled.",
    "C-07": "Root account MFA is NOT enabled.",
    "C-08": "1/1 bucket(s) do not have versioning enabled: ['cloudguard-test-bucket']",
    "C-09": "EBS default encryption is DISABLED for this account/region.",
    "C-10": "No active AWS Config configuration recorder found.",
    "C-11": "1/1 bucket(s) have no CMEK: ['cloudguard-gdpr-2026-bucket']",
    "C-12": "1/1 bucket(s) do not enforce public access prevention: ['cloudguard-gdpr-2026-bucket (pap=inherited)']",
    "C-13": "DATA_READ audit log type is NOT enabled at the project level.",
    "C-14": "DATA_WRITE audit log type is NOT enabled at the project level.",
    "C-15": "ADMIN_READ audit log type is NOT enabled at the project level.",
    "C-16": "1/1 Cloud SQL instance(s) do not require SSL: ['cloudguard-test-sql']",
    "C-17": "1/1 Cloud SQL instance(s) do not have backups enabled: ['cloudguard-test-sql']",
    "C-18": "Public IAM bindings found: [\"bucket/cloudguard-gdpr-2026-bucket: allUsers → roles/storage.objectViewer\"]",
    "C-19": "1/1 disk(s) do not use CMEK: ['cloudguard-test-disk']",
    "C-20": "1 secret(s) have no active versions: ['cloudguard-test-secret']",
}

# ── Load controls from YAML ───────────────────────────────────────────────────

controls_path = Path(__file__).parent / "controls" / "gdpr_controls.yaml"
with controls_path.open() as f:
    data = yaml.safe_load(f)

control_defs = [ControlDefinition(**c) for c in data["controls"]]

# ── Build synthetic FAIL results for all 20 controls ─────────────────────────

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

# ── Build EvaluationSummary (0 PASS, 20 FAIL, 0 ERROR) ───────────────────────

summary = EvaluationSummary(
    total=20,
    passed=0,
    failed=20,
    errored=0,
    precision=1.0,   # 20 TP / (20 TP + 0 FP)
    recall=1.0,      # 20 TP / (20 TP + 0 FN)
    f1=1.0,
    false_positive_rate=0.0,
    elapsed_seconds=0.0,
    true_positives=20,
    false_positives=0,
    true_negatives=0,
    false_negatives=0,
)

# ── Generate LLM HTML report ──────────────────────────────────────────────────

output_path = Path(__file__).parent / "cloudguard" / "reports" / "report_misconfigured_all_fail.html"
reporter = LLMReporter(timeout=300)

print("Calling Ollama LLM for explanations (two batches of 10) …")
t0 = time.monotonic()
reporter.write_html(results, summary, output_path)
elapsed = time.monotonic() - t0

print(f"Done in {elapsed:.1f}s  →  {output_path}")
