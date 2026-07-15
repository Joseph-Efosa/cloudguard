"""
Reporter — writes results.json and report.json (a direct copy).

Per the architecture spec (Section 5.2):
  results.json  — intermediate structured output from the evaluator (single source of truth)
  report.json   — identical copy of results.json, used for precision/recall/F1 measurement

The LLM never touches either of these files.
report.html is produced separately by cloudguard.llm_reporter.LLMReporter.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import shutil

from cloudguard.evaluator import EvaluationSummary
from cloudguard.models import CheckResult

logger = logging.getLogger(__name__)


def write_results_json(
    results: list[CheckResult],
    summary: EvaluationSummary,
    output_path: Path,
    scan_meta: dict | None = None,
) -> None:
    """Write the deterministic evaluator output to results.json."""
    payload = {
        "scan": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(summary.elapsed_seconds, 3),
            **(scan_meta or {}),
        },
        "summary": {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "errored": summary.errored,
            "precision": round(summary.precision, 4),
            "recall": round(summary.recall, 4),
            "f1_score": round(summary.f1, 4),
            "false_positive_rate": round(summary.false_positive_rate, 4),
        },
        "results": [
            {
                "id": r.control_id,
                "title": r.title,
                "article": r.article,
                "gdpr_clause": r.gdpr_clause,
                "csp": r.csp,
                "service": r.service,
                "status": r.status.value,
                "detail": r.detail,
            }
            for r in results
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))
    logger.info("results.json written to %s", output_path)


def copy_to_report_json(results_path: Path, report_path: Path) -> None:
    """
    Copy results.json → report.json unchanged.
    report.json is the file used to calculate accuracy metrics.
    The LLM never reads or writes this file.
    """
    report_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(results_path, report_path)
    logger.info("report.json written to %s (direct copy of results.json)", report_path)
