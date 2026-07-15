#!/usr/bin/env python3
"""
CloudGuard — Automated GDPR Compliance Monitoring for AWS + GCP
Joseph Oviawe · A00047180 · TU Dublin MSc Cybersecurity · June 2026

Data flow (per architecture spec):
  Scheduler/CLI
    → Control Engine  (loads controls.yaml, dispatches per CSP)
      → AWS Connector (boto3)  ──┐
      → GCP Connector (SDK)   ──┴─→ Evaluator
                                       → results.json  (deterministic, single source of truth)
                                         → report.json  (direct copy — used for P/R/F1 metrics)
                                         → LLM Report Generator (Ollama)
                                              → report.html  (natural-language explanations)
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from cloudguard.engine import ControlEngine
from cloudguard.evaluator import compute_metrics
from cloudguard.reporter import copy_to_report_json, write_results_json
from cloudguard.llm_reporter import LLMReporter
from cloudguard.terraform_manager import destroy, print_destroy_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cloudguard")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gdpr_monitor.py",
        description="CloudGuard — GDPR compliance scanner for AWS + GCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan (AWS + GCP):
  python gdpr_monitor.py --gcp-project my-gcp-project

  # AWS only:
  python gdpr_monitor.py --csp aws --aws-region eu-west-1

  # GCP only:
  python gdpr_monitor.py --csp gcp --gcp-project my-gcp-project

  # Specific controls:
  python gdpr_monitor.py --controls C-01 C-02 C-11

  # With ground-truth JSON for accuracy metrics (P/R/F1):
  python gdpr_monitor.py --ground-truth ground_truth_misconfigured.json

  # Custom Ollama model:
  python gdpr_monitor.py --csp aws --llm-model mistral

  # Skip LLM (produce JSON only):
  python gdpr_monitor.py --csp aws --no-llm
""",
    )

    # Cloud targets
    parser.add_argument("--gcp-project", default=os.environ.get("CLOUDGUARD_GCP_PROJECT"),
                        help="GCP project ID (or set CLOUDGUARD_GCP_PROJECT env var)")
    parser.add_argument("--aws-region", default=os.environ.get("CLOUDGUARD_AWS_REGION", "eu-west-1"),
                        help="AWS region (default: eu-west-1)")
    parser.add_argument("--csp", choices=["aws", "gcp"], default=None,
                        help="Limit scan to a single CSP")
    parser.add_argument("--controls", nargs="+", metavar="ID",
                        help="Run only specific control IDs (e.g. C-01 C-05)")
    parser.add_argument("--controls-file", type=Path,
                        default=Path(__file__).parent / "controls" / "gdpr_controls.yaml",
                        help="Path to YAML control set (default: controls/gdpr_controls.yaml)")

    # Output
    parser.add_argument("--output-dir", type=Path, default=Path("reports"),
                        help="Directory for output reports (default: reports/)")

    # Evaluation
    parser.add_argument("--ground-truth", type=Path, default=None,
                        help="JSON mapping control_id → true (compliant) / false (violation)")

    # LLM
    parser.add_argument("--llm-model", default=os.environ.get("CLOUDGUARD_LLM_MODEL", "llama3"),
                        help="Ollama model name (default: llama3)")
    parser.add_argument("--ollama-url", default=os.environ.get("CLOUDGUARD_OLLAMA_URL", "http://localhost:11434"),
                        help="Ollama base URL (default: http://localhost:11434)")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip LLM report generation (produce JSON outputs only)")

    # Terraform cleanup
    parser.add_argument("--destroy", action="store_true",
                        help="Run terraform destroy after the scan to avoid accruing cloud costs")
    parser.add_argument("--no-destroy-confirm", action="store_true",
                        help="Skip the destroy confirmation prompt (use in CI/CD)")

    # CI/CD
    parser.add_argument("--fail-on-violations", action="store_true",
                        help="Exit with code 1 if any FAIL results are found")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-control log lines")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # ── Step 1: Control Engine dispatches to AWS / GCP connectors ─────────────
    engine = ControlEngine(
        controls_path=args.controls_file,
        aws_region=args.aws_region,
        gcp_project_id=args.gcp_project,
        csp_filter=args.csp,
        control_ids=args.controls,
    )

    logger.info("CloudGuard starting scan...")
    results, elapsed = engine.run()

    # ── Step 2: Evaluator metrics ──────────────────────────────────────────────
    ground_truth: dict[str, bool] | None = None
    if args.ground_truth and args.ground_truth.exists():
        ground_truth = {
            k: v for k, v in json.loads(args.ground_truth.read_text()).items()
            if not k.startswith("_")
        }
        logger.info("Ground truth loaded (%d entries)", len(ground_truth))

    summary = compute_metrics(results, elapsed, ground_truth)

    # ── Step 3: Write results.json (deterministic evaluator output) ────────────
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_path = args.output_dir / f"results_{ts}.json"
    report_json_path = args.output_dir / f"report_{ts}.json"
    report_html_path = args.output_dir / f"report_{ts}.html"

    scan_meta = {
        "aws_region": args.aws_region,
        "gcp_project": args.gcp_project,
        "csp_filter": args.csp,
        "llm_model": args.llm_model if not args.no_llm else "disabled",
    }
    write_results_json(results, summary, results_path, scan_meta)

    # ── Step 4: Copy results.json → report.json (accuracy metrics source) ──────
    copy_to_report_json(results_path, report_json_path)

    # ── Step 5: LLM Report Generator → report.html ────────────────────────────
    if not args.no_llm:
        llm_reporter = LLMReporter(model=args.llm_model, ollama_url=args.ollama_url)
        llm_reporter.write_html(results, summary, report_html_path)
    else:
        logger.info("LLM report generation skipped (--no-llm)")
        report_html_path = None

    # ── Console summary ────────────────────────────────────────────────────────
    print("\n" + "═" * 62)
    print("  CloudGuard — GDPR Compliance Scan Results")
    print("═" * 62)
    print(f"  Controls evaluated : {summary.total}")
    print(f"  ✓ PASS             : {summary.passed}")
    print(f"  ✗ FAIL             : {summary.failed}")
    print(f"  ⚠ ERROR            : {summary.errored}")
    print(f"  Duration           : {elapsed:.2f}s")

    if ground_truth:
        print(f"\n  Precision          : {summary.precision:.4f}")
        print(f"  Recall             : {summary.recall:.4f}")
        print(f"  F1 Score           : {summary.f1:.4f}")
        print(f"  False Positive Rate: {summary.false_positive_rate:.4f}")

    print(f"\n  results.json → {results_path}")
    print(f"  report.json  → {report_json_path}")
    if report_html_path:
        print(f"  report.html  → {report_html_path}  [LLM: {args.llm_model}]")
    print("═" * 62 + "\n")

    if summary.failed > 0:
        print("FAILED controls:")
        for r in results:
            if r.status.value == "FAIL":
                print(f"  [{r.control_id}] {r.title}")
                print(f"    {r.detail}")
        print()

    # ── Step 6: Terraform destroy (post-scan cleanup) ─────────────────────────
    if args.destroy:
        print("\n⚠  Post-scan Terraform destroy requested.")
        if not args.no_destroy_confirm:
            confirm = input("   This will DELETE all test infrastructure. Type 'yes' to confirm: ").strip().lower()
            if confirm != "yes":
                print("   Destroy cancelled. Resources still running — remember to clean up manually.")
            else:
                destroy_results = destroy(
                    csp=args.csp,
                    gcp_project=args.gcp_project,
                    aws_region=args.aws_region,
                )
                print_destroy_summary(destroy_results)
        else:
            destroy_results = destroy(
                csp=args.csp,
                gcp_project=args.gcp_project,
                aws_region=args.aws_region,
            )
            print_destroy_summary(destroy_results)

    if args.fail_on_violations and summary.failed > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
