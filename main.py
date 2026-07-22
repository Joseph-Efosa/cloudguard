#!/usr/bin/env python3
"""
CloudGuard — Automated GDPR Compliance Monitoring for AWS + GCP
Joseph Oviawe · A00047180 · TU Dublin · June 2026
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from cloudguard.engine import ControlEngine
from cloudguard.evaluator import compute_metrics
from cloudguard.reporter import write_results_json
from cloudguard.llm_reporter import LLMReporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cloudguard")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CloudGuard — GDPR compliance scanner for AWS + GCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan (AWS + GCP):
  python main.py --gcp-project my-gcp-project

  # AWS only:
  python main.py --csp aws --aws-region eu-west-1

  # GCP only:
  python main.py --csp gcp --gcp-project my-gcp-project

  # Specific controls:
  python main.py --controls C-01 C-02 C-03

  # With ground-truth JSON for accuracy metrics:
  python main.py --ground-truth ground_truth.json
""",
    )
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
                        help="Path to YAML control set")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"),
                        help="Directory for output reports (default: reports/)")
    parser.add_argument("--ground-truth", type=Path, default=None,
                        help="JSON file mapping control_id → true/false (compliant=true)")
    parser.add_argument("--fail-on-violations", action="store_true",
                        help="Exit with code 1 if any FAIL results are found (CI/CD use)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-control log output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.quiet:
        logging.getLogger("cloudguard").setLevel(logging.WARNING)

    engine = ControlEngine(
        controls_path=args.controls_file,
        aws_region=args.aws_region,
        gcp_project_id=args.gcp_project,
        csp_filter=args.csp,
        control_ids=args.controls,
    )

    logger.info("CloudGuard starting scan...")
    results, elapsed = engine.run()

    ground_truth: dict[str, bool] | None = None
    if args.ground_truth and args.ground_truth.exists():
        ground_truth = json.loads(args.ground_truth.read_text())
        logger.info("Ground truth loaded (%d entries)", len(ground_truth))

    summary = compute_metrics(results, elapsed, ground_truth)

    # ── reports ───────────────────────────────────────────────────────────────
    from datetime import datetime
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = args.output_dir / f"cloudguard_{ts}.json"
    html_path = args.output_dir / f"cloudguard_{ts}.html"

    scan_meta = {
        "aws_region": args.aws_region,
        "gcp_project": args.gcp_project,
        "csp_filter": args.csp,
    }
    write_results_json(results, summary, json_path, scan_meta)
    LLMReporter().write_html(results, summary, html_path)

    # ── console summary ───────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  CloudGuard GDPR Compliance Scan — Results")
    print("═" * 60)
    print(f"  Controls evaluated : {summary.total}")
    print(f"  ✓ PASS             : {summary.passed}")
    print(f"  ✗ FAIL             : {summary.failed}")
    print(f"  ⚠ ERROR            : {summary.errored}")
    print(f"  Duration           : {elapsed:.2f}s")
    if ground_truth:
        print(f"\n  Precision : {summary.precision:.4f}")
        print(f"  Recall    : {summary.recall:.4f}")
        print(f"  F1 Score  : {summary.f1:.4f}")
        print(f"  FPR       : {summary.false_positive_rate:.4f}")
    print(f"\n  JSON  → {json_path}")
    print(f"  HTML  → {html_path}")
    print("═" * 60 + "\n")

    if summary.failed > 0:
        print("FAILED controls:")
        for r in results:
            if r.status.value == "FAIL":
                print(f"  [{r.control_id}] {r.title}")
                print(f"    {r.detail}")

    if args.fail_on_violations and summary.failed > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
