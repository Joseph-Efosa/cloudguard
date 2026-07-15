"""
Terraform Manager — runs terraform destroy after each scan to keep the test
account clean and avoid accruing cloud costs.

Destroy is always attempted even if the scan produced errors, so no resources
are accidentally left running.
"""

import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

TERRAFORM_DIRS = {
    "aws": Path(__file__).parent.parent / "terraform" / "aws",
    "gcp": Path(__file__).parent.parent / "terraform" / "gcp",
}


def _run_terraform(cmd: list[str], cwd: Path) -> tuple[int, str]:
    logger.info("Running: %s (in %s)", " ".join(cmd), cwd)
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.stdout:
        for line in result.stdout.strip().splitlines():
            logger.info("  tf> %s", line)
    if result.stderr:
        for line in result.stderr.strip().splitlines():
            logger.warning("  tf! %s", line)
    return result.returncode, result.stdout + result.stderr


def _check_terraform() -> bool:
    result = subprocess.run(["terraform", "version"], capture_output=True)
    return result.returncode == 0


def destroy(
    csp: str | None = None,
    gcp_project: str | None = None,
    aws_region: str = "eu-west-1",
    auto_approve: bool = True,
) -> dict[str, bool]:
    """
    Run terraform destroy for the specified CSP(s).

    Returns a dict mapping csp → success (True/False).
    """
    if not _check_terraform():
        logger.error("terraform binary not found — skipping destroy. Install from https://developer.hashicorp.com/terraform/install")
        return {}

    targets = ["aws", "gcp"] if csp is None else [csp]
    results: dict[str, bool] = {}

    for provider in targets:
        tf_dir = TERRAFORM_DIRS.get(provider)
        if not tf_dir or not tf_dir.exists():
            logger.warning("Terraform directory not found for %s: %s", provider, tf_dir)
            results[provider] = False
            continue

        if provider == "gcp" and not gcp_project:
            logger.warning("GCP project ID required for terraform destroy — skipping GCP destroy.")
            results[provider] = False
            continue

        logger.info("━━━ Terraform destroy: %s ━━━", provider.upper())

        # Build var flags
        var_flags: list[str] = []
        if provider == "aws":
            var_flags = [f"-var=aws_region={aws_region}"]
        elif provider == "gcp":
            var_flags = [f"-var=project_id={gcp_project}"]

        # terraform init (idempotent — needed if .terraform dir is absent)
        init_code, _ = _run_terraform(["terraform", "init", "-input=false"], cwd=tf_dir)
        if init_code != 0:
            logger.error("terraform init failed for %s — skipping destroy", provider)
            results[provider] = False
            continue

        # terraform destroy
        destroy_cmd = ["terraform", "destroy", "-input=false"] + var_flags
        if auto_approve:
            destroy_cmd.append("-auto-approve")

        code, _ = _run_terraform(destroy_cmd, cwd=tf_dir)
        if code == 0:
            logger.info("✓ %s resources destroyed successfully.", provider.upper())
            results[provider] = True
        else:
            logger.error("✗ terraform destroy failed for %s (exit %d).", provider, code)
            results[provider] = False

    return results


def print_destroy_summary(results: dict[str, bool]) -> None:
    if not results:
        return
    print("\n" + "─" * 62)
    print("  Terraform Destroy — Post-Scan Cleanup")
    print("─" * 62)
    for provider, ok in results.items():
        icon = "✓" if ok else "✗"
        status = "destroyed" if ok else "FAILED — check logs, manual cleanup may be needed"
        print(f"  {icon} {provider.upper():<5} {status}")
    print("─" * 62 + "\n")
