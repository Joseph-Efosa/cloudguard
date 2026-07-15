"""Control Engine — loads the YAML control set and routes each control to the correct connector."""

import logging
import time
from pathlib import Path
from typing import Optional

import yaml

from cloudguard.connectors.aws_connector import AWSConnector
from cloudguard.connectors.gcp_connector import GCPConnector
from cloudguard.models import CheckResult, ControlDefinition, Status

logger = logging.getLogger(__name__)

DEFAULT_CONTROLS_PATH = Path(__file__).parent.parent / "controls" / "gdpr_controls.yaml"


class ControlEngine:
    """
    Loads controls from YAML, instantiates the correct connector per CSP,
    dispatches each check, and returns the full list of results.
    """

    def __init__(
        self,
        controls_path: Path = DEFAULT_CONTROLS_PATH,
        aws_region: str = "eu-west-1",
        gcp_project_id: Optional[str] = None,
        csp_filter: Optional[str] = None,
        control_ids: Optional[list[str]] = None,
    ):
        self.controls_path = controls_path
        self.aws_region = aws_region
        self.gcp_project_id = gcp_project_id
        self.csp_filter = csp_filter
        self.control_ids = [c.upper() for c in control_ids] if control_ids else None

        self._aws: Optional[AWSConnector] = None
        self._gcp: Optional[GCPConnector] = None

    # ── connector access ──────────────────────────────────────────────────────

    @property
    def aws(self) -> AWSConnector:
        if self._aws is None:
            self._aws = AWSConnector(region=self.aws_region)
        return self._aws

    @property
    def gcp(self) -> GCPConnector:
        if self._gcp is None:
            if not self.gcp_project_id:
                raise ValueError(
                    "GCP project ID is required to run GCP checks. "
                    "Set --gcp-project or the CLOUDGUARD_GCP_PROJECT environment variable."
                )
            self._gcp = GCPConnector(project_id=self.gcp_project_id)
        return self._gcp

    # ── control loading ───────────────────────────────────────────────────────

    def load_controls(self) -> list[ControlDefinition]:
        with open(self.controls_path) as fh:
            data = yaml.safe_load(fh)

        controls = []
        for raw in data.get("controls", []):
            controls.append(ControlDefinition(
                id=raw["id"],
                title=raw["title"],
                article=raw["article"],
                gdpr_clause=raw["gdpr_clause"],
                csp=raw["csp"],
                service=raw["service"],
                check=raw["check"],
                description=raw["description"],
                remediation=raw["remediation"],
            ))
        return controls

    # ── main scan ─────────────────────────────────────────────────────────────

    def run(self) -> tuple[list[CheckResult], float]:
        controls = self.load_controls()

        if self.control_ids:
            controls = [c for c in controls if c.id in self.control_ids]
        if self.csp_filter:
            controls = [c for c in controls if c.csp == self.csp_filter.lower()]

        logger.info("Running %d control(s)...", len(controls))
        results: list[CheckResult] = []
        t_start = time.monotonic()

        for ctrl in controls:
            logger.info("[%s] %s — %s", ctrl.id, ctrl.csp.upper(), ctrl.title)
            try:
                if ctrl.csp == "aws":
                    result = self.aws.run(ctrl)
                elif ctrl.csp == "gcp":
                    result = self.gcp.run(ctrl)
                else:
                    result = CheckResult(
                        ctrl.id, ctrl.title, ctrl.article, ctrl.gdpr_clause,
                        ctrl.csp, ctrl.service,
                        Status.ERROR, f"Unknown CSP: {ctrl.csp}", ctrl.remediation,
                    )
            except Exception as exc:  # noqa: BLE001
                result = CheckResult(
                    ctrl.id, ctrl.title, ctrl.article, ctrl.gdpr_clause,
                    ctrl.csp, ctrl.service,
                    Status.ERROR, f"Unhandled exception: {exc}", ctrl.remediation,
                )

            icon = {"PASS": "✓", "FAIL": "✗", "ERROR": "⚠"}.get(result.status.value, "?")
            logger.info("  %s %s — %s", icon, result.status.value, result.detail[:120])
            results.append(result)

        elapsed = time.monotonic() - t_start
        logger.info("Scan complete in %.2f s", elapsed)
        return results, elapsed
