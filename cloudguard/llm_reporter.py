"""
LLM Report Generator — calls a self-hosted Ollama model to produce report.html.

The LLM receives only the deterministic Pass/Fail/Error output from results.json.
It does not see raw cloud API responses, credentials, or any configuration data.
It does not make compliance decisions — those are the sole output of the evaluator.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from cloudguard.evaluator import EvaluationSummary
from cloudguard.models import CheckResult, Status

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3"


class LLMReporter:
    """
    Generates report.html by prompting a local Ollama model with structured
    Pass/Fail/Error results and asking it to write plain-English explanations
    and remediation guidance per control.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        timeout: int = 300,
    ):
        self.model = model
        self.ollama_url = ollama_url.rstrip("/")
        self.timeout = timeout

    # ── Ollama API call ───────────────────────────────────────────────────────

    def _call_ollama(self, prompt: str) -> str:
        try:
            import requests
        except ImportError:
            raise RuntimeError("'requests' package is required: pip install requests")

        url = f"{self.ollama_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 4096},
        }
        logger.info("Calling Ollama (%s) at %s ...", self.model, url)
        t0 = time.monotonic()
        resp = requests.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        elapsed = time.monotonic() - t0
        logger.info("Ollama responded in %.1fs", elapsed)
        return resp.json().get("response", "")

    # ── Prompt construction ───────────────────────────────────────────────────

    def _build_prompt(self, results: list[CheckResult]) -> str:
        lines = []
        for r in results:
            lines.append(
                f"- ID: {r.control_id} | Status: {r.status.value} | "
                f"Article: {r.article} | CSP: {r.csp.upper()} | "
                f"Control: {r.title} | Detail: {r.detail}"
            )
        controls_block = "\n".join(lines)

        return f"""You are a GDPR compliance expert writing a technical compliance report for a cloud security audit.

Below are the results of an automated GDPR compliance scan across AWS and GCP infrastructure.
Each line shows one control: its ID, pass/fail/error status, the GDPR Article it maps to, the cloud provider, the control name, and the scan detail.

SCAN RESULTS:
{controls_block}

Your task: For EACH control above, write a JSON array where each element has these exact keys:
  "id"          — the control ID (e.g. "C-01")
  "explanation" — 2 sentences: what was checked and why it matters under the cited GDPR Article
  "status_note" — 1 sentence describing what the status (PASS/FAIL/ERROR) means in plain English
  "remediation" — For FAIL: 1-2 specific remediation steps referencing the cloud service. For PASS or ERROR: empty string ""

Return ONLY the JSON array, no markdown fences, no preamble, no commentary. Start your response with [ and end with ].
"""

    # ── LLM response parsing ──────────────────────────────────────────────────

    def _parse_llm_json(self, raw: str) -> list[dict]:
        raw = raw.strip()
        start = raw.find("[")
        end = raw.rfind("]")
        if start == -1 or end == -1:
            raise ValueError("LLM response did not contain a JSON array")
        return json.loads(raw[start : end + 1])

    # ── HTML generation ───────────────────────────────────────────────────────

    _CSS = """
:root {
  --bg:#0f1117; --surface:#1a1d27; --border:#2a2d3e;
  --text:#e2e8f0; --muted:#8892a4;
  --pass:#27ae60; --fail:#e74c3c; --error:#f39c12; --accent:#4f8ef7;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:auto}
h1{font-size:1.6rem;margin-bottom:.25rem}
.subtitle{color:var(--muted);font-size:.9rem;margin-bottom:.4rem}
.meta{color:var(--muted);font-size:.78rem;margin-bottom:2rem}
.badge{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.72rem;font-weight:700;letter-spacing:.04em}
.badge.PASS{background:rgba(39,174,96,.15);color:var(--pass)}
.badge.FAIL{background:rgba(231,76,60,.15);color:var(--fail)}
.badge.ERROR{background:rgba(243,156,18,.15);color:var(--error)}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1.8rem;min-width:130px;text-align:center}
.card .val{font-size:2rem;font-weight:700}
.card .lbl{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.card.pass .val{color:var(--pass)}.card.fail .val{color:var(--fail)}.card.error .val{color:var(--error)}.card.metric .val{color:var(--accent);font-size:1.5rem}
.progress{background:var(--surface);border:1px solid var(--border);border-radius:8px;height:10px;overflow:hidden;margin-bottom:2rem;display:flex}
.p-pass{background:var(--pass)}.p-fail{background:var(--fail)}.p-error{background:var(--error)}
.section-head{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:2rem 0 .8rem}
.control{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1.4rem;margin-bottom:1rem}
.ctrl-header{display:flex;align-items:center;gap:.7rem;margin-bottom:.6rem}
.ctrl-id{font-weight:700;color:var(--accent);font-size:.85rem}
.ctrl-title{font-weight:600;font-size:.95rem}
.article-tag{background:rgba(79,142,247,.1);color:var(--accent);border-radius:3px;padding:.1rem .4rem;font-size:.7rem}
.csp-aws{background:rgba(255,153,0,.12);color:#ff9900;border-radius:3px;padding:.1rem .4rem;font-size:.7rem;font-weight:700}
.csp-gcp{background:rgba(66,133,244,.12);color:#4285f4;border-radius:3px;padding:.1rem .4rem;font-size:.7rem;font-weight:700}
.explanation{font-size:.88rem;color:var(--text);line-height:1.6;margin-bottom:.5rem}
.status-note{font-size:.82rem;color:var(--muted);margin-bottom:.5rem}
.remediation{font-size:.82rem;color:#f0a070;border-left:2px solid var(--fail);padding-left:.7rem;margin-top:.5rem;line-height:1.5}
.scan-detail{font-size:.76rem;color:var(--muted);font-family:monospace;margin-top:.4rem;overflow-wrap:anywhere}
.llm-note{font-size:.72rem;color:var(--muted);margin-top:2rem;text-align:center;border-top:1px solid var(--border);padding-top:1rem}
"""

    def _build_html(
        self,
        results: list[CheckResult],
        summary: EvaluationSummary,
        llm_data: list[dict],
        fallback: bool = False,
    ) -> str:
        llm_map = {item["id"]: item for item in llm_data}
        t = summary.total or 1

        cards = f"""
        <div class="cards">
          <div class="card pass"><div class="val">{summary.passed}</div><div class="lbl">Passed</div></div>
          <div class="card fail"><div class="val">{summary.failed}</div><div class="lbl">Failed</div></div>
          <div class="card error"><div class="val">{summary.errored}</div><div class="lbl">Errors</div></div>
          <div class="card metric"><div class="val">{summary.precision:.0%}</div><div class="lbl">Precision</div></div>
          <div class="card metric"><div class="val">{summary.recall:.0%}</div><div class="lbl">Recall</div></div>
          <div class="card metric"><div class="val">{summary.f1:.2f}</div><div class="lbl">F1 Score</div></div>
        </div>
        <div class="progress">
          <div class="p-pass" style="width:{summary.passed/t*100:.1f}%"></div>
          <div class="p-fail" style="width:{summary.failed/t*100:.1f}%"></div>
          <div class="p-error" style="width:{summary.errored/t*100:.1f}%"></div>
        </div>"""

        def ctrl_html(r: CheckResult) -> str:
            info = llm_map.get(r.control_id, {})
            explanation = _esc(info.get("explanation", ""))
            status_note = _esc(info.get("status_note", ""))
            remediation = _esc(info.get("remediation", ""))
            csp_cls = f"csp-{r.csp}"
            rem_html = f'<div class="remediation"><strong>Remediation:</strong> {remediation}</div>' if remediation else ""
            return f"""
        <div class="control">
          <div class="ctrl-header">
            <span class="ctrl-id">{_esc(r.control_id)}</span>
            <span class="badge {r.status.value}">{r.status.value}</span>
            <span class="article-tag">{_esc(r.article)}</span>
            <span class="{csp_cls}">{r.csp.upper()}</span>
            <span class="ctrl-title">{_esc(r.title)}</span>
          </div>
          <div class="explanation">{explanation}</div>
          <div class="status-note">{status_note}</div>
          {rem_html}
          <div class="scan-detail">Scanner detail: {_esc(r.detail)}</div>
        </div>"""

        controls_html = "\n".join(ctrl_html(r) for r in results)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        llm_label = f"LLM: {self.model} via Ollama (self-hosted)" if not fallback else "LLM unavailable — showing scanner output only"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CloudGuard GDPR Compliance Report</title>
  <style>{self._CSS}</style>
</head>
<body>
  <h1>CloudGuard — GDPR Compliance Report</h1>
  <p class="subtitle">Automated GDPR Compliance Monitoring &nbsp;·&nbsp; AWS + GCP Hybrid Multi-Cloud</p>
  <p class="meta">Scan: {ts} &nbsp;·&nbsp; Duration: {summary.elapsed_seconds:.2f}s &nbsp;·&nbsp; Controls: {summary.total} &nbsp;·&nbsp; {llm_label}</p>
  {cards}
  <div class="section-head">Control Results — LLM-Generated Explanations &amp; Remediation</div>
  {controls_html}
  <div class="llm-note">
    Compliance determinations (Pass / Fail / Error) are produced by the deterministic evaluator only.<br>
    Natural-language explanations and remediation guidance are generated by {self.model} served locally via Ollama.<br>
    The LLM does not query cloud APIs, does not see credentials or raw responses, and does not influence compliance outcomes.<br>
    Joseph Oviawe · A00047180 · TU Dublin MSc Cybersecurity · June 2026
  </div>
</body>
</html>"""

    # ── Public entry point ────────────────────────────────────────────────────

    def write_html(
        self,
        results: list[CheckResult],
        summary: EvaluationSummary,
        output_path: Path,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fallback = False
        llm_data: list[dict] = []

        try:
            # Split into two batches (AWS C-01–C-10, GCP C-11–C-20) so each
            # Ollama call stays well within the timeout budget.
            batch_size = 10
            for i in range(0, len(results), batch_size):
                batch = results[i : i + batch_size]
                prompt = self._build_prompt(batch)
                raw = self._call_ollama(prompt)
                llm_data.extend(self._parse_llm_json(raw))
            logger.info("LLM generated explanations for %d controls", len(llm_data))
        except Exception as exc:
            logger.warning("LLM report generation failed (%s) — falling back to scanner output only", exc)
            fallback = True
            # Build minimal fallback entries so the HTML still renders
            llm_data = [
                {
                    "id": r.control_id,
                    "explanation": f"{r.title}. {r.gdpr_clause} ({r.article}).",
                    "status_note": f"Status: {r.status.value}. {r.detail}",
                    "remediation": r.remediation if r.status == Status.FAIL else "",
                }
                for r in results
            ]

        html = self._build_html(results, summary, llm_data, fallback=fallback)
        output_path.write_text(html)
        logger.info("HTML report written to %s", output_path)


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
