"""Evaluator — computes summary metrics from a list of CheckResults."""

from dataclasses import dataclass

from cloudguard.models import CheckResult, Status


@dataclass
class EvaluationSummary:
    total: int
    passed: int
    failed: int
    errored: int
    precision: float     # TP / (TP + FP)  — of reported failures, how many are real
    recall: float        # TP / (TP + FN)  — of real violations, how many did we catch
    f1: float
    false_positive_rate: float
    elapsed_seconds: float

    # ground-truth fields (populated only in evaluation mode)
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0


def compute_metrics(
    results: list[CheckResult],
    elapsed: float,
    ground_truth: dict[str, bool] | None = None,
) -> EvaluationSummary:
    """
    Compute precision/recall/F1 from results.

    If ground_truth is supplied it must be a dict mapping control_id → True (compliant)
    / False (violation).  When absent, metrics are computed assuming every FAIL is a
    true positive (no false-positive / false-negative oracle available).
    """
    total = len(results)
    passed = sum(1 for r in results if r.status == Status.PASS)
    failed = sum(1 for r in results if r.status == Status.FAIL)
    errored = sum(1 for r in results if r.status == Status.ERROR)

    if ground_truth:
        tp = fp = tn = fn = 0
        for r in results:
            if r.status == Status.ERROR:
                continue
            reported_fail = r.status == Status.FAIL
            actual_violation = not ground_truth.get(r.control_id, True)

            if reported_fail and actual_violation:
                tp += 1
            elif reported_fail and not actual_violation:
                fp += 1
            elif not reported_fail and actual_violation:
                fn += 1
            else:  # not reported_fail and not actual_violation
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    else:
        tp = fp = tn = fn = 0
        # Without ground truth, treat every FAIL as a TP and every PASS as a TN.
        precision = 1.0
        recall = 1.0 if failed > 0 else 1.0
        fpr = 0.0

    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return EvaluationSummary(
        total=total,
        passed=passed,
        failed=failed,
        errored=errored,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
        elapsed_seconds=elapsed,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
    )
