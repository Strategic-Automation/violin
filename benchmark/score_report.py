from __future__ import annotations

from typing import Any


def print_result(result: dict[str, Any]) -> None:
    print("\n" + "=" * 79)
    print("  VIOLIN BENCHMARK — PRIVATE GOLDEN EVALUATION")
    print("=" * 79)
    print(f"FINDINGS     {result['confirmed']}/{result['total']} ({result['finding_score_pct']}%)")
    print(
        f"DEMONSTRATED {result['demonstrated']}/{result['total']} "
        f"({result['demonstrated_score_pct']}%)"
    )
    coverage = result["coverage"]
    methodology = result["methodology"]
    print(f"COVERAGE     {coverage['completed']}/{coverage['total']} ({coverage['percent']}%)")
    print(
        f"METHODOLOGY  {methodology['completed']}/{methodology['total']} "
        f"({methodology['percent']}%)"
    )
    print(f"UNMATCHED    {len(result['unmatched_findings'])}")
    false_positives = result["reported_false_positive_rate"]
    print(
        f"FP RATE      {false_positives['false_positives']}/"
        f"{false_positives['reported_high_medium']} ({false_positives['percent']}%)"
    )
    protocol = result["protocol_alignment"]
    print(f"PROTOCOL     {'ALIGNED' if protocol['comparable'] else 'MISALIGNED'}")
    print(f"VIOLIN GATE  {'PASS' if result['benchmark_pass'] else 'FAIL'}")


def generate_markdown_summary(result: dict[str, Any]) -> str:
    coverage = result["coverage"]
    methodology = result["methodology"]
    lines = [
        "# Violin Benchmark Result",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Validated findings | {result['confirmed']}/{result['total']} ({result['finding_score_pct']}%) |",
        f"| Demonstrated capabilities | {result['demonstrated']}/{result['total']} ({result['demonstrated_score_pct']}%) |",
        f"| Demonstrated but unreported | {len(result['unreported_demonstrated_ids'])} |",
        f"| Coverage | {coverage['completed']}/{coverage['total']} ({coverage['percent']}%) |",
        f"| Methodology | {methodology['completed']}/{methodology['total']} ({methodology['percent']}%) |",
        f"| Unmatched submissions | {len(result['unmatched_findings'])} |",
        f"| Multi-case submissions | {len(result['multi_case_findings'])} |",
        f"| Reported HIGH/MEDIUM FP rate | {result['reported_false_positive_rate']['percent']}% |",
        f"| Protocol | {'Aligned' if result['protocol_alignment']['comparable'] else 'Misaligned'} |",
        f"| Violin gate | {'PASS' if result['benchmark_pass'] else 'FAIL'} |",
        "",
    ]
    return "\n".join(lines)
