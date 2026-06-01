#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path


def load_json(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def artifact_payload(report, kind):
    for artifact in report.get("artifacts", []):
        if artifact.get("kind") != kind:
            continue
        try:
            return json.loads(artifact.get("contents", "{}"))
        except json.JSONDecodeError:
            return None
    return None


def confidence(report):
    payload = artifact_payload(report, "confidence_score")
    if payload:
        return payload.get("score"), payload.get("grade")
    return None, None


def mutation_score(report):
    return (
        report.get("quality", {})
        .get("mutation", {})
        .get("score_percent")
    )


def severity_counts(report):
    counts = {}
    for finding in report.get("findings", []):
        severity = finding.get("severity", "error")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def scan_summary(path):
    scan = load_json(path)
    if not scan:
        return {}
    return {
        "targets": len(scan.get("targets", [])),
        "projects": len([scan.get("project")] if scan.get("project") else []),
    }


def report_summary(path):
    report = load_json(path)
    if not report:
        return {}
    score, grade = confidence(report)
    mutation = mutation_score(report)
    quality = report.get("quality", {})
    return {
        "targets": len(report.get("targets", [])),
        "findings": len(report.get("findings", [])),
        "severity": severity_counts(report),
        "confidence": score,
        "grade": grade,
        "mutation_score": mutation,
        "replay_cases": quality.get("replay", {}).get("cases", 0),
        "commands": sum(len(run.get("commands", [])) for run in report.get("runs", [])),
        "budget_timeouts": quality.get("budget", {}).get("timed_out_commands", 0),
        "budget_skips": quality.get("budget", {}).get("skipped_commands", 0),
    }


def tier(summary):
    if summary.get("confidence") is None:
        return "scan"
    confidence = summary.get("confidence")
    findings = summary.get("findings", 0)
    if confidence is not None and confidence >= 80 and findings == 0:
        return "high"
    if confidence is not None and confidence >= 50:
        return "medium"
    return "low"


def previous_by_name(history, run_id):
    previous = {}
    for item in history:
        if item.get("run_id") == run_id:
            continue
        previous[item.get("name")] = item
    return previous


def delta(current, previous, key):
    if not previous:
        return ""
    before = previous.get(key)
    after = current.get(key)
    if before is None or after is None:
        return ""
    change = after - before
    if change == 0:
        return "0"
    return f"{change:+}"


def threshold_failures(summaries):
    failures = []
    min_tier = os.environ.get("VERITAS_CANARY_MIN_TIER")
    min_confidence = int_threshold("VERITAS_CANARY_MIN_CONFIDENCE")
    max_findings = int_threshold("VERITAS_CANARY_MAX_FINDINGS")

    if min_tier:
        order = {"scan": 0, "low": 1, "medium": 2, "high": 3}
        wanted = order.get(min_tier)
        if wanted is None:
            failures.append(f"invalid VERITAS_CANARY_MIN_TIER={min_tier!r}")
        else:
            for item in summaries:
                if order.get(item.get("tier"), -1) < wanted:
                    failures.append(
                        f"{item['name']} tier {item.get('tier')} is below required {min_tier}"
                    )

    if min_confidence is not None:
        if isinstance(min_confidence, str):
            failures.append(
                f"invalid VERITAS_CANARY_MIN_CONFIDENCE={min_confidence!r}"
            )
        else:
            for item in summaries:
                confidence = item.get("confidence")
                if confidence is None:
                    failures.append(f"{item['name']} has no confidence score")
                elif confidence < min_confidence:
                    failures.append(
                        f"{item['name']} confidence {confidence} is below required {min_confidence}"
                    )

    if max_findings is not None:
        if isinstance(max_findings, str):
            failures.append(f"invalid VERITAS_CANARY_MAX_FINDINGS={max_findings!r}")
        else:
            for item in summaries:
                findings = item.get("findings")
                if findings is not None and findings > max_findings:
                    failures.append(
                        f"{item['name']} findings {findings} exceeds allowed {max_findings}"
                    )

    return failures


def int_threshold(name):
    value = os.environ.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except ValueError:
        return value


def main():
    if len(sys.argv) != 3:
        print("usage: canary-dashboard.py <report-dir> <mode>", file=sys.stderr)
        return 2

    report_dir = Path(sys.argv[1])
    mode = sys.argv[2]
    run_id = str(int(time.time()))
    canaries_path = report_dir / "canaries.json"
    canaries = load_json(canaries_path) or []
    summaries = []

    for canary in canaries:
        name = canary["name"]
        item = {
            "run_id": run_id,
            "name": name,
            "language": canary["language"],
            "repository": canary["repository"],
            "sha": canary["sha"],
            "mode": mode,
        }
        item.update(scan_summary(report_dir / f"{name}-scan.json"))
        if (report_dir / f"{name}-report.json").exists():
            item.update(report_summary(report_dir / f"{name}-report.json"))
        item["tier"] = tier(item)
        summaries.append(item)

    history_path = report_dir / "canary-history.jsonl"
    history = []
    if history_path.exists():
        history = [
            json.loads(line)
            for line in history_path.read_text().splitlines()
            if line.strip()
        ]
    previous = previous_by_name(history, run_id)
    with history_path.open("a") as handle:
        for item in summaries:
            handle.write(json.dumps(item, sort_keys=True) + "\n")

    failures = threshold_failures(summaries)
    summary_path = report_dir / "canary-summary.json"
    summary_path.write_text(
        json.dumps(
            {"run_id": run_id, "canaries": summaries, "threshold_failures": failures},
            indent=2,
        )
        + "\n"
    )

    lines = [
        "# Veritas External Canary Dashboard",
        "",
        f"- Mode: `{mode}`",
        f"- Run ID: `{run_id}`",
        f"- Threshold status: `{'passed' if not failures else 'failed'}`",
        "",
        "| Canary | Lang | Tier | Targets | Findings | Confidence | Mutation | Replay | Trend |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in summaries:
        prior = previous.get(item["name"])
        trend_bits = []
        conf_delta = delta(item, prior, "confidence")
        mutation_delta = delta(item, prior, "mutation_score")
        finding_delta = delta(item, prior, "findings")
        if conf_delta:
            trend_bits.append(f"conf {conf_delta}")
        if mutation_delta:
            trend_bits.append(f"mut {mutation_delta}")
        if finding_delta:
            trend_bits.append(f"find {finding_delta}")
        trend = ", ".join(trend_bits) if trend_bits else "new"
        lines.append(
            "| {name} | {language} | {tier} | {targets} | {findings} | {confidence} | {mutation_score} | {replay_cases} | {trend} |".format(
                name=item["name"],
                language=item["language"],
                tier=item["tier"],
                targets=item.get("targets", 0),
                findings=item.get("findings", 0),
                confidence=item.get("confidence", ""),
                mutation_score=item.get("mutation_score", ""),
                replay_cases=item.get("replay_cases", 0),
                trend=trend,
            )
        )

    lines.extend([
        "",
        "## Notes",
        "",
        "- `scan` tier means the canary parsed and target discovery completed.",
        "- `high`, `medium`, and `low` are verify-mode confidence tiers from the saved Veritas report.",
        "- Trend values compare against the previous local history entry for the same canary when available.",
        "",
    ])
    if failures:
        lines.extend(["## Threshold Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)
        lines.append("")
    (report_dir / "canary-dashboard.md").write_text("\n".join(lines))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
