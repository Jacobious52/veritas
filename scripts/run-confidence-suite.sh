#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${VERITAS_CONFIDENCE_OUT_DIR:-${repo_root}/target/confidence-suite}"
suite="${VERITAS_CONFIDENCE_SUITE:-veritas-confidence-suite.toml}"
mkdir -p "${out_dir}"

report="${out_dir}/confidence-report.json"
summary="${out_dir}/confidence-summary.json"
history="${out_dir}/confidence-history.jsonl"

cd "${repo_root}"
cargo run -p veritas-cli --locked -- --root examples bench --suite "${suite}" --format json >"${report}"

python3 - "${report}" "${summary}" "${history}" <<'PY'
import json
import sys
import time
from pathlib import Path

report_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
history_path = Path(sys.argv[3])
report = json.loads(report_path.read_text())
cases = report.get("cases", [])
summary = {
    "run_id": str(int(time.time())),
    "suite": report.get("suite"),
    "profile": report.get("profile"),
    "passed": report.get("passed"),
    "total_cases": len(cases),
    "passed_cases": sum(1 for case in cases if case.get("passed")),
    "total_duration_ms": report.get("summary", {}).get("total_duration_ms", 0),
    "total_targets": report.get("summary", {}).get("total_targets", 0),
    "high_risk_targets": report.get("summary", {}).get("high_risk_targets", 0),
    "total_mutants_executed": report.get("summary", {}).get("total_mutants_executed", 0),
    "total_replay_cases": report.get("summary", {}).get("total_replay_cases", 0),
    "total_evolution_selected": report.get("summary", {}).get("total_evolution_selected", 0),
    "slowest_case": report.get("summary", {}).get("slowest_case"),
    "cases": [
        {
            "name": case.get("name"),
            "language": case.get("language"),
            "passed": case.get("passed"),
            "duration_ms": case.get("duration_ms"),
            "targets": case.get("metrics", {}).get("target_count"),
            "mutants_executed": case.get("metrics", {}).get("mutants_executed"),
            "mutation_score_percent": case.get("metrics", {}).get("mutation_score_percent"),
            "replay_cases": case.get("metrics", {}).get("replay_cases"),
            "evolution_selected": case.get("metrics", {}).get("evolution_selected"),
            "threshold_failures": case.get("threshold_failures", []),
        }
        for case in cases
    ],
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
with history_path.open("a") as handle:
    handle.write(json.dumps(summary, sort_keys=True) + "\n")
PY

echo "confidence report: ${report}"
echo "confidence summary: ${summary}"
echo "confidence history: ${history}"
