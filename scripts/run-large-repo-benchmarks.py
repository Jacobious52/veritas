#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path


LANGUAGE_EXTENSIONS = {
    "rust": [".rs"],
    "go": [".go"],
    "python": [".py"],
}


COMMENT_PREFIX = {
    "rust": "//",
    "go": "//",
    "python": "#",
}


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    manifest_path = resolve_path(repo_root, Path(args.manifest))
    manifest = tomllib.loads(manifest_path.read_text())
    out_dir = resolve_path(repo_root, Path(args.out_dir))
    checkout_root = resolve_path(repo_root, Path(args.checkout_root))
    out_dir.mkdir(parents=True, exist_ok=True)
    checkout_root.mkdir(parents=True, exist_ok=True)

    requested_modes = selected_modes(args, manifest)
    selected_names = set(args.repo or [])
    budgets = manifest.get("budgets", {})
    veritas = veritas_command(repo_root, args.veritas_bin)
    run_id = str(int(time.time()))
    results = []

    for repo in manifest.get("repo", []):
        if selected_names and repo["name"] not in selected_names:
            continue
        repo_modes = [
            mode
            for mode in repo.get("modes", manifest.get("default_modes", []))
            if mode in requested_modes
        ]
        if not repo_modes:
            continue
        checkout = prepare_repo(repo_root, checkout_root, repo)
        workspace = benchmark_workspace(checkout, repo)
        repo_result = {
            "run_id": run_id,
            "name": repo["name"],
            "language": repo["language"],
            "profile": repo.get("profile", "large-repo"),
            "repository": repo.get("repository"),
            "sha": repo.get("sha"),
            "root_path": repo.get("root_path", "."),
            "target": repo.get("target", "."),
            "budgets": repo.get("budgets", {}),
            "checkout": str(checkout),
            "workspace": str(workspace),
            "modes": [],
        }
        for mode in repo_modes:
            if mode == "scan":
                repo_result["modes"].append(run_scan(veritas, workspace, repo, out_dir, budgets))
            elif mode == "mutation-list":
                repo_result["modes"].append(run_mutation_list(veritas, workspace, repo, out_dir, budgets))
            elif mode == "mutation-inventory":
                repo_result["modes"].append(run_mutation_inventory(veritas, workspace, repo, out_dir, budgets))
            elif mode == "changed-only":
                repo_result["modes"].append(
                    run_changed_only(veritas, checkout, workspace, repo, out_dir, budgets)
                )
            else:
                repo_result["modes"].append(
                    {"mode": mode, "status": "skipped", "error": "unknown mode"}
                )
        results.append(repo_result)

    summary = summarize(manifest_path, run_id, requested_modes, results, budgets)
    write_outputs(out_dir, summary)
    print(f"large repo summary: {out_dir / 'large-repo-summary.json'}")
    print(f"large repo dashboard: {out_dir / 'large-repo-dashboard.md'}")
    if summary["threshold_failures"] and not args.allow_failures:
        return 1
    return 0


def parse_args():
    parser = argparse.ArgumentParser(description="Run pinned large-repo Veritas benchmarks")
    parser.add_argument("--manifest", default="benchmarks/large-repos.toml")
    parser.add_argument("--out-dir", default="target/large-repo-benchmarks/reports")
    parser.add_argument(
        "--checkout-root",
        default=os.environ.get(
            "VERITAS_LARGE_REPO_CHECKOUT_ROOT",
            "/tmp/veritas-large-repo-benchmarks/repos",
        ),
    )
    parser.add_argument(
        "--mode",
        action="append",
        choices=["scan", "mutation-list", "mutation-inventory", "changed-only", "all"],
    )
    parser.add_argument("--repo", action="append", help="Run only a named manifest repo")
    parser.add_argument("--veritas-bin", default=os.environ.get("VERITAS_BIN"))
    parser.add_argument("--allow-failures", action="store_true")
    return parser.parse_args()


def selected_modes(args, manifest):
    modes = args.mode or manifest.get("default_modes", ["scan"])
    if "all" in modes:
        return {"scan", "mutation-list", "mutation-inventory", "changed-only"}
    return set(modes)


def resolve_path(repo_root, path):
    return path if path.is_absolute() else repo_root / path


def veritas_command(repo_root, explicit):
    if explicit:
        return [explicit]
    return ["cargo", "run", "-p", "veritas-cli", "--locked", "--"]


def prepare_repo(repo_root, checkout_root, repo):
    name = repo["name"]
    dest = checkout_root / name
    if repo.get("local_path"):
        source = resolve_path(repo_root, Path(repo["local_path"]))
        if dest.exists():
            shutil.rmtree(dest)
        ignore = shutil.ignore_patterns(".git", ".veritas", "target", "__pycache__", ".pytest_cache")
        shutil.copytree(source, dest, ignore=ignore)
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
        subprocess.run(["git", "config", "user.email", "veritas@example.test"], cwd=dest, check=True)
        subprocess.run(["git", "config", "user.name", "veritas"], cwd=dest, check=True)
        subprocess.run(["git", "add", "."], cwd=dest, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=dest, check=True)
        return dest

    if not dest.exists():
        dest.mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
        subprocess.run(["git", "remote", "add", "origin", repo["repository"]], cwd=dest, check=True)
    subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", repo["sha"]], cwd=dest, check=True)
    subprocess.run(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], cwd=dest, check=True)
    subprocess.run(["git", "clean", "-fdx", "-q"], cwd=dest, check=True)
    return dest


def benchmark_workspace(checkout, repo):
    root_path = repo.get("root_path", ".")
    workspace = checkout / root_path
    if not workspace.exists():
        raise RuntimeError(f"benchmark root_path does not exist for {repo['name']}: {root_path}")
    return workspace


def run_scan(veritas, workspace, repo, out_dir, budgets):
    output = out_dir / f"{repo['name']}-scan.json"
    result = timed_command(
        veritas + ["--root", str(workspace), "scan", "--format", "json"],
        timeout=budget(repo, budgets, "scan_timeout_seconds", 120),
    )
    output.write_text(result["stdout"])
    metrics = {}
    if result["status"] == "passed":
        metrics = scan_metrics(load_json_text(result["stdout"]))
    return mode_result("scan", result, metrics, str(output))


def run_mutation_list(veritas, workspace, repo, out_dir, budgets):
    output = out_dir / f"{repo['name']}-mutants.json"
    result = timed_command(
        veritas
        + [
            "--root",
            str(workspace),
            "mutants",
            "list",
            "--lang",
            repo["language"],
            "--target",
            repo.get("target", "."),
            "--format",
            "json",
        ],
        timeout=budget(repo, budgets, "mutation_list_timeout_seconds", 180),
    )
    output.write_text(result["stdout"])
    metrics = {}
    if result["status"] == "passed":
        metrics = mutant_metrics(load_json_text(result["stdout"]))
    cleanup_workspace(veritas, workspace)
    return mode_result("mutation-list", result, metrics, str(output))


def run_mutation_inventory(veritas, workspace, repo, out_dir, budgets):
    output = out_dir / f"{repo['name']}-mutation-inventory.json"
    scan = timed_command(
        veritas + ["--root", str(workspace), "scan", "--format", "json"],
        timeout=budget(repo, budgets, "scan_timeout_seconds", 120),
    )
    if scan["status"] != "passed":
        output.write_text(json.dumps({"scan_status": scan["status"], "stderr": scan["stderr"]}, indent=2))
        return mode_result("mutation-inventory", scan, {}, str(output))

    scan_payload = load_json_text(scan["stdout"])
    paths = inventory_source_paths(scan_payload, repo)
    max_paths = budget(repo, budgets, "mutation_inventory_max_paths", 0)
    if max_paths > 0:
        paths = paths[:max_paths]
    max_mutants = budget(repo, budgets, "mutation_inventory_max_mutants_per_path", 64)
    target_timeout = budget(repo, budgets, "mutation_inventory_target_timeout_seconds", 90)
    records_by_id = {}
    path_results = []
    start = time.monotonic()
    status = "passed"
    stderr = ""

    for path in paths:
        result = timed_command(
            veritas
            + [
                "--root",
                str(workspace),
                "mutants",
                "list",
                "--lang",
                repo["language"],
                "--target",
                path,
                "--max-mutants",
                str(max_mutants),
                "--format",
                "json",
            ],
            timeout=target_timeout,
        )
        cleanup_workspace(veritas, workspace)
        path_item = {
            "path": path,
            "status": result["status"],
            "duration_ms": result["duration_ms"],
            "mutants": 0,
            "cap_hit": False,
        }
        if result["status"] == "passed":
            payload = load_json_text(result["stdout"])
            records = payload.get("records", [])
            path_item["mutants"] = len(records)
            path_item["cap_hit"] = len(records) >= max_mutants
            for record in records:
                records_by_id.setdefault(record.get("id", ""), record)
        else:
            status = "failed"
            path_item["stderr_tail"] = result["stderr"][-2000:]
            stderr += result["stderr"][-2000:]
        path_results.append(path_item)

    records = [record for key, record in sorted(records_by_id.items()) if key]
    payload = {
        "version": 1,
        "repo": repo["name"],
        "language": repo["language"],
        "workspace": str(workspace),
        "source_paths": len(paths),
        "max_mutants_per_path": max_mutants,
        "unique_mutants": len(records),
        "path_results": path_results,
        "records": records,
        "metrics": inventory_metrics(records, path_results, len(paths), max_mutants),
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    command_result = {
        "status": status,
        "exit_code": 0 if status == "passed" else 1,
        "duration_ms": int((time.monotonic() - start) * 1000),
        "stdout": json.dumps(payload),
        "stderr": stderr,
        "command": ["mutation-inventory", repo["name"]],
    }
    return mode_result("mutation-inventory", command_result, payload["metrics"], str(output))


def run_changed_only(veritas, checkout, workspace, repo, out_dir, budgets):
    reset_workspace(checkout)
    changed_path = choose_changed_path(workspace, repo)
    insert_change_marker(changed_path, repo)
    output = out_dir / f"{repo['name']}-changed-verify.md"
    report_output = out_dir / f"{repo['name']}-changed-report.json"
    result = timed_command(
        veritas
        + [
            "--root",
            str(workspace),
            "verify",
            "--changed",
            "--profile",
            "ci",
            "--lang",
            repo["language"],
        ],
        timeout=budget(repo, budgets, "changed_verify_timeout_seconds", 240),
    )
    output.write_text(result["stdout"])
    metrics = {"changed_path": str(changed_path.relative_to(workspace))}
    report_path = workspace / ".veritas" / "report.json"
    if report_path.exists():
        shutil.copyfile(report_path, report_output)
        metrics.update(report_metrics(load_json(report_path)))
        if result["status"] == "failed":
            result["status"] = "reported"
    cleanup_workspace(veritas, workspace)
    reset_workspace(checkout)
    return mode_result("changed-only", result, metrics, str(output), report_path=str(report_output))


def timed_command(command, timeout):
    start = time.monotonic()
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
        status = "passed" if completed.returncode == 0 else "failed"
        return {
            "status": status,
            "exit_code": completed.returncode,
            "duration_ms": int((time.monotonic() - start) * 1000),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": command,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "status": "timed_out",
            "exit_code": None,
            "duration_ms": int((time.monotonic() - start) * 1000),
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "command": command,
        }


def mode_result(mode, command_result, metrics, output_path, report_path=None):
    item = {
        "mode": mode,
        "status": command_result["status"],
        "exit_code": command_result["exit_code"],
        "duration_ms": command_result["duration_ms"],
        "command": shell_join(command_result["command"]),
        "output_path": output_path,
        "metrics": metrics,
    }
    if report_path:
        item["report_path"] = report_path
    if command_result["status"] != "passed":
        item["stderr_tail"] = command_result["stderr"][-4000:]
    return item


def scan_metrics(scan):
    targets = scan.get("targets", [])
    by_kind = {}
    for target in targets:
        by_kind[target.get("kind", "unknown")] = by_kind.get(target.get("kind", "unknown"), 0) + 1
    return {
        "targets": len(targets),
        "projects": len([scan.get("project")] if scan.get("project") else []),
        "targets_by_kind": by_kind,
    }


def mutant_metrics(payload):
    records = payload.get("records", [])
    by_status = {}
    by_domain = {}
    for record in records:
        by_status[record.get("status", "unknown")] = by_status.get(record.get("status", "unknown"), 0) + 1
        by_domain[record.get("domain", "unknown")] = by_domain.get(record.get("domain", "unknown"), 0) + 1
    return {
        "mutants": payload.get("count", len(records)),
        "records": len(records),
        "by_status": by_status,
        "by_domain": by_domain,
    }


def inventory_metrics(records, path_results, source_paths, max_mutants):
    by_status = {}
    by_domain = {}
    by_operator = {}
    for record in records:
        by_status[record.get("status", "unknown")] = by_status.get(record.get("status", "unknown"), 0) + 1
        by_domain[record.get("domain", "unknown")] = by_domain.get(record.get("domain", "unknown"), 0) + 1
        by_operator[record.get("operator", "unknown")] = by_operator.get(record.get("operator", "unknown"), 0) + 1
    paths_with_mutants = sum(1 for item in path_results if item.get("mutants", 0) > 0)
    cap_hit_paths = sum(1 for item in path_results if item.get("cap_hit"))
    failed_paths = sum(1 for item in path_results if item.get("status") != "passed")
    return {
        "mutants": len(records),
        "unique_mutants": len(records),
        "source_paths": source_paths,
        "paths_with_mutants": paths_with_mutants,
        "paths_without_mutants": max(source_paths - paths_with_mutants - failed_paths, 0),
        "failed_paths": failed_paths,
        "cap_hit_paths": cap_hit_paths,
        "max_mutants_per_path": max_mutants,
        "by_status": by_status,
        "by_domain": by_domain,
        "by_operator": by_operator,
    }


def report_metrics(report):
    quality = report.get("quality", {})
    confidence = artifact_payload(report, "confidence_score") or {}
    return {
        "targets": len(report.get("targets", [])),
        "findings": len(report.get("findings", [])),
        "commands": sum(len(run.get("commands", [])) for run in report.get("runs", [])),
        "confidence": confidence.get("score"),
        "mutation_score": quality.get("mutation", {}).get("score_percent"),
        "mutants_executed": quality.get("mutation", {}).get("executed", 0),
        "replay_cases": quality.get("replay", {}).get("cases", 0),
        "budget_skips": quality.get("budget", {}).get("skipped_commands", 0),
        "budget_timeouts": quality.get("budget", {}).get("timed_out_commands", 0),
        "phase_timings": quality.get("performance", {}),
    }


def artifact_payload(report, kind):
    for artifact in report.get("artifacts", []):
        if artifact.get("kind") == kind:
            try:
                return json.loads(artifact.get("contents", "{}"))
            except json.JSONDecodeError:
                return None
    return None


def summarize(manifest_path, run_id, modes, results, budgets):
    failures = []
    for repo in results:
        repo_budgets = {"budgets": repo.get("budgets", {})}
        min_targets = budget(repo_budgets, budgets, "min_targets", 0)
        min_mutants = budget(repo_budgets, budgets, "min_mutants", 0)
        min_inventory_mutants = budget(repo_budgets, budgets, "min_inventory_mutants", 0)
        min_changed_targets = budget(repo_budgets, budgets, "min_changed_targets", 0)
        for item in repo["modes"]:
            if item["status"] not in ("passed", "reported"):
                failures.append(f"{repo['name']} {item['mode']} {item['status']}")
            if item["mode"] == "scan" and item["metrics"].get("targets", 0) < min_targets:
                failures.append(
                    f"{repo['name']} scan targets {item['metrics'].get('targets', 0)} below {min_targets}"
                )
            if item["mode"] == "mutation-list" and item["metrics"].get("mutants", 0) < min_mutants:
                failures.append(
                    f"{repo['name']} mutation candidates {item['metrics'].get('mutants', 0)} below {min_mutants}"
                )
            if (
                item["mode"] == "mutation-inventory"
                and item["metrics"].get("unique_mutants", 0) < min_inventory_mutants
            ):
                failures.append(
                    f"{repo['name']} inventory mutants {item['metrics'].get('unique_mutants', 0)} below {min_inventory_mutants}"
                )
            if (
                item["mode"] == "changed-only"
                and item["metrics"].get("targets", 0) < min_changed_targets
            ):
                failures.append(
                    f"{repo['name']} changed targets {item['metrics'].get('targets', 0)} below {min_changed_targets}"
                )
    return {
        "run_id": run_id,
        "manifest": str(manifest_path),
        "modes": sorted(modes),
        "passed": not failures,
        "threshold_failures": failures,
        "summary": aggregate(results),
        "repos": results,
    }


def aggregate(results):
    modes = [mode for repo in results for mode in repo["modes"]]
    return {
        "repos": len(results),
        "mode_runs": len(modes),
        "passed_mode_runs": sum(1 for mode in modes if mode["status"] in ("passed", "reported")),
        "total_duration_ms": sum(mode.get("duration_ms", 0) for mode in modes),
        "total_scan_targets": sum(
            mode.get("metrics", {}).get("targets", 0)
            for mode in modes
            if mode["mode"] == "scan"
        ),
        "total_mutation_candidates": sum(
            mode.get("metrics", {}).get("mutants", 0)
            for mode in modes
            if mode["mode"] == "mutation-list"
        ),
        "total_inventory_mutants": sum(
            mode.get("metrics", {}).get("unique_mutants", 0)
            for mode in modes
            if mode["mode"] == "mutation-inventory"
        ),
        "inventory_source_paths": sum(
            mode.get("metrics", {}).get("source_paths", 0)
            for mode in modes
            if mode["mode"] == "mutation-inventory"
        ),
        "changed_verify_targets": sum(
            mode.get("metrics", {}).get("targets", 0)
            for mode in modes
            if mode["mode"] == "changed-only"
        ),
        "slowest_mode": max(modes, key=lambda mode: mode.get("duration_ms", 0), default={}).get("mode"),
    }


def write_outputs(out_dir, summary):
    (out_dir / "large-repo-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    with (out_dir / "large-repo-history.jsonl").open("a") as handle:
        handle.write(json.dumps(history_row(summary), sort_keys=True) + "\n")
    (out_dir / "large-repo-dashboard.md").write_text(render_dashboard(summary))


def history_row(summary):
    row = {
        "run_id": summary["run_id"],
        "passed": summary["passed"],
        **summary["summary"],
    }
    return row


def render_dashboard(summary):
    lines = [
        "# Veritas Large-Repo Benchmark Dashboard",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Status: `{'passed' if summary['passed'] else 'failed'}`",
        f"- Modes: `{', '.join(summary['modes'])}`",
        "",
        "| Repo | Profile | Lang | Mode | Status | Duration | Targets | Mutants | Changed Targets | Findings | Confidence |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for repo in summary["repos"]:
        for mode in repo["modes"]:
            metrics = mode.get("metrics", {})
            lines.append(
                "| {name} | {profile} | {lang} | {mode} | {status} | {duration} | {targets} | {mutants} | {changed_targets} | {findings} | {confidence} |".format(
                    name=repo["name"],
                    profile=repo["profile"],
                    lang=repo["language"],
                    mode=mode["mode"],
                    status=mode["status"],
                    duration=mode["duration_ms"],
                    targets=metrics.get("targets", ""),
                    mutants=metrics.get("mutants", ""),
                    changed_targets=metrics.get("targets", "") if mode["mode"] == "changed-only" else "",
                    findings=metrics.get("findings", ""),
                    confidence=metrics.get("confidence", ""),
                )
            )
    lines.extend(["", "## Threshold Failures", ""])
    if summary["threshold_failures"]:
        lines.extend(f"- {failure}" for failure in summary["threshold_failures"])
    else:
        lines.append("- None")
    lines.extend([
        "",
        "## Notes",
        "",
        "- `scan` measures Tree-sitter/project discovery and target counts.",
        "- `mutation-list` previews generic Tree-sitter mutation candidates without running native tests.",
        "- `mutation-inventory` walks discovered source files, previews bounded mutation candidates per file, dedupes them by mutant id, and reports cap-hit/source-path coverage.",
        "- `changed-only` applies a harmless marker to a configured source file and runs `verify --changed --profile ci` to simulate AI-agent scoped verification.",
    ])
    return "\n".join(lines) + "\n"


def budget(repo, budgets, key, default):
    repo_budgets = repo.get("budgets", {})
    return int(repo_budgets.get(key, budgets.get(key, default)))


def choose_changed_path(workspace, repo):
    configured = repo.get("changed_path")
    if configured:
        path = workspace / configured
        if path.exists():
            return path
    extensions = LANGUAGE_EXTENSIONS.get(repo["language"], [])
    for path in workspace.rglob("*"):
        if path.suffix in extensions and should_use_source_path(path):
            return path
    raise RuntimeError(f"no changed path found for {repo['name']}")


def inventory_source_paths(scan, repo):
    extensions = set(LANGUAGE_EXTENSIONS.get(repo["language"], []))
    paths = []
    for target in scan.get("targets", []):
        path = target.get("path")
        if not path or path == ".":
            continue
        if extensions and Path(path).suffix not in extensions:
            continue
        if target.get("kind") not in ("function", "file"):
            continue
        paths.append(path)
    return sorted(set(paths))


def insert_change_marker(path, repo):
    marker = f"{COMMENT_PREFIX.get(repo['language'], '#')} veritas large-repo changed-only benchmark"
    changed_line = repo.get("changed_line")
    if not changed_line:
        with path.open("a") as handle:
            handle.write(f"\n{marker}\n")
        return

    lines = path.read_text().splitlines(keepends=True)
    index = max(0, min(int(changed_line), len(lines)) - 1)
    anchor = lines[index] if lines else ""
    indent = anchor[: len(anchor) - len(anchor.lstrip())]
    newline = "\r\n" if anchor.endswith("\r\n") else "\n"
    lines.insert(index + 1, f"{indent}{marker}{newline}")
    path.write_text("".join(lines))


def should_use_source_path(path):
    parts = set(path.parts)
    return not (
        ".git" in parts
        or ".veritas" in parts
        or "target" in parts
        or "vendor" in parts
        or "__pycache__" in parts
    )


def cleanup_workspace(veritas, workspace):
    timed_command(veritas + ["--root", str(workspace), "cleanup"], timeout=60)


def reset_workspace(workspace):
    if (workspace / ".git").exists():
        subprocess.run(["git", "reset", "--hard", "-q", "HEAD"], cwd=workspace, check=True)
        subprocess.run(["git", "clean", "-fd", "-q", ".veritas"], cwd=workspace, check=False)


def load_json(path):
    return json.loads(path.read_text())


def load_json_text(text):
    return json.loads(text)


def shell_join(command):
    return " ".join(str(part) for part in command)


if __name__ == "__main__":
    raise SystemExit(main())
