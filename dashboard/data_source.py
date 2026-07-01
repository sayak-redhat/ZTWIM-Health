"""Hybrid data source hub for live Jira and Result fallback."""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
RESULT_DIR = ROOT_DIR / "Result"
GITHUB_API_BASE = "https://api.github.com"
DEFAULT_GITHUB_REPO = "openshift/zero-trust-workload-identity-manager"
DEFAULT_REGRESSION_ARTIFACTS_DIR = "/home/sayadas/RedHat-Workspace/ztwim-test-framework"
CONFIG_FILE = Path(os.environ.get("ZTWIM_CONFIG_FILE", ROOT_DIR / "config" / "report-config.json"))


@dataclass
class SourceResult:
    source: str
    eng_bugs: list[dict]
    cust_bugs: list[dict]
    cves: list[dict]
    other: list[dict]
    date_range_label: str | None
    category_breakdown: dict[str, dict[str, int]] | None
    warnings: list[str]


@dataclass
class GitHubPRSourceResult:
    repo: str
    open_pr_count: int
    open_prs_in_repo: list[dict]
    closed_prs_in_range: list[dict]
    warnings: list[str]


@dataclass
class RegressionTestSourceResult:
    artifacts_dir: str
    runs: list[dict]
    warnings: list[str]
    log_summary: dict[str, object] = field(default_factory=dict)


def _load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


_CONFIG = _load_config()


def default_github_repo() -> str:
    return (os.environ.get("GITHUB_REPO") or _CONFIG.get("github_repo", DEFAULT_GITHUB_REPO)).strip()


def default_regression_artifacts_dir() -> str:
    return (
        os.environ.get("ZTWIM_REGRESSION_ARTIFACTS_DIR")
        or _CONFIG.get("regression_artifacts_dir", DEFAULT_REGRESSION_ARTIFACTS_DIR)
    ).strip()


def _parse_run_timestamp(raw: str) -> datetime | None:
    for fmt in ("%Y-%m-%d_%H-%M-%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _parse_duration_seconds(raw: str | float | int | None) -> float:
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if not text:
        return 0.0
    if ":" not in text:
        try:
            return float(text)
        except ValueError:
            return 0.0
    parts = text.split(":")
    try:
        if len(parts) == 3:
            hh = int(parts[0])
            mm = int(parts[1])
            ss = float(parts[2])
            return float(hh * 3600 + mm * 60) + ss
        if len(parts) == 2:
            mm = int(parts[0])
            ss = float(parts[1])
            return float(mm * 60) + ss
    except ValueError:
        return 0.0
    return 0.0


def _suite_from_test_id(test_id: str) -> str:
    lower = test_id.lower()
    if "tests/federation/" in lower:
        return "federation"
    if "tests/ossm/" in lower:
        return "ossm"
    return "unknown"


def _github_token() -> str:
    return (os.environ.get("GITHUB_TOKEN") or _CONFIG.get("github_token", "")).strip()


def _parse_github_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def _github_headers(token: str) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ztwim-velocity-dashboard",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_get_json(url: str, token: str) -> list | dict:
    req = urllib.request.Request(url, headers=_github_headers(token), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API request failed (HTTP {exc.code}): {detail[:240]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub API request failed: {exc}") from exc


def _fetch_repo_pulls(
    repo: str,
    state: str,
    token: str,
    start_date: date | None = None,
    end_date: date | None = None,
    max_pages: int = 50,
) -> tuple[list[dict], bool]:
    page = 1
    per_page = 100
    collected: list[dict] = []
    truncated = False

    while page <= max_pages:
        query = urllib.parse.urlencode(
            {
                "state": state,
                "sort": "updated",
                "direction": "desc",
                "per_page": per_page,
                "page": page,
            }
        )
        url = f"{GITHUB_API_BASE}/repos/{repo}/pulls?{query}"
        data = _github_get_json(url, token)
        if not isinstance(data, list):
            raise RuntimeError("Unexpected GitHub API response shape for pull requests list.")
        if not data:
            break

        if state == "closed" and start_date and end_date:
            page_dates: list[date] = []
            for pr in data:
                closed_at = _parse_github_datetime(pr.get("closed_at"))
                if not closed_at:
                    continue
                closed_date = closed_at.date()
                page_dates.append(closed_date)
                if start_date <= closed_date <= end_date:
                    collected.append(pr)
            if page_dates and max(page_dates) < start_date:
                break
        else:
            collected.extend(data)

        if len(data) < per_page:
            break
        page += 1

    if page > max_pages:
        truncated = True
    return collected, truncated


def load_github_pr_source(start_date: date, end_date: date, repo: str | None = None) -> GitHubPRSourceResult:
    repo_name = (repo or default_github_repo()).strip()
    if not repo_name or "/" not in repo_name:
        raise RuntimeError("GitHub repo must be in `owner/repo` format.")

    token = _github_token()
    warnings: list[str] = []
    if not token:
        warnings.append(
            "GitHub token is not configured. Unauthenticated API requests can hit low rate limits."
        )

    open_prs, open_truncated = _fetch_repo_pulls(repo=repo_name, state="open", token=token)
    closed_prs, closed_truncated = _fetch_repo_pulls(
        repo=repo_name,
        state="closed",
        token=token,
        start_date=start_date,
        end_date=end_date,
    )
    if open_truncated or closed_truncated:
        warnings.append("GitHub PR data was truncated due to pagination safety limits.")

    return GitHubPRSourceResult(
        repo=repo_name,
        open_pr_count=len(open_prs),
        open_prs_in_repo=open_prs,
        closed_prs_in_range=closed_prs,
        warnings=warnings,
    )


def _parse_junit_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    value = raw.strip()
    if not value:
        return None
    value = value.replace("Z", "")
    if "+" in value:
        value = value.split("+", maxsplit=1)[0]
    if "." in value:
        value = value.split(".", maxsplit=1)[0]
    return _parse_run_timestamp(value)


def _extract_openshift_version_from_junit(suites: list[ET.Element]) -> str:
    for suite in suites:
        for prop in suite.findall("./properties/property"):
            name = (prop.attrib.get("name") or "").strip().lower()
            value = (prop.attrib.get("value") or "").strip()
            if not value:
                continue
            if ("openshift" in name and "version" in name) or name in {"ocp_version", "ocp.version"}:
                return value
    return ""


def _parse_junit_report(path: Path) -> dict | None:
    tree = ET.parse(path)
    root = tree.getroot()
    suites = [node for node in root.iter("testsuite")]
    if not suites and root.tag == "testsuite":
        suites = [root]
    if not suites:
        return None

    total_tests = 0
    failed_tests = 0
    skipped_tests = 0
    duration_seconds = 0.0
    failed_test_rows: list[dict] = []
    skipped_test_rows: list[dict] = []
    suite_names: set[str] = set()
    run_timestamp: datetime | None = None

    for suite in suites:
        suite_name = (suite.attrib.get("name") or "").strip()
        if suite_name:
            suite_names.add(suite_name)
        if run_timestamp is None:
            run_timestamp = _parse_junit_timestamp(suite.attrib.get("timestamp"))

        for testcase in suite.iter("testcase"):
            total_tests += 1
            case_duration = _parse_duration_seconds(testcase.attrib.get("time"))
            duration_seconds += case_duration

            case_name = (testcase.attrib.get("name") or "unknown_test").strip()
            class_name = (testcase.attrib.get("classname") or "").strip()
            test_id = f"{class_name}::{case_name}" if class_name else case_name

            failure_node = testcase.find("failure")
            error_node = testcase.find("error")
            skipped_node = testcase.find("skipped")

            if failure_node is not None or error_node is not None:
                failed_tests += 1
                detail_node = failure_node if failure_node is not None else error_node
                message = ""
                if detail_node is not None:
                    message = (detail_node.attrib.get("message") or (detail_node.text or "")).strip()
                failed_test_rows.append(
                    {
                        "test_id": test_id,
                        "result": "failed",
                        "duration_seconds": round(case_duration, 2),
                        "message": message[:240],
                    }
                )
            elif skipped_node is not None:
                skipped_tests += 1
                message = (skipped_node.attrib.get("message") or (skipped_node.text or "")).strip()
                skipped_test_rows.append(
                    {
                        "test_id": test_id,
                        "result": "skipped",
                        "duration_seconds": round(case_duration, 2),
                        "message": message[:240],
                    }
                )

    if total_tests == 0:
        for suite in suites:
            total_tests += int(float(suite.attrib.get("tests", 0) or 0))
            failed_tests += int(float(suite.attrib.get("failures", 0) or 0))
            failed_tests += int(float(suite.attrib.get("errors", 0) or 0))
            skipped_tests += int(float(suite.attrib.get("skipped", 0) or 0))
            duration_seconds += _parse_duration_seconds(suite.attrib.get("time"))

    passed_tests = max(total_tests - failed_tests - skipped_tests, 0)
    if run_timestamp is None:
        run_timestamp = datetime.fromtimestamp(path.stat().st_mtime)

    if len(suite_names) == 1:
        suite = next(iter(suite_names))
    elif len(suite_names) > 1:
        suite = "multi-suite"
    else:
        suite = path.stem
    openshift_version = _extract_openshift_version_from_junit(suites)

    run_id = f"{path.stem}-{run_timestamp.strftime('%Y%m%d%H%M%S')}"
    return {
        "run_id": run_id,
        "run_timestamp": run_timestamp.isoformat(timespec="seconds"),
        "suite": suite,
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "skipped_tests": skipped_tests,
        "duration_seconds": round(duration_seconds, 2),
        "openshift_version": openshift_version,
        "failed_test_rows": failed_test_rows,
        "skipped_test_rows": skipped_test_rows,
        "source_type": "junit",
        "source_path": str(path),
    }


def _parse_pytest_html_report(path: Path) -> dict | None:
    content = path.read_text(encoding="utf-8")
    match = re.search(r'data-jsonblob="(?P<blob>.*?)"', content, flags=re.DOTALL)
    if not match:
        return None

    payload = json.loads(html.unescape(match.group("blob")))
    tests_blob = payload.get("tests") or {}
    if not isinstance(tests_blob, dict):
        return None
    env_blob = payload.get("environment") or {}
    openshift_version = ""
    if isinstance(env_blob, dict):
        for key, value in env_blob.items():
            key_lower = str(key).strip().lower()
            if ("openshift" in key_lower and "version" in key_lower) or key_lower in {"ocp version", "ocp_version"}:
                openshift_version = str(value).strip()
                break

    total_tests = 0
    failed_tests = 0
    skipped_tests = 0
    duration_seconds = 0.0
    failed_test_rows: list[dict] = []
    suite_counts = {"federation": 0, "ossm": 0, "unknown": 0}
    fail_results = {"failed", "error", "xpassed"}
    skip_results = {"skipped", "xfailed"}
    skipped_test_rows: list[dict] = []

    for test_id, entries in tests_blob.items():
        if not isinstance(entries, list):
            continue
        suite_key = _suite_from_test_id(str(test_id))
        suite_counts[suite_key] = suite_counts.get(suite_key, 0) + len(entries)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            total_tests += 1
            result = str(entry.get("result", "")).strip().lower()
            case_duration = _parse_duration_seconds(entry.get("duration"))
            duration_seconds += case_duration
            resolved_test_id = str(entry.get("testId") or test_id)
            if result in fail_results:
                failed_tests += 1
                log_text = (entry.get("log") or "").strip()
                first_line = log_text.splitlines()[0].strip() if log_text else ""
                failed_test_rows.append(
                    {
                        "test_id": resolved_test_id,
                        "result": result,
                        "duration_seconds": round(case_duration, 2),
                        "message": first_line[:240],
                    }
                )
            elif result in skip_results:
                skipped_tests += 1
                log_text = (entry.get("log") or "").strip()
                first_line = log_text.splitlines()[0].strip() if log_text else ""
                skipped_test_rows.append(
                    {
                        "test_id": resolved_test_id,
                        "result": result,
                        "duration_seconds": round(case_duration, 2),
                        "message": first_line[:240],
                    }
                )

    passed_tests = max(total_tests - failed_tests - skipped_tests, 0)
    run_timestamp = _parse_run_timestamp(path.parent.name) or datetime.fromtimestamp(path.stat().st_mtime)
    suite = max(suite_counts.items(), key=lambda item: item[1])[0] if total_tests else "unknown"
    run_id = path.parent.name if path.parent.name else f"html-{run_timestamp.strftime('%Y%m%d%H%M%S')}"
    return {
        "run_id": run_id,
        "run_timestamp": run_timestamp.isoformat(timespec="seconds"),
        "suite": suite,
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "skipped_tests": skipped_tests,
        "duration_seconds": round(duration_seconds, 2),
        "openshift_version": openshift_version,
        "failed_test_rows": failed_test_rows,
        "skipped_test_rows": skipped_test_rows,
        "source_type": "pytest-html",
        "source_path": str(path),
    }


def _list_regression_junit_files(artifacts_root: Path) -> list[Path]:
    reports_dir = artifacts_root / "reports"
    if not reports_dir.exists():
        return []
    files = sorted(reports_dir.glob("junit-*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
    if files:
        return files
    return sorted(reports_dir.glob("*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)


def _list_regression_html_files(artifacts_root: Path) -> list[Path]:
    reports_dir = artifacts_root / "test-reports"
    if not reports_dir.exists():
        return []
    candidates = sorted(reports_dir.glob("*/test-report.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    seen: set[str] = set()
    files: list[Path] = []
    for path in candidates:
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        files.append(path)
    return files


def _filter_runs_by_window(runs: list[dict], start_date: date, end_date: date) -> list[dict]:
    filtered: list[dict] = []
    for run in runs:
        raw = str(run.get("run_timestamp", "")).strip()
        run_ts: datetime | None = None
        try:
            run_ts = datetime.fromisoformat(raw)
        except ValueError:
            run_ts = None
        if run_ts and (run_ts.date() < start_date or run_ts.date() > end_date):
            continue
        filtered.append(run)
    filtered.sort(key=lambda r: str(r.get("run_timestamp", "")), reverse=True)
    return filtered


def _collect_regression_log_summary(artifacts_root: Path) -> dict[str, object]:
    log_path = artifacts_root / "logs" / "pytest.log"
    summary: dict[str, object] = {
        "available": False,
        "log_path": str(log_path),
        "updated_at": "",
        "warning_count": 0,
        "error_count": 0,
        "failed_mentions": 0,
        "recent_signals": [],
    }
    if not log_path.exists():
        return summary

    text = log_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    warning_count = 0
    error_count = 0
    failed_mentions = 0
    signal_lines: list[str] = []
    for line in lines:
        lower = line.lower()
        if " warning " in lower or lower.startswith("warning"):
            warning_count += 1
            signal_lines.append(line.strip())
        if " error " in lower or lower.startswith("error"):
            error_count += 1
            signal_lines.append(line.strip())
        if " failed " in lower or "failure" in lower:
            failed_mentions += 1
            signal_lines.append(line.strip())

    deduped_signals: list[str] = []
    seen: set[str] = set()
    for item in reversed(signal_lines):
        if item in seen:
            continue
        seen.add(item)
        deduped_signals.append(item)
        if len(deduped_signals) >= 10:
            break
    deduped_signals.reverse()

    summary.update(
        {
            "available": True,
            "updated_at": datetime.fromtimestamp(log_path.stat().st_mtime).isoformat(timespec="seconds"),
            "warning_count": warning_count,
            "error_count": error_count,
            "failed_mentions": failed_mentions,
            "recent_signals": deduped_signals,
        }
    )
    return summary


def load_regression_test_source(
    start_date: date,
    end_date: date,
    artifacts_dir: str | None = None,
) -> RegressionTestSourceResult:
    artifacts_path_raw = (artifacts_dir or default_regression_artifacts_dir()).strip()
    artifacts_path = Path(artifacts_path_raw).expanduser()
    warnings: list[str] = []
    runs: list[dict] = []
    log_summary = _collect_regression_log_summary(artifacts_path)

    if not artifacts_path.exists():
        warnings.append(f"Regression artifacts path does not exist: {artifacts_path}")
        return RegressionTestSourceResult(
            artifacts_dir=str(artifacts_path),
            runs=[],
            warnings=warnings,
            log_summary=log_summary,
        )

    junit_files = _list_regression_junit_files(artifacts_path)
    if junit_files:
        for file_path in junit_files:
            try:
                parsed = _parse_junit_report(file_path)
            except Exception as exc:  # pylint: disable=broad-except
                warnings.append(f"Could not parse JUnit report `{file_path.name}`: {exc}")
                continue
            if parsed:
                runs.append(parsed)
    else:
        warnings.append(
            "No JUnit XML reports found under `reports/`; falling back to pytest-html report parsing."
        )
        html_files = _list_regression_html_files(artifacts_path)
        for file_path in html_files:
            try:
                parsed = _parse_pytest_html_report(file_path)
            except Exception as exc:  # pylint: disable=broad-except
                warnings.append(f"Could not parse HTML report `{file_path}`: {exc}")
                continue
            if parsed:
                runs.append(parsed)

    runs = _filter_runs_by_window(runs, start_date=start_date, end_date=end_date)
    if not runs:
        warnings.append("No regression runs found in selected date range.")

    return RegressionTestSourceResult(
        artifacts_dir=str(artifacts_path),
        runs=runs,
        warnings=warnings,
        log_summary=log_summary,
    )


def _closed_bug_row_to_issue(
    key: str,
    bug_type: str,
    start_date: str,
    closed_date: str,
    resolution: str,
    summary: str,
) -> dict:
    issue_type_name = "Vulnerability" if bug_type.strip() == "CVE" else "Bug"
    return {
        "key": key,
        "fields": {
            "summary": summary.strip(),
            "status": {"name": "Done", "statusCategory": {"key": "done"}},
            "priority": {"name": "Undefined"},
            "assignee": {"displayName": "Unknown"},
            "reporter": {"displayName": "Unknown"},
            "created": f"{start_date}T00:00:00.000+0000",
            "updated": f"{closed_date}T00:00:00.000+0000",
            "resolutiondate": f"{closed_date}T00:00:00.000+0000",
            "components": [{"name": "zero-trust-workload-identity-manager"}],
            "issuetype": {"name": issue_type_name},
            "resolution": {"name": resolution.strip()},
            "_type_hint": bug_type.strip(),
        },
    }


def _open_bug_row_to_issue(
    key: str,
    bug_type: str,
    status: str,
    priority: str,
    assignee: str,
    updated: str,
    summary: str,
) -> dict:
    issue_type_name = "Vulnerability" if bug_type.strip() == "CVE" else "Bug"
    updated_date = (updated or "1970-01-01").strip()
    return {
        "key": key,
        "fields": {
            "summary": summary.strip(),
            "status": {
                "name": status.strip() or "Open",
                "statusCategory": {"key": "indeterminate"},
            },
            "priority": {"name": (priority or "Undefined").strip()},
            "assignee": {"displayName": (assignee or "Unassigned").strip()},
            "reporter": {"displayName": "Unknown"},
            "created": f"{updated_date}T00:00:00.000+0000",
            "updated": f"{updated_date}T00:00:00.000+0000",
            "resolutiondate": "",
            "components": [{"name": "zero-trust-workload-identity-manager"}],
            "issuetype": {"name": issue_type_name},
            "resolution": {"name": ""},
            "_type_hint": bug_type.strip(),
        },
    }


def _parse_result_report(path: Path) -> SourceResult:
    content = path.read_text(encoding="utf-8")
    warnings: list[str] = []

    date_range_label = None
    m_range = re.search(r"^Date range:\s*(.+)$", content, flags=re.MULTILINE)
    if m_range:
        date_range_label = m_range.group(1).strip()

    category_breakdown: dict[str, dict[str, int]] = {}
    category_rows = re.findall(
        r"^\| (?P<label>Engineering Bugs \(Red Hat\)|Customer Bugs \(OCPBUGS\)|CVEs / Vulnerabilities) \| "
        r"(?P<total>\d+) \| (?P<fixed>\d+) \| (?P<inprog>\d+) \| (?P<untouched>\d+) \|$",
        content,
        flags=re.MULTILINE,
    )
    label_map = {
        "Engineering Bugs (Red Hat)": "Engineering Bug",
        "Customer Bugs (OCPBUGS)": "Customer Bug",
        "CVEs / Vulnerabilities": "CVE",
    }
    for label, total, fixed, inprog, untouched in category_rows:
        category_breakdown[label_map[label]] = {
            "total": int(total),
            "fixed": int(fixed),
            "in_progress": int(inprog),
            "not_touched": int(untouched),
        }

    row_pattern = re.compile(
        r"^\| \[(?P<key>[^\]]+)\]\([^)]+\) \| (?P<type>[^|]+) \| (?P<start>\d{4}-\d{2}-\d{2}) \| "
        r"(?P<closed>\d{4}-\d{2}-\d{2}) \| (?P<wd>\d+) \| (?P<resolution>[^|]+) \| (?P<summary>.*)\|$"
    )
    open_row_pattern = re.compile(
        r"^\| \[(?P<key>[^\]]+)\]\([^)]+\) \| (?P<type>[^|]+) \| (?P<status>[^|]+) \| "
        r"(?P<priority>[^|]+) \| (?P<assignee>[^|]+) \| (?P<updated>[^|]+) \| (?P<summary>.*)\|$"
    )

    in_duration = False
    eng_bugs: list[dict] = []
    cust_bugs: list[dict] = []
    cves: list[dict] = []
    for line in content.splitlines():
        if line.strip() in {"## Closed Bug Duration (Working Days)", "## Closed Issue Duration (Working Days)"}:
            in_duration = True
            continue
        if in_duration and line.startswith("## "):
            break
        if not in_duration:
            continue
        matched = row_pattern.match(line.strip())
        if not matched:
            continue
        issue = _closed_bug_row_to_issue(
            key=matched.group("key").strip(),
            bug_type=matched.group("type").strip(),
            start_date=matched.group("start").strip(),
            closed_date=matched.group("closed").strip(),
            resolution=matched.group("resolution").strip(),
            summary=matched.group("summary").strip(),
        )
        if matched.group("type").strip() == "Customer Bug":
            cust_bugs.append(issue)
        elif matched.group("type").strip() == "CVE":
            cves.append(issue)
        else:
            eng_bugs.append(issue)

    in_open_items = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("## Attention Needed (All Open Items:"):
            in_open_items = True
            continue
        if in_open_items and stripped.startswith("## "):
            break
        if not in_open_items:
            continue
        matched = open_row_pattern.match(stripped)
        if not matched:
            continue
        issue = _open_bug_row_to_issue(
            key=matched.group("key").strip(),
            bug_type=matched.group("type").strip(),
            status=matched.group("status").strip(),
            priority=matched.group("priority").strip(),
            assignee=matched.group("assignee").strip(),
            updated=matched.group("updated").strip(),
            summary=matched.group("summary").strip(),
        )
        issue_type = matched.group("type").strip()
        if issue_type == "Customer Bug":
            cust_bugs.append(issue)
        elif issue_type == "CVE":
            cves.append(issue)
        else:
            eng_bugs.append(issue)

    if not eng_bugs and not cust_bugs and not cves:
        warnings.append("Result fallback found no rows; metrics may be empty.")

    warnings.append(
        "Fallback mode uses pre-rendered report rows; open-age and some live Jira dimensions are limited."
    )

    return SourceResult(
        source=f"Result fallback ({path.name})",
        eng_bugs=eng_bugs,
        cust_bugs=cust_bugs,
        cves=cves,
        other=[],
        date_range_label=date_range_label,
        category_breakdown=category_breakdown or None,
        warnings=warnings,
    )


def _needs_cve_duration_refresh(parsed: SourceResult) -> bool:
    cve_fixed = ((parsed.category_breakdown or {}).get("CVE") or {}).get("fixed", 0)
    return cve_fixed > 0 and len(parsed.cves) == 0


def _script_date_field(date_field: str) -> str:
    if date_field in ("created", "updated"):
        return date_field
    # Dashboard supports resolutiondate semantics; report script currently does not.
    return "updated"


def _target_range_label(start_date: date, end_date: date, date_field: str) -> str:
    return f"{start_date.isoformat()} to {end_date.isoformat()} ({_script_date_field(date_field)})"


def _find_result_report_for_range(start_date: date, end_date: date, date_field: str) -> Path | None:
    target = _target_range_label(start_date, end_date, date_field)
    reports = sorted(RESULT_DIR.glob("ztwim-quality-summary-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    for report in reports:
        content = report.read_text(encoding="utf-8")
        m = re.search(r"^Date range:\s*(.+)$", content, flags=re.MULTILINE)
        if m and m.group(1).strip() == target:
            return report
    return None


def _latest_result_report_path() -> Path | None:
    reports = sorted(RESULT_DIR.glob("ztwim-quality-summary-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        return None
    return reports[0]


def _run_report_script(start_date: date, end_date: date, date_field: str, debug: bool = False) -> None:
    script = SCRIPTS_DIR / "ztwim-quality-summary-report.py"
    cmd = [
        sys.executable,
        str(script),
        "--start-date",
        start_date.isoformat(),
        "--end-date",
        end_date.isoformat(),
        "--date-field",
        _script_date_field(date_field),
        "--md",
    ]
    if debug:
        cmd.append("--debug")
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"Report script run failed: {err[:500]}")


def _load_or_generate_result_report(start_date: date, end_date: date, date_field: str, debug: bool = False) -> SourceResult:
    report = _find_result_report_for_range(start_date, end_date, date_field)
    generated = False
    if report is None:
        try:
            _run_report_script(start_date, end_date, date_field, debug=debug)
            report = _find_result_report_for_range(start_date, end_date, date_field)
            generated = True
        except RuntimeError as exc:
            latest = _latest_result_report_path()
            if latest:
                parsed = _parse_result_report(latest)
                parsed.warnings.insert(
                    0,
                    (
                        f"Could not generate report for selected range ({start_date} to {end_date}): {exc}. "
                        f"Using latest available report `{latest.name}`."
                    ),
                )
                return parsed
            raise RuntimeError(
                f"{exc} Also no existing files were found in `{RESULT_DIR}`."
            ) from exc
    if report is None:
        latest = _latest_result_report_path()
        if latest:
            parsed = _parse_result_report(latest)
            parsed.warnings.insert(
                0,
                (
                    f"No matching Result report found for selected range "
                    f"({start_date} to {end_date}); using latest `{latest.name}`."
                ),
            )
            return parsed
        raise RuntimeError("No matching Result report found after script run.")
    parsed = _parse_result_report(report)
    if not generated and _needs_cve_duration_refresh(parsed):
        try:
            _run_report_script(start_date, end_date, date_field, debug=debug)
            refreshed = _find_result_report_for_range(start_date, end_date, date_field)
            if refreshed:
                parsed = _parse_result_report(refreshed)
                parsed.warnings.insert(
                    0,
                    "Existing report lacked CVE duration rows; regenerated report for complete velocity metrics.",
                )
        except RuntimeError as exc:
            parsed.warnings.insert(
                0,
                f"Could not refresh report for CVE duration rows: {exc}",
            )
    if generated:
        parsed.warnings.insert(0, "No cached Result file for selected range; generated a new report via script.")
    return parsed


class DataSourceHub:
    def __init__(self, mode: str = "result") -> None:
        _ = mode
        self.mode = "result"

    def load(self, start_date, end_date, date_field: str, debug: bool = False) -> SourceResult:
        if not start_date or not end_date:
            raise RuntimeError("Result mode requires start_date and end_date.")
        return _load_or_generate_result_report(start_date, end_date, date_field, debug=debug)
