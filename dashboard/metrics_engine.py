"""Velocity and dashboard metrics engine."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from statistics import median


def parse_issue_date(issue: dict, field: str) -> date | None:
    raw = ((issue.get("fields", {}).get(field) or "")[:10]).strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        return None


def issue_status_bucket(issue: dict) -> str:
    category = issue.get("fields", {}).get("status", {}).get("statusCategory", {}).get("key", "")
    if category == "done":
        return "Fixed/Closed"
    if category in ("indeterminate", "new"):
        status_name = issue.get("fields", {}).get("status", {}).get("name", "").lower()
        if any(word in status_name for word in ("progress", "review", "assigned")):
            return "In Progress"
        return "Not Touched"
    return "Unknown"


def working_days_between(start: date, end: date) -> int:
    if end < start:
        return 0
    total_days = (end - start).days + 1
    whole_weeks, extra_days = divmod(total_days, 7)
    weekdays = whole_weeks * 5
    for i in range(extra_days):
        if (start.weekday() + i) % 7 < 5:
            weekdays += 1
    return weekdays


def closed_date_value(issue: dict) -> date | None:
    resolved = parse_issue_date(issue, "resolutiondate")
    if resolved:
        return resolved
    return parse_issue_date(issue, "updated")


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * pct
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return float(sorted_values[lower])
    frac = pos - lower
    return float(sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * frac)


def in_window(value: date | None, start: date | None, end: date | None) -> bool:
    if value is None:
        return False
    if start and value < start:
        return False
    if end and value > end:
        return False
    return True


@dataclass
class ClosureRecord:
    key: str
    bug_type: str
    start_date: date
    closed_date: date
    window_date: date
    working_days: int
    priority: str
    resolution: str
    summary: str


def build_closure_records(
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    cves: list[dict],
    date_view: str,
    start: date | None,
    end: date | None,
) -> list[ClosureRecord]:
    rows: list[ClosureRecord] = []
    for bug_type, issues in (
        ("Engineering Bug", eng_bugs),
        ("Customer Bug", cust_bugs),
        ("CVE", cves),
    ):
        for issue in issues:
            if issue_status_bucket(issue) != "Fixed/Closed":
                continue
            created = parse_issue_date(issue, "created")
            closed = closed_date_value(issue)
            updated = parse_issue_date(issue, "updated")
            if not created or not closed or closed < created:
                continue
            window_date = closed if date_view == "resolutiondate" else updated
            if not in_window(window_date, start, end):
                continue
            f = issue.get("fields", {})
            rows.append(
                ClosureRecord(
                    key=issue.get("key", "?"),
                    bug_type=bug_type,
                    start_date=created,
                    closed_date=closed,
                    window_date=window_date if window_date else closed,
                    working_days=working_days_between(created, closed),
                    priority=(f.get("priority") or {}).get("name", "Undefined"),
                    resolution=(f.get("resolution") or {}).get("name", "-"),
                    summary=(f.get("summary", "") or "").strip(),
                )
            )
    rows.sort(key=lambda r: (r.window_date.isoformat(), r.working_days, r.key), reverse=True)
    return rows


def bucket_throughput(records: list[ClosureRecord]) -> tuple[list[dict], list[dict]]:
    weekly: dict[str, int] = defaultdict(int)
    monthly: dict[str, int] = defaultdict(int)
    for row in records:
        y, w, _ = row.window_date.isocalendar()
        weekly[f"{y}-W{w:02d}"] += 1
        monthly[row.window_date.strftime("%Y-%m")] += 1
    weekly_series = [{"period": p, "count": c} for p, c in sorted(weekly.items())]
    monthly_series = [{"period": p, "count": c} for p, c in sorted(monthly.items())]
    return weekly_series, monthly_series


def _type_velocity_summary(
    closure_rows: list[ClosureRecord],
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    cves: list[dict],
    category_breakdown: dict[str, dict[str, int]] | None = None,
) -> list[dict]:
    closure_by_type = Counter(r.bug_type for r in closure_rows)
    durations_by_type: dict[str, list[int]] = defaultdict(list)
    for row in closure_rows:
        durations_by_type[row.bug_type].append(row.working_days)

    totals_from_issues = {
        "Engineering Bug": len(eng_bugs),
        "Customer Bug": len(cust_bugs),
        "CVE": len(cves),
    }
    types = ("Engineering Bug", "Customer Bug", "CVE")
    result: list[dict] = []
    for bug_type in types:
        if category_breakdown and bug_type in category_breakdown:
            total = category_breakdown[bug_type]["total"]
            fixed = category_breakdown[bug_type]["fixed"]
        else:
            total = totals_from_issues.get(bug_type, 0)
            fixed = closure_by_type.get(bug_type, 0)
        durations = durations_by_type.get(bug_type, [])
        result.append(
            {
                "type": bug_type,
                "total_items": total,
                "closed_items": fixed,
                "closure_rate_pct": (fixed * 100.0 / total) if total else 0.0,
                "avg_close_days": (sum(durations) / len(durations)) if durations else 0.0,
                "median_close_days": float(median(durations)) if durations else 0.0,
            }
        )
    return result


def compute_velocity_metrics(
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    cves: list[dict],
    date_view: str,
    start: date | None,
    end: date | None,
    category_breakdown: dict[str, dict[str, int]] | None = None,
) -> dict:
    closure_rows = build_closure_records(eng_bugs, cust_bugs, cves, date_view, start, end)
    durations = [r.working_days for r in closure_rows]
    weekly_series, monthly_series = bucket_throughput(closure_rows)
    by_type = Counter(r.bug_type for r in closure_rows)

    if durations:
        summary = {
            "closed_bug_count": len(durations),
            "median_close_days": float(median(durations)),
            "p75_close_days": percentile(durations, 0.75),
            "p90_close_days": percentile(durations, 0.90),
            "avg_close_days": sum(durations) / len(durations),
            "max_close_days": max(durations),
        }
    else:
        summary = {
            "closed_bug_count": 0,
            "median_close_days": 0.0,
            "p75_close_days": 0.0,
            "p90_close_days": 0.0,
            "avg_close_days": 0.0,
            "max_close_days": 0.0,
        }

    return {
        "date_view": date_view,
        "summary": summary,
        "split_by_type": dict(by_type),
        "avg_velocity_by_type": _type_velocity_summary(
            closure_rows=closure_rows,
            eng_bugs=eng_bugs,
            cust_bugs=cust_bugs,
            cves=cves,
            category_breakdown=category_breakdown,
        ),
        "weekly_throughput": weekly_series,
        "monthly_throughput": monthly_series,
        "closure_rows": [
            {
                "key": r.key,
                "type": r.bug_type,
                "start_date": r.start_date.isoformat(),
                "closed_date": r.closed_date.isoformat(),
                "window_date": r.window_date.isoformat(),
                "working_days": r.working_days,
                "priority": r.priority,
                "resolution": r.resolution,
                "summary": r.summary,
            }
            for r in closure_rows
        ],
    }


def _parse_github_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def compute_github_pr_velocity_metrics(open_pr_count: int, closed_prs: list[dict]) -> dict:
    close_durations_days: list[float] = []
    merged_pr_count = 0
    closed_pr_rows: list[dict] = []

    for pr in closed_prs:
        created_at = _parse_github_datetime(pr.get("created_at"))
        closed_at = _parse_github_datetime(pr.get("closed_at"))
        if not created_at or not closed_at or closed_at < created_at:
            continue

        duration_days = (closed_at - created_at).total_seconds() / 86400.0
        close_durations_days.append(duration_days)
        is_merged = bool(pr.get("merged_at"))
        if is_merged:
            merged_pr_count += 1

        user = pr.get("user") or {}
        closed_pr_rows.append(
            {
                "number": int(pr.get("number", 0) or 0),
                "title": (pr.get("title") or "").strip(),
                "author": (user.get("login") or "unknown").strip(),
                "created_at": created_at.strftime("%Y-%m-%d"),
                "closed_at": closed_at.strftime("%Y-%m-%d"),
                "merged": is_merged,
                "close_days": round(duration_days, 2),
                "url": pr.get("html_url", ""),
            }
        )

    closed_pr_rows.sort(key=lambda row: (row["closed_at"], row["number"]), reverse=True)
    closed_pr_count = len(closed_pr_rows)
    closed_unmerged_pr_count = max(closed_pr_count - merged_pr_count, 0)

    if close_durations_days:
        avg_close_days = sum(close_durations_days) / len(close_durations_days)
        median_close_days = float(median(close_durations_days))
        p90_close_days = percentile(close_durations_days, 0.90)
    else:
        avg_close_days = 0.0
        median_close_days = 0.0
        p90_close_days = 0.0

    return {
        "summary": {
            "open_pr_count": int(open_pr_count),
            "closed_pr_count": closed_pr_count,
            "merged_pr_count": merged_pr_count,
            "closed_unmerged_pr_count": closed_unmerged_pr_count,
            "avg_close_days": avg_close_days,
            "median_close_days": median_close_days,
            "p90_close_days": p90_close_days,
        },
        "closed_pr_rows": closed_pr_rows,
    }


def compute_regression_metrics(
    runs: list[dict],
    start: date | None,
    end: date | None,
) -> dict:
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    skipped_tests = 0
    total_duration_seconds = 0.0
    run_rows: list[dict] = []
    failed_test_rows: list[dict] = []
    skipped_test_rows: list[dict] = []

    for run in runs:
        run_timestamp_raw = str(run.get("run_timestamp", "")).strip()
        run_timestamp: datetime | None = None
        if run_timestamp_raw:
            try:
                run_timestamp = datetime.fromisoformat(run_timestamp_raw)
            except ValueError:
                run_timestamp = None
        if run_timestamp:
            run_date = run_timestamp.date()
            if start and run_date < start:
                continue
            if end and run_date > end:
                continue

        run_total = int(run.get("total_tests", 0) or 0)
        run_passed = int(run.get("passed_tests", 0) or 0)
        run_failed = int(run.get("failed_tests", 0) or 0)
        run_skipped = int(run.get("skipped_tests", 0) or 0)
        run_duration_seconds = float(run.get("duration_seconds", 0.0) or 0.0)

        total_tests += run_total
        passed_tests += run_passed
        failed_tests += run_failed
        skipped_tests += run_skipped
        total_duration_seconds += run_duration_seconds

        run_pass_rate = (run_passed * 100.0 / run_total) if run_total else 0.0
        run_rows.append(
            {
                "run_id": str(run.get("run_id", "")),
                "run_timestamp": run_timestamp_raw,
                "suite": str(run.get("suite", "unknown")),
                "openshift_version": str(run.get("openshift_version", "")),
                "total_tests": run_total,
                "passed_tests": run_passed,
                "failed_tests": run_failed,
                "skipped_tests": run_skipped,
                "pass_rate_pct": round(run_pass_rate, 2),
                "duration_minutes": round(run_duration_seconds / 60.0, 2),
                "source_type": str(run.get("source_type", "")),
                "source_path": str(run.get("source_path", "")),
            }
        )

        for failure in run.get("failed_test_rows", []) or []:
            failed_test_rows.append(
                {
                    "run_id": str(run.get("run_id", "")),
                    "run_timestamp": run_timestamp_raw,
                    "suite": str(run.get("suite", "unknown")),
                    "test_id": str(failure.get("test_id", "")),
                    "result": str(failure.get("result", "failed")),
                    "duration_seconds": float(failure.get("duration_seconds", 0.0) or 0.0),
                    "message": str(failure.get("message", "")),
                }
            )
        for skipped in run.get("skipped_test_rows", []) or []:
            skipped_test_rows.append(
                {
                    "run_id": str(run.get("run_id", "")),
                    "run_timestamp": run_timestamp_raw,
                    "suite": str(run.get("suite", "unknown")),
                    "test_id": str(skipped.get("test_id", "")),
                    "result": str(skipped.get("result", "skipped")),
                    "duration_seconds": float(skipped.get("duration_seconds", 0.0) or 0.0),
                    "message": str(skipped.get("message", "")),
                }
            )

    run_rows.sort(key=lambda row: row["run_timestamp"], reverse=True)
    failed_test_rows.sort(key=lambda row: (row["run_timestamp"], row["test_id"]), reverse=True)
    skipped_test_rows.sort(key=lambda row: (row["run_timestamp"], row["test_id"]), reverse=True)
    total_runs = len(run_rows)
    pass_rate_pct = (passed_tests * 100.0 / total_tests) if total_tests else 0.0
    total_duration_minutes = total_duration_seconds / 60.0
    avg_duration_minutes = (total_duration_minutes / total_runs) if total_runs else 0.0
    latest_run_timestamp = run_rows[0]["run_timestamp"] if run_rows else ""
    avg_tests_per_run = (total_tests / total_runs) if total_runs else 0.0
    avg_passed_per_run = (passed_tests / total_runs) if total_runs else 0.0
    avg_failed_per_run = (failed_tests / total_runs) if total_runs else 0.0
    avg_skipped_per_run = (skipped_tests / total_runs) if total_runs else 0.0

    failed_counter = Counter(row["test_id"] for row in failed_test_rows if row.get("test_id"))
    skipped_counter = Counter(row["test_id"] for row in skipped_test_rows if row.get("test_id"))
    top_failed_tests = [
        {"test_id": test_id, "fail_count": count}
        for test_id, count in failed_counter.most_common(15)
    ]
    top_skipped_tests = [
        {"test_id": test_id, "skip_count": count}
        for test_id, count in skipped_counter.most_common(15)
    ]

    message_counter = Counter()
    for row in failed_test_rows:
        msg = (row.get("message") or "").strip()
        if msg:
            message_counter[msg[:180]] += 1
    top_failure_signatures = [
        {"message": message, "count": count}
        for message, count in message_counter.most_common(10)
    ]

    return {
        "summary": {
            "total_runs": total_runs,
            "total_tests": total_tests,
            "total_test_executions": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "skipped_tests": skipped_tests,
            "pass_rate_pct": pass_rate_pct,
            "total_duration_minutes": total_duration_minutes,
            "avg_run_duration_minutes": avg_duration_minutes,
            "avg_tests_per_run": avg_tests_per_run,
            "avg_passed_per_run": avg_passed_per_run,
            "avg_failed_per_run": avg_failed_per_run,
            "avg_skipped_per_run": avg_skipped_per_run,
            "latest_run_timestamp": latest_run_timestamp,
        },
        "run_rows": run_rows,
        "failed_test_rows": failed_test_rows,
        "skipped_test_rows": skipped_test_rows,
        "top_failed_tests": top_failed_tests,
        "top_skipped_tests": top_skipped_tests,
        "top_failure_signatures": top_failure_signatures,
    }
