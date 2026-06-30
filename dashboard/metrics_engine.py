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


def percentile(values: list[int], pct: float) -> float:
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
