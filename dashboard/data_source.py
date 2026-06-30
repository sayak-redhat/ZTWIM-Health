"""Hybrid data source hub for live Jira and Result fallback."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
RESULT_DIR = ROOT_DIR / "Result"


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

    if not eng_bugs and not cust_bugs and not cves:
        warnings.append("Result fallback found no closed duration rows; metrics may be empty.")

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
