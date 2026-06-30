#!/usr/bin/env python3
"""ZTWIM Jira Bug & CVE Report

Generates a report with three sections:
  1. Engineering bugs (SPIRE project — raised by Red Hat engineers)
  2. Customer-facing bugs (OCPBUGS project — raised by customers/field)
  3. CVEs / Vulnerabilities (OCPBUGS — security scanner findings)

Each issue includes a clickable Jira URL, status, priority, assignee, and dates.
Status dashboard shows: fixed, in-progress, not-touched, total.

Usage:
  export JIRA_EMAIL="you@redhat.com"
  export JIRA_TOKEN="your-api-token"

  python3 ztwim-quality-summary-report.py --md      # generate Result/ztwim-quality-summary-<timestamp>.md
  python3 ztwim-quality-summary-report.py --txt     # generate Result/ztwim-quality-summary-<timestamp>.txt
  python3 ztwim-quality-summary-report.py --debug   # verbose debug logs
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import ztwim_data_layer as data_layer

BASE = data_layer.BASE
EMAIL = data_layer.EMAIL
TOKEN = data_layer.TOKEN
MAX_RESULTS = 100

# SFDC field ID is auto-discovered; override if known
SFDC_FIELD_ID = os.environ.get("JIRA_SFDC_FIELD", "")

FIELDS = [
    "key", "summary", "status", "priority", "assignee", "reporter",
    "created", "updated", "resolutiondate", "components", "issuetype", "resolution",
]

RESULT_DIR = Path(__file__).resolve().parent.parent / "Result"
REPORT_FILE_PREFIX = "ztwim-quality-summary"
REPORT_TIMESTAMP_FMT = "%Y%m%d-%H%M%S"

PICKER_QUERIES = [
    "ZTWIM", "Zero Trust Workload Identity",
    "spire-agent CVE", "spiffe-spire CVE",
    "zero-trust-workload-identity-manager",
]

DYNAMIC_JQL_SOURCES = [
    "project = SPIRE AND issuetype = Bug ORDER BY created DESC",
]
CUSTOMER_BUG_JQL = (
    'project = OCPBUGS AND issuetype = Bug '
    'AND component = "zero-trust-workload-identity-manager" ORDER BY created DESC'
)

# Red Hat engineering email domains
def auth_header() -> str:
    return "Basic " + base64.b64encode(f"{EMAIL}:{TOKEN}".encode()).decode()


def jira_request(method: str, url: str, body: dict | None = None) -> dict | list | None:
    headers = {"Authorization": auth_header(), "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode()[:200]}", file=sys.stderr)
        return None


# Custom field IDs — populated by discover_custom_fields()
CUSTOM_FIELDS: dict[str, str] = {}

# Fields we want to discover: display_name -> search patterns (matched against Jira field name)
WANTED_FIELDS = {
    "sfdc":          ["sfdc cases", "sfdc case", "salesforce case"],
    "sla_date":      ["sla date", "sla due"],
    "cve_id":        ["cve id"],
    "cvss_score":    ["cvss score", "cvss"],
    "cwe_id":        ["cwe id", "cwe"],
    "cve_source":    ["source"],
    "update_stream": ["update stream"],
}


def discover_custom_fields(debug: bool = False) -> None:
    """Find custom field IDs from Jira field metadata."""
    data = jira_request("GET", f"{BASE}/rest/api/3/field")
    if not data or not isinstance(data, list):
        return
    remaining = set(WANTED_FIELDS.keys()) - set(CUSTOM_FIELDS.keys())
    if not remaining:
        return
    for wanted_key in remaining:
        patterns = WANTED_FIELDS[wanted_key]
        for field in data:
            fname = field.get("name", "").lower()
            if any(p in fname for p in patterns):
                CUSTOM_FIELDS[wanted_key] = field["id"]
                if debug:
                    print(f"  [field] {wanted_key} = {field['id']} ({field.get('name')})", file=sys.stderr)
                break


def get_custom_value(issue: dict, key: str) -> str:
    """Extract a custom field value from an issue."""
    fid = CUSTOM_FIELDS.get(key, "")
    if not fid:
        return ""
    f = issue.get("fields", {})
    val = f.get(fid, None)
    if not val:
        return ""
    if isinstance(val, dict):
        return val.get("value", val.get("name", str(val)))
    if isinstance(val, list):
        parts = []
        for v in val:
            if isinstance(v, dict):
                parts.append(v.get("value", v.get("name", str(v))))
            elif v:
                parts.append(str(v))
        return ", ".join(parts)
    return str(val).strip()


def get_sfdc_value(issue: dict) -> str:
    return get_custom_value(issue, "sfdc")


def jira_search(jql: str, debug: bool = False) -> list[dict]:
    if not jql.strip():
        return []
    issues: list[dict] = []
    next_token: str | None = None
    while True:
        body: dict = {"jql": jql, "maxResults": MAX_RESULTS, "fields": FIELDS}
        if next_token:
            body["nextPageToken"] = next_token
        data = jira_request("POST", f"{BASE}/rest/api/3/search/jql", body)
        if not data or not isinstance(data, dict):
            return issues
        if data.get("errorMessages"):
            if debug:
                print(f"  [jql] error: {data['errorMessages']}", file=sys.stderr)
            return issues
        batch = data.get("issues", [])
        if debug:
            print(f"  [jql] +{len(batch)} | {jql[:90]}", file=sys.stderr)
        issues.extend(batch)
        if data.get("isLast", True) or not data.get("nextPageToken"):
            break
        next_token = data["nextPageToken"]
    return issues


def fetch_by_keys(issue_keys: list[str]) -> list[dict]:
    if not issue_keys:
        return []
    all_issues: list[dict] = []
    for i in range(0, len(issue_keys), 50):
        batch_keys = issue_keys[i : i + 50]
        jql = f"key in ({', '.join(batch_keys)}) ORDER BY created DESC"
        all_issues.extend(jira_search(jql))
    return all_issues


def fetch_via_jql_sources(debug: bool = False) -> list[dict]:
    all_issues: list[dict] = []
    for jql in DYNAMIC_JQL_SOURCES:
        batch = jira_search(jql, debug=debug)
        if batch:
            all_issues.extend(batch)
    return all_issues


def discover_via_picker(debug: bool = False) -> set[str]:
    found: set[str] = set()
    for query in PICKER_QUERIES:
        encoded = urllib.request.quote(query)
        url = f"{BASE}/rest/api/3/issue/picker?query={encoded}"
        data = jira_request("GET", url)
        if not data or not isinstance(data, dict):
            continue
        for section in data.get("sections", []):
            for issue in section.get("issues", []):
                if issue.get("key"):
                    found.add(issue["key"])
    return found


def discover_via_component_api(debug: bool = False) -> set[str]:
    found: set[str] = set()
    comp_data = jira_request("GET", f"{BASE}/rest/api/3/project/OCPBUGS/components")
    if not comp_data or not isinstance(comp_data, list):
        return found
    ztwim_comps = [
        c for c in comp_data
        if "zero-trust" in c.get("name", "").lower()
        or "spiffe" in c.get("name", "").lower()
    ]
    for comp in ztwim_comps:
        for jql in [
            f"component = {comp['id']} ORDER BY created DESC",
            f"component = {comp['id']} AND issuetype in (Bug, Vulnerability) ORDER BY created DESC",
        ]:
            data = jira_request("POST", f"{BASE}/rest/api/3/search/jql",
                                {"jql": jql, "maxResults": 100, "fields": ["key"]})
            if data and isinstance(data, dict) and data.get("issues"):
                for issue in data["issues"]:
                    found.add(issue["key"])
                break
    return found


def discover_keys_live(debug: bool = False) -> dict[str, list[str]]:
    """Discover and classify ZTWIM keys in-memory (no local key file)."""
    print("Discovering ZTWIM issues...\n", file=sys.stderr)
    discovered: set[str] = set()
    for source_fn, label in [
        (lambda: {i["key"] for i in fetch_via_jql_sources(debug)}, "SPIRE JQL"),
        (lambda: {i["key"] for i in jira_search(CUSTOMER_BUG_JQL, debug=debug)}, "OCPBUGS Bug JQL"),
        (lambda: discover_via_picker(debug), "Issue picker"),
        (lambda: discover_via_component_api(debug), "Component API"),
    ]:
        batch = source_fn()
        print(f"  {label}: {len(batch)} keys", file=sys.stderr)
        discovered |= batch

    if not discovered:
        print("No keys found.", file=sys.stderr)
        print(file=sys.stderr)
        return {"bugs": [], "cves": [], "other": []}

    fetched = fetch_by_keys(sorted(discovered))
    ztwim = [i for i in fetched if is_ztwim_related(i)]
    keys: dict[str, list[str]] = {"bugs": [], "cves": [], "other": []}
    for issue in ztwim:
        cat = classify_issue(issue)
        keys.get(cat, keys["other"]).append(issue["key"])

    for cat in keys:
        keys[cat] = sorted(set(keys[cat]))
    print(
        f"  ZTWIM classified keys: bugs={len(keys['bugs'])}, cves={len(keys['cves'])}, other={len(keys['other'])}",
        file=sys.stderr,
    )
    print(file=sys.stderr)
    return keys


def classify_issue(issue: dict) -> str:
    """Classify as bugs/cves/other — keys match the keys dict exactly."""
    f = issue.get("fields", {})
    itype = (f.get("issuetype") or {}).get("name", "").lower()

    if itype == "bug":
        return "bugs"
    if itype in ("vulnerability", "cve"):
        return "cves"
    if itype and itype not in ("bug", "vulnerability", "cve"):
        return "other"

    # issuetype missing (permission issue) — classify by content
    summary = f.get("summary", "").lower()
    comp_names = " ".join(c.get("name", "") for c in f.get("components", [])).lower()

    if "cve-" in summary or "-rhel9" in comp_names:
        return "cves"

    key = issue.get("key", "")
    if key.startswith("SPIRE-"):
        return "bugs"
    if "zero-trust-workload-identity-manager" in comp_names and "-rhel9" not in comp_names:
        return "bugs"

    return "other"


def is_ztwim_related(issue: dict) -> bool:
    f = issue.get("fields", {})
    comp_names = [c.get("name", "").lower() for c in f.get("components", [])]
    blob = f"{f.get('summary', '')} {f.get('description', '')}".lower()
    return (
        any("zero-trust" in c or "spiffe" in c for c in comp_names)
        or "ztwim" in blob
        or "zero trust workload identity" in blob
        or "spiffe-spire" in blob
    )


def issue_url(key: str) -> str:
    return f"{BASE}/browse/{key}"


def status_category(issue: dict) -> str:
    cat = issue["fields"]["status"].get("statusCategory", {}).get("key", "")
    if cat == "done":
        return "Fixed/Closed"
    if cat == "indeterminate" or cat == "new":
        status_name = issue["fields"]["status"].get("name", "").lower()
        if "progress" in status_name or "review" in status_name or "assigned" in status_name:
            return "In Progress"
        return "Not Touched"
    return issue["fields"]["status"].get("name", "Unknown")


def is_customer_bug(issue: dict) -> bool:
    """Customer bug = has SFDC case link OR is an OCPBUGS bug without SPIRE key."""
    key = issue.get("key", "")
    if key.startswith("SPIRE-"):
        return False
    sfdc = get_sfdc_value(issue)
    if sfdc:
        return True
    return key.startswith("OCPBUGS-")


def status_dashboard(issues: list[dict]) -> dict[str, int]:
    cats = Counter(status_category(i) for i in issues)
    return {
        "Fixed/Closed": cats.get("Fixed/Closed", 0),
        "In Progress": cats.get("In Progress", 0),
        "Not Touched": cats.get("Not Touched", 0),
        "Total": len(issues),
    }


def print_dashboard(label: str, dashboard: dict[str, int]) -> None:
    total = dashboard["Total"]
    fixed = dashboard["Fixed/Closed"]
    prog = dashboard["In Progress"]
    untouched = dashboard["Not Touched"]
    bar_w = 40
    if total > 0:
        f_w = int(bar_w * fixed / total)
        p_w = int(bar_w * prog / total)
        u_w = bar_w - f_w - p_w
        bar = f"[{'█' * f_w}{'▓' * p_w}{'░' * u_w}]"
    else:
        bar = f"[{'░' * bar_w}]"
    print(f"  {label}")
    print(f"    {bar}  {total} total")
    print(f"    Fixed/Closed: {fixed}  |  In Progress: {prog}  |  Not Touched: {untouched}")


def fmt_issue_line(issue: dict) -> str:
    f = issue["fields"]
    key = issue["key"]
    url = issue_url(key)
    status = f["status"].get("name", "?")
    priority = (f.get("priority") or {}).get("name", "?")
    assignee = (f.get("assignee") or {}).get("displayName", "Unassigned")
    reporter = (f.get("reporter") or {}).get("displayName", "Unknown")
    created = (f.get("created") or "")[:10]
    updated = (f.get("updated") or "")[:10]
    summary = f.get("summary", "").strip()
    resolution = (f.get("resolution") or {}).get("name", "-")
    sfdc = get_sfdc_value(issue)
    sfdc_str = f"  SFDC: {sfdc}" if sfdc else ""
    return (
        f"  {key:<16} {status:<14} {priority:<12} {created}  {updated}  "
        f"{assignee:<20} {reporter:<20} {resolution:<12} {summary[:60]}\n"
        f"  {'':>16} {url}{sfdc_str}"
    )


def fmt_issue_md(issue: dict, is_cve: bool = False) -> str:
    f = issue["fields"]
    key = issue["key"]
    url = issue_url(key)
    status = f["status"].get("name", "?")
    priority = (f.get("priority") or {}).get("name", "?")
    assignee = (f.get("assignee") or {}).get("displayName", "Unassigned")
    reporter = (f.get("reporter") or {}).get("displayName", "Unknown")
    created = (f.get("created") or "")[:10]
    updated = (f.get("updated") or "")[:10]
    summary = f.get("summary", "").strip()
    resolution = (f.get("resolution") or {}).get("name", "-")

    if is_cve:
        cve_id = get_custom_value(issue, "cve_id") or "-"
        cvss = get_custom_value(issue, "cvss_score") or "-"
        cwe = get_custom_value(issue, "cwe_id") or "-"
        sla = get_custom_value(issue, "sla_date") or "-"
        if sla and sla != "-":
            sla = sla[:10]
        stream = get_custom_value(issue, "update_stream") or "-"
        source = get_custom_value(issue, "cve_source") or "-"
        return f"| [{key}]({url}) | {status} | {cve_id} | {cvss} | {sla} | {stream} | {assignee} | {resolution} | {source} | {cwe} | {summary[:60]} |"
    else:
        sfdc = get_sfdc_value(issue) or "-"
        return f"| [{key}]({url}) | {status} | {priority} | {assignee} | {reporter} | {created} | {updated} | {resolution} | {sfdc} | {summary[:80]} |"


def print_section(title: str, issues: list[dict], md: bool = False) -> None:
    dashboard = status_dashboard(issues)

    if md:
        print(f"\n## {title} ({len(issues)})\n")
        print_dashboard(title, dashboard)
        print()
        if not issues:
            print("_(none)_\n")
            return
        print("| Key | Status | Priority | Assignee | Reporter | Created | Updated | Resolution | SFDC Case | Summary |")
        print("|-----|--------|----------|----------|----------|---------|---------|------------|-----------|---------|")
        for issue in issues:
            print(fmt_issue_md(issue))
        print()
    else:
        print("=" * 130)
        print(f"  {title} ({len(issues)})")
        print("=" * 130)
        print_dashboard(title, dashboard)
        print()
        if not issues:
            print("  (none)\n")
            return
        print(f"  {'KEY':<16} {'STATUS':<14} {'PRIORITY':<12} {'CREATED'}   {'UPDATED'}   "
              f"{'ASSIGNEE':<20} {'REPORTER':<20} {'RESOLUTION':<12} SUMMARY")
        print(f"  {'-'*126}")
        for issue in issues:
            print(fmt_issue_line(issue))
        by_status = Counter(issue["fields"]["status"]["name"] for issue in issues)
        by_priority = Counter((issue["fields"].get("priority") or {}).get("name", "?") for issue in issues)
        print(f"\n  By status:   {dict(by_status)}")
        print(f"  By priority: {dict(by_priority)}")
        print()


def priority_rank(issue: dict) -> int:
    p = ((issue.get("fields", {}).get("priority") or {}).get("name", "Undefined") or "Undefined").strip().lower()
    ranks = {
        "blocker": 0,
        "critical": 1,
        "highest": 1,
        "major": 2,
        "high": 2,
        "normal": 3,
        "medium": 3,
        "minor": 4,
        "low": 4,
        "undefined": 5,
    }
    return ranks.get(p, 6)


def clean_summary(issue: dict, limit: int = 90) -> str:
    summary = (issue.get("fields", {}).get("summary", "") or "").strip().replace("|", "/")
    summary = " ".join(summary.split())
    return summary[:limit]


def parse_date_arg(raw_date: str, arg_name: str) -> date:
    try:
        return datetime.strptime(raw_date, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{arg_name} must be in YYYY-MM-DD format (got: {raw_date})") from exc


def issue_date_value(issue: dict, date_field: str) -> date | None:
    raw_date = ((issue.get("fields", {}).get(date_field) or "")[:10]).strip()
    if not raw_date:
        return None
    try:
        return datetime.strptime(raw_date, "%Y-%m-%d").date()
    except ValueError:
        return None


def filter_issues_by_date_range(
    issues: list[dict],
    start_date: date | None,
    end_date: date | None,
    date_field: str,
) -> list[dict]:
    if start_date is None and end_date is None:
        return issues

    filtered: list[dict] = []
    for issue in issues:
        issue_date = issue_date_value(issue, date_field)
        if issue_date is None:
            continue
        if start_date and issue_date < start_date:
            continue
        if end_date and issue_date > end_date:
            continue
        filtered.append(issue)
    return filtered


def format_date_range(start_date: date | None, end_date: date | None, date_field: str) -> str | None:
    if start_date is None and end_date is None:
        return None
    start = start_date.isoformat() if start_date else "beginning"
    end = end_date.isoformat() if end_date else "today"
    return f"{start} to {end} ({date_field})"


def working_days_between(start_date: date, end_date: date) -> int:
    """Count weekday business days (Mon-Fri), inclusive."""
    if end_date < start_date:
        return 0
    total_days = (end_date - start_date).days + 1
    whole_weeks, extra_days = divmod(total_days, 7)
    weekdays = whole_weeks * 5
    for i in range(extra_days):
        if (start_date.weekday() + i) % 7 < 5:
            weekdays += 1
    return weekdays


def closed_date_value(issue: dict) -> date | None:
    """Use Jira resolution date when available, else fallback to updated date."""
    resolved = issue_date_value(issue, "resolutiondate")
    if resolved:
        return resolved
    return issue_date_value(issue, "updated")


def collect_closed_bug_durations(
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    all_cves: list[dict],
) -> list[tuple[str, dict, date, date, int]]:
    rows: list[tuple[str, dict, date, date, int]] = []
    for bucket, seq in [
        ("Engineering Bug", eng_bugs),
        ("Customer Bug", cust_bugs),
        ("CVE", all_cves),
    ]:
        for issue in seq:
            if status_category(issue) != "Fixed/Closed":
                continue
            start = issue_date_value(issue, "created")
            closed = closed_date_value(issue)
            if not start or not closed or closed < start:
                continue
            rows.append((bucket, issue, start, closed, working_days_between(start, closed)))
    rows.sort(
        key=lambda x: (
            x[3].isoformat(),
            x[4],
            x[1].get("key", ""),
        ),
        reverse=True,
    )
    return rows


def collect_open_items(
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    all_cves: list[dict],
) -> list[tuple[str, dict]]:
    open_items: list[tuple[str, dict]] = []
    open_items.extend(("Engineering Bug", i) for i in eng_bugs if status_category(i) != "Fixed/Closed")
    open_items.extend(("Customer Bug", i) for i in cust_bugs if status_category(i) != "Fixed/Closed")
    open_items.extend(("CVE", i) for i in all_cves if status_category(i) != "Fixed/Closed")
    status_order = {"In Progress": 0, "Not Touched": 1}
    type_order = {"Engineering Bug": 0, "Customer Bug": 1, "CVE": 2}
    open_items.sort(
        key=lambda x: (
            type_order.get(x[0], 99),
            status_order.get(status_category(x[1]), 2),
            priority_rank(x[1]),
            -int(((x[1].get("fields", {}).get("updated") or "0000-00-00")[:10]).replace("-", "")),
            x[1].get("key", ""),
        )
    )
    return open_items


def collect_recent_closures(
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    all_cves: list[dict],
    lookback_days: int = 30,
) -> list[tuple[str, dict]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    recent_closed: list[tuple[str, dict]] = []
    for bucket, seq in [("Engineering Bug", eng_bugs), ("Customer Bug", cust_bugs), ("CVE", all_cves)]:
        for issue in seq:
            if status_category(issue) != "Fixed/Closed":
                continue
            updated_raw = (issue.get("fields", {}).get("updated") or "")[:10]
            try:
                updated_dt = datetime.strptime(updated_raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if updated_dt >= cutoff:
                recent_closed.append((bucket, issue))
    recent_closed.sort(
        key=lambda x: (
            (x[1].get("fields", {}).get("updated") or "")[:10],
            -priority_rank(x[1]),
        ),
        reverse=True,
    )
    return recent_closed


def render_quality_summary_md(
    now: str,
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    all_cves: list[dict],
    date_range_label: str | None = None,
) -> str:
    total_issues = eng_bugs + cust_bugs + all_cves
    overall = status_dashboard(total_issues)
    eng_d = status_dashboard(eng_bugs)
    cust_d = status_dashboard(cust_bugs)
    cve_d = status_dashboard(all_cves)
    open_items = collect_open_items(eng_bugs, cust_bugs, all_cves)
    recent_closed = collect_recent_closures(eng_bugs, cust_bugs, all_cves, lookback_days=30)
    closed_bug_rows = collect_closed_bug_durations(eng_bugs, cust_bugs, all_cves)

    total = overall["Total"]
    closure_pct = (overall["Fixed/Closed"] * 100.0 / total) if total else 0.0
    risk_open = overall["In Progress"] + overall["Not Touched"]

    lines: list[str] = []
    lines.extend([
        "# ZTWIM Quality Summary",
        "",
        f"Generated: {now}",
        f"Date range: {date_range_label}" if date_range_label else "",
        "",
        f"Source: [{BASE}/jira/software/c/projects/OCPBUGS]({BASE}/jira/software/c/projects/OCPBUGS) + "
        f"[SPIRE]({BASE}/jira/software/c/projects/SPIRE)",
        "",
        "## Executive Snapshot",
        "",
        f"- Total tracked issues: **{total}**",
        f"- Closed/Resolved: **{overall['Fixed/Closed']}** ({closure_pct:.1f}%)",
        f"- Open risk backlog: **{risk_open}** (In Progress: {overall['In Progress']}, Not Touched: {overall['Not Touched']})",
        f"- Engineering bugs: **{eng_d['Total']}** | Customer bugs: **{cust_d['Total']}** | CVEs: **{cve_d['Total']}**",
        "",
        "## Category Breakdown",
        "",
        "| Category | Total | Fixed/Closed | In Progress | Not Touched |",
        "|---|---:|---:|---:|---:|",
        f"| Engineering Bugs (Red Hat) | {eng_d['Total']} | {eng_d['Fixed/Closed']} | {eng_d['In Progress']} | {eng_d['Not Touched']} |",
        f"| Customer Bugs (OCPBUGS) | {cust_d['Total']} | {cust_d['Fixed/Closed']} | {cust_d['In Progress']} | {cust_d['Not Touched']} |",
        f"| CVEs / Vulnerabilities | {cve_d['Total']} | {cve_d['Fixed/Closed']} | {cve_d['In Progress']} | {cve_d['Not Touched']} |",
        f"| **TOTAL** | **{overall['Total']}** | **{overall['Fixed/Closed']}** | **{overall['In Progress']}** | **{overall['Not Touched']}** |",
        "",
        f"## Attention Needed (All Open Items: {len(open_items)})",
        "",
    ])

    if not open_items:
        lines.extend(["_No open items._", ""])
    else:
        lines.extend([
            "| Key | Type | Status | Priority | Assignee | Updated | Summary |",
            "|---|---|---|---|---|---|---|",
        ])
        for bucket, issue in open_items:
            f = issue.get("fields", {})
            key = issue.get("key", "?")
            lines.append(
                f"| [{key}]({issue_url(key)}) | {bucket} | "
                f"{(f.get('status') or {}).get('name', '-')} | "
                f"{(f.get('priority') or {}).get('name', 'Undefined')} | "
                f"{(f.get('assignee') or {}).get('displayName', 'Unassigned')} | "
                f"{(f.get('updated') or '')[:10]} | {clean_summary(issue, limit=130)} |"
            )
        lines.append("")

    lines.extend(["## Recent Closures (Last 30 Days)", ""])
    if not recent_closed:
        lines.extend(["_No closures in the last 30 days._", ""])
    else:
        lines.extend([
            "| Key | Type | Updated | Resolution | Summary |",
            "|---|---|---|---|---|",
        ])
        for bucket, issue in recent_closed[:20]:
            f = issue.get("fields", {})
            key = issue.get("key", "?")
            lines.append(
                f"| [{key}]({issue_url(key)}) | {bucket} | {(f.get('updated') or '')[:10]} | "
                f"{(f.get('resolution') or {}).get('name', '-')} | {clean_summary(issue, limit=130)} |"
            )
        lines.append("")

    lines.extend(["## Closed Bug Duration (Working Days)", ""])
    if not closed_bug_rows:
        lines.extend(["_No closed bugs with valid start/closed dates._", ""])
    else:
        avg_working_days = sum(r[4] for r in closed_bug_rows) / len(closed_bug_rows)
        max_row = max(closed_bug_rows, key=lambda r: r[4])
        lines.extend([
            f"- Closed items tracked: **{len(closed_bug_rows)}**",
            f"- Average working days to close: **{avg_working_days:.1f}**",
            f"- Longest closure: **{max_row[4]}** working days (`{max_row[1].get('key', '?')}`)",
            "",
            "| Key | Type | Start Date | Closed Date | Working Days | Resolution | Summary |",
            "|---|---|---|---|---:|---|---|",
        ])
        for bucket, issue, start, closed, workdays in closed_bug_rows:
            f = issue.get("fields", {})
            key = issue.get("key", "?")
            lines.append(
                f"| [{key}]({issue_url(key)}) | {bucket} | {start.isoformat()} | {closed.isoformat()} | "
                f"{workdays} | {(f.get('resolution') or {}).get('name', '-')} | {clean_summary(issue, limit=120)} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_quality_summary_txt(
    now: str,
    eng_bugs: list[dict],
    cust_bugs: list[dict],
    all_cves: list[dict],
    date_range_label: str | None = None,
) -> str:
    total_issues = eng_bugs + cust_bugs + all_cves
    overall = status_dashboard(total_issues)
    eng_d = status_dashboard(eng_bugs)
    cust_d = status_dashboard(cust_bugs)
    cve_d = status_dashboard(all_cves)
    open_items = collect_open_items(eng_bugs, cust_bugs, all_cves)
    recent_closed = collect_recent_closures(eng_bugs, cust_bugs, all_cves, lookback_days=30)
    closed_bug_rows = collect_closed_bug_durations(eng_bugs, cust_bugs, all_cves)

    total = overall["Total"]
    closure_pct = (overall["Fixed/Closed"] * 100.0 / total) if total else 0.0
    risk_open = overall["In Progress"] + overall["Not Touched"]

    lines: list[str] = []
    lines.extend([
        "ZTWIM QUALITY SUMMARY",
        "=" * 80,
        f"Generated: {now}",
        f"Date range: {date_range_label}" if date_range_label else "",
        f"Source: {BASE}/jira/software/c/projects/OCPBUGS + {BASE}/jira/software/c/projects/SPIRE",
        "",
        "EXECUTIVE SNAPSHOT",
        "-" * 80,
        f"Total tracked issues: {total}",
        f"Closed/Resolved: {overall['Fixed/Closed']} ({closure_pct:.1f}%)",
        f"Open risk backlog: {risk_open} (In Progress: {overall['In Progress']}, Not Touched: {overall['Not Touched']})",
        f"Engineering bugs: {eng_d['Total']} | Customer bugs: {cust_d['Total']} | CVEs: {cve_d['Total']}",
        "",
        "CATEGORY BREAKDOWN",
        "-" * 80,
        f"{'Category':<33} {'Total':>7} {'Fixed':>7} {'In Prog':>9} {'Not Touched':>12}",
        "-" * 80,
        f"{'Engineering Bugs (Red Hat)':<33} {eng_d['Total']:>7} {eng_d['Fixed/Closed']:>7} {eng_d['In Progress']:>9} {eng_d['Not Touched']:>12}",
        f"{'Customer Bugs (OCPBUGS)':<33} {cust_d['Total']:>7} {cust_d['Fixed/Closed']:>7} {cust_d['In Progress']:>9} {cust_d['Not Touched']:>12}",
        f"{'CVEs / Vulnerabilities':<33} {cve_d['Total']:>7} {cve_d['Fixed/Closed']:>7} {cve_d['In Progress']:>9} {cve_d['Not Touched']:>12}",
        "-" * 80,
        f"{'TOTAL':<33} {overall['Total']:>7} {overall['Fixed/Closed']:>7} {overall['In Progress']:>9} {overall['Not Touched']:>12}",
        "",
        f"ATTENTION NEEDED (ALL OPEN ITEMS: {len(open_items)})",
        "-" * 80,
    ])

    if not open_items:
        lines.extend(["No open items.", ""])
    else:
        lines.append(f"{'KEY':<13} {'TYPE':<16} {'STATUS':<14} {'PRIORITY':<10} {'UPDATED':<10} SUMMARY")
        lines.append("-" * 80)
        for bucket, issue in open_items:
            f = issue.get("fields", {})
            lines.append(
                f"{issue.get('key','?'):<13} {bucket:<16} "
                f"{(f.get('status') or {}).get('name', '-')[:14]:<14} "
                f"{(f.get('priority') or {}).get('name', 'Undefined')[:10]:<10} "
                f"{(f.get('updated') or '')[:10]:<10} "
                f"{clean_summary(issue, limit=95)}"
            )
        lines.append("")

    lines.extend(["RECENT CLOSURES (LAST 30 DAYS)", "-" * 80])
    if not recent_closed:
        lines.extend(["No closures in the last 30 days.", ""])
    else:
        lines.append(f"{'KEY':<13} {'TYPE':<16} {'UPDATED':<10} {'RESOLUTION':<12} SUMMARY")
        lines.append("-" * 80)
        for bucket, issue in recent_closed[:20]:
            f = issue.get("fields", {})
            lines.append(
                f"{issue.get('key','?'):<13} {bucket:<16} {(f.get('updated') or '')[:10]:<10} "
                f"{((f.get('resolution') or {}).get('name', '-')[:12]):<12} {clean_summary(issue, limit=100)}"
            )
        lines.append("")

    lines.extend(["CLOSED BUG DURATION (WORKING DAYS)", "-" * 80])
    if not closed_bug_rows:
        lines.extend(["No closed bugs with valid start/closed dates.", ""])
    else:
        avg_working_days = sum(r[4] for r in closed_bug_rows) / len(closed_bug_rows)
        max_row = max(closed_bug_rows, key=lambda r: r[4])
        lines.extend([
            f"Closed items tracked: {len(closed_bug_rows)}",
            f"Average working days to close: {avg_working_days:.1f}",
            f"Longest closure: {max_row[4]} working days ({max_row[1].get('key', '?')})",
            "",
            f"{'KEY':<13} {'TYPE':<16} {'START':<10} {'CLOSED':<10} {'WORK DAYS':<10} {'RESOLUTION':<12} SUMMARY",
            "-" * 120,
        ])
        for bucket, issue, start, closed, workdays in closed_bug_rows:
            f = issue.get("fields", {})
            lines.append(
                f"{issue.get('key','?'):<13} {bucket:<16} {start.isoformat():<10} {closed.isoformat():<10} "
                f"{str(workdays):<10} {((f.get('resolution') or {}).get('name', '-')[:12]):<12} "
                f"{clean_summary(issue, limit=90)}"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_output_file_path(use_txt: bool) -> Path:
    timestamp = datetime.now(timezone.utc).strftime(REPORT_TIMESTAMP_FMT)
    extension = "txt" if use_txt else "md"
    return RESULT_DIR / f"{REPORT_FILE_PREFIX}-{timestamp}.{extension}"


def cleanup_old_reports() -> None:
    """If report count grows above threshold, keep only latest three files."""
    all_reports = sorted(
        [
            p
            for p in RESULT_DIR.glob(f"{REPORT_FILE_PREFIX}-*")
            if p.is_file() and p.suffix in {".md", ".txt"}
        ],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if len(all_reports) <= 8:
        return
    for old_file in all_reports[3:]:
        old_file.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ZTWIM quality summary report")
    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument("--md", action="store_true", help="Write markdown report")
    out_group.add_argument("--txt", action="store_true", help="Write plain text report")
    parser.add_argument("--start-date", help="Include issues on/after this date (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="Include issues on/before this date (YYYY-MM-DD)")
    parser.add_argument(
        "--date-field",
        choices=("created", "updated"),
        default="updated",
        help="Issue date field used by --start-date/--end-date (default: updated)",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    try:
        start_date = data_layer.parse_date_arg(args.start_date, "--start-date") if args.start_date else None
        end_date = data_layer.parse_date_arg(args.end_date, "--end-date") if args.end_date else None
    except ValueError as exc:
        parser.error(str(exc))

    if start_date and end_date and start_date > end_date:
        parser.error("--start-date must be less than or equal to --end-date")

    try:
        dataset = data_layer.build_issue_dataset(
            start_date=start_date,
            end_date=end_date,
            date_field=args.date_field,
            debug=args.debug,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    date_range_label = dataset.date_range_label
    eng_bugs = dataset.eng_bugs
    cust_bugs = dataset.cust_bugs
    all_cves = dataset.cves

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    if args.txt:
        output_file = build_output_file_path(use_txt=True)
        output_file.write_text(
            render_quality_summary_txt(
                now,
                eng_bugs,
                cust_bugs,
                all_cves,
                date_range_label=date_range_label,
            ),
            encoding="utf-8",
        )
    else:
        output_file = build_output_file_path(use_txt=False)
        output_file.write_text(
            render_quality_summary_md(
                now,
                eng_bugs,
                cust_bugs,
                all_cves,
                date_range_label=date_range_label,
            ),
            encoding="utf-8",
        )
    cleanup_old_reports()
    print(f"Quality summary written to {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
