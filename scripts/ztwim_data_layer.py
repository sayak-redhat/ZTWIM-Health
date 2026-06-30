#!/usr/bin/env python3
"""Shared data-layer utilities for report CLI and dashboard."""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = Path(os.environ.get("ZTWIM_CONFIG_FILE", ROOT_DIR / "config" / "report-config.json"))


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

BASE = os.environ.get("JIRA_BASE") or _CONFIG.get("jira_base", "https://redhat.atlassian.net")
EMAIL = os.environ.get("JIRA_EMAIL") or _CONFIG.get("jira_email", "")
TOKEN = os.environ.get("JIRA_TOKEN") or _CONFIG.get("jira_token", "")
MAX_RESULTS = 100

FIELDS = [
    "key",
    "summary",
    "status",
    "priority",
    "assignee",
    "reporter",
    "created",
    "updated",
    "resolutiondate",
    "components",
    "issuetype",
    "resolution",
]

PICKER_QUERIES = [
    "ZTWIM",
    "Zero Trust Workload Identity",
    "spire-agent CVE",
    "spiffe-spire CVE",
    "zero-trust-workload-identity-manager",
]

DYNAMIC_JQL_SOURCES = [
    "project = SPIRE AND issuetype = Bug ORDER BY created DESC",
]

CUSTOMER_BUG_JQL = (
    'project = OCPBUGS AND issuetype = Bug '
    'AND component = "zero-trust-workload-identity-manager" ORDER BY created DESC'
)

CUSTOM_FIELDS: dict[str, str] = {}

WANTED_FIELDS = {
    "sfdc": ["sfdc cases", "sfdc case", "salesforce case"],
    "sla_date": ["sla date", "sla due"],
    "cve_id": ["cve id"],
    "cvss_score": ["cvss score", "cvss"],
    "cwe_id": ["cwe id", "cwe"],
    "cve_source": ["source"],
    "update_stream": ["update stream"],
}


@dataclass
class IssueDataset:
    eng_bugs: list[dict]
    cust_bugs: list[dict]
    cves: list[dict]
    other: list[dict]
    date_range_label: str | None


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


def format_date_range(start_date: date | None, end_date: date | None, date_field: str) -> str | None:
    if start_date is None and end_date is None:
        return None
    start = start_date.isoformat() if start_date else "beginning"
    end = end_date.isoformat() if end_date else "today"
    return f"{start} to {end} ({date_field})"


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


def discover_custom_fields(debug: bool = False) -> None:
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
    _ = debug
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
    _ = debug
    found: set[str] = set()
    comp_data = jira_request("GET", f"{BASE}/rest/api/3/project/OCPBUGS/components")
    if not comp_data or not isinstance(comp_data, list):
        return found
    ztwim_comps = [
        c
        for c in comp_data
        if "zero-trust" in c.get("name", "").lower() or "spiffe" in c.get("name", "").lower()
    ]
    for comp in ztwim_comps:
        for jql in [
            f"component = {comp['id']} ORDER BY created DESC",
            f"component = {comp['id']} AND issuetype in (Bug, Vulnerability) ORDER BY created DESC",
        ]:
            data = jira_request(
                "POST",
                f"{BASE}/rest/api/3/search/jql",
                {"jql": jql, "maxResults": 100, "fields": ["key"]},
            )
            if data and isinstance(data, dict) and data.get("issues"):
                for issue in data["issues"]:
                    found.add(issue["key"])
                break
    return found


def classify_issue(issue: dict) -> str:
    f = issue.get("fields", {})
    itype = (f.get("issuetype") or {}).get("name", "").lower()
    if itype == "bug":
        return "bugs"
    if itype in ("vulnerability", "cve"):
        return "cves"
    if itype and itype not in ("bug", "vulnerability", "cve"):
        return "other"

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


def discover_keys_live(debug: bool = False) -> dict[str, list[str]]:
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


def is_customer_bug(issue: dict) -> bool:
    key = issue.get("key", "")
    if key.startswith("SPIRE-"):
        return False
    sfdc = get_sfdc_value(issue)
    if sfdc:
        return True
    return key.startswith("OCPBUGS-")


def ensure_credentials() -> None:
    if not EMAIL or not TOKEN:
        raise RuntimeError(
            "Set Jira credentials via env (`JIRA_EMAIL`, `JIRA_TOKEN`) "
            f"or config file `{CONFIG_FILE}`."
        )


def build_issue_dataset(
    start_date: date | None = None,
    end_date: date | None = None,
    date_field: str = "updated",
    debug: bool = False,
) -> IssueDataset:
    ensure_credentials()
    date_range_label = format_date_range(start_date, end_date, date_field)

    keys = discover_keys_live(debug)
    discover_custom_fields(debug)
    for fid in CUSTOM_FIELDS.values():
        if fid not in FIELDS:
            FIELDS.append(fid)
    if debug:
        print(f"[debug] Custom fields: {CUSTOM_FIELDS}", file=sys.stderr)

    all_bug_keys = sorted(set(keys["bugs"]))
    all_cve_keys = sorted(set(keys["cves"]))
    all_other_keys = sorted(set(keys.get("other", [])))

    all_bugs = fetch_by_keys(all_bug_keys)
    all_cves = fetch_by_keys(all_cve_keys)
    all_other = fetch_by_keys(all_other_keys)

    known_bug_keys = {i.get("key", "") for i in all_bugs}
    for issue in fetch_via_jql_sources(debug):
        key = issue.get("key", "")
        if key and key not in known_bug_keys:
            all_bugs.append(issue)
            known_bug_keys.add(key)

    all_bugs = filter_issues_by_date_range(all_bugs, start_date, end_date, date_field)
    all_cves = filter_issues_by_date_range(all_cves, start_date, end_date, date_field)
    all_other = filter_issues_by_date_range(all_other, start_date, end_date, date_field)

    for lst in (all_bugs, all_cves, all_other):
        lst.sort(key=lambda i: i.get("fields", {}).get("created", ""), reverse=True)

    cust_bugs = [i for i in all_bugs if is_customer_bug(i)]
    eng_bugs = [i for i in all_bugs if not is_customer_bug(i)]

    return IssueDataset(
        eng_bugs=eng_bugs,
        cust_bugs=cust_bugs,
        cves=all_cves,
        other=all_other,
        date_range_label=date_range_label,
    )
