"""Hybrid data source hub for live Jira and Result fallback."""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
import ast
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
DEFAULT_RCA_DOWNSTREAM_REPO = DEFAULT_GITHUB_REPO
DEFAULT_RCA_UPSTREAM_ORG = "spiffe"
DEFAULT_RCA_UPSTREAM_PRIORITY_REPOS = ["spiffe/spire"]
DEFAULT_RCA_MAX_BUGS = 5
DEFAULT_RCA_TEST_FRAMEWORK_DIR = "/home/sayadas/RedHat-Workspace/ztwim-test-framework"
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


@dataclass
class CustomerBugDossierResult:
    bugs: list[dict]
    warnings: list[str]


@dataclass
class CustomerBugEvidenceResult:
    downstream_repo: str
    upstream_org: str
    upstream_priority_repos: list[str]
    records: list[dict]
    warnings: list[str]


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


def default_rca_downstream_repo() -> str:
    value = (
        os.environ.get("ZTWIM_RCA_DOWNSTREAM_REPO")
        or _CONFIG.get("rca_downstream_repo", DEFAULT_RCA_DOWNSTREAM_REPO)
    ).strip()
    return value or DEFAULT_RCA_DOWNSTREAM_REPO


def default_rca_upstream_org() -> str:
    value = (
        os.environ.get("ZTWIM_RCA_UPSTREAM_ORG")
        or _CONFIG.get("rca_upstream_org", DEFAULT_RCA_UPSTREAM_ORG)
    ).strip()
    return value or DEFAULT_RCA_UPSTREAM_ORG


def default_rca_upstream_priority_repos() -> list[str]:
    from_env = (os.environ.get("ZTWIM_RCA_UPSTREAM_REPOS") or "").strip()
    if from_env:
        repos = [chunk.strip() for chunk in from_env.split(",") if chunk.strip()]
        return repos or list(DEFAULT_RCA_UPSTREAM_PRIORITY_REPOS)
    configured = _CONFIG.get("rca_upstream_repos", DEFAULT_RCA_UPSTREAM_PRIORITY_REPOS)
    if isinstance(configured, list):
        repos = [str(item).strip() for item in configured if str(item).strip()]
        if repos:
            return repos
    return list(DEFAULT_RCA_UPSTREAM_PRIORITY_REPOS)


def default_rca_max_bugs() -> int:
    raw = (
        os.environ.get("ZTWIM_RCA_MAX_BUGS")
        or str(_CONFIG.get("rca_max_bugs", DEFAULT_RCA_MAX_BUGS))
    ).strip()
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_RCA_MAX_BUGS
    if parsed <= 0:
        return DEFAULT_RCA_MAX_BUGS
    return min(parsed, 20)


def default_rca_test_framework_dir() -> str:
    value = (
        os.environ.get("ZTWIM_RCA_TEST_FRAMEWORK_DIR")
        or _CONFIG.get("rca_test_framework_dir", DEFAULT_RCA_TEST_FRAMEWORK_DIR)
    ).strip()
    return value or DEFAULT_RCA_TEST_FRAMEWORK_DIR


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


def _jira_base() -> str:
    return (os.environ.get("JIRA_BASE") or _CONFIG.get("jira_base", "https://redhat.atlassian.net")).strip()


def _jira_email() -> str:
    return (os.environ.get("JIRA_EMAIL") or _CONFIG.get("jira_email", "")).strip()


def _jira_token() -> str:
    return (os.environ.get("JIRA_TOKEN") or _CONFIG.get("jira_token", "")).strip()


def _jira_issue_fields_for_rca() -> list[str]:
    return [
        "key",
        "summary",
        "description",
        "status",
        "priority",
        "assignee",
        "reporter",
        "components",
        "labels",
        "created",
        "updated",
        "resolution",
        "resolutiondate",
        "issuelinks",
        "environment",
        "comment",
    ]


def _jira_auth_header(email: str, token: str) -> str:
    from base64 import b64encode

    return "Basic " + b64encode(f"{email}:{token}".encode("utf-8")).decode("utf-8")


def _jira_request_json(
    method: str,
    url: str,
    email: str,
    token: str,
    body: dict | None = None,
) -> dict | list:
    headers = {
        "Authorization": _jira_auth_header(email=email, token=token),
        "Accept": "application/json",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Jira API request failed (HTTP {exc.code}): {detail[:260]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Jira API request failed: {exc}") from exc


def _jira_search_issues(
    jql: str,
    email: str,
    token: str,
    max_results: int = 100,
    fields: list[str] | None = None,
) -> list[dict]:
    if not jql.strip():
        return []
    base = _jira_base()
    endpoint = f"{base}/rest/api/3/search/jql"
    collected: list[dict] = []
    next_page_token: str | None = None
    wanted_fields = fields or _jira_issue_fields_for_rca()
    while True:
        body: dict = {"jql": jql, "maxResults": max_results, "fields": wanted_fields}
        if next_page_token:
            body["nextPageToken"] = next_page_token
        payload = _jira_request_json("POST", endpoint, email=email, token=token, body=body)
        if not isinstance(payload, dict):
            break
        batch = payload.get("issues") or []
        if not isinstance(batch, list):
            break
        collected.extend([issue for issue in batch if isinstance(issue, dict)])
        if payload.get("isLast", True) or not payload.get("nextPageToken"):
            break
        next_page_token = str(payload.get("nextPageToken") or "").strip() or None
        if not next_page_token:
            break
    return collected


def _jira_adf_to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        parts = [_jira_adf_to_text(item) for item in value]
        return " ".join(part for part in parts if part).strip()
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"].strip()
        content = value.get("content")
        if isinstance(content, list):
            parts = [_jira_adf_to_text(item) for item in content]
            return " ".join(part for part in parts if part).strip()
    return ""


def _jira_issue_link_keys(issue: dict) -> list[str]:
    fields = issue.get("fields") or {}
    links = fields.get("issuelinks") or []
    if not isinstance(links, list):
        return []
    keys: set[str] = set()
    for link in links:
        if not isinstance(link, dict):
            continue
        outward = link.get("outwardIssue") or {}
        inward = link.get("inwardIssue") or {}
        for candidate in (outward, inward):
            key = str(candidate.get("key") or "").strip()
            if key:
                keys.add(key)
    return sorted(keys)


def _jira_issue_comments(issue: dict, limit: int = 4) -> list[dict]:
    fields = issue.get("fields") or {}
    comment_blob = fields.get("comment") or {}
    comments = comment_blob.get("comments") if isinstance(comment_blob, dict) else []
    if not isinstance(comments, list):
        return []
    rows: list[dict] = []
    for entry in comments[:limit]:
        if not isinstance(entry, dict):
            continue
        body_text = _jira_adf_to_text(entry.get("body"))
        author = (entry.get("author") or {}).get("displayName", "Unknown")
        rows.append(
            {
                "author": str(author).strip() or "Unknown",
                "created": str(entry.get("created") or "")[:10],
                "body": body_text[:500],
            }
        )
    return rows


def _is_open_issue(issue: dict) -> bool:
    fields = issue.get("fields") or {}
    status = fields.get("status") or {}
    category = (status.get("statusCategory") or {}).get("key", "")
    if str(category).strip().lower() == "done":
        return False
    resolution = fields.get("resolution")
    if isinstance(resolution, dict) and (resolution.get("name") or "").strip():
        return False
    return True


def _customer_bug_issue_to_dossier(issue: dict) -> dict:
    fields = issue.get("fields") or {}
    components = [
        str(component.get("name") or "").strip()
        for component in (fields.get("components") or [])
        if isinstance(component, dict) and str(component.get("name") or "").strip()
    ]
    labels = [str(label).strip() for label in (fields.get("labels") or []) if str(label).strip()]
    assignee = (fields.get("assignee") or {}).get("displayName", "Unassigned")
    reporter = (fields.get("reporter") or {}).get("displayName", "Unknown")
    description_text = _jira_adf_to_text(fields.get("description"))
    environment_text = _jira_adf_to_text(fields.get("environment"))
    return {
        "key": str(issue.get("key") or "").strip(),
        "summary": str(fields.get("summary") or "").strip(),
        "description": description_text[:4000],
        "environment": environment_text[:800],
        "status": str((fields.get("status") or {}).get("name") or "Unknown").strip(),
        "priority": str((fields.get("priority") or {}).get("name") or "Undefined").strip(),
        "assignee": str(assignee).strip() or "Unassigned",
        "reporter": str(reporter).strip() or "Unknown",
        "created": str(fields.get("created") or "")[:10],
        "updated": str(fields.get("updated") or "")[:10],
        "components": components,
        "labels": labels,
        "linked_issue_keys": _jira_issue_link_keys(issue),
        "recent_comments": _jira_issue_comments(issue),
        "url": f"{_jira_base()}/browse/{str(issue.get('key') or '').strip()}",
    }


def load_open_customer_bug_dossiers(
    start_date: date,
    end_date: date,
    max_bugs: int | None = None,
) -> CustomerBugDossierResult:
    email = _jira_email()
    token = _jira_token()
    if not email or not token:
        raise RuntimeError("Jira credentials are required for deep customer bug analysis.")

    limit = max_bugs or default_rca_max_bugs()
    limit = max(1, min(limit, 20))
    jql = (
        "project = OCPBUGS AND issuetype = Bug "
        'AND component = "zero-trust-workload-identity-manager" '
        "AND resolution = Unresolved "
        f'AND created >= "{start_date.isoformat()}" AND created <= "{end_date.isoformat()}" '
        "ORDER BY created DESC"
    )
    issues = _jira_search_issues(
        jql=jql,
        email=email,
        token=token,
        max_results=min(100, limit * 6),
        fields=_jira_issue_fields_for_rca(),
    )

    warnings: list[str] = []
    open_issues = [issue for issue in issues if _is_open_issue(issue)]
    dossiers = [_customer_bug_issue_to_dossier(issue) for issue in open_issues[:limit]]
    if not dossiers:
        warnings.append("No open customer bugs were found for the selected created-date range.")
    if len(open_issues) > limit:
        warnings.append(f"Analyzed first {limit} open customer bugs out of {len(open_issues)} total matches.")
    return CustomerBugDossierResult(bugs=dossiers, warnings=warnings)


def _github_search_issue_items(query: str, token: str, per_page: int = 8) -> list[dict]:
    encoded = urllib.parse.urlencode(
        {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": max(1, min(per_page, 30)),
        }
    )
    url = f"{GITHUB_API_BASE}/search/issues?{encoded}"
    payload = _github_get_json(url=url, token=token)
    if not isinstance(payload, dict):
        return []
    items = payload.get("items") or []
    return [item for item in items if isinstance(item, dict)]


def _repo_from_repository_url(raw_url: str) -> str:
    marker = "/repos/"
    if marker not in raw_url:
        return ""
    return raw_url.split(marker, maxsplit=1)[1].strip("/")


def _issue_summary_tokens(summary: str, limit: int = 8) -> list[str]:
    stop_words = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "that",
        "this",
        "when",
        "fails",
        "fail",
        "error",
        "issue",
        "ztwim",
        "bug",
    }
    tokens: list[str] = []
    for token in re.findall(r"[a-zA-Z0-9_-]+", summary.lower()):
        if len(token) < 4:
            continue
        if token in stop_words:
            continue
        if token not in tokens:
            tokens.append(token)
        if len(tokens) >= limit:
            break
    return tokens


def _bug_search_terms(bug: dict) -> list[dict]:
    key = str(bug.get("key") or "").strip()
    summary = str(bug.get("summary") or "").strip()
    tokens = _issue_summary_tokens(summary, limit=8)
    terms: list[dict] = []
    if key:
        terms.append({"text": key, "kind": "key"})
    if tokens:
        terms.append({"text": " ".join(tokens[:3]), "kind": "keywords"})
        if len(tokens) >= 5:
            terms.append({"text": " ".join(tokens[3:6]), "kind": "keywords"})
    elif summary:
        terms.append({"text": summary[:80], "kind": "summary"})
    return terms


def _match_confidence(bug: dict, item: dict, term_kind: str) -> tuple[str, str] | None:
    bug_key = str(bug.get("key") or "").strip().lower()
    summary_tokens = _issue_summary_tokens(str(bug.get("summary") or ""), limit=8)
    title = str(item.get("title") or "")
    body = str(item.get("body") or "")
    text = f"{title} {body}".lower()
    if bug_key and bug_key in text:
        return "high", "Exact bug key match"
    overlap = sum(1 for token in summary_tokens if token and token in text)
    if overlap >= 2:
        return "medium", f"Summary keyword overlap ({overlap})"
    if overlap == 1:
        return "low", "Single summary keyword overlap"
    if term_kind == "key":
        return "medium", "Matched by bug key query"
    return None


def _evidence_row_from_item(item: dict, confidence: str, reason: str, scope: str) -> dict:
    repo = _repo_from_repository_url(str(item.get("repository_url") or ""))
    is_pr = bool(item.get("pull_request"))
    return {
        "title": str(item.get("title") or "").strip(),
        "url": str(item.get("html_url") or "").strip(),
        "repo": repo,
        "kind": "pull_request" if is_pr else "issue",
        "state": str(item.get("state") or "").strip(),
        "created_at": str(item.get("created_at") or "")[:10],
        "updated_at": str(item.get("updated_at") or "")[:10],
        "confidence": confidence,
        "match_reason": reason,
        "scope": scope,
        "snippet": str(item.get("body") or "").strip().replace("\n", " ")[:240],
    }


def _dedupe_evidence_rows(rows: list[dict], limit: int) -> list[dict]:
    seen: set[str] = set()
    deduped: list[dict] = []
    for row in rows:
        url = str(row.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        deduped.append(row)
        if len(deduped) >= limit:
            break
    return deduped


def load_customer_bug_github_evidence(
    bug_dossiers: list[dict],
    downstream_repo: str | None = None,
    upstream_org: str | None = None,
    upstream_priority_repos: list[str] | None = None,
    per_bug_limit: int = 8,
) -> CustomerBugEvidenceResult:
    resolved_downstream_repo = (downstream_repo or default_rca_downstream_repo()).strip()
    resolved_upstream_org = (upstream_org or default_rca_upstream_org()).strip()
    resolved_upstream_priority_repos = upstream_priority_repos or default_rca_upstream_priority_repos()

    token = _github_token()
    warnings: list[str] = []
    if not token:
        warnings.append("GitHub token is not configured. Deep evidence collection may hit rate limits.")
    github_search_error: str = ""

    def _safe_github_search(query: str, per_page: int) -> list[dict]:
        nonlocal github_search_error
        if github_search_error:
            return []
        try:
            return _github_search_issue_items(query=query, token=token, per_page=per_page)
        except RuntimeError as exc:
            github_search_error = str(exc)
            warnings.append(f"GitHub evidence search is unavailable right now: {exc}")
            return []

    records: list[dict] = []
    safe_limit = max(2, min(per_bug_limit, 15))
    for bug in bug_dossiers:
        bug_key = str(bug.get("key") or "").strip()
        terms = _bug_search_terms(bug)
        downstream_candidates: list[dict] = []
        upstream_candidates: list[dict] = []
        for term in terms:
            text = str(term.get("text") or "").strip()
            kind = str(term.get("kind") or "keywords")
            if not text:
                continue

            if resolved_downstream_repo and "/" in resolved_downstream_repo:
                q = f'{text} repo:{resolved_downstream_repo}'
                for item in _safe_github_search(query=q, per_page=8):
                    matched = _match_confidence(bug=bug, item=item, term_kind=kind)
                    if not matched:
                        continue
                    confidence, reason = matched
                    downstream_candidates.append(
                        _evidence_row_from_item(
                            item=item,
                            confidence=confidence,
                            reason=reason,
                            scope="downstream",
                        )
                    )

            for repo in resolved_upstream_priority_repos:
                repo_name = str(repo).strip()
                if not repo_name or "/" not in repo_name:
                    continue
                q = f'{text} repo:{repo_name}'
                for item in _safe_github_search(query=q, per_page=6):
                    matched = _match_confidence(bug=bug, item=item, term_kind=kind)
                    if not matched:
                        continue
                    confidence, reason = matched
                    upstream_candidates.append(
                        _evidence_row_from_item(
                            item=item,
                            confidence=confidence,
                            reason=f"{reason}; priority upstream repo",
                            scope="upstream",
                        )
                    )

            if len(upstream_candidates) < safe_limit and resolved_upstream_org:
                q = f'{text} org:{resolved_upstream_org}'
                for item in _safe_github_search(query=q, per_page=6):
                    matched = _match_confidence(bug=bug, item=item, term_kind=kind)
                    if not matched:
                        continue
                    confidence, reason = matched
                    upstream_candidates.append(
                        _evidence_row_from_item(
                            item=item,
                            confidence=confidence,
                            reason=f"{reason}; upstream org match",
                            scope="upstream",
                        )
                    )

            if len(downstream_candidates) >= safe_limit and len(upstream_candidates) >= safe_limit:
                break

        records.append(
            {
                "bug_key": bug_key,
                "downstream_evidence": _dedupe_evidence_rows(downstream_candidates, limit=safe_limit),
                "upstream_evidence": _dedupe_evidence_rows(upstream_candidates, limit=safe_limit),
            }
        )

    return CustomerBugEvidenceResult(
        downstream_repo=resolved_downstream_repo,
        upstream_org=resolved_upstream_org,
        upstream_priority_repos=[repo for repo in resolved_upstream_priority_repos if repo.strip()],
        records=records,
        warnings=warnings,
    )


def _text_tokens(text: str, limit: int = 40) -> list[str]:
    stop_words = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "that",
        "this",
        "when",
        "fails",
        "fail",
        "error",
        "issue",
        "test",
        "tests",
        "should",
        "using",
        "into",
        "after",
        "before",
        "within",
        "through",
        "cluster",
        "clusters",
        "operator",
        "ztwim",
        "spire",
        "server",
        "trust",
        "bundle",
        "identity",
        "workload",
        "manager",
        "config",
        "configuration",
        "token",
        "sync",
        "remote",
        "local",
        "description",
        "problem",
    }
    tokens: list[str] = []
    for token in re.findall(r"[a-zA-Z0-9_-]+", str(text or "").lower()):
        if len(token) < 4:
            continue
        if token in stop_words:
            continue
        if token not in tokens:
            tokens.append(token)
        if len(tokens) >= limit:
            break
    return tokens


def _suite_from_test_path(path: Path) -> str:
    parts = list(path.parts)
    if "tests" in parts:
        idx = parts.index("tests")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "unknown"


def _extract_test_scenarios_from_file(path: Path) -> list[dict]:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    relative_path = str(path)
    suite = _suite_from_test_path(path)
    scenarios: list[dict] = []

    def _append_scenario(function_node: ast.FunctionDef, class_name: str = "") -> None:
        if not function_node.name.startswith("test_"):
            return
        fn_doc = ast.get_docstring(function_node) or ""
        clean_name = function_node.name.replace("test_", "").replace("_", " ").strip()
        if class_name:
            title = f"{class_name}::{clean_name}"
            scenario_id = f"{class_name}.{function_node.name}"
        else:
            title = clean_name
            scenario_id = function_node.name
        keywords = _text_tokens(f"{class_name} {function_node.name} {fn_doc} {relative_path}", limit=24)
        scenarios.append(
            {
                "id": scenario_id,
                "title": title,
                "path": relative_path,
                "suite": suite,
                "description": fn_doc.strip(),
                "keywords": keywords,
            }
        )

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            _append_scenario(node, class_name="")
        elif isinstance(node, ast.ClassDef):
            class_name = node.name
            for child in node.body:
                if isinstance(child, ast.FunctionDef):
                    _append_scenario(child, class_name=class_name)

    return scenarios


def load_test_framework_scenarios(test_framework_dir: str | None = None) -> dict:
    root = Path((test_framework_dir or default_rca_test_framework_dir()).strip()).expanduser()
    tests_root = root / "tests"
    warnings: list[str] = []
    if not root.exists():
        return {
            "scenarios": [],
            "suite_breakdown": {},
            "warnings": [f"Test framework path does not exist: {root}"],
            "test_framework_dir": str(root),
        }
    if not tests_root.exists():
        return {
            "scenarios": [],
            "suite_breakdown": {},
            "warnings": [f"Test framework has no tests directory: {tests_root}"],
            "test_framework_dir": str(root),
        }

    scenarios: list[dict] = []
    for path in sorted(tests_root.glob("**/*.py")):
        scenarios.extend(_extract_test_scenarios_from_file(path))

    if not scenarios:
        warnings.append("No test scenarios were extracted from the test framework files.")

    suite_breakdown: dict[str, int] = {}
    for item in scenarios:
        suite = str(item.get("suite") or "unknown")
        suite_breakdown[suite] = suite_breakdown.get(suite, 0) + 1

    return {
        "scenarios": scenarios,
        "suite_breakdown": suite_breakdown,
        "warnings": warnings,
        "test_framework_dir": str(root),
    }


def _bug_text_for_coverage(bug: dict) -> str:
    comments = bug.get("recent_comments") or []
    comment_text = " ".join(str(c.get("body") or "") for c in comments if isinstance(c, dict))
    fields = [
        bug.get("summary", ""),
        bug.get("description", ""),
        bug.get("environment", ""),
        " ".join(bug.get("components", []) or []),
        " ".join(bug.get("labels", []) or []),
        comment_text,
    ]
    return " ".join(str(item or "") for item in fields).strip()


def _scenario_token_frequency(scenarios: list[dict]) -> dict[str, int]:
    freq: dict[str, int] = {}
    for scenario in scenarios:
        seen = set(str(token).strip() for token in (scenario.get("keywords") or []) if str(token).strip())
        for token in seen:
            freq[token] = freq.get(token, 0) + 1
    return freq


def _coverage_for_bug(bug: dict, scenarios: list[dict], token_frequency: dict[str, int]) -> dict:
    bug_tokens = _text_tokens(_bug_text_for_coverage(bug), limit=40)
    if not bug_tokens:
        return {
            "coverage_status": "unknown",
            "coverage_reason": "Bug text is too sparse to map against internal test scenarios.",
            "covered_scenarios": [],
            "coverage_gaps": [],
            "bug_keywords": [],
        }

    signal_threshold = max(2, int(0.15 * max(len(scenarios), 1)))
    signal_tokens = [token for token in bug_tokens if token_frequency.get(token, 0) <= signal_threshold]
    if not signal_tokens:
        signal_tokens = bug_tokens[:]

    matches: list[dict] = []
    covered_keywords: set[str] = set()
    for scenario in scenarios:
        scenario_keywords = scenario.get("keywords") or []
        overlap = [token for token in bug_tokens if token in scenario_keywords]
        if not overlap:
            continue
        signal_overlap = [token for token in overlap if token in signal_tokens]
        if not signal_overlap and len(overlap) < 3:
            continue
        covered_keywords.update(overlap)
        weighted_score = len(overlap) + (2 * len(signal_overlap))
        matches.append(
            {
                "scenario_id": scenario.get("id", ""),
                "title": scenario.get("title", ""),
                "suite": scenario.get("suite", ""),
                "path": scenario.get("path", ""),
                "match_score": weighted_score,
                "signal_match_count": len(signal_overlap),
                "matched_keywords": overlap[:8],
                "description": scenario.get("description", ""),
            }
        )

    matches.sort(key=lambda item: (int(item.get("match_score", 0)), str(item.get("title", ""))), reverse=True)
    top_matches = matches[:10]
    uncovered = [token for token in signal_tokens if token not in covered_keywords][:10]

    downstream_e2e_matches = [item for item in matches if str(item.get("suite") or "") == "e2e_singleCluster"]
    downstream_e2e_matches = downstream_e2e_matches[:10]
    e2e_covered_keywords: set[str] = set()
    for item in downstream_e2e_matches:
        for token in item.get("matched_keywords", []) or []:
            if token:
                e2e_covered_keywords.add(str(token))
    e2e_uncovered = [token for token in signal_tokens if token not in e2e_covered_keywords][:10]

    if not top_matches:
        status = "not_covered"
        reason = "No internal regression scenarios matched this bug signature."
    elif int(top_matches[0].get("match_score", 0)) >= 5 and len(top_matches) >= 3 and len(uncovered) <= 3:
        status = "likely_covered"
        reason = "Internal tests appear to cover related behavior, so miss is likely execution or assertion depth."
    else:
        status = "partial_coverage"
        reason = "Some related internal tests exist, but coverage is partial for this bug signature."

    if not downstream_e2e_matches:
        e2e_status = "not_covered"
        e2e_reason = "No downstream e2e_singleCluster scenarios matched this bug signature."
    elif (
        int(downstream_e2e_matches[0].get("match_score", 0)) >= 5
        and len(downstream_e2e_matches) >= 2
        and len(e2e_uncovered) <= 3
    ):
        e2e_status = "likely_covered"
        e2e_reason = "Downstream e2e scenarios appear to cover related behavior."
    else:
        e2e_status = "partial_coverage"
        e2e_reason = "Downstream e2e coverage is partial for this bug signature."

    return {
        "coverage_status": status,
        "coverage_reason": reason,
        "covered_scenarios": top_matches,
        "coverage_gaps": uncovered,
        "bug_keywords": bug_tokens,
        "downstream_e2e_coverage_status": e2e_status,
        "downstream_e2e_coverage_reason": e2e_reason,
        "downstream_e2e_covered_scenarios": downstream_e2e_matches,
        "downstream_e2e_coverage_gaps": e2e_uncovered,
    }


def analyze_customer_bug_test_coverage(bug_dossiers: list[dict], test_framework_dir: str | None = None) -> dict:
    scenario_blob = load_test_framework_scenarios(test_framework_dir=test_framework_dir)
    scenarios = list(scenario_blob.get("scenarios", []))
    token_frequency = _scenario_token_frequency(scenarios)
    coverage_by_bug: dict[str, dict] = {}
    for bug in bug_dossiers:
        key = str(bug.get("key") or "").strip()
        if not key:
            continue
        coverage_by_bug[key] = _coverage_for_bug(bug=bug, scenarios=scenarios, token_frequency=token_frequency)
    return {
        "coverage_by_bug": coverage_by_bug,
        "suite_breakdown": scenario_blob.get("suite_breakdown", {}),
        "test_framework_dir": scenario_blob.get("test_framework_dir", ""),
        "test_scenario_count": len(scenarios),
        "warnings": list(scenario_blob.get("warnings", [])),
    }


def load_customer_bug_root_cause_context(
    start_date: date,
    end_date: date,
    max_bugs: int | None = None,
    downstream_repo: str | None = None,
    upstream_org: str | None = None,
    upstream_priority_repos: list[str] | None = None,
    test_framework_dir: str | None = None,
) -> dict:
    dossier_result = load_open_customer_bug_dossiers(
        start_date=start_date,
        end_date=end_date,
        max_bugs=max_bugs,
    )
    evidence_result = load_customer_bug_github_evidence(
        bug_dossiers=dossier_result.bugs,
        downstream_repo=downstream_repo,
        upstream_org=upstream_org,
        upstream_priority_repos=upstream_priority_repos,
    )
    coverage_result = analyze_customer_bug_test_coverage(
        bug_dossiers=dossier_result.bugs,
        test_framework_dir=test_framework_dir,
    )

    evidence_map = {str(record.get("bug_key") or ""): record for record in evidence_result.records}
    coverage_map = dict(coverage_result.get("coverage_by_bug", {}))
    merged_bugs: list[dict] = []
    for bug in dossier_result.bugs:
        key = str(bug.get("key") or "")
        record = evidence_map.get(key, {})
        coverage = coverage_map.get(key, {})
        merged_bugs.append(
            {
                **bug,
                "downstream_evidence": list(record.get("downstream_evidence") or []),
                "upstream_evidence": list(record.get("upstream_evidence") or []),
                "test_coverage": coverage,
            }
        )

    warnings = list(dossier_result.warnings) + list(evidence_result.warnings) + list(coverage_result.get("warnings", []))
    return {
        "bugs": merged_bugs,
        "targets": {
            "downstream_repo": evidence_result.downstream_repo,
            "upstream_org": evidence_result.upstream_org,
            "upstream_priority_repos": evidence_result.upstream_priority_repos,
            "test_framework_dir": coverage_result.get("test_framework_dir", ""),
            "test_scenario_count": int(coverage_result.get("test_scenario_count", 0) or 0),
            "test_suite_breakdown": coverage_result.get("suite_breakdown", {}),
        },
        "warnings": warnings,
    }


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
