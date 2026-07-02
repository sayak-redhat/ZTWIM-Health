"""Streamlit dashboard for ZTWIM velocity insights."""

from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timedelta, timezone

import streamlit as st

from claude_agent import generate_insights, generate_root_cause_insights
from data_source import (
    DataSourceHub,
    default_github_repo,
    default_rca_downstream_repo,
    default_rca_max_bugs,
    default_rca_test_framework_dir,
    default_rca_upstream_org,
    default_rca_upstream_priority_repos,
    default_regression_artifacts_dir,
    load_github_pr_source,
    load_customer_bug_root_cause_context,
    load_regression_test_source,
)
from metrics_engine import (
    compute_github_pr_velocity_metrics,
    compute_regression_metrics,
    compute_velocity_metrics,
    issue_status_bucket,
)


@st.cache_data(ttl=300, show_spinner=False)
def _load_dashboard_payload(
    start_date_iso: str,
    end_date_iso: str,
    date_view: str,
    debug_mode: bool,
) -> dict:
    start_date = datetime.strptime(start_date_iso, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_iso, "%Y-%m-%d").date()
    hub = DataSourceHub(mode="result")
    source = hub.load(start_date=start_date, end_date=end_date, date_field=date_view, debug=debug_mode)
    metrics = compute_velocity_metrics(
        eng_bugs=source.eng_bugs,
        cust_bugs=source.cust_bugs,
        cves=source.cves,
        date_view=date_view,
        start=start_date,
        end=end_date,
        category_breakdown=source.category_breakdown,
    )
    return {
        "metrics": metrics,
        "issues": {
            "eng_bugs": source.eng_bugs,
            "cust_bugs": source.cust_bugs,
            "cves": source.cves,
        },
        "source": {
            "name": source.source,
            "date_range_label": source.date_range_label,
            "category_breakdown": source.category_breakdown,
            "warnings": source.warnings,
        },
    }


@st.cache_data(ttl=300, show_spinner=False)
def _load_github_payload(start_date_iso: str, end_date_iso: str, github_repo: str) -> dict:
    start_date = datetime.strptime(start_date_iso, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_iso, "%Y-%m-%d").date()
    source = load_github_pr_source(start_date=start_date, end_date=end_date, repo=github_repo)
    metrics = compute_github_pr_velocity_metrics(
        open_pr_count=source.open_pr_count,
        closed_prs=source.closed_prs_in_range,
    )
    source_warnings = list(source.warnings)
    # Backward-compatible fallback for older cached/source shapes.
    open_prs_in_repo = getattr(source, "open_prs_in_repo", [])
    if not hasattr(source, "open_prs_in_repo") and source.open_pr_count > 0:
        source_warnings.append(
            "Open PR detail rows are unavailable from a stale app process; restart Streamlit to load latest code."
        )
    return {
        "metrics": metrics,
        "open_pr_rows": _open_pr_rows(open_prs_in_repo),
        "source": {
            "repo": source.repo,
            "warnings": source_warnings,
        },
    }


@st.cache_data(ttl=300, show_spinner=False)
def _load_regression_payload(start_date_iso: str, end_date_iso: str, regression_artifacts_dir: str) -> dict:
    start_date = datetime.strptime(start_date_iso, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_iso, "%Y-%m-%d").date()
    source = load_regression_test_source(
        start_date=start_date,
        end_date=end_date,
        artifacts_dir=regression_artifacts_dir,
    )
    metrics = compute_regression_metrics(runs=source.runs, start=start_date, end=end_date)
    source_warnings = list(getattr(source, "warnings", []))
    log_summary = getattr(source, "log_summary", {})
    if not hasattr(source, "log_summary"):
        source_warnings.append(
            "Log summary is unavailable from a stale app process; restart Streamlit to load latest code."
        )
    return {
        "metrics": metrics,
        "source": {
            "artifacts_dir": source.artifacts_dir,
            "warnings": source_warnings,
            "log_summary": log_summary,
        },
    }


@st.cache_data(ttl=300, show_spinner=False)
def _load_customer_bug_rca_payload(
    start_date_iso: str,
    end_date_iso: str,
    downstream_repo: str,
    upstream_org: str,
    upstream_priority_repos_csv: str,
    max_bugs: int,
    test_framework_dir: str,
) -> dict:
    start_date = datetime.strptime(start_date_iso, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_iso, "%Y-%m-%d").date()
    priority_repos = [item.strip() for item in upstream_priority_repos_csv.split(",") if item.strip()]
    return load_customer_bug_root_cause_context(
        start_date=start_date,
        end_date=end_date,
        max_bugs=max_bugs,
        downstream_repo=downstream_repo.strip(),
        upstream_org=upstream_org.strip(),
        upstream_priority_repos=priority_repos,
        test_framework_dir=test_framework_dir.strip(),
    )


def _rows_to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _to_date(value):
    if hasattr(value, "isoformat"):
        return value
    return datetime.strptime(str(value), "%Y-%m-%d").date()


def _run_with_loading_animation(
    banner_message: str,
    spinner_message: str,
    loader,
    min_seconds: float = 0.4,
):
    loading_notice = st.empty()
    loading_notice.markdown(
        f'<div class="ztwim-loading-banner">{banner_message}</div>',
        unsafe_allow_html=True,
    )
    started = time.perf_counter()
    try:
        with st.spinner(spinner_message):
            return loader()
    finally:
        elapsed = time.perf_counter() - started
        if elapsed < min_seconds:
            time.sleep(min_seconds - elapsed)
        loading_notice.empty()


def _open_issue_rows(issues: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for issue in issues:
        if issue_status_bucket(issue) == "Fixed/Closed":
            continue
        fields = issue.get("fields", {})
        rows.append(
            {
                "key": issue.get("key", "?"),
                "status": (fields.get("status") or {}).get("name", "Unknown"),
                "priority": (fields.get("priority") or {}).get("name", "Undefined"),
                "assignee": (fields.get("assignee") or {}).get("displayName", "Unassigned"),
                "updated": ((fields.get("updated") or "")[:10]).strip(),
                "summary": (fields.get("summary", "") or "").strip(),
            }
        )
    rows.sort(key=lambda r: (r["updated"], r["key"]), reverse=True)
    return rows


def _open_pr_rows(prs: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for pr in prs:
        user = pr.get("user") or {}
        rows.append(
            {
                "number": int(pr.get("number", 0) or 0),
                "title": (pr.get("title") or "").strip(),
                "author": (user.get("login") or "unknown").strip(),
                "created_at": (pr.get("created_at") or "")[:10],
                "updated_at": (pr.get("updated_at") or "")[:10],
                "draft": bool(pr.get("draft", False)),
                "url": pr.get("html_url", ""),
            }
        )
    rows.sort(key=lambda r: (r["updated_at"], r["number"]), reverse=True)
    return rows


def _regression_ai_insight_rows(reg_metrics: dict, log_summary: dict) -> list[dict]:
    summary = reg_metrics.get("summary", {})
    run_rows = reg_metrics.get("run_rows", [])
    if not run_rows:
        return [
            {
                "insight": "No regression runs",
                "metric": "Data availability",
                "current_value": "No runs in selected range",
                "trend": "N/A",
                "recommendation": "Widen date range or verify artifacts path.",
            }
        ]

    latest = run_rows[0]
    baseline_rows = run_rows[1:4] if len(run_rows) > 1 else run_rows[:1]

    def _avg(rows: list[dict], key: str) -> float:
        if not rows:
            return 0.0
        return sum(float(row.get(key, 0.0) or 0.0) for row in rows) / len(rows)

    def _trend_label(delta: float, better_when_higher: bool, threshold: float) -> str:
        if abs(delta) < threshold:
            return "Stable"
        if better_when_higher:
            return "Improving" if delta > 0 else "Declining"
        return "Improving" if delta < 0 else "Declining"

    latest_pass_rate = float(latest.get("pass_rate_pct", 0.0) or 0.0)
    baseline_pass_rate = _avg(baseline_rows, "pass_rate_pct")
    pass_rate_delta = latest_pass_rate - baseline_pass_rate

    latest_failed = float(latest.get("failed_tests", 0.0) or 0.0)
    baseline_failed = _avg(baseline_rows, "failed_tests")
    failed_delta = latest_failed - baseline_failed

    latest_skipped = float(latest.get("skipped_tests", 0.0) or 0.0)
    baseline_skipped = _avg(baseline_rows, "skipped_tests")
    skipped_delta = latest_skipped - baseline_skipped

    latest_duration = float(latest.get("duration_minutes", 0.0) or 0.0)
    baseline_duration = _avg(baseline_rows, "duration_minutes")
    duration_delta = latest_duration - baseline_duration

    log_error_count = int(log_summary.get("error_count", 0)) if isinstance(log_summary, dict) else 0
    log_warning_count = int(log_summary.get("warning_count", 0)) if isinstance(log_summary, dict) else 0

    return [
        {
            "insight": "Pass rate health",
            "metric": "Latest run pass rate",
            "current_value": f"{latest_pass_rate:.1f}% (overall {float(summary.get('pass_rate_pct', 0.0)):.1f}%)",
            "trend": _trend_label(pass_rate_delta, better_when_higher=True, threshold=1.0),
            "recommendation": "Protect pass-rate baseline; investigate any decline >1%.",
        },
        {
            "insight": "Failure pressure",
            "metric": "Failed tests per run",
            "current_value": (
                f"Latest {latest_failed:.0f} | Avg/run {float(summary.get('avg_failed_per_run', 0.0)):.1f}"
            ),
            "trend": _trend_label(failed_delta, better_when_higher=False, threshold=1.0),
            "recommendation": "Prioritize top failed tests and recurring failure signatures.",
        },
        {
            "insight": "Skip behavior",
            "metric": "Skipped tests per run",
            "current_value": (
                f"Latest {latest_skipped:.0f} | Avg/run {float(summary.get('avg_skipped_per_run', 0.0)):.1f}"
            ),
            "trend": _trend_label(skipped_delta, better_when_higher=False, threshold=1.0),
            "recommendation": "Reduce non-actionable skips; separate infra-skip vs intentional skip.",
        },
        {
            "insight": "Execution efficiency",
            "metric": "Run duration (minutes)",
            "current_value": (
                f"Latest {latest_duration:.1f} | Avg/run {float(summary.get('avg_run_duration_minutes', 0.0)):.1f}"
            ),
            "trend": _trend_label(duration_delta, better_when_higher=False, threshold=2.0),
            "recommendation": "Watch runtime drift; optimize slow suites and flaky setup paths.",
        },
        {
            "insight": "Log risk signal",
            "metric": "pytest.log warnings/errors",
            "current_value": f"errors={log_error_count}, warnings={log_warning_count}",
            "trend": "Needs attention" if (log_error_count > 0 or log_warning_count > 0) else "Stable",
            "recommendation": "Track recurring log errors/warnings and map to failing/unstable tests.",
        },
    ]


def _apply_visual_theme() -> None:
    st.markdown(
        """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        [data-testid="stToolbar"] {display: none;}
        [data-testid="stDecoration"] {display: none;}
        .stApp {
            background: linear-gradient(180deg, #0b1220 0%, #111827 100%);
            color: #e5e7eb;
        }
        h1, h2, h3 {
            color: #f9fafb;
        }
        p, li, label {
            color: #d1d5db;
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #111827 0%, #0b1220 100%);
        }
        [data-testid="stSidebar"] * {
            color: #e5e7eb;
        }
        [data-testid="stSidebar"] .stButton > button {
            background: linear-gradient(90deg, #ee0000, #f97316);
            color: #ffffff;
            border: none;
        }
        [data-testid="stMetric"] {
            background: #0f172a;
            border: 1px solid #334155;
            border-left: 4px solid #ee0000;
            border-radius: 12px;
            padding: 12px 14px;
            box-shadow: 0 2px 8px rgba(2, 6, 23, 0.45);
        }
        [data-testid="stMetricLabel"] {
            color: #cbd5e1;
            font-weight: 600;
        }
        [data-testid="stMetricValue"] {
            color: #f8fafc;
        }
        div[data-testid="stDataFrame"] {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 0.3rem;
        }
        button[kind="primary"] {
            background: linear-gradient(90deg, #2563eb, #7c3aed);
            color: #ffffff;
            border: none;
        }
        .stDownloadButton > button {
            background: #111827;
            color: #e5e7eb;
            border: 1px solid #334155;
        }
        [data-testid="stSpinner"] > div {
            border-top-color: #ee0000 !important;
        }
        [data-testid="stSpinner"] p {
            color: #f8fafc !important;
            font-weight: 600;
        }
        .ztwim-loading-banner {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid #334155;
            border-left: 4px solid #ee0000;
            color: #f8fafc;
            border-radius: 10px;
            padding: 0.65rem 0.8rem;
            margin: 0.25rem 0 0.75rem 0;
            font-weight: 600;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="ZTWIM Health Dashboard", layout="wide")
    _apply_visual_theme()
    st.title("ZTWIM Health Dashboard")

    today = datetime.now(timezone.utc).date()
    default_start = today - timedelta(days=60)

    with st.sidebar:
        st.header("Filters")
        start_date = _to_date(st.date_input("Start date", value=default_start))
        end_date = _to_date(st.date_input("End date", value=today))
        github_repo = st.text_input(
            "GitHub repository",
            value=default_github_repo(),
            help="owner/repo format",
        ).strip()
        regression_artifacts_dir = st.text_input(
            "Regression artifacts path",
            value=default_regression_artifacts_dir(),
            help="Path to ztwim-test-framework with reports/ or test-reports/",
        ).strip()
        date_view = st.selectbox(
            "Velocity date semantics",
            options=[
                ("resolutiondate", "Closed Date (resolutiondate)"),
                ("updated", "Updated Date"),
            ],
            format_func=lambda x: x[1],
            index=0,
        )[0]
        debug_mode = st.checkbox("Debug fetch", value=False)
        refresh = st.button("Force Refresh From Source", type="primary")

    if start_date > end_date:
        st.error("Start date must be <= end date.")
        st.stop()

    # Deep RCA settings are sourced from config/env, not dashboard inputs.
    rca_downstream_repo = default_rca_downstream_repo()
    rca_upstream_org = default_rca_upstream_org()
    rca_upstream_priority_repos_csv = ",".join(default_rca_upstream_priority_repos())
    rca_max_bugs = default_rca_max_bugs()
    rca_test_framework_dir = default_rca_test_framework_dir()

    if refresh:
        _load_dashboard_payload.clear()
        _load_github_payload.clear()
        _load_regression_payload.clear()
        _load_customer_bug_rca_payload.clear()

    try:
        payload = _run_with_loading_animation(
            banner_message="Loading dashboard metrics. Please wait...",
            spinner_message="Loading dashboard data...",
            loader=lambda: _load_dashboard_payload(
                start_date_iso=start_date.isoformat(),
                end_date_iso=end_date.isoformat(),
                date_view=date_view,
                debug_mode=debug_mode,
            ),
        )
    except Exception as exc:  # pylint: disable=broad-except
        st.error(f"Failed to load dashboard data: {exc}")
        st.info(
            "If you want auto-generation for new date ranges, set Jira credentials in "
            "`config/report-config.json` (`jira_email`, `jira_token`) or env vars."
        )
        st.stop()
    metrics = payload["metrics"]
    issues = payload["issues"]
    summary = metrics["summary"]
    all_closed_rows = sorted(metrics["closure_rows"], key=lambda r: r["working_days"], reverse=True)
    engineering_bug_rows = [row for row in all_closed_rows if row["type"] == "Engineering Bug"]
    customer_bug_rows = [row for row in all_closed_rows if row["type"] == "Customer Bug"]
    closed_cve_rows = [row for row in all_closed_rows if row["type"] == "CVE"]
    open_engineering_rows = _open_issue_rows(issues["eng_bugs"])
    open_customer_rows = _open_issue_rows(issues["cust_bugs"])
    open_cve_rows = _open_issue_rows(issues["cves"])

    bug_tab, github_tab, regression_tab = st.tabs(["Bug Dashboard", "GitHub Dashboard", "Regression Dashboard"])

    with bug_tab:
        st.subheader("Overview")
        c1, c2, c3 = st.columns(3)
        c1.metric("Median Close Days", f"{summary['median_close_days']:.1f}")
        c2.metric("P90 Close Days", f"{summary['p90_close_days']:.1f}")
        c3.metric("Closed Bugs", int(summary["closed_bug_count"]))
        closed_count = int(summary["closed_bug_count"])
        median_close_days = float(summary["median_close_days"])
        p90_close_days = float(summary["p90_close_days"])
        if closed_count >= 30:
            confidence_note = "high confidence (enough data)"
        elif closed_count >= 10:
            confidence_note = "medium confidence (some data)"
        else:
            confidence_note = "low confidence (small data, trend may change quickly)"

        st.caption(
            f"How reliable this trend is: {confidence_note}. Based on {closed_count} closed bugs in this date range."
        )
        st.markdown(
            "\n".join(
                [
                    "**Overview field guide (simple):**",
                    (
                        f"- **Median Close Days ({median_close_days:.1f})**: The usual time to fix a bug. "
                        "Around half of bugs are fixed in this time or faster."
                    ),
                    (
                        f"- **P90 Close Days ({p90_close_days:.1f})**: The slower end of delivery. "
                        "Most bugs (9 out of 10) are fixed within this time."
                    ),
                    (
                        f"- **Closed Bugs ({closed_count})**: How many bugs were completed in this date range. "
                        "A bigger number usually means these KPIs are more trustworthy."
                    ),
                ]
            )
        )
        st.subheader("Velocity By Type")
        st.dataframe(metrics["avg_velocity_by_type"], use_container_width=True)

        st.subheader("CVE Snapshot")
        cve_row = next((row for row in metrics["avg_velocity_by_type"] if row["type"] == "CVE"), None)
        if cve_row:
            cve_total = int(cve_row["total_items"])
            cve_closed = int(cve_row["closed_items"])
            cve_open = max(cve_total - cve_closed, 0)
            cc1, cc2, cc3, cc4 = st.columns(4)
            cc1.metric("Total CVEs", cve_total)
            cc2.metric("Open CVEs", cve_open)
            cc3.metric("Closed CVEs", cve_closed)
            cc4.metric("Closure Rate", f"{cve_row['closure_rate_pct']:.1f}%")
            st.caption(
                "CVE velocity (working days): "
                f"avg {cve_row['avg_close_days']:.1f}, median {cve_row['median_close_days']:.1f}"
            )
        else:
            st.info("No CVE data available for the selected date range.")

        st.subheader("Open Engineering Bugs")
        if open_engineering_rows:
            st.dataframe(open_engineering_rows, use_container_width=True)
        else:
            st.info("No open engineering bugs found for this date range/result data.")

        st.subheader("Open Customer Bugs")
        if open_customer_rows:
            st.dataframe(open_customer_rows, use_container_width=True)
        else:
            st.info("No open customer bugs found for this date range/result data.")

        st.subheader("Open CVEs")
        if open_cve_rows:
            st.dataframe(open_cve_rows, use_container_width=True)
        else:
            st.info("No open CVEs found for this date range/result data.")

        st.subheader("Closed Engineering Bugs (Details Table)")
        if engineering_bug_rows:
            st.dataframe(engineering_bug_rows, use_container_width=True)
        else:
            st.info("No closed engineering bug records available for this date range.")

        st.subheader("Closed Customer Bugs (Details Table)")
        if customer_bug_rows:
            st.dataframe(customer_bug_rows, use_container_width=True)
        else:
            st.info("No closed customer bug records available for this date range.")

        st.subheader("Closed CVEs (Details Table)")
        if closed_cve_rows:
            st.dataframe(closed_cve_rows, use_container_width=True)
        else:
            st.info("No closed CVE records available for this date range.")

        st.subheader("AI Insights")
        context = {
            "date_window": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "date_semantics": date_view,
            "source": "Result directory",
        }
        if st.button("Generate Insights", key="generate_insights_bug"):
            with st.spinner("Generating insights..."):
                insight_text = generate_insights(metrics=metrics, context=context)
            st.markdown(insight_text)

        st.subheader("Deep Root-Cause Insights (Open Customer Bugs)")
        st.caption(
            "Investigates open customer bugs created in selected range using Jira details, downstream/upstream repo "
            "evidence, and downstream e2e test-coverage gaps."
        )
        if st.button("Generate Deep Root-Cause Insights", key="generate_root_cause_insights_bug"):
            try:
                rca_payload = _run_with_loading_animation(
                    banner_message="Loading customer bug dossiers, repo evidence, and test coverage...",
                    spinner_message="Collecting Jira + repo evidence + test-framework coverage...",
                    loader=lambda: _load_customer_bug_rca_payload(
                        start_date_iso=start_date.isoformat(),
                        end_date_iso=end_date.isoformat(),
                        downstream_repo=rca_downstream_repo,
                        upstream_org=rca_upstream_org,
                        upstream_priority_repos_csv=rca_upstream_priority_repos_csv,
                        max_bugs=rca_max_bugs,
                        test_framework_dir=rca_test_framework_dir,
                    ),
                    min_seconds=0.5,
                )
            except Exception as exc:  # pylint: disable=broad-except
                st.warning(f"Deep root-cause analysis is unavailable right now: {exc}")
                rca_payload = None

            if rca_payload:
                for warning in rca_payload.get("warnings", []):
                    st.caption(f"RCA note: {warning}")

                bug_rows = []
                for bug in rca_payload.get("bugs", []):
                    bug_rows.append(
                        {
                            "key": bug.get("key", ""),
                            "status": bug.get("status", ""),
                            "priority": bug.get("priority", ""),
                            "created": bug.get("created", ""),
                            "downstream_evidence": len(bug.get("downstream_evidence", []) or []),
                            "upstream_evidence": len(bug.get("upstream_evidence", []) or []),
                            "test_coverage_status": (bug.get("test_coverage") or {}).get("coverage_status", "unknown"),
                            "downstream_e2e_status": (bug.get("test_coverage") or {}).get(
                                "downstream_e2e_coverage_status", "unknown"
                            ),
                            "matched_test_scenarios": len((bug.get("test_coverage") or {}).get("covered_scenarios", [])),
                            "matched_downstream_e2e_scenarios": len(
                                ((bug.get("test_coverage") or {}).get("downstream_e2e_covered_scenarios", []) or [])
                            ),
                            "summary": bug.get("summary", ""),
                        }
                    )
                if bug_rows:
                    st.dataframe(bug_rows, use_container_width=True)
                else:
                    st.info("No open customer bugs found for deep root-cause analysis in selected range.")

                rca_context = {
                    "date_window": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                    "selection_rule": "Open customer bugs created in selected date range",
                    "downstream_repo": rca_payload.get("targets", {}).get("downstream_repo", rca_downstream_repo),
                    "upstream_org": rca_payload.get("targets", {}).get("upstream_org", rca_upstream_org),
                    "upstream_priority_repos": rca_payload.get("targets", {}).get(
                        "upstream_priority_repos",
                        [repo.strip() for repo in rca_upstream_priority_repos_csv.split(",") if repo.strip()],
                    ),
                    "test_framework_dir": rca_payload.get("targets", {}).get("test_framework_dir", rca_test_framework_dir),
                    "test_scenario_count": rca_payload.get("targets", {}).get("test_scenario_count", 0),
                    "test_suite_breakdown": rca_payload.get("targets", {}).get("test_suite_breakdown", {}),
                }
                with st.spinner("Generating deep root-cause insights..."):
                    deep_insight_text = generate_root_cause_insights(payload=rca_payload, context=rca_context)
                st.markdown(deep_insight_text)

        st.subheader("Export")
        metrics_json = json.dumps(metrics, indent=2)
        metrics_csv = _rows_to_csv(metrics["closure_rows"])
        e1, e2 = st.columns(2)
        with e1:
            st.download_button(
                "Download Metrics JSON",
                data=metrics_json,
                file_name="ztwim-velocity-metrics.json",
                mime="application/json",
            )
        with e2:
            st.download_button(
                "Download Closure Rows CSV",
                data=metrics_csv,
                file_name="ztwim-closure-rows.csv",
                mime="text/csv",
            )

    with github_tab:
        st.subheader("GitHub PR Velocity")
        if not github_repo:
            st.info("Set a GitHub repository in sidebar to view PR velocity.")
        else:
            try:
                gh_payload = _run_with_loading_animation(
                    banner_message="Loading GitHub PR velocity data...",
                    spinner_message="Loading GitHub PR velocity...",
                    loader=lambda: _load_github_payload(
                        start_date_iso=start_date.isoformat(),
                        end_date_iso=end_date.isoformat(),
                        github_repo=github_repo,
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                st.warning(f"GitHub velocity is unavailable right now: {exc}")
                gh_payload = None

            if gh_payload:
                gh_metrics = gh_payload["metrics"]
                gh_summary = gh_metrics["summary"]
                gh_open_rows = gh_payload["open_pr_rows"]
                gh_rows = gh_metrics["closed_pr_rows"]
                gc1, gc2, gc3, gc4, gc5 = st.columns(5)
                gc1.metric("Open PRs", int(gh_summary["open_pr_count"]))
                gc2.metric("Closed PRs", int(gh_summary["closed_pr_count"]))
                gc3.metric("Merged PRs", int(gh_summary["merged_pr_count"]))
                gc4.metric("Closed (Not Merged)", int(gh_summary["closed_unmerged_pr_count"]))
                gc5.metric("Avg PR Close Days", f"{gh_summary['avg_close_days']:.1f}")

                closed_pr_count = int(gh_summary["closed_pr_count"])
                if closed_pr_count >= 30:
                    gh_confidence = "high confidence (enough data)"
                elif closed_pr_count >= 10:
                    gh_confidence = "medium confidence (some data)"
                else:
                    gh_confidence = "low confidence (small data, trend may change quickly)"
                st.caption(
                    f"Repository: `{gh_payload['source']['repo']}`. "
                    f"How reliable this trend is: {gh_confidence}. "
                    f"Based on {closed_pr_count} closed PRs in this date range."
                )
                st.markdown(
                    "\n".join(
                        [
                            "**GitHub velocity field guide (simple):**",
                            "- **Open PRs**: How many pull requests are currently open in this repository.",
                            "- **Closed PRs**: Total pull requests closed in the selected date range.",
                            "- **Merged PRs**: Closed PRs that were successfully merged.",
                            "- **Closed (Not Merged)**: PRs closed without being merged.",
                            "- **Avg PR Close Days**: Average time between PR creation and closure.",
                        ]
                    )
                )
                for warning in gh_payload["source"]["warnings"]:
                    st.caption(f"GitHub note: {warning}")

                st.subheader("Open PRs (Current)")
                st.caption("This table shows currently open PRs in the configured repository.")
                if gh_open_rows:
                    st.dataframe(gh_open_rows[:100], use_container_width=True)
                    if len(gh_open_rows) > 100:
                        st.caption("Showing first 100 open PRs for readability.")
                else:
                    st.info("No open pull requests found.")

                st.subheader("Closed PRs In Selected Date Range")
                if gh_rows:
                    st.dataframe(gh_rows[:100], use_container_width=True)
                    if len(gh_rows) > 100:
                        st.caption("Showing first 100 closed PRs for readability.")
                else:
                    st.info("No closed pull requests found for this date range.")

                st.subheader("AI Insights")
                gh_context = {
                    "date_window": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                    "source": "GitHub API",
                    "repository": gh_payload["source"]["repo"],
                }
                if st.button("Generate Insights", key="generate_insights_github"):
                    with st.spinner("Generating insights..."):
                        gh_insight_text = generate_insights(metrics=gh_metrics, context=gh_context)
                    st.markdown(gh_insight_text)

    with regression_tab:
        st.subheader("Regression Testing Dashboard")
        if not regression_artifacts_dir:
            st.info("Set a regression artifacts path in sidebar to view regression KPIs.")
        else:
            try:
                reg_payload = _run_with_loading_animation(
                    banner_message="Loading regression artifacts...",
                    spinner_message="Loading regression test artifacts...",
                    loader=lambda: _load_regression_payload(
                        start_date_iso=start_date.isoformat(),
                        end_date_iso=end_date.isoformat(),
                        regression_artifacts_dir=regression_artifacts_dir,
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                st.warning(f"Regression dashboard is unavailable right now: {exc}")
                reg_payload = None

            if reg_payload:
                reg_metrics = reg_payload["metrics"]
                run_rows = reg_metrics.get("run_rows", [])
                top_failed_tests = reg_metrics.get("top_failed_tests", [])
                top_skipped_tests = reg_metrics.get("top_skipped_tests", [])
                log_summary = reg_payload["source"].get("log_summary", {})

                st.caption(f"Artifacts source: `{reg_payload['source']['artifacts_dir']}`")
                if log_summary.get("available"):
                    st.caption(
                        "Logs summary: "
                        f"errors={int(log_summary.get('error_count', 0))}, "
                        f"warnings={int(log_summary.get('warning_count', 0))}, "
                        f"failed_mentions={int(log_summary.get('failed_mentions', 0))}, "
                        f"updated={log_summary.get('updated_at', '-')}"
                    )
                else:
                    st.caption("Logs summary: pytest.log not available under artifacts path.")
                for warning in reg_payload["source"]["warnings"]:
                    st.caption(f"Regression note: {warning}")

                st.subheader("Regression Runs")
                if run_rows:
                    st.dataframe(run_rows[:200], use_container_width=True)
                    if len(run_rows) > 200:
                        st.caption("Showing first 200 runs for readability.")
                else:
                    st.info("No regression runs found for this date range.")

                st.subheader("Most Failed Tests")
                if top_failed_tests:
                    st.dataframe(top_failed_tests, use_container_width=True)
                else:
                    st.info("No repeated failed tests found in selected runs.")

                st.subheader("Most Skipped Tests")
                if top_skipped_tests:
                    st.dataframe(top_skipped_tests, use_container_width=True)
                else:
                    st.info("No repeated skipped tests found in selected runs.")

                st.subheader("AI Insights")
                reg_context = {
                    "date_window": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                    "source": "Regression test artifacts",
                    "artifacts_dir": reg_payload["source"]["artifacts_dir"],
                    "log_summary": log_summary,
                    "openshift_versions_seen": sorted(
                        {
                            str(row.get("openshift_version", "")).strip()
                            for row in run_rows
                            if str(row.get("openshift_version", "")).strip()
                        }
                    ),
                    "top_failed_tests": top_failed_tests,
                    "top_skipped_tests": top_skipped_tests,
                }
                if st.button("Generate Insights", key="generate_insights_regression"):
                    with st.spinner("Generating insights..."):
                        reg_insight_text = generate_insights(metrics=reg_metrics, context=reg_context)
                    st.markdown(reg_insight_text)


if __name__ == "__main__":
    main()
