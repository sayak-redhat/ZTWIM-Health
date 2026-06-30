"""Streamlit dashboard for ZTWIM velocity insights."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import streamlit as st

from claude_agent import generate_insights
from data_source import DataSourceHub
from metrics_engine import compute_velocity_metrics


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
        "source": {
            "name": source.source,
            "date_range_label": source.date_range_label,
            "category_breakdown": source.category_breakdown,
            "warnings": source.warnings,
        },
    }


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


def main() -> None:
    st.set_page_config(page_title="ZTWIM Velocity Dashboard", layout="wide")
    st.title("ZTWIM Bug Dashboard")

    today = datetime.now(timezone.utc).date()
    default_start = today - timedelta(days=60)

    with st.sidebar:
        st.header("Filters")
        start_date = _to_date(st.date_input("Start date", value=default_start))
        end_date = _to_date(st.date_input("End date", value=today))
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

    if refresh:
        _load_dashboard_payload.clear()

    try:
        with st.spinner("Loading dashboard data..."):
            payload = _load_dashboard_payload(
                start_date_iso=start_date.isoformat(),
                end_date_iso=end_date.isoformat(),
                date_view=date_view,
                debug_mode=debug_mode,
            )
    except Exception as exc:  # pylint: disable=broad-except
        st.error(f"Failed to load dashboard data: {exc}")
        st.info(
            "If you want auto-generation for new date ranges, set Jira credentials in "
            "`config/report-config.json` (`jira_email`, `jira_token`) or env vars."
        )
        st.stop()
    metrics = payload["metrics"]
    summary = metrics["summary"]
    all_closed_rows = sorted(metrics["closure_rows"], key=lambda r: r["working_days"], reverse=True)
    engineering_bug_rows = [row for row in all_closed_rows if row["type"] == "Engineering Bug"]
    customer_bug_rows = [row for row in all_closed_rows if row["type"] == "Customer Bug"]
    closed_cve_rows = [row for row in all_closed_rows if row["type"] == "CVE"]

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

    st.caption(f"How reliable this trend is: {confidence_note}. Based on {closed_count} closed bugs in this date range.")
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

    st.subheader("AI Insights (Claude)")
    context = {
        "date_window": {"start": start_date.isoformat(), "end": end_date.isoformat()},
        "date_semantics": date_view,
        "source": "Result directory",
    }
    if st.button("Generate Insights"):
        with st.spinner("Calling Claude..."):
            insight_text = generate_insights(metrics=metrics, context=context)
        st.markdown(insight_text)

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


if __name__ == "__main__":
    main()
