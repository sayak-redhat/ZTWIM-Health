import unittest
from datetime import date

from dashboard.metrics_engine import (
    compute_github_pr_velocity_metrics,
    compute_regression_metrics,
    compute_velocity_metrics,
)


def _issue(
    key: str,
    created: str,
    updated: str,
    resolutiondate: str,
    done: bool = True,
):
    return {
        "key": key,
        "fields": {
            "summary": f"Summary {key}",
            "status": {
                "name": "Done" if done else "In Progress",
                "statusCategory": {"key": "done" if done else "indeterminate"},
            },
            "priority": {"name": "High"},
            "resolution": {"name": "Done"},
            "created": f"{created}T00:00:00.000+0000",
            "updated": f"{updated}T00:00:00.000+0000",
            "resolutiondate": f"{resolutiondate}T00:00:00.000+0000",
        },
    }


def _pr(
    number: int,
    created_at: str,
    closed_at: str,
    merged_at: str | None,
    title: str | None = None,
):
    return {
        "number": number,
        "title": title or f"PR {number}",
        "html_url": f"https://github.com/org/repo/pull/{number}",
        "created_at": created_at,
        "closed_at": closed_at,
        "merged_at": merged_at,
        "user": {"login": "tester"},
    }


class MetricsEngineTests(unittest.TestCase):
    def test_median_and_percentiles(self):
        bugs = [
            _issue("SPIRE-1", "2026-06-02", "2026-06-03", "2026-06-03"),
            _issue("SPIRE-2", "2026-06-02", "2026-06-06", "2026-06-06"),
            _issue("SPIRE-3", "2026-06-02", "2026-06-11", "2026-06-11"),
        ]
        metrics = compute_velocity_metrics(
            eng_bugs=bugs,
            cust_bugs=[],
            cves=[],
            date_view="resolutiondate",
            start=date(2026, 6, 1),
            end=date(2026, 6, 30),
        )
        self.assertEqual(metrics["summary"]["closed_bug_count"], 3)
        self.assertGreater(metrics["summary"]["median_close_days"], 0)
        self.assertGreaterEqual(metrics["summary"]["p90_close_days"], metrics["summary"]["median_close_days"])

    def test_date_view_filtering(self):
        issue = _issue("SPIRE-9", "2026-05-01", "2026-06-15", "2026-05-20")
        resolution_view = compute_velocity_metrics(
            eng_bugs=[issue],
            cust_bugs=[],
            cves=[],
            date_view="resolutiondate",
            start=date(2026, 6, 1),
            end=date(2026, 6, 30),
        )
        updated_view = compute_velocity_metrics(
            eng_bugs=[issue],
            cust_bugs=[],
            cves=[],
            date_view="updated",
            start=date(2026, 6, 1),
            end=date(2026, 6, 30),
        )
        self.assertEqual(resolution_view["summary"]["closed_bug_count"], 0)
        self.assertEqual(updated_view["summary"]["closed_bug_count"], 1)

    def test_github_pr_velocity_summary_split(self):
        prs = [
            _pr(
                101,
                created_at="2026-06-01T00:00:00Z",
                closed_at="2026-06-06T00:00:00Z",
                merged_at="2026-06-06T00:00:00Z",
            ),
            _pr(
                102,
                created_at="2026-06-01T00:00:00Z",
                closed_at="2026-06-03T00:00:00Z",
                merged_at=None,
            ),
        ]
        metrics = compute_github_pr_velocity_metrics(open_pr_count=7, closed_prs=prs)
        summary = metrics["summary"]
        self.assertEqual(summary["open_pr_count"], 7)
        self.assertEqual(summary["closed_pr_count"], 2)
        self.assertEqual(summary["merged_pr_count"], 1)
        self.assertEqual(summary["closed_unmerged_pr_count"], 1)
        self.assertGreater(summary["avg_close_days"], 0.0)
        self.assertEqual(len(metrics["closed_pr_rows"]), 2)

    def test_github_pr_velocity_handles_empty_or_invalid_rows(self):
        prs = [
            _pr(
                201,
                created_at="2026-06-05T00:00:00Z",
                closed_at="2026-06-01T00:00:00Z",
                merged_at=None,
                title="Invalid chronology",
            ),
            {
                "number": 202,
                "title": "Missing timestamps",
                "html_url": "https://github.com/org/repo/pull/202",
                "user": {"login": "tester"},
            },
        ]
        metrics = compute_github_pr_velocity_metrics(open_pr_count=3, closed_prs=prs)
        summary = metrics["summary"]
        self.assertEqual(summary["open_pr_count"], 3)
        self.assertEqual(summary["closed_pr_count"], 0)
        self.assertEqual(summary["merged_pr_count"], 0)
        self.assertEqual(summary["closed_unmerged_pr_count"], 0)
        self.assertEqual(summary["avg_close_days"], 0.0)
        self.assertEqual(metrics["closed_pr_rows"], [])

    def test_regression_metrics_core_kpis(self):
        runs = [
            {
                "run_id": "run-1",
                "run_timestamp": "2026-06-25T09:34:32",
                "suite": "federation",
                "openshift_version": "4.16.3",
                "total_tests": 10,
                "passed_tests": 8,
                "failed_tests": 1,
                "skipped_tests": 1,
                "duration_seconds": 600.0,
                "failed_test_rows": [
                    {
                        "test_id": "tests/federation/test_a.py::test_one",
                        "result": "failed",
                        "duration_seconds": 12.5,
                        "message": "AssertionError",
                    }
                ],
                "skipped_test_rows": [
                    {
                        "test_id": "tests/federation/test_a.py::test_skip",
                        "result": "skipped",
                        "duration_seconds": 2.0,
                        "message": "env missing",
                    }
                ],
                "source_type": "junit",
                "source_path": "/tmp/junit-1.xml",
            },
            {
                "run_id": "run-2",
                "run_timestamp": "2026-06-26T09:34:32",
                "suite": "ossm",
                "openshift_version": "4.16.3",
                "total_tests": 20,
                "passed_tests": 19,
                "failed_tests": 1,
                "skipped_tests": 0,
                "duration_seconds": 900.0,
                "failed_test_rows": [
                    {
                        "test_id": "tests/ossm/test_beta.py::test_two",
                        "result": "failed",
                        "duration_seconds": 3.0,
                        "message": "RBAC denied",
                    }
                ],
                "skipped_test_rows": [],
                "source_type": "junit",
                "source_path": "/tmp/junit-2.xml",
            },
        ]
        metrics = compute_regression_metrics(
            runs=runs,
            start=date(2026, 6, 1),
            end=date(2026, 6, 30),
        )
        summary = metrics["summary"]
        self.assertEqual(summary["total_runs"], 2)
        self.assertEqual(summary["total_tests"], 30)
        self.assertEqual(summary["passed_tests"], 27)
        self.assertEqual(summary["failed_tests"], 2)
        self.assertEqual(summary["skipped_tests"], 1)
        self.assertAlmostEqual(summary["pass_rate_pct"], 90.0)
        self.assertAlmostEqual(summary["avg_tests_per_run"], 15.0)
        self.assertAlmostEqual(summary["avg_failed_per_run"], 1.0)
        self.assertAlmostEqual(summary["avg_skipped_per_run"], 0.5)
        self.assertEqual(len(metrics["run_rows"]), 2)
        self.assertEqual(metrics["run_rows"][0]["openshift_version"], "4.16.3")
        self.assertEqual(len(metrics["failed_test_rows"]), 2)
        self.assertEqual(len(metrics["skipped_test_rows"]), 1)
        self.assertEqual(metrics["top_skipped_tests"][0]["test_id"], "tests/federation/test_a.py::test_skip")

    def test_regression_metrics_empty(self):
        metrics = compute_regression_metrics(
            runs=[],
            start=date(2026, 6, 1),
            end=date(2026, 6, 30),
        )
        summary = metrics["summary"]
        self.assertEqual(summary["total_runs"], 0)
        self.assertEqual(summary["total_tests"], 0)
        self.assertEqual(summary["pass_rate_pct"], 0.0)
        self.assertEqual(metrics["run_rows"], [])
        self.assertEqual(metrics["failed_test_rows"], [])


if __name__ == "__main__":
    unittest.main()
