import unittest
from datetime import date

from dashboard.metrics_engine import compute_velocity_metrics


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


if __name__ == "__main__":
    unittest.main()
