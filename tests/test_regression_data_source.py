import html
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from dashboard.data_source import load_regression_test_source


class RegressionDataSourceTests(unittest.TestCase):
    def test_load_regression_source_from_junit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reports_dir = Path(tmpdir) / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            junit_path = reports_dir / "junit-federation.xml"
            junit_path.write_text(
                (
                    "<testsuite name='federation' tests='3' failures='1' skipped='1' "
                    "timestamp='2026-06-26T09:34:32' time='12.5'>"
                    "<properties><property name='OpenShift Version' value='4.16.3'/></properties>"
                    "<testcase classname='tests.federation.test_a' name='test_ok' time='2.0'/>"
                    "<testcase classname='tests.federation.test_a' name='test_fail' time='5.0'>"
                    "<failure message='boom'>traceback</failure>"
                    "</testcase>"
                    "<testcase classname='tests.federation.test_a' name='test_skip' time='5.5'>"
                    "<skipped message='skip'/>"
                    "</testcase>"
                    "</testsuite>"
                ),
                encoding="utf-8",
            )

            result = load_regression_test_source(
                start_date=date(2026, 6, 1),
                end_date=date(2026, 6, 30),
                artifacts_dir=tmpdir,
            )

            self.assertEqual(len(result.runs), 1)
            run = result.runs[0]
            self.assertEqual(run["source_type"], "junit")
            self.assertEqual(run["total_tests"], 3)
            self.assertEqual(run["passed_tests"], 1)
            self.assertEqual(run["failed_tests"], 1)
            self.assertEqual(run["skipped_tests"], 1)
            self.assertEqual(len(run["failed_test_rows"]), 1)
            self.assertEqual(len(run["skipped_test_rows"]), 1)
            self.assertEqual(run["openshift_version"], "4.16.3")

    def test_load_regression_source_falls_back_to_pytest_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "test-reports" / "2026-06-26_09-34-32"
            run_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "environment": {
                    "OpenShift Version": "4.22.0",
                },
                "tests": {
                    "tests/federation/test_alpha.py::test_ok": [
                        {
                            "result": "Passed",
                            "duration": "00:00:05",
                            "testId": "tests/federation/test_alpha.py::test_ok",
                            "log": "",
                        }
                    ],
                    "tests/ossm/test_beta.py::test_fail": [
                        {
                            "result": "Failed",
                            "duration": "00:00:03",
                            "testId": "tests/ossm/test_beta.py::test_fail",
                            "log": "AssertionError\ntraceback...",
                        }
                    ],
                }
            }
            html_path = run_dir / "test-report.html"
            html_path.write_text(
                f"<html><body><div id='data-container' data-jsonblob=\"{html.escape(json.dumps(payload))}\"></div></body></html>",
                encoding="utf-8",
            )

            result = load_regression_test_source(
                start_date=date(2026, 6, 1),
                end_date=date(2026, 6, 30),
                artifacts_dir=tmpdir,
            )

            self.assertEqual(len(result.runs), 1)
            run = result.runs[0]
            self.assertEqual(run["source_type"], "pytest-html")
            self.assertEqual(run["total_tests"], 2)
            self.assertEqual(run["failed_tests"], 1)
            self.assertEqual(run["skipped_tests"], 0)
            self.assertEqual(run["openshift_version"], "4.22.0")
            self.assertTrue(any("No JUnit XML reports found" in warning for warning in result.warnings))

    def test_load_regression_source_missing_path(self):
        result = load_regression_test_source(
            start_date=date(2026, 6, 1),
            end_date=date(2026, 6, 30),
            artifacts_dir="/tmp/path-that-should-not-exist-ztwim-health",
        )
        self.assertEqual(result.runs, [])
        self.assertTrue(any("does not exist" in warning for warning in result.warnings))


if __name__ == "__main__":
    unittest.main()
