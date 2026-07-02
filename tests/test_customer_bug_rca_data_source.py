import unittest
import tempfile
from datetime import date
from pathlib import Path
from unittest.mock import patch

from dashboard.data_source import (
    CustomerBugDossierResult,
    CustomerBugEvidenceResult,
    analyze_customer_bug_test_coverage,
    load_test_framework_scenarios,
    load_customer_bug_github_evidence,
    load_customer_bug_root_cause_context,
    load_open_customer_bug_dossiers,
)


def _jira_issue(
    key: str,
    status: str,
    status_category: str,
    summary: str,
    created: str = "2026-07-01",
    resolution_name: str = "",
):
    resolution = {"name": resolution_name} if resolution_name else None
    return {
        "key": key,
        "fields": {
            "summary": summary,
            "description": {
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": f"Description for {key}"}],
                    }
                ],
            },
            "environment": {"type": "doc", "content": [{"type": "text", "text": "OpenShift 4.16"}]},
            "status": {"name": status, "statusCategory": {"key": status_category}},
            "priority": {"name": "High"},
            "assignee": {"displayName": "Engineer One"},
            "reporter": {"displayName": "Support Team"},
            "created": f"{created}T00:00:00.000+0000",
            "updated": f"{created}T10:00:00.000+0000",
            "resolution": resolution,
            "components": [{"name": "zero-trust-workload-identity-manager"}],
            "labels": ["customer", "ztwim"],
            "issuelinks": [{"outwardIssue": {"key": "SPIRE-900"}}],
            "comment": {
                "comments": [
                    {
                        "author": {"displayName": "Customer"},
                        "created": f"{created}T08:00:00.000+0000",
                        "body": {
                            "type": "doc",
                            "content": [
                                {"type": "paragraph", "content": [{"type": "text", "text": "Fails after upgrade"}]}
                            ],
                        },
                    }
                ]
            },
        },
    }


def _gh_item(repo: str, title: str, url: str, body: str, is_pr: bool = False):
    item = {
        "title": title,
        "html_url": url,
        "body": body,
        "state": "open",
        "created_at": "2026-07-01T00:00:00Z",
        "updated_at": "2026-07-02T00:00:00Z",
        "repository_url": f"https://api.github.com/repos/{repo}",
    }
    if is_pr:
        item["pull_request"] = {"url": f"{url}.json"}
    return item


class CustomerBugRcaDataSourceTests(unittest.TestCase):
    @patch("dashboard.data_source._jira_email", return_value="user@example.com")
    @patch("dashboard.data_source._jira_token", return_value="secret")
    @patch("dashboard.data_source._jira_search_issues")
    def test_load_open_customer_bug_dossiers_filters_open_and_limits(
        self,
        mock_search,
        _mock_token,
        _mock_email,
    ):
        mock_search.return_value = [
            _jira_issue("OCPBUGS-1", "In Progress", "indeterminate", "ZTWIM token exchange fails on rotation"),
            _jira_issue("OCPBUGS-2", "Done", "done", "Closed bug should be ignored", resolution_name="Done"),
            _jira_issue("OCPBUGS-3", "To Do", "new", "SPIFFE trust domain mismatch after upgrade"),
        ]
        result = load_open_customer_bug_dossiers(
            start_date=date(2026, 7, 1),
            end_date=date(2026, 7, 31),
            max_bugs=1,
        )
        self.assertEqual(len(result.bugs), 1)
        self.assertEqual(result.bugs[0]["key"], "OCPBUGS-1")
        self.assertEqual(result.bugs[0]["linked_issue_keys"], ["SPIRE-900"])
        self.assertEqual(len(result.bugs[0]["recent_comments"]), 1)
        self.assertTrue(any("Analyzed first 1" in warning for warning in result.warnings))

    @patch("dashboard.data_source._jira_email", return_value="")
    @patch("dashboard.data_source._jira_token", return_value="")
    def test_load_open_customer_bug_dossiers_requires_jira_credentials(self, _mock_token, _mock_email):
        with self.assertRaises(RuntimeError):
            load_open_customer_bug_dossiers(
                start_date=date(2026, 7, 1),
                end_date=date(2026, 7, 31),
                max_bugs=2,
            )

    @patch("dashboard.data_source._github_search_issue_items")
    def test_load_customer_bug_github_evidence_collects_downstream_and_upstream(self, mock_search):
        def fake_search(query: str, token: str, per_page: int = 8):
            _ = token, per_page
            if "repo:openshift/zero-trust-workload-identity-manager" in query:
                return [
                    _gh_item(
                        repo="openshift/zero-trust-workload-identity-manager",
                        title="Fix OCPBUGS-1 token exchange race",
                        url="https://github.com/openshift/zero-trust-workload-identity-manager/pull/1",
                        body="Resolves OCPBUGS-1 by retrying token fetch",
                        is_pr=True,
                    )
                ]
            if "repo:spiffe/spire" in query:
                return [
                    _gh_item(
                        repo="spiffe/spire",
                        title="Investigate trust domain mismatch",
                        url="https://github.com/spiffe/spire/issues/2",
                        body="Related to token exchange mismatch and OCPBUGS-1 report",
                        is_pr=False,
                    )
                ]
            return []

        mock_search.side_effect = fake_search
        result = load_customer_bug_github_evidence(
            bug_dossiers=[
                {
                    "key": "OCPBUGS-1",
                    "summary": "ZTWIM token exchange race with trust domain mismatch",
                }
            ],
            downstream_repo="openshift/zero-trust-workload-identity-manager",
            upstream_org="spiffe",
            upstream_priority_repos=["spiffe/spire"],
            per_bug_limit=5,
        )
        self.assertEqual(result.downstream_repo, "openshift/zero-trust-workload-identity-manager")
        self.assertEqual(result.upstream_org, "spiffe")
        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record["bug_key"], "OCPBUGS-1")
        self.assertEqual(len(record["downstream_evidence"]), 1)
        self.assertEqual(len(record["upstream_evidence"]), 1)
        self.assertEqual(record["downstream_evidence"][0]["kind"], "pull_request")
        self.assertEqual(record["upstream_evidence"][0]["repo"], "spiffe/spire")

    @patch("dashboard.data_source.load_customer_bug_github_evidence")
    @patch("dashboard.data_source.load_open_customer_bug_dossiers")
    @patch("dashboard.data_source.analyze_customer_bug_test_coverage")
    def test_load_customer_bug_root_cause_context_merges_records(
        self,
        mock_coverage,
        mock_dossiers,
        mock_evidence,
    ):
        mock_dossiers.return_value = CustomerBugDossierResult(
            bugs=[
                {"key": "OCPBUGS-99", "summary": "Failure to sync identities"},
            ],
            warnings=["sample dossier warning"],
        )
        mock_evidence.return_value = CustomerBugEvidenceResult(
            downstream_repo="openshift/zero-trust-workload-identity-manager",
            upstream_org="spiffe",
            upstream_priority_repos=["spiffe/spire"],
            records=[
                {
                    "bug_key": "OCPBUGS-99",
                    "downstream_evidence": [{"url": "https://example/downstream"}],
                    "upstream_evidence": [{"url": "https://example/upstream"}],
                }
            ],
            warnings=["sample evidence warning"],
        )
        mock_coverage.return_value = {
            "coverage_by_bug": {
                "OCPBUGS-99": {
                    "coverage_status": "partial_coverage",
                    "coverage_reason": "sample reason",
                    "covered_scenarios": [{"id": "test_alpha"}],
                    "coverage_gaps": ["gcinterval"],
                    "bug_keywords": ["gcinterval"],
                    "downstream_e2e_coverage_status": "not_covered",
                    "downstream_e2e_coverage_reason": "no matching e2e scenario",
                    "downstream_e2e_covered_scenarios": [],
                    "downstream_e2e_coverage_gaps": ["gcinterval"],
                }
            },
            "suite_breakdown": {"e2e_singleCluster": 10},
            "test_framework_dir": "/tmp/test-framework",
            "test_scenario_count": 10,
            "warnings": ["sample coverage warning"],
        }
        payload = load_customer_bug_root_cause_context(
            start_date=date(2026, 7, 1),
            end_date=date(2026, 7, 31),
            max_bugs=4,
            downstream_repo="openshift/zero-trust-workload-identity-manager",
            upstream_org="spiffe",
            upstream_priority_repos=["spiffe/spire"],
        )
        self.assertEqual(payload["targets"]["upstream_org"], "spiffe")
        self.assertEqual(payload["targets"]["test_scenario_count"], 10)
        self.assertEqual(len(payload["bugs"]), 1)
        self.assertEqual(payload["bugs"][0]["downstream_evidence"][0]["url"], "https://example/downstream")
        self.assertEqual(payload["bugs"][0]["upstream_evidence"][0]["url"], "https://example/upstream")
        self.assertEqual(payload["bugs"][0]["test_coverage"]["coverage_status"], "partial_coverage")
        self.assertEqual(payload["bugs"][0]["test_coverage"]["downstream_e2e_coverage_status"], "not_covered")
        self.assertEqual(len(payload["warnings"]), 3)

    def test_load_test_framework_scenarios_extracts_test_cases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tests_dir = Path(tmpdir) / "tests" / "e2e_singleCluster"
            tests_dir.mkdir(parents=True, exist_ok=True)
            file_path = tests_dir / "test_sample_case.py"
            file_path.write_text(
                (
                    "class TestRuntime:\n"
                    "    def test_gcinterval_cpu_guardrail(self):\n"
                    "        \"\"\"validate gcInterval guardrail for cpu pressure\"\"\"\n"
                    "        assert True\n\n"
                    "def test_spire_server_config_sync():\n"
                    "    \"\"\"ensures spire server config sync\"\"\"\n"
                    "    assert True\n"
                ),
                encoding="utf-8",
            )

            blob = load_test_framework_scenarios(test_framework_dir=tmpdir)
            self.assertEqual(blob["warnings"], [])
            self.assertEqual(blob["suite_breakdown"].get("e2e_singleCluster"), 2)
            self.assertEqual(len(blob["scenarios"]), 2)
            titles = [item["title"] for item in blob["scenarios"]]
            self.assertTrue(any("gcinterval cpu guardrail" in title for title in titles))

    def test_analyze_customer_bug_test_coverage_detects_partial_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tests_dir = Path(tmpdir) / "tests" / "e2e_singleCluster"
            tests_dir.mkdir(parents=True, exist_ok=True)
            file_path = tests_dir / "test_operator_behavior.py"
            file_path.write_text(
                (
                    "def test_spire_server_cpu_guardrail_config():\n"
                    "    \"\"\"covers spire server cpu guardrail configuration\"\"\"\n"
                    "    assert True\n"
                ),
                encoding="utf-8",
            )
            bug_dossiers = [
                {
                    "key": "OCPBUGS-500",
                    "summary": "spire server cpu guardrail missing",
                    "description": "gcinterval hardcoded causes cpu pressure",
                    "environment": "",
                    "components": ["zero-trust-workload-identity-manager"],
                    "labels": ["customer"],
                    "recent_comments": [],
                }
            ]
            coverage = analyze_customer_bug_test_coverage(
                bug_dossiers=bug_dossiers,
                test_framework_dir=tmpdir,
            )
            bug_cov = coverage["coverage_by_bug"]["OCPBUGS-500"]
            self.assertIn(bug_cov["coverage_status"], {"partial_coverage", "likely_covered"})
            self.assertGreaterEqual(len(bug_cov["covered_scenarios"]), 1)


if __name__ == "__main__":
    unittest.main()
