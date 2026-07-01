# ZTWIM Health Dashboard Setup Guide

This README is written for a new contributor who cloned this repository and wants to run the report script and dashboard safely.

## What This Project Does

- Generates ZTWIM quality reports from Jira (`scripts/ztwim-quality-summary-report.py`).
- Saves report outputs into `Result/`.
- Runs a Streamlit dashboard (`dashboard/app.py`) that reads `Result/` and shows:
  - bug/CVE velocity metrics,
  - open bug tables (Engineering, Customer, CVE),
  - closed issue tables,
  - AI-generated insights,
  - GitHub PR velocity metrics (open PRs, closed PR split, average close time) in a dedicated tab,
  - regression testing KPIs from `ztwim-test-framework` artifacts in a dedicated tab.

## Repository Paths You Will Use

- `scripts/ztwim-quality-summary-report.py` - report generator
- `dashboard/app.py` - Streamlit dashboard
- `dashboard/data_source.py` - Jira/GitHub/regression data loaders
- `dashboard/metrics_engine.py` - KPI computation for all dashboard tabs
- `config/report-config.example.json` - safe template config
- `config/report-config.json` - your local secret config (not committed)
- `Result/` - generated report files (not committed)

## Prerequisites

- Python 3.10+ (3.11+ preferred)
- `pip`
- Jira access (`https://redhat.atlassian.net`)
- Network access to Jira and optionally Vertex/Anthropic

Optional for Vertex AI insights:

- `gcloud` CLI installed
- Google account access with required org permissions

Optional for GitHub PR velocity:

- access to GitHub repository API (`owner/repo`)
- `GITHUB_TOKEN` or `github_token` in config (recommended)

Optional for Regression dashboard:

- local path to `ztwim-test-framework` artifacts (or equivalent folder structure)
- expected subfolders:
  - `reports/` with `junit-*.xml` (preferred), or
  - `test-reports/*/test-report.html` (fallback)

## Quick Start After Clone

From repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install claude-agent-sdk
```

Create your local config:

```bash
cp config/report-config.example.json config/report-config.json
```

Edit `config/report-config.json` and fill at least:

- `jira_email`
- `jira_token`

Optional for GitHub PR velocity:

- `github_repo` (default: `openshift/zero-trust-workload-identity-manager`)
- `github_token` (recommended to avoid API rate limits)

Optional for Regression dashboard:

- `regression_artifacts_dir` (default: `/home/sayadas/RedHat-Workspace/ztwim-test-framework`)

Optional environment overrides:

- `GITHUB_REPO`
- `GITHUB_TOKEN`
- `ZTWIM_REGRESSION_ARTIFACTS_DIR`

Then start dashboard:

```bash
streamlit run dashboard/app.py
```

## Beginner Walkthrough (Two-Line Steps)

1. **Clone and enter the repo.**  
   You need to run all commands from the project root so paths like `scripts/` and `dashboard/` work correctly.

2. **Create and activate a virtual environment.**  
   This keeps project dependencies isolated from your system Python and avoids package conflicts.

3. **Install requirements.**  
   `streamlit` runs the dashboard, and `claude-agent-sdk` is needed only for Vertex-based AI insight generation.

4. **Copy config template to local config.**  
   `config/report-config.example.json` is safe to commit; `config/report-config.json` is your private working config.

5. **Set Jira credentials in local config.**  
   Without `jira_email` and `jira_token`, the app cannot generate date-range reports from Jira when needed.

6. **(Optional) Configure Vertex for Claude insights.**  
   If Vertex auth is not set, dashboard still works but AI section may use fallback rule-based insights.

7. **Start Streamlit dashboard.**  
   This launches a local web UI where you choose dates, view metrics, and trigger AI insight generation.

8. **Pick a date range in Filters.**  
   Dashboard looks for matching file in `Result/`; if missing, it attempts to run the Python report script automatically.

9. **Read output tables and KPI cards across all tabs.**  
   Bug tab shows open + closed Jira issue views, GitHub tab shows PR velocity and open/closed PR tables, and Regression tab shows run-level KPIs with top failed/skipped tests.

10. **Click “Generate Insights” for natural-language summary.**  
    The app sends computed metrics JSON to Claude (Vertex/API) and returns recommendations; fallback is used if model path is unavailable.

11. **Export data if needed.**  
    Bug tab includes JSON/CSV exports for computed Jira velocity metrics and closure rows.

12. **Keep secrets local and uncommitted.**  
    Never commit `config/report-config.json` or tokens; rotate credentials immediately if they are exposed.

## Configuration Priority

The app reads config in this order:

1. Environment variables
2. `config/report-config.json`

Optional custom config path:

```bash
export ZTWIM_CONFIG_FILE="/absolute/path/to/report-config.json"
```

## Vertex AI Setup (Recommended in This Project)

Use this if you want Claude insights through Google Vertex AI.

### 1) Authenticate

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project cloudability-it-gemini
```

### 2) Set environment variables

```bash
export CLAUDE_CODE_USE_VERTEX=1
export CLOUD_ML_REGION=global
export ANTHROPIC_VERTEX_PROJECT_ID=itpc-gcp-hcm-pe-eng-claude
export ANTHROPIC_MODEL=claude-opus-4-6
```

### 3) Make persistent (`~/.bashrc`)

```bash
echo 'export CLAUDE_CODE_USE_VERTEX=1' >> ~/.bashrc
echo 'export CLOUD_ML_REGION=global' >> ~/.bashrc
echo 'export ANTHROPIC_VERTEX_PROJECT_ID=itpc-gcp-hcm-pe-eng-claude' >> ~/.bashrc
echo 'export ANTHROPIC_MODEL=claude-opus-4-6' >> ~/.bashrc
source ~/.bashrc
```

### 4) Verify

```bash
env | rg "CLAUDE_CODE_USE_VERTEX|CLOUD_ML_REGION|ANTHROPIC_VERTEX_PROJECT_ID|ANTHROPIC_MODEL"
```

## Run the Report Script Manually

Examples:

```bash
python3 scripts/ztwim-quality-summary-report.py --md
python3 scripts/ztwim-quality-summary-report.py --txt
python3 scripts/ztwim-quality-summary-report.py --start-date 2026-06-01 --end-date 2026-06-30 --date-field updated --md
```

Date filter options:

- `--start-date YYYY-MM-DD`
- `--end-date YYYY-MM-DD`
- `--date-field {created,updated}`

Outputs are created under `Result/`.

## Run / Restart the Dashboard

Start:

```bash
streamlit run dashboard/app.py
```

Stop:

- Press `Ctrl + C` in the terminal running Streamlit.

Restart:

```bash
streamlit run dashboard/app.py
```

If default port is busy:

```bash
streamlit run dashboard/app.py --server.port 8502
```

## Dashboard Tabs At a Glance

### Bug Dashboard

- Uses Jira-derived report data from `Result/`.
- Shows:
  - Overview KPIs (median/p90 close days, closed bug count)
  - Velocity by type (Engineering Bug, Customer Bug, CVE)
  - CVE snapshot
  - Open issue tables (Engineering, Customer, CVE)
  - Closed issue detail tables
  - AI insights and export options

### GitHub Dashboard

- Uses GitHub Pull Request API for configured repo.
- Shows:
  - Open PR count (current repository state)
  - Closed PR count in selected date window
  - Merged vs closed-without-merge split
  - Avg/median/p90 PR close duration
  - Open PR table and closed PR table
  - AI insights with repository context

### Regression Dashboard

- Uses regression test artifacts from configured path.
- Ingestion order:
  1. `reports/junit-*.xml` (preferred)
  2. `test-reports/*/test-report.html` (fallback)
- Shows:
  - Regression run table (with OpenShift version when available)
  - Most failed tests
  - Most skipped tests
  - Log signal summary (`logs/pytest.log` if present)
  - AI insights based on run trends and failure/skip patterns

## How AI Insights Works

When you click **Generate Insights** on any tab, the dashboard sends computed metrics (JSON) and tab-specific context to `dashboard/claude_agent.py`.

Insight modes:

1. Vertex mode (`CLAUDE_CODE_USE_VERTEX=1`) using `claude_agent_sdk`
2. Direct Anthropic API key mode (`ANTHROPIC_API_KEY`)
3. Rule-based fallback (no external model)

Default model in this project is Opus (`claude-opus-4-6`), unless overridden.
Insight context differs by tab:

- Bug tab: Jira velocity and closure/open issue context
- GitHub tab: repository-level PR velocity context
- Regression tab: run trend context, OpenShift version mix, and top failure/skip signals

## Dashboard Data Source Behavior

- Bug dashboard source:
  - prefers matching `Result/` report for selected date range;
  - if not present, attempts to run the report script and generate it;
  - if generation fails, falls back to latest available report with limited fidelity.
- GitHub dashboard source:
  - loads open PRs + closed PRs from GitHub API for selected repo;
  - closed metrics are filtered by `closed_at` in selected date range.
- Regression dashboard source:
  - reads local regression artifacts path;
  - prefers JUnit XML, falls back to pytest-html parsing;
  - adds warnings when artifacts are missing, parsing fails, or no runs exist in selected range.

## GitHub PR Velocity Behavior

- GitHub PR velocity uses the same Start/End date filters from the sidebar.
- Closed PR metrics are filtered by `closed_at` within selected range.
- Open PR metric is current open PR count for the configured repository.
- Closed PRs are split into:
  - merged PRs
  - closed without merge
- Average PR close days = average of (`closed_at` - `created_at`) across closed PRs in range.
- Repo source is configurable with:
  - config: `github_repo`, `github_token`
  - env: `GITHUB_REPO`, `GITHUB_TOKEN`

## Regression Testing Dashboard Behavior

- Regression dashboard uses the same Start/End date filters from the sidebar.
- Artifacts path is configurable with:
  - config: `regression_artifacts_dir`
  - env: `ZTWIM_REGRESSION_ARTIFACTS_DIR`
- Artifact ingestion order:
  1. JUnit XML from `<artifacts_dir>/reports/junit-*.xml` (preferred)
  2. pytest-html fallback from `<artifacts_dir>/test-reports/*/test-report.html`
- Regression tab now shows:
  - regression runs table (includes OpenShift version)
  - most failed tests and most skipped tests
  - AI insights contextualized with run trends and OpenShift version mix

## Common Problems and Fixes

### 1) `Permission denied on resource project GCP_PROJECT_ID`

You still have placeholder project id in env or shell config.

Fix:

- replace `GCP_PROJECT_ID` with real value
- reload shell (`source ~/.bashrc`)
- retry

### 2) `Set Jira credentials ...`

Fill `jira_email` and `jira_token` in `config/report-config.json` or set env vars.

### 3) Vertex insights not working

Check:

```bash
gcloud auth list
gcloud config get-value project
python3 -c "import claude_agent_sdk; print('claude_agent_sdk ok')"
```

### 4) GitHub tab shows API/rate-limit warning

Set a GitHub token:

- config: `github_token`
- env: `GITHUB_TOKEN`

Also verify repo format is `owner/repo`.

### 5) Regression tab shows no runs

Check:

- configured path exists (`regression_artifacts_dir` or `ZTWIM_REGRESSION_ARTIFACTS_DIR`)
- path contains `reports/junit-*.xml` or `test-reports/*/test-report.html`
- selected date range includes artifact timestamps

## Security and Git Hygiene (Important)

- Never commit real secrets.
- This repo ignores:
  - `config/report-config.json`
  - `Result/*.md`, `Result/*.txt`
  - `.env*`, venvs, caches

Use template:

- keep `config/report-config.example.json` in git
- keep `config/report-config.json` local only

If sensitive files were tracked previously, untrack them:

```bash
git rm --cached config/report-config.json
git rm --cached Result/*.md Result/*.txt
```

If any token was exposed, rotate it immediately.

## Start Date / End Date Code Flow (End-to-End)

This section explains how selected date range flows through Python code for all three dashboard tabs.

### 1) Date range enters from UI

In `dashboard/app.py`:

- user selects `Start date` and `End date`
- optional tab inputs:
  - `GitHub repository` (`owner/repo`)
  - `Regression artifacts path`
- bug tab also uses `Velocity date semantics` (`resolutiondate` or `updated`)

### 2) Bug tab flow (Jira report pipeline)

In `dashboard/data_source.py`:

- `DataSourceHub.load(...)` resolves a matching `Result/` report for selected date range
- if no matching report exists, it attempts report generation via:
  - `scripts/ztwim-quality-summary-report.py --start-date ... --end-date ... --date-field ... --md`
- report parser extracts:
  - closed issue rows (Engineering, Customer, CVE)
  - open issue rows from "Attention Needed" section when present

In `dashboard/metrics_engine.py`:

- `compute_velocity_metrics(...)` computes bug/CVE KPIs, type summaries, and closure rows

### 3) GitHub tab flow (PR velocity pipeline)

In `dashboard/data_source.py`:

- `load_github_pr_source(...)` calls GitHub PR API:
  - open PR list (current state)
  - closed PR list (filtered by selected date range)
- supports config/env overrides for repo and token

In `dashboard/metrics_engine.py`:

- `compute_github_pr_velocity_metrics(...)` computes:
  - open PR count
  - closed PR count
  - merged vs closed-without-merge split
  - avg/median/p90 close days
  - closed PR detail rows

### 4) Regression tab flow (test artifacts pipeline)

In `dashboard/data_source.py`:

- `load_regression_test_source(...)` reads artifacts directory
- ingestion order:
  1. JUnit XML reports
  2. pytest-html reports (fallback)
- extracts per-run totals, failed/skipped test detail rows, OpenShift version (when available), and optional `pytest.log` signal summary

In `dashboard/metrics_engine.py`:

- `compute_regression_metrics(...)` computes:
  - run/test totals and pass rate
  - average per-run test outcomes
  - duration KPIs
  - top failed and top skipped tests
  - failure signature aggregates

### 5) AI insight generation flow

In `dashboard/app.py`:

- each tab has its own **Generate Insights** button
- button action calls:
  - `generate_insights(metrics=metrics, context=context)`

In `dashboard/claude_agent.py`:

- tries Vertex path first when enabled (`CLAUDE_CODE_USE_VERTEX=1`)
- otherwise tries direct Anthropic API key path
- if neither is available, returns rule-based fallback insights

So: **selected date range drives data loading for Bug/GitHub/Regression tabs first, then each tab computes KPIs, then Claude summarizes that tab's computed metrics.**
