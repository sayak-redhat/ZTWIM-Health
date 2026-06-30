# ZTWIM Bug Dashboard Setup Guide

This README is written for a new contributor who cloned this repository and wants to run the report script and dashboard safely.

## What This Project Does

- Generates ZTWIM quality reports from Jira (`scripts/ztwim-quality-summary-report.py`).
- Saves report outputs into `Result/`.
- Runs a Streamlit dashboard (`dashboard/app.py`) that reads `Result/` and shows:
  - bug/CVE velocity metrics,
  - closed issue tables,
  - AI-generated insights.

## Repository Paths You Will Use

- `scripts/ztwim-quality-summary-report.py` - report generator
- `dashboard/app.py` - Streamlit dashboard
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

9. **Read output tables and KPI cards.**  
   KPIs summarize velocity, while engineering/customer/CVE tables show detailed closed-item records for that range.

10. **Click “Generate Insights” for natural-language summary.**  
    The app sends computed metrics JSON to Claude (Vertex/API) and returns recommendations; fallback is used if model path is unavailable.

11. **Export data if needed.**  
    Use JSON/CSV export buttons to share the same metrics visible on screen with other team members.

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

## How AI Insights Works

When you click **Generate Insights**, the dashboard sends computed metrics (JSON) to `dashboard/claude_agent.py`.

Insight modes:

1. Vertex mode (`CLAUDE_CODE_USE_VERTEX=1`) using `claude_agent_sdk`
2. Direct Anthropic API key mode (`ANTHROPIC_API_KEY`)
3. Rule-based fallback (no external model)

Default model in this project is Opus (`claude-opus-4-6`), unless overridden.

## Dashboard Data Source Behavior

- Dashboard uses `Result/` files.
- For selected date range:
  - if matching report exists, it loads it;
  - if not, it tries to run the report script and generate one.
- If generation fails (for example missing Jira creds), it falls back to the latest available `Result` file and shows limited data.

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

This section explains how selected date range flows through Python code, from Jira fetch to dashboard, and where Claude insights are generated.

### 1) Date range enters from UI

In `dashboard/app.py`:

- user selects `Start date`, `End date`, and date semantics (`resolutiondate` or `updated`)
- those values are passed into `_load_dashboard_payload(...)`

### 2) Data source resolves report for that range

In `dashboard/data_source.py`:

- `DataSourceHub.load(...)` calls `_load_or_generate_result_report(start_date, end_date, date_field, ...)`
- it looks for matching file in `Result/` using `Date range: <start> to <end> (<field>)`
- if matching file does not exist, it runs:
  - `scripts/ztwim-quality-summary-report.py --start-date ... --end-date ... --date-field ... --md`
- then it parses the generated/loaded report and builds structured rows for:
  - Engineering Bug
  - Customer Bug
  - CVE

### 3) Jira fetch path during report generation

In `scripts/ztwim-quality-summary-report.py` + `scripts/ztwim_data_layer.py`:

- CLI parses `--start-date`, `--end-date`, `--date-field`
- `build_issue_dataset(...)` performs:
  - Jira discovery (`discover_keys_live`)
  - fetch by keys (`fetch_by_keys`)
  - classification (bugs/cves/other)
  - date filtering (`filter_issues_by_date_range`)
- report renderer writes markdown/text to `Result/` with date range label embedded

### 4) Metrics computation for dashboard

In `dashboard/metrics_engine.py`:

- `compute_velocity_metrics(...)` computes:
  - median / p75 / p90 close days
  - closure counts and split by type
  - CVE/Engineering/Customer velocity summaries
  - closure detail rows shown in tables
  - open-age KPI is currently disabled and not included in metric output

### 5) Dashboard rendering

Back in `dashboard/app.py`:

- metrics are displayed in:
  - Overview KPIs
  - Velocity By Type
  - CVE Snapshot
  - Closed Engineering Bugs table
  - Closed Customer Bugs table
  - Closed CVEs table

### 6) Where Claude is used for insights

In `dashboard/app.py`:

- clicking **Generate Insights** calls:
  - `generate_insights(metrics=metrics, context=context)`

In `dashboard/claude_agent.py`:

- tries Vertex path first when enabled (`CLAUDE_CODE_USE_VERTEX=1`)
- otherwise tries direct Anthropic API key path
- if neither is available, returns rule-based fallback insights

So: **date range drives data selection/generation first, then metrics are computed, then Claude summarizes those computed metrics.**
