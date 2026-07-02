"""Claude insights generator for velocity dashboard."""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
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
# Default insight model is Opus unless explicitly overridden.
DEFAULT_MODEL = os.environ.get("CLAUDE_MODEL") or _CONFIG.get("claude_model", "claude-opus-4-6")


def _prompt_from_metrics(metrics: dict, context: dict | None = None) -> str:
    return (
        "Role: Software Delivery Analyst\n"
        "Task: Analyze JSON payload and output exactly:\n"
        "1) Brief Exec Summary\n"
        "2) 3 Key Insights (Velocity & Risk)\n"
        "3) 3 Next-Sprint Actions\n\n"
        f"Context:\n{json.dumps(context or {}, indent=2)}\n\n"
        f"Metrics:\n{json.dumps(metrics, indent=2)}"
    )


def _prompt_from_root_cause_payload(payload: dict, context: dict | None = None) -> str:
    return (
        "Act as a senior cloud-native identity incident investigator. Analyze the provided context and payload.\n\n"
        "For EACH bug, output these 8 markdown sections:\n"
        "1) Probable Root Cause (distinguish downstream-specific vs. upstream-inherited)\n"
        "2) Downstream Evidence Assessment\n"
        "3) Upstream Evidence Assessment\n"
        "4) Downstream E2E Coverage Gap Assessment (specific missing e2e_singleCluster scenarios)\n"
        "5) Why Internal Engineering Missed It\n"
        "6) Engineering-Only Mitigations (code, validation, release checks; no process/support/biz actions)\n"
        "7) High-Level Engineering Solution Path\n"
        "8) Confidence (High/Medium/Low) + Unknowns\n\n"
        "Strict Rules:\n"
        "- Rely only on provided data. If evidence is weak, explicitly state it.\n"
        "- Explicitly use ZTWIM test_coverage data to explain gaps.\n"
        "- Provide concrete engineering actions, not generic advice.\n\n"
        f"Context:\n{json.dumps(context or {}, indent=2)}\n\n"
        f"Investigation Payload:\n{json.dumps(payload, indent=2)}"
    )


def _vertex_enabled() -> bool:
    raw = os.environ.get("CLAUDE_CODE_USE_VERTEX", str(_CONFIG.get("claude_use_vertex", "0"))).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _configure_vertex_environment(model: str) -> tuple[str, str]:
    project_id = (os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID") or _CONFIG.get("anthropic_vertex_project_id", "")).strip()
    region = (os.environ.get("CLOUD_ML_REGION") or _CONFIG.get("cloud_ml_region", "")).strip()
    anthropic_model = (os.environ.get("ANTHROPIC_MODEL") or _CONFIG.get("anthropic_model", model)).strip()

    if project_id:
        os.environ["ANTHROPIC_VERTEX_PROJECT_ID"] = project_id
    if region:
        os.environ["CLOUD_ML_REGION"] = region
    if anthropic_model:
        os.environ["ANTHROPIC_MODEL"] = anthropic_model
    os.environ["CLAUDE_CODE_USE_VERTEX"] = "1"
    return project_id, region


async def _query_vertex(prompt: str) -> str:
    from claude_agent_sdk import AssistantMessage, TextBlock, query

    chunks: list[str] = []
    try:
        async for message in query(prompt=prompt):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        chunks.append(block.text.strip())
                continue

            # Best-effort compatibility across SDK message variants.
            content = getattr(message, "content", None)
            if content:
                for block in content:
                    text = getattr(block, "text", "")
                    if isinstance(text, str) and text.strip():
                        chunks.append(text.strip())
            text = getattr(message, "text", "")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
    except Exception:
        # Some SDK builds can raise on terminal "success" result events.
        # If we already captured assistant text, keep it instead of failing hard.
        if chunks:
            return "\n".join(chunks).strip()
        raise
    return "\n".join(chunks).strip()


def _generate_with_vertex(metrics: dict, context: dict | None = None, model: str = DEFAULT_MODEL) -> str:
    try:
        import claude_agent_sdk  # noqa: F401
    except ImportError:
        return (
            "Vertex mode is enabled, but `claude_agent_sdk` is not installed.\n\n"
            "Install it with: `pip install claude-agent-sdk`"
        )

    project_id, region = _configure_vertex_environment(model=model)
    if not project_id or not region:
        return (
            "Vertex mode is enabled, but required settings are missing.\n\n"
            "Set `ANTHROPIC_VERTEX_PROJECT_ID` and `CLOUD_ML_REGION`, "
            "or provide them in `config/report-config.json`."
        )

    prompt = _prompt_from_metrics(metrics, context)
    try:
        return asyncio.run(_query_vertex(prompt)) or "Vertex Claude returned no text content."
    except RuntimeError:
        # Streamlit/runtime may already have an event loop.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_query_vertex(prompt)) or "Vertex Claude returned no text content."
        finally:
            loop.close()
    except Exception as exc:  # pylint: disable=broad-except
        return f"Vertex Claude request failed: {exc}"


def _fallback_insights(metrics: dict) -> str:
    summary = metrics.get("summary", {})
    median_days = summary.get("median_close_days", 0)
    p90_days = summary.get("p90_close_days", 0)
    throughput = metrics.get("weekly_throughput", [])
    latest_throughput = throughput[-1]["count"] if throughput else 0
    return (
        "Claude API key not configured, so this is a rule-based insight summary.\n\n"
        f"- Median close time is {median_days:.1f} working days; P90 is {p90_days:.1f} days.\n"
        f"- Latest weekly closure throughput is {latest_throughput} bugs/week.\n"
        "- Focus actions: reduce long-tail closures (P90), protect closure throughput, and remove repeat offenders."
    )


def _fallback_root_cause_insights(payload: dict) -> str:
    bugs = payload.get("bugs", []) if isinstance(payload, dict) else []
    if not bugs:
        return (
            "No open customer bugs were available in the selected created-date range for deep root-cause analysis.\n\n"
            "Try widening the date range or verifying Jira access."
        )
    lines = [
        "Claude is unavailable, so this is a rule-based deep analysis fallback.",
        "",
        f"- Bugs analyzed: {len(bugs)}",
    ]
    for bug in bugs[:5]:
        key = bug.get("key", "?")
        summary = bug.get("summary", "")
        downstream_count = len(bug.get("downstream_evidence", []) or [])
        upstream_count = len(bug.get("upstream_evidence", []) or [])
        test_coverage = bug.get("test_coverage") or {}
        coverage_status = test_coverage.get("coverage_status", "unknown")
        covered_scenarios = test_coverage.get("covered_scenarios", []) or []
        coverage_gaps = test_coverage.get("coverage_gaps", []) or []
        downstream_e2e_status = test_coverage.get("downstream_e2e_coverage_status", "unknown")
        downstream_e2e_gaps = test_coverage.get("downstream_e2e_coverage_gaps", []) or []
        lines.extend(
            [
                "",
                f"### {key}",
                f"- Summary: {summary}",
                f"- Internal test coverage signal: {coverage_status} ({len(covered_scenarios)} matched scenarios)",
                f"- Repo evidence footprint: downstream={downstream_count}, upstream={upstream_count}",
                f"- Downstream e2e coverage signal: {downstream_e2e_status}",
                (
                    "- Probable root cause: "
                    "Needs manual triage. Available evidence is insufficient for confident automated attribution."
                ),
                (
                    "- Why internal team may have missed it: "
                    "Likely gap in downstream e2e scenario coverage, assertion depth, or execution matrix."
                ),
                (
                    "- Engineering mitigations: "
                    "add targeted regression tests for uncovered keywords/scenarios, enforce bug-to-test mapping, "
                    "and add pre-release stress checks for impacted configuration paths."
                ),
                (
                    "- High-level engineering solution: "
                    "patch downstream behavior, validate with scenario-specific tests, and pin/verify upstream dependency assumptions."
                ),
            ]
        )
        if coverage_gaps:
            lines.append(f"- Coverage gaps keywords: {', '.join(str(item) for item in coverage_gaps[:8])}")
        if downstream_e2e_gaps:
            lines.append(
                f"- Downstream e2e missing-angle keywords: {', '.join(str(item) for item in downstream_e2e_gaps[:8])}"
            )
    return "\n".join(lines).strip()


def generate_insights(metrics: dict, context: dict | None = None, model: str = DEFAULT_MODEL) -> str:
    vertex_error_text = ""
    if _vertex_enabled():
        vertex_text = _generate_with_vertex(metrics=metrics, context=context, model=model)
        if vertex_text and "request failed" not in vertex_text.lower() and "returned an error result" not in vertex_text.lower():
            return vertex_text
        vertex_error_text = vertex_text

    api_key = (os.environ.get("ANTHROPIC_API_KEY") or _CONFIG.get("anthropic_api_key", "")).strip()
    if not api_key:
        if _vertex_enabled():
            if vertex_error_text:
                return (
                    "Vertex Claude is currently unavailable; showing fallback insights.\n\n"
                    f"Vertex detail: {vertex_error_text}\n\n"
                    f"Fallback insights:\n\n{_fallback_insights(metrics)}"
                )
            return (
                "Vertex Claude is enabled but produced no response; showing fallback insights.\n\n"
                f"{_fallback_insights(metrics)}"
            )
        return _fallback_insights(metrics)

    prompt = _prompt_from_metrics(metrics, context)
    payload = {
        "model": model,
        "max_tokens": 700,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")
        return f"Claude request failed (HTTP {exc.code}).\n\n{err[:500]}"
    except Exception as exc:  # pylint: disable=broad-except
        return f"Claude request failed: {exc}"

    parts = body.get("content", [])
    text = "\n".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()
    return text or "Claude returned no text content."


def generate_root_cause_insights(payload: dict, context: dict | None = None, model: str = DEFAULT_MODEL) -> str:
    vertex_error_text = ""
    prompt = _prompt_from_root_cause_payload(payload=payload, context=context)
    if _vertex_enabled():
        try:
            project_id, region = _configure_vertex_environment(model=model)
            if not project_id or not region:
                vertex_error_text = (
                    "Vertex mode is enabled, but required settings are missing. "
                    "Set `ANTHROPIC_VERTEX_PROJECT_ID` and `CLOUD_ML_REGION`."
                )
            else:
                try:
                    vertex_text = asyncio.run(_query_vertex(prompt)) or "Vertex Claude returned no text content."
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    try:
                        vertex_text = (
                            loop.run_until_complete(_query_vertex(prompt))
                            or "Vertex Claude returned no text content."
                        )
                    finally:
                        loop.close()
                if vertex_text and "request failed" not in vertex_text.lower():
                    return vertex_text
                vertex_error_text = vertex_text
        except Exception as exc:  # pylint: disable=broad-except
            vertex_error_text = f"Vertex Claude request failed: {exc}"

    api_key = (os.environ.get("ANTHROPIC_API_KEY") or _CONFIG.get("anthropic_api_key", "")).strip()
    if not api_key:
        if _vertex_enabled() and vertex_error_text:
            return (
                "Vertex Claude is currently unavailable; showing fallback deep analysis.\n\n"
                f"Vertex detail: {vertex_error_text}\n\n"
                f"{_fallback_root_cause_insights(payload)}"
            )
        return _fallback_root_cause_insights(payload)

    req_payload = {
        "model": model,
        "max_tokens": 1400,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=json.dumps(req_payload).encode("utf-8"),
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")
        return (
            f"Claude deep analysis request failed (HTTP {exc.code}).\n\n{err[:500]}\n\n"
            f"Fallback:\n\n{_fallback_root_cause_insights(payload)}"
        )
    except Exception as exc:  # pylint: disable=broad-except
        return (
            f"Claude deep analysis request failed: {exc}\n\n"
            f"Fallback:\n\n{_fallback_root_cause_insights(payload)}"
        )

    parts = body.get("content", [])
    text = "\n".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()
    if text:
        return text
    return _fallback_root_cause_insights(payload)
