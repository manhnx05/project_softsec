"""Export fuzzing pipeline results as a flow diagram, Markdown, and HTML.

The HTML report is fully self-contained: the flow diagram is rendered as inline
SVG (no CDN, no JavaScript), so the artifact can be submitted or archived as-is.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.testing.fuzz_pipeline import FuzzPipelineResult, FuzzStage

STATUS_COLORS = {
    "PASS": ("#DCFCE7", "#166534"),
    "FINDING": ("#FEF3C7", "#92400E"),
    "UNAVAILABLE": ("#E5E7EB", "#374151"),
    "ERROR": ("#FEE2E2", "#991B1B"),
    "INFO": ("#EAF2FF", "#1F2937"),
}

REPORT_FILES = {
    "json": "fuzzing_report.json",
    "markdown": "fuzzing_report.md",
    "html": "fuzzing_report.html",
}


def _wrap(text: str, width: int = 26, max_lines: int = 3) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if not current or len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)

    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: width - 1] + "…"
    return lines or [""]


def _flow_nodes(result: FuzzPipelineResult) -> list[tuple[str, str, str]]:
    nodes = [
        (
            "Seed data",
            f"seed={result.seed} · {result.iterations} iterations",
            "INFO",
        )
    ]
    nodes.extend(
        (stage.name, f"{stage.status} · {stage.mode}", stage.status)
        for stage in result.stages
    )
    nodes.append(("Fuzzing report", "JSON · Markdown · HTML", "INFO"))
    return nodes


def render_flow_svg(result: FuzzPipelineResult) -> str:
    """Render the fuzzing flow as a self-contained inline SVG diagram."""
    nodes = _flow_nodes(result)
    box_width, box_height, gap = 216, 84, 56
    margin = 32
    width = margin * 2 + len(nodes) * box_width + (len(nodes) - 1) * gap
    height = 168
    top = (height - box_height) // 2

    parts = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" role="img" '
            'aria-label="Fuzzing pipeline flow">'
        ),
        (
            "<defs><marker id=\"flow-arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" "
            'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            '<path d="M 0 0 L 10 5 L 0 10 z" fill="#2F6B9F"/></marker></defs>'
        ),
    ]

    for index, (name, subtitle, status) in enumerate(nodes):
        left = margin + index * (box_width + gap)
        fill, stroke = STATUS_COLORS.get(status, STATUS_COLORS["INFO"])
        parts.append(
            f'<rect x="{left}" y="{top}" width="{box_width}" height="{box_height}" '
            f'rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
        )
        lines = _wrap(name, width=27, max_lines=2)
        for offset, line in enumerate(lines):
            parts.append(
                f'<text x="{left + 12}" y="{top + 24 + offset * 15}" '
                f'font-family="Segoe UI, Arial, sans-serif" font-size="13" '
                f'font-weight="600" fill="{stroke}">{html.escape(line)}</text>'
            )
        badge = f'<text x="{left + 12}" y="{top + 62}" ' \
            f'font-family="Segoe UI, Arial, sans-serif" font-size="12" ' \
            f'font-weight="700" fill="{stroke}">{html.escape(status)}</text>'
        caption = (
            f'<text x="{left + 12}" y="{top + 77}" '
            f'font-family="Segoe UI, Arial, sans-serif" font-size="10" '
            f'fill="#4B5563">{html.escape(_wrap(subtitle, width=34, max_lines=1)[0])}</text>'
        )
        parts.append(badge)
        parts.append(caption)

        if index < len(nodes) - 1:
            start_x = left + box_width
            end_x = left + box_width + gap
            mid_y = top + box_height / 2
            parts.append(
                f'<line x1="{start_x + 6}" y1="{mid_y}" x2="{end_x - 6}" y2="{mid_y}" '
                'stroke="#2F6B9F" stroke-width="1.6" marker-end="url(#flow-arrow)"/>'
            )

    parts.append("</svg>")
    return "".join(parts)


def build_flow_mermaid(result: FuzzPipelineResult) -> str:
    """Return the fuzzing flow as a Mermaid flowchart for documentation."""
    lines = [
        "flowchart LR",
        f'    seed["Seed data<br/>seed={result.seed} · {result.iterations} iterations"]',
    ]
    previous = "seed"
    for index, stage in enumerate(result.stages):
        node = f"stage{index}"
        lines.append(f'    {node}["{stage.name}<br/>{stage.status}"]')
        lines.append(f"    {previous} --> {node}")
        previous = node
    lines.append(f'    {previous} --> report["Fuzzing report<br/>JSON / Markdown / HTML"]')
    return "\n".join(lines)


def _coverage_rows(stage: FuzzStage) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for key, value in stage.coverage.items():
        if isinstance(value, list):
            rows.append((key, ", ".join(str(item) for item in value)))
        elif isinstance(value, dict):
            continue
        else:
            rows.append((key, str(value)))
    return rows


def _table_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def build_markdown(result: FuzzPipelineResult) -> str:
    """Render the fuzzing result as a standalone Markdown report."""
    summary = result.summary
    lines = [
        "# Fuzzing pipeline report",
        "",
        f"- Generated at: {result.generated_at}",
        f"- Seed: `{result.seed}`",
        f"- Iterations per fuzz target: {result.iterations}",
        f"- Overall result: **{'PASS' if result.passed else 'FAIL'}**",
        (
            f"- Stages: {summary['stages_total']} total · {summary['PASS']} PASS · "
            f"{summary['FINDING']} FINDING · {summary['UNAVAILABLE']} UNAVAILABLE · "
            f"{summary['ERROR']} ERROR"
        ),
        "",
        "## Stage summary",
        "",
        "| # | Stage | Mode | Status | Summary |",
        "| --- | --- | --- | --- | --- |",
    ]
    for index, stage in enumerate(result.stages, start=1):
        lines.append(
            f"| {index} | {_table_cell(stage.name)} | {_table_cell(stage.mode)} | "
            f"{stage.status} | {_table_cell(stage.summary)} |"
        )

    lines.extend(["", "## Coverage", ""])
    for stage in result.stages:
        rows = _coverage_rows(stage)
        lines.append(f"### {stage.name}")
        lines.append("")
        if rows:
            lines.append("| Metric | Value |")
            lines.append("| --- | --- |")
            for key, value in rows:
                lines.append(f"| {_table_cell(key)} | {_table_cell(value)} |")
        else:
            lines.append("No coverage data was produced for this stage.")
        lines.append("")

    lines.extend(["## Seed data (fixed boundary inputs)", ""])
    for stage in result.stages:
        if stage.seed_data:
            values = ", ".join(f"`{value}`" for value in stage.seed_data)
            lines.append(f"- **{stage.name}**: {values}")
    lines.append("")

    lines.extend(["## Findings", ""])
    if result.findings:
        lines.extend(f"- {finding}" for finding in result.findings)
    else:
        lines.append("No fuzzing finding was reported.")
    lines.extend(
        [
            "",
            "## Flow",
            "",
            "```mermaid",
            build_flow_mermaid(result),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _html_coverage(stage: FuzzStage) -> str:
    rows = _coverage_rows(stage)
    if not rows:
        return ""
    body = "".join(
        f"<tr><th>{html.escape(key)}</th><td>{html.escape(value)}</td></tr>"
        for key, value in rows
    )
    return (
        f"<h3>{html.escape(stage.name)}</h3>"
        f'<table class="coverage">{body}</table>'
    )


def render_html(result: FuzzPipelineResult) -> str:
    """Render a self-contained HTML report with an inline SVG flow diagram."""
    summary = result.summary
    verdict = "PASS" if result.passed else "FAIL"

    stage_rows = "".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td>{html.escape(stage.name)}</td>"
        f"<td>{html.escape(stage.mode)}</td>"
        f'<td class="status {stage.status.lower()}">{html.escape(stage.status)}</td>'
        f"<td>{html.escape(stage.summary)}</td>"
        "</tr>"
        for index, stage in enumerate(result.stages, start=1)
    )

    seed_items = "".join(
        f"<li><strong>{html.escape(stage.name)}</strong>: "
        + ", ".join(f"<code>{html.escape(str(value))}</code>" for value in stage.seed_data)
        + "</li>"
        for stage in result.stages
        if stage.seed_data
    ) or "<li>No fixed seed inputs were recorded.</li>"

    findings = "".join(
        f"<li>{html.escape(finding)}</li>" for finding in result.findings
    ) or "<li>No fuzzing finding was reported.</li>"

    coverage = "".join(
        _html_coverage(stage) for stage in result.stages
    ) or "<p>No coverage data was produced.</p>"

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8"/>
<title>Fuzzing pipeline report</title>
<style>
  body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 32px; color: #1F2937; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #4B5563; margin-top: 0; }}
  .verdict {{ display: inline-block; padding: 4px 12px; border-radius: 999px;
             font-weight: 700; font-size: 14px; }}
  .verdict.pass {{ background: #DCFCE7; color: #166534; }}
  .verdict.fail {{ background: #FEE2E2; color: #991B1B; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
  th, td {{ border: 1px solid #E5E7EB; padding: 8px 10px; text-align: left;
            vertical-align: top; font-size: 14px; }}
  th {{ background: #F9FAFB; }}
  table.coverage th {{ width: 320px; }}
  .status {{ font-weight: 700; }}
  .status.pass {{ color: #166534; }}
  .status.finding {{ color: #92400E; }}
  .status.unavailable {{ color: #374151; }}
  .status.error {{ color: #991B1B; }}
  .flow {{ overflow-x: auto; margin: 16px 0 24px; }}
  details {{ margin-top: 24px; }}
  pre {{ background: #F9FAFB; padding: 12px; overflow-x: auto; }}
</style>
</head>
<body>
<h1>Fuzzing pipeline report</h1>
<p class="meta">Generated at {html.escape(result.generated_at)} · seed
<code>{result.seed}</code> · {result.iterations} iterations per target</p>
<p><span class="verdict {verdict.lower()}">{verdict}</span></p>
<p>{summary["stages_total"]} stages · {summary["PASS"]} PASS ·
{summary["FINDING"]} FINDING · {summary["UNAVAILABLE"]} UNAVAILABLE ·
{summary["ERROR"]} ERROR</p>

<h2>Fuzzing flow</h2>
<div class="flow">{render_flow_svg(result)}</div>

<h2>Stage summary</h2>
<table>
<thead><tr><th>#</th><th>Stage</th><th>Mode</th><th>Status</th><th>Summary</th></tr></thead>
<tbody>{stage_rows}</tbody>
</table>

<h2>Coverage</h2>
{coverage}

<h2>Seed data (fixed boundary inputs)</h2>
<ul>{seed_items}</ul>

<h2>Findings</h2>
<ul>{findings}</ul>

<details>
<summary>Mermaid source</summary>
<pre>{html.escape(build_flow_mermaid(result))}</pre>
</details>
</body>
</html>
"""


def export_fuzzing_report(
    result: FuzzPipelineResult,
    directory: Path | str,
) -> dict[str, Path]:
    """Write the JSON, Markdown, and HTML fuzzing artifacts into ``directory``."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    artifacts = {
        "json": target / REPORT_FILES["json"],
        "markdown": target / REPORT_FILES["markdown"],
        "html": target / REPORT_FILES["html"],
    }
    artifacts["json"].write_text(
        json.dumps(result.to_dict(), indent=2),
        encoding="utf-8",
    )
    artifacts["markdown"].write_text(build_markdown(result), encoding="utf-8")
    artifacts["html"].write_text(render_html(result), encoding="utf-8")
    return artifacts
