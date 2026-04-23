from datetime import datetime
from pathlib import Path

from utils import safe_slug

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<title>PhantomAI Report - {{ target }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 40px 24px; }
  header { border-bottom: 1px solid #30363d; padding-bottom: 24px; margin-bottom: 32px; }
  header h1 { font-size: 28px; color: #f0f6fc; }
  header .meta { color: #8b949e; font-size: 14px; margin-top: 8px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
  .badge.critical { background: #490202; color: #ff7b72; }
  .badge.high { background: #3d1a00; color: #ffa657; }
  .badge.medium { background: #3a2a00; color: #e3b341; }
  .badge.low { background: #012a1e; color: #3fb950; }
  .badge.info, .badge.informational { background: #0c2d6b; color: #79c0ff; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 40px; }
  .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
  .summary-card .count { font-size: 32px; font-weight: 700; }
  .summary-card .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
  .executive { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 40px; }
  .executive h2 { font-size: 18px; margin-bottom: 12px; color: #f0f6fc; }
  .executive p { color: #c9d1d9; margin-bottom: 10px; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 16px; }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
  .finding-header h3 { font-size: 16px; color: #f0f6fc; }
  .finding-section { margin-bottom: 14px; }
  .finding-section label { font-size: 11px; text-transform: uppercase; color: #8b949e; display: block; margin-bottom: 4px; }
  .finding-section p { color: #c9d1d9; font-size: 14px; }
  .steps ol { color: #c9d1d9; font-size: 14px; padding-left: 20px; }
  .steps li { margin-bottom: 6px; }
  code { background: #0d1117; border: 1px solid #30363d; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; color: #79c0ff; }
  .footer { text-align: center; color: #8b949e; font-size: 12px; margin-top: 48px; padding-top: 24px; border-top: 1px solid #30363d; }
</style>
</head>
<body>
<div class=\"container\">
  <header>
    <h1>PhantomAI - Penetration Test Report</h1>
    <div class=\"meta\">
      Target: <strong>{{ target }}</strong> &nbsp;-&nbsp;
      Generated: {{ generated_at }} &nbsp;-&nbsp;
      Overall risk: <span class=\"badge {{ overall_risk_class }}\">{{ overall_risk | upper }}</span>
    </div>
  </header>

  <div class=\"summary-grid\">
    <div class=\"summary-card\">
      <div class=\"count\" style=\"color:#ff7b72\">{{ counts.critical }}</div>
      <div class=\"label\">Critical</div>
    </div>
    <div class=\"summary-card\">
      <div class=\"count\" style=\"color:#ffa657\">{{ counts.high }}</div>
      <div class=\"label\">High</div>
    </div>
    <div class=\"summary-card\">
      <div class=\"count\" style=\"color:#e3b341\">{{ counts.medium }}</div>
      <div class=\"label\">Medium</div>
    </div>
    <div class=\"summary-card\">
      <div class=\"count\" style=\"color:#3fb950\">{{ counts.low }}</div>
      <div class=\"label\">Low</div>
    </div>
    <div class=\"summary-card\">
      <div class=\"count\" style=\"color:#79c0ff\">{{ counts.info }}</div>
      <div class=\"label\">Info</div>
    </div>
  </div>

  <div class=\"executive\">
    <h2>Executive Summary</h2>
    {% for para in executive_summary %}
    <p>{{ para }}</p>
    {% endfor %}
  </div>

  <h2 style=\"margin-bottom:16px; color:#f0f6fc\">Findings</h2>

  {% for f in findings %}
  <div class=\"finding\">
    <div class=\"finding-header\">
      <span class=\"badge {{ f.severity }}\">{{ f.severity | upper }}</span>
      <h3>{{ f.title }}</h3>
    </div>
    {% if f.affected_url %}
    <div class=\"finding-section\">
      <label>Affected URL</label>
      <p><code>{{ f.affected_url }}</code></p>
    </div>
    {% endif %}
    <div class=\"finding-section\">
      <label>Description</label>
      <p>{{ f.description }}</p>
    </div>
    <div class=\"finding-section\">
      <label>Impact</label>
      <p>{{ f.impact }}</p>
    </div>
    {% if f.steps_to_reproduce %}
    <div class=\"finding-section steps\">
      <label>Steps to reproduce</label>
      <ol>{% for step in f.steps_to_reproduce %}<li>{{ step }}</li>{% endfor %}</ol>
    </div>
    {% endif %}
    <div class=\"finding-section\">
      <label>Remediation</label>
      <p>{{ f.remediation }}</p>
    </div>
  </div>
  {% endfor %}

  <div class=\"footer\">Generated by PhantomAI &nbsp;-&nbsp; For authorized testing only</div>
</div>
</body>
</html>"""


def generate_html_report(
    target: str,
    ai_report: dict,
    output_path: str = None,
    report_dir: str = "reports",
) -> str:
    from jinja2 import Environment

    findings = ai_report.get("findings", [])
    counts = ai_report.get(
        "findings_by_severity",
        {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )
    executive_summary = ai_report.get("executive_summary", "No summary available.").split("\n\n")
    overall_risk = ai_report.get("overall_risk", "informational")
    overall_risk_class = "info" if overall_risk == "informational" else overall_risk

    env = Environment(autoescape=False)
    template = env.from_string(REPORT_TEMPLATE)
    html = template.render(
        target=target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        overall_risk=overall_risk,
        overall_risk_class=overall_risk_class,
        counts=counts,
        executive_summary=executive_summary,
        findings=findings,
    )

    if output_path is None:
        report_root = Path(report_dir)
        report_root.mkdir(parents=True, exist_ok=True)
        safe = safe_slug(target)
        output_path = str(report_root / f"phantomai_report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M')}.html")

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html, encoding="utf-8")
    return output_path
