from jinja2 import Template
from .reporter import SASTReport, report_to_dict, FIX_SUGGESTIONS


HTML_TEMPLATE = Template('''\
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI SAST Report</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }
.container { max-width: 1100px; margin: 0 auto; padding: 20px; }
h1 { font-size: 1.8rem; margin-bottom: 5px; color: #1a1a2e; }
.subtitle { color: #666; font-size: 0.9rem; margin-bottom: 25px; }

/* Dashboard */
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 30px; }
.stat-card { background: #fff; border-radius: 10px; padding: 18px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.stat-card .value { font-size: 2rem; font-weight: 700; }
.stat-card .label { font-size: 0.8rem; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-card.confirmed .value { color: #e74c3c; }
.stat-card.fp .value { color: #27ae60; }
.stat-card.uncertain .value { color: #f39c12; }
.stat-card.total .value { color: #3498db; }

/* Chart */
.chart-section { background: #fff; border-radius: 10px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.chart-section h2 { font-size: 1.1rem; margin-bottom: 15px; color: #1a1a2e; }
.bar-chart { display: flex; flex-direction: column; gap: 10px; }
.bar-row { display: flex; align-items: center; gap: 10px; }
.bar-label { width: 120px; font-size: 0.85rem; text-align: right; color: #555; }
.bar-track { flex: 1; background: #eee; border-radius: 6px; height: 24px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 6px; display: flex; align-items: center; padding-left: 8px; font-size: 0.75rem; color: #fff; font-weight: 600; min-width: 30px; transition: width 0.3s; }
.bar-fill.sqli { background: #e74c3c; }
.bar-fill.xss { background: #e67e22; }
.bar-fill.path { background: #9b59b6; }

/* Metrics */
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
.metric-card { background: #fff; border-radius: 10px; padding: 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.metric-card .metric-label { font-size: 0.8rem; color: #888; margin-bottom: 4px; }
.metric-card .metric-value { font-size: 1.4rem; font-weight: 700; color: #1a1a2e; }

/* Findings */
.findings-header { font-size: 1.2rem; margin-bottom: 15px; color: #1a1a2e; }
.finding-card { background: #fff; border-radius: 10px; padding: 20px; margin-bottom: 15px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-left: 4px solid #ccc; }
.finding-card.CONFIRMED { border-left-color: #e74c3c; }
.finding-card.FALSE_POSITIVE { border-left-color: #27ae60; }
.finding-card.UNCERTAIN { border-left-color: #f39c12; }

.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }
.finding-title { font-weight: 600; font-size: 0.95rem; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: #fff; }
.badge.CONFIRMED { background: #e74c3c; }
.badge.FALSE_POSITIVE { background: #27ae60; }
.badge.UNCERTAIN { background: #f39c12; }
.badge.severity-ERROR { background: #c0392b; }
.badge.severity-WARNING { background: #e67e22; }
.badge.severity-INFO { background: #3498db; }

.finding-meta { display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.82rem; color: #666; margin-bottom: 12px; }
.finding-meta span { display: flex; align-items: center; gap: 4px; }

.code-block { background: #1e1e2e; color: #cdd6f4; padding: 14px; border-radius: 8px; font-family: "Fira Code", "Consolas", monospace; font-size: 0.82rem; overflow-x: auto; margin-bottom: 12px; white-space: pre; line-height: 1.5; }

.confidence-bar-container { margin-bottom: 12px; }
.confidence-label { font-size: 0.8rem; color: #888; margin-bottom: 4px; }
.confidence-track { background: #eee; border-radius: 6px; height: 10px; overflow: hidden; }
.confidence-fill { height: 100%; border-radius: 6px; background: linear-gradient(90deg, #f39c12, #27ae60); }

.reasoning { background: #f8f9fa; padding: 12px; border-radius: 8px; font-size: 0.85rem; color: #555; margin-bottom: 12px; }
.reasoning strong { color: #333; }

.taint-path { margin-bottom: 12px; }
.taint-path h4 { font-size: 0.85rem; color: #555; margin-bottom: 6px; }
.taint-path ol { padding-left: 20px; font-size: 0.82rem; color: #666; font-family: monospace; }
.taint-path li { margin-bottom: 3px; }

.fix-box { background: #eaf7ea; border: 1px solid #b7e4c7; border-radius: 8px; padding: 12px; font-size: 0.85rem; color: #2d6a4f; }
.fix-box strong { color: #1b4332; }

.footer { text-align: center; color: #aaa; font-size: 0.75rem; margin-top: 30px; padding: 15px 0; border-top: 1px solid #eee; }
</style>
</head>
<body>
<div class="container">
  <h1>AI SAST Analysis Report</h1>
  <div class="subtitle">{{ report.source_dir }} &mdash; {{ report.analyzed_at }}</div>

  <!-- Dashboard -->
  <div class="dashboard">
    <div class="stat-card total">
      <div class="value">{{ report.semgrep_findings_count }}</div>
      <div class="label">Semgrep Findings</div>
    </div>
    <div class="stat-card confirmed">
      <div class="value">{{ report.confirmed_count }}</div>
      <div class="label">Confirmed</div>
    </div>
    <div class="stat-card fp">
      <div class="value">{{ report.false_positive_count }}</div>
      <div class="label">False Positive</div>
    </div>
    <div class="stat-card uncertain">
      <div class="value">{{ report.uncertain_count }}</div>
      <div class="label">Uncertain</div>
    </div>
    <div class="stat-card">
      <div class="value">{{ report.total_files }}</div>
      <div class="label">Files Analyzed</div>
    </div>
  </div>

  <!-- Vulnerability Type Distribution -->
  <div class="chart-section">
    <h2>Vulnerability Type Distribution</h2>
    <div class="bar-chart">
      <div class="bar-row">
        <span class="bar-label">SQL Injection</span>
        <div class="bar-track">
          <div class="bar-fill sqli" style="width: {{ type_pcts.sql_injection }}%;">{{ type_counts.sql_injection }}</div>
        </div>
      </div>
      <div class="bar-row">
        <span class="bar-label">XSS</span>
        <div class="bar-track">
          <div class="bar-fill xss" style="width: {{ type_pcts.xss }}%;">{{ type_counts.xss }}</div>
        </div>
      </div>
      <div class="bar-row">
        <span class="bar-label">Path Traversal</span>
        <div class="bar-track">
          <div class="bar-fill path" style="width: {{ type_pcts.path_traversal }}%;">{{ type_counts.path_traversal }}</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Metrics -->
  <div class="metrics">
    <div class="metric-card">
      <div class="metric-label">Precision (Est.)</div>
      <div class="metric-value">{{ "%.1f"|format(report.metrics.precision_estimate * 100) }}%</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Recall (Est.)</div>
      <div class="metric-value">{{ "%.1f"|format(report.metrics.recall_estimate * 100) }}%</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">FP Reduction Rate</div>
      <div class="metric-value">{{ "%.1f"|format(report.metrics.fp_reduction_rate) }}%</div>
    </div>
  </div>

  <!-- Findings -->
  <h2 class="findings-header">Findings ({{ findings|length }})</h2>
  {% for f in findings %}
  <div class="finding-card {{ f.verdict }}">
    <div class="finding-header">
      <span class="finding-title">{{ f.finding.vulnerability_type | replace("_", " ") | title }} &mdash; {{ f.finding.rule_id }}</span>
      <span>
        <span class="badge {{ f.verdict }}">{{ f.verdict }}</span>
        <span class="badge severity-{{ f.finding.severity }}">{{ f.finding.severity }}</span>
      </span>
    </div>

    <div class="finding-meta">
      <span>{{ f.finding.file_path }}</span>
      <span>Line {{ f.finding.start_line }}{% if f.finding.end_line != f.finding.start_line %}-{{ f.finding.end_line }}{% endif %}</span>
      {% if f.finding.cwe %}<span>{{ f.finding.cwe }}</span>{% endif %}
    </div>

    <div class="code-block">{{ f.finding.code_snippet | e }}</div>

    <div class="confidence-bar-container">
      <div class="confidence-label">Confidence: {{ "%.0f"|format(f.confidence * 100) }}%</div>
      <div class="confidence-track">
        <div class="confidence-fill" style="width: {{ "%.0f"|format(f.confidence * 100) }}%;"></div>
      </div>
    </div>

    {% if f.taint_path %}
    <div class="taint-path">
      <h4>Taint Path:</h4>
      <ol>
        {% for step in f.taint_path %}
        <li>{{ step }}</li>
        {% endfor %}
      </ol>
    </div>
    {% endif %}

    <div class="reasoning">
      <strong>Analysis:</strong> {{ f.reasoning }}
      {% if f.llm_assisted %}<br><em>(LLM-assisted analysis)</em>{% endif %}
    </div>

    {% if f.fix_suggestion %}
    <div class="fix-box">
      <strong>Fix:</strong> {{ f.fix_suggestion }}
    </div>
    {% endif %}
  </div>
  {% endfor %}

  {% if not findings %}
  <div style="text-align: center; padding: 40px; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
    <div style="font-size: 2rem; margin-bottom: 10px;">&#10004;</div>
    <div style="font-size: 1.1rem; color: #27ae60; font-weight: 600;">No vulnerabilities found</div>
  </div>
  {% endif %}

  <div class="footer">
    Generated by AI SAST POC &mdash; COONTEC AEZIZ
  </div>
</div>
</body>
</html>
''')


def generate_html_report(report: SASTReport, output_path: str) -> str:
    """Generate an HTML report from a SASTReport and write to output_path.

    Returns the output path.
    """
    report_dict = report_to_dict(report)
    findings = report_dict["findings"]

    # Count by vulnerability type
    type_counts = {"sql_injection": 0, "xss": 0, "path_traversal": 0}
    for f in findings:
        vtype = f["finding"].get("vulnerability_type", "")
        if vtype in type_counts:
            type_counts[vtype] += 1

    total_findings = len(findings)
    type_pcts = {}
    for vtype, count in type_counts.items():
        type_pcts[vtype] = (count / total_findings * 100) if total_findings > 0 else 0

    # Add fix_suggestion to each finding if not already present
    for f in findings:
        if not f.get("fix_suggestion"):
            vtype = f["finding"].get("vulnerability_type", "")
            f["fix_suggestion"] = FIX_SUGGESTIONS.get(vtype, "")

    html = HTML_TEMPLATE.render(
        report=report_dict,
        findings=findings,
        type_counts=type_counts,
        type_pcts=type_pcts,
    )

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html)

    return output_path
