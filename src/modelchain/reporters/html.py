from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from modelchain.generator import SBOMResult

_SBOM_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ModelChain SBOM - {{ metadata.model_name }} {{ metadata.model_version }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }
  h1, h2, h3 { color: #58a6ff; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .passed { color: #3fb950; }
  .failed { color: #f85149; }
  table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; }
  th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; }
  code { background: #1f2429; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.9em; }
  .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
  .badge-green { background: #1b4721; color: #3fb950; }
  .badge-red { background: #49242a; color: #f85149; }
  .badge-yellow { background: #493d1b; color: #d29922; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }
  .summary-item { text-align: center; padding: 1rem; background: #1c2128; border-radius: 6px; }
  .summary-number { font-size: 2em; font-weight: bold; color: #58a6ff; }
  .summary-label { font-size: 0.85em; color: #8b949e; }
</style>
</head>
<body>
<h1>ModelChain SBOM Report</h1>
<p>Generator: {{ generator }} | Format: {{ fmt }} | Generated: {{ generated_at }}</p>

<div class="card">
  <h2>Model Information</h2>
  <table>
    <tr><th>Name</th><td>{{ metadata.model_name }}</td></tr>
    <tr><th>Version</th><td>{{ metadata.model_version }}</td></tr>
    <tr><th>Type</th><td>{{ metadata.model_type }}</td></tr>
    <tr><th>Framework</th><td>{{ metadata.framework }} {{ metadata.framework_version }}</td></tr>
    <tr><th>Base Model</th><td>{{ metadata.base_model or 'N/A' }}</td></tr>
    <tr><th>Author</th><td>{{ metadata.author or 'N/A' }}</td></tr>
    <tr><th>License</th><td>{{ metadata.license or 'N/A' }}</td></tr>
  </table>
</div>

{% if metadata.datasets %}
<div class="card">
  <h2>Datasets ({{ metadata.datasets|length }})</h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Source</th><th>License</th><th>Hash</th></tr>
    {% for ds in metadata.datasets %}
    <tr>
      <td>{{ ds.name }}</td>
      <td>{{ ds.version }}</td>
      <td>{{ ds.source }}</td>
      <td>{{ ds.license }}</td>
      <td><code>{{ ds.hash[:16] }}...</code></td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

{% if metadata.adapters %}
<div class="card">
  <h2>Adapters ({{ metadata.adapters|length }})</h2>
  <table>
    <tr><th>Name</th><th>Type</th><th>Base Model</th><th>Hash</th></tr>
    {% for adp in metadata.adapters %}
    <tr>
      <td>{{ adp.name }}</td>
      <td>{{ adp.type }}</td>
      <td>{{ adp.base_model }}</td>
      <td><code>{{ adp.hash[:16] }}...</code></td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

{% if metadata.dependencies %}
<div class="card">
  <h2>Dependencies ({{ metadata.dependencies|length }})</h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Type</th><th>License</th></tr>
    {% for dep in metadata.dependencies %}
    <tr>
      <td>{{ dep.name }}</td>
      <td>{{ dep.version }}</td>
      <td>{{ dep.type }}</td>
      <td>{{ dep.license }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<div class="card">
  <h2>Audit Summary</h2>
  <div class="summary-grid">
    <div class="summary-item">
      <div class="summary-number">{{ audit_summary.total_components }}</div>
      <div class="summary-label">Total Components</div>
    </div>
    <div class="summary-item">
      <div class="summary-number">{{ audit_summary.datasets }}</div>
      <div class="summary-label">Datasets</div>
    </div>
    <div class="summary-item">
      <div class="summary-number">{{ audit_summary.adapters }}</div>
      <div class="summary-label">Adapters</div>
    </div>
    <div class="summary-item">
      <div class="summary-number">{{ audit_summary.dependencies }}</div>
      <div class="summary-label">Dependencies</div>
    </div>
    <div class="summary-item">
      <div class="summary-number {% if audit_summary.integrity_verified %}passed{% else %}failed{% endif %}">{{ audit_summary.integrity_verified }}</div>
      <div class="summary-label">Integrity Verified</div>
    </div>
    <div class="summary-item">
      <div class="summary-number {% if audit_summary.vulnerabilities_found > 0 %}failed{% else %}passed{% endif %}">{{ audit_summary.vulnerabilities_found }}</div>
      <div class="summary-label">Vulnerabilities</div>
    </div>
  </div>
</div>

{% for report in compliance_reports %}
<div class="card">
  <h2>{{ report.framework }}</h2>
  <p>Status: <span class="badge {% if report.passed %}badge-green{% else %}badge-red{% endif %}">{{ 'PASSED' if report.passed else 'FAILED' }}</span></p>
  {% if report.summary %}
  <p>Passed: {{ report.summary.passed }}/{{ report.summary.total_requirements or report.summary.total_categories }}</p>
  {% endif %}
</div>
{% endfor %}

</body>
</html>"""


class HTMLReporter:
    """Reports SBOM results as HTML files using Jinja2 templates.

    Uses Jinja2 autoescaping to prevent XSS in generated HTML reports.
    """

    def __init__(self):
        self._env = Environment(autoescape=select_autoescape(["html", "xml"]))
        self._template = self._env.from_string(_SBOM_TEMPLATE)

    def report_sbom(self, result: SBOMResult, path: str | Path) -> Path:
        """Write SBOM result as HTML.

        Args:
            result: SBOM generation result.
            path: Output file path.

        Returns:
            Path to the written file.
        """
        html = self._template.render(
            metadata=result.metadata,
            sbom=result.sbom,
            manifest=result.manifest,
            audit_summary=result.audit_summary,
            compliance_reports=result.compliance_reports,
            generator=result.generator,
            fmt=result.format,
            generated_at=result.generated_at,
        )
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html)
        return p
