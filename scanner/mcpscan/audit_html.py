"""Self-contained, offline HTML reports for portfolio audits."""
from __future__ import annotations

import base64
import hashlib
from html import escape


_STYLE = """
:root{color-scheme:light dark;--bg:#f4f7fb;--paper:#fff;--ink:#17233a;--muted:#495873;
--border:#cdd6e5;--accent:#244ead;--good:#166345;--bad:#a22342}
@media(prefers-color-scheme:dark){:root{--bg:#101828;--paper:#172236;--ink:#edf2ff;
--muted:#bdcbe3;--border:#3a4962;--accent:#a4beff;--good:#80e0b5;--bad:#ff9caf}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}
main{max-width:1150px;margin:auto;padding:clamp(16px,4vw,48px)}header{margin-bottom:28px}h1{font-size:clamp(2rem,5vw,3.3rem);line-height:1.1;margin:.25em 0}h2,h3,h4,p{margin:.45em 0}
.kicker{font-weight:700;letter-spacing:.14em;color:var(--accent);font-size:.8rem}.muted,small{color:var(--muted)}
.badge{font-weight:750;border:1px solid currentColor;border-radius:99px;padding:3px 10px;display:inline-block}
.good{color:var(--good)}.bad{color:var(--bad)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:16px 0}
.card,.panel,.project{background:var(--paper);border:1px solid var(--border);border-radius:12px;padding:16px}
.card strong{display:block;font-size:1.7rem}.filters{display:flex;gap:12px;flex-wrap:wrap;align-items:end;margin:14px 0}
label{display:grid;gap:4px;font-weight:600}input,select{font:inherit;color:inherit;background:var(--paper);border:1px solid var(--border);border-radius:6px;padding:7px}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}.project{margin:12px 0}summary{cursor:pointer;font-size:1.1em;font-weight:700;overflow-wrap:anywhere}
.scroller{overflow:auto;margin:.7rem 0 1rem}table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted)}
code{font-size:.88em;overflow-wrap:anywhere}footer{margin-top:24px}[hidden]{display:none!important}
@media print{body{background:white;color:black}.filters{display:none}.project{break-inside:avoid}}
"""

_SCRIPT = """(() => {
  const query = document.querySelector('#report-search');
  const severity = document.querySelector('#report-severity');
  const status = document.querySelector('#report-status');
  const count = document.querySelector('#finding-count');
  const rows = Array.from(document.querySelectorAll('[data-finding]'));
  const projects = Array.from(document.querySelectorAll('[data-project]'));
  const filters = document.querySelector('#report-filters');
  const update = () => {
    const q = query.value.trim().toLowerCase();
    let shown = 0;
    for (const row of rows) {
      const haystack = `${row.closest('[data-project]').dataset.project} ${row.textContent}`.toLowerCase();
      const statusMatch = !status.value || (status.value === 'violation' ? row.dataset.violation === 'yes' : row.dataset.status === status.value);
      row.hidden = !haystack.includes(q) || (severity.value && row.dataset.severity !== severity.value) || !statusMatch;
      if (!row.hidden) shown += 1;
    }
    for (const project of projects) {
      const empty = project.querySelector('[data-no-match]');
      if (empty) empty.hidden = Boolean(project.querySelector('[data-finding]:not([hidden])'));
    }
    count.textContent = `${shown} of ${rows.length} findings shown`;
  };
  filters.hidden = false;
  query.addEventListener('input', update);
  severity.addEventListener('change', update);
  status.addEventListener('change', update);
  update();
})();"""


def _e(value) -> str:
    return escape(str(value), quote=True)


def _table(caption: str, headers: tuple[str, ...], rows: list[str]) -> str:
    head = ''.join(f'<th scope="col">{_e(col)}</th>' for col in headers)
    return (f'<div class="scroller"><table><caption>{_e(caption)}</caption>'
            f'<thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def _findings(project: dict) -> str:
    if not project['findings']:
        return '<p class="muted">No findings.</p>'
    rows = []
    for finding in project['findings']:
        violation = 'yes' if finding['policy_violation'] else 'no'
        cells = (finding['severity'], finding['status'], finding['rule_id'], finding['server'],
                 finding['tool'], finding['location'], violation)
        rows.append(f'<tr data-finding data-severity="{_e(cells[0])}" data-status="{_e(cells[1])}" '
                    f'data-violation="{violation}">'
                    + ''.join(f'<td>{_e(value)}</td>' for value in cells) + '</tr>')
    return (_table('Static scanner findings', ('Severity', 'Status', 'Rule', 'Server', 'Tool', 'Location',
                                               'Counts toward policy'), rows)
            + '<p data-no-match hidden>No findings match the current filters in this project.</p>')


def _drift(drift: dict | None) -> str:
    if drift is None:
        return '<p class="muted">No baseline supplied; drift was not evaluated.</p>'
    if not drift['changed']:
        return '<p class="muted">No metadata drift from baseline.</p>'
    rows = []
    for key, change in (('servers_added', 'added'), ('servers_removed', 'removed')):
        for server in drift[key]:
            rows.append(f'<tr><td>{change} server</td><td>{_e(server)}</td><td>—</td><td>—</td></tr>')
    for row in drift['tools']:
        fields = ', '.join(row.get('fields', ())) or '—'
        cells = (row['change'], row['server'], row['tool'], fields)
        rows.append('<tr>' + ''.join(f'<td>{_e(value)}</td>' for value in cells) + '</tr>')
    return _table('Changes from baseline', ('Change', 'Server', 'Tool', 'Fields'), rows)


def render(report: dict) -> str:
    summary, policy = report['summary'], report['policy']
    script_hash = base64.b64encode(hashlib.sha256(_SCRIPT.encode('utf-8')).digest()).decode('ascii')
    policy_csp = ("default-src 'none'; style-src 'unsafe-inline'; "
                  f"script-src 'sha256-{script_hash}'; base-uri 'none'; form-action 'none'")
    status, tone = ('PASS', 'good') if report['passed'] else ('FAIL', 'bad')
    budget = policy.get('max_tool_changes')
    cards = ''.join(f'<div class="card"><strong>{_e(summary[key])}</strong>{label}</div>'
                    for key, label in (('projects', 'Projects'), ('tools_scanned', 'Tools scanned'),
                                       ('policy_violations', 'Gated findings'), ('tool_changes', 'Tool changes'),
                                       ('resolved_findings', 'Findings absent from current snapshots')))
    sections = []
    for project in report['projects']:
        name = _e(project['id'])
        sections.append(f'<details open class="project" data-project="{name}"><summary>{name}</summary>'
                        f'<p class="muted">{_e(project["servers_scanned"])} servers · '
                        f'{_e(project["tools_scanned"])} tools · {_e(project["policy_violations"])} gated findings · '
                        f'{_e(project["resolved_findings"])} findings absent from current snapshot</p>'
                        f'<h3>Findings</h3>{_findings(project)}'
                        f'<h3>Metadata drift</h3>{_drift(project["metadata_drift"])}</details>')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_e(policy_csp)}">
<title>MCP audit report</title><style>{_STYLE}</style></head><body><main>
<header><div class="kicker">MCPWN / OFFLINE AUDIT</div><h1>Portfolio audit</h1>
<p><span class="badge {tone}">{status}</span> <span class="muted">Policy result for the supplied snapshots</span></p></header>
<section aria-label="Audit totals" class="cards">{cards}</section>
<section class="panel"><h2>Policy</h2>
<p>Minimum severity: <strong>{_e(policy['minimum_severity'])}</strong> · Gate: <strong>{_e(policy['gate'])}</strong> ·
Findings budget: <strong>{_e(policy['max_violations'])}</strong> · Tool change budget: <strong>{_e(budget if budget is not None else 'not set')}</strong></p>
</section>
<section aria-labelledby="projects-heading"><h2 id="projects-heading">Projects</h2>
<div class="filters" id="report-filters" hidden>
<label>Search findings<input type="search" id="report-search" placeholder="Project, tool or rule"></label>
<label>Severity<select id="report-severity"><option value="">All severities</option><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select></label>
<label>Status<select id="report-status"><option value="">All statuses</option><option value="violation">Counts toward policy</option><option value="new">New</option><option value="escalated">Escalated</option><option value="existing">Existing</option><option value="unbaselined">No baseline</option></select></label>
<span id="finding-count" role="status"></span></div>
{''.join(sections)}</section>
<footer class="muted">An audit pass does not certify that a server is safe. Raw descriptions, schemas and evidence are omitted; identifiers and locations may still be private.</footer>
</main><script>{_SCRIPT}</script></body></html>'''
