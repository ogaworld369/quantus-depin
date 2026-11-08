#!/usr/bin/env python3
"""Build the static dashboard (GitHub Pages) from a verification run.

Reads results/scores.json (produced by scripts/run_verification.py)
and writes a single self-contained HTML page to docs/index.html.

Display rules (project honesty bar):
  * The adjusted weight is the headline metric. Raw counts are shown
    alongside, never as the headline.
  * Disqualified nodes, rejected submissions, anomaly flags and
    not-evaluated spot checks are shown as they are.
  * Chain cross-checks are labelled NOT IMPLEMENTED until they are.

Standard library only.
"""

import html
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCORES_PATH = os.path.join(ROOT, "results", "scores.json")
OUT_PATH = os.path.join(ROOT, "docs", "index.html")

SPOT_LABELS = {
    "passed": "passed",
    "failed": "FAILED",
    "not_evaluated": "not evaluated",
    None: "not evaluated",
}

CSS = """
:root { color-scheme: dark; }
body { margin: 0; background: #0b0e13; color: #e8ecf1;
       font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 880px; margin: 0 auto; padding: 40px 20px 64px; }
h1 { font-size: 28px; font-weight: 600; letter-spacing: .2px; margin: 0 0 4px; }
.sub { color: #9aa7b4; margin: 0 0 32px; }
.cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }
.card { background: #131922; border: 1px solid #22304a; border-radius: 14px;
        padding: 18px 22px; min-width: 180px; }
.card .label { color: #9aa7b4; font-size: 13px; margin-bottom: 6px; }
.card .value { font-size: 30px; font-weight: 600; }
.card .note { color: #9aa7b4; font-size: 12px; margin-top: 4px; }
.warn { background: #2a2113; border: 1px solid #6b5518; color: #f0d48a;
        border-radius: 12px; padding: 14px 18px; margin-bottom: 32px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #22304a; }
th { color: #9aa7b4; font-weight: 500; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
code { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; }
.status-ok { color: #7ee2a0; }
.status-disqualified { color: #ff8a80; }
.flag { color: #f0d48a; font-size: 12px; display: block; }
h2 { font-size: 18px; margin: 36px 0 12px; }
.muted { color: #9aa7b4; font-size: 13px; }
ul { padding-left: 20px; }
li { margin: 4px 0; font-size: 14px; }
footer { margin-top: 48px; color: #5f6d7d; font-size: 12px; }
"""


def esc(x):
    return html.escape(str(x))


def fmt_ts(unix):
    if not unix:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(unix))


def node_rows(nodes):
    rows = []
    for n in sorted(nodes, key=lambda x: -x["adjusted_weight"]):
        m = n.get("metrics") or {}
        flags = "".join('<span class="flag">%s</span>' % esc(f)
                        for f in n.get("flags", []))
        reasons = "".join('<span class="flag">%s</span>' % esc(r)
                          for r in n.get("disqualify_reasons", []))
        rows.append(
            "<tr>"
            "<td><code>%s</code><br><span class=\"muted\">%s</span></td>"
            "<td class=\"status-%s\">%s</td>"
            "<td class=\"num\">%.4f</td>"
            "<td class=\"num\">%d</td>"
            "<td class=\"num\">%s</td>"
            "<td>%s%s%s</td>"
            "</tr>" % (
                esc(n["device_id"]), esc(n.get("account") or "-"),
                esc(n["status"]), esc(n["status"]),
                n["adjusted_weight"], n["raw_count"],
                ("%.3f" % m["settled_days"]) if m else "-",
                esc(SPOT_LABELS.get(n.get("spot_check"), "not evaluated")),
                flags, reasons))
    return "\n".join(rows)


def main():
    with open(SCORES_PATH, "r", encoding="utf-8") as f:
        run = json.load(f)
    scores = run["scores"]
    summary = scores["summary"]
    chain = run.get("chain_checks", {})
    chain_pending = chain.get("status") == "not_implemented"

    rejected_html = ""
    if scores["rejected_submissions"]:
        items = []
        for r in scores["rejected_submissions"]:
            items.append("<li><code>%s</code> (%s): %s</li>" % (
                esc(r.get("claimed_device_id") or "unknown device"),
                esc(r.get("account") or "-"),
                esc("; ".join(r.get("reasons", [])))))
        rejected_html = ("<h2>Rejected submissions</h2>"
                         "<p class=\"muted\">Invalid submissions are "
                         "rejected without attribution: they never "
                         "create, damage, or disqualify a node.</p>"
                         "<ul>%s</ul>" % "".join(items))

    chain_banner = ""
    if chain_pending:
        chain_banner = (
            "<div class=\"warn\"><strong>Chain cross-checks: NOT "
            "IMPLEMENTED.</strong> Checkpoint block hashes in these "
            "bundles have not been compared with the real Quantus "
            "chain, and spot-check expected values are not computed "
            "from chain data. Figures below reflect the internal "
            "consistency of signed records and the scoring rules "
            "only.</div>")

    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quantus DePIN - Participation Registry</title>
<style>%s</style>
</head>
<body>
<main>
<h1>Quantus DePIN</h1>
<p class="sub">Verifiable participation records for phone full nodes.
Adjusted weight is the headline metric; raw counts are shown alongside.
Scored at %s (unix %d).</p>
%s
<div class="cards">
  <div class="card"><div class="label">Total adjusted weight</div>
    <div class="value">%.4f</div>
    <div class="note">Headline metric (SPEC scoring rules)</div></div>
  <div class="card"><div class="label">Raw node count</div>
    <div class="value">%d</div>
    <div class="note">Unadjusted count, shown for reference</div></div>
  <div class="card"><div class="label">Disqualified</div>
    <div class="value">%d</div>
    <div class="note">History revoked (signed evidence only)</div></div>
  <div class="card"><div class="label">Closed clusters capped</div>
    <div class="value">%d</div>
    <div class="note">Mutual-witness clusters discounted</div></div>
</div>
<h2>Nodes</h2>
<table>
<tr><th>Device</th><th>Status</th><th class="num">Adjusted weight</th>
<th class="num">Raw count</th><th class="num">Settled days</th>
<th>Spot check / flags</th></tr>
%s
</table>
%s
<h2>How to verify these numbers</h2>
<p class="muted">Every figure on this page is recomputed from the
public bundles in <code>submissions/</code> by the open reference
implementation in <code>tools/</code>. Run
<code>python3 scripts/run_verification.py</code> and
<code>python3 scripts/build_dashboard.py</code> locally to reproduce
this page exactly.</p>
<footer>Quantus DePIN registry - off-chain participation records.
These records do not affect Quantus consensus, block production, or
miner rewards.</footer>
</main>
</body>
</html>
""" % (
        CSS,
        esc(fmt_ts(run["scored_at_unix"])), run["scored_at_unix"],
        chain_banner,
        summary["total_adjusted_weight"],
        summary["raw_node_count"],
        summary["disqualified_count"],
        summary["closed_clusters_capped"],
        node_rows(scores["nodes"]),
        rejected_html,
    )

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(page)
    print("wrote %s" % OUT_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
