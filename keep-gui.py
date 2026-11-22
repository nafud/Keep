#!/usr/bin/env python3
"""keep-gui.py: the local viewer of Keep for the verdict reports.

    python3 -I keep-gui.py REPORT.json [REPORT.json ...] [--port N] [--no-browser] [--check]

REPORT.json is a file of the schema keep-report/1: the verdict.json that keytriage.sh writes
to the evidence medium, or the file that "vkverify.py --json" writes. With more than one report
the viewer adds a comparison of the volumes across the reports, for example the memory images
taken before and after an event.

The viewer runs on the investigator's workstation, on collected reports. It is not run on the
system under examination. It starts a web server on the loopback address 127.0.0.1 only, serves
one page and the reports, and opens the page in the browser.

What it shows and what it cannot show. A report names a key by the first 16 digits of its
SHA-256 and holds no key. The viewer passes on a fixed list of fields and drops every other
field, so a file that is not a report cannot put anything else on the page. It reads nothing but
the files named on the command line, loads no resource from the network and writes no file.

--port N       listen on port N (default 8377, or a free port if that one is taken)
--no-browser   do not open the browser, only print the address
--check        read the reports, print one line per volume and exit, without a server

Python standard library only.
"""
import argparse
import hashlib
import json
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCHEMA = "keep-report/1"
TOP = ("tool", "host", "kernel", "os", "cryptsetup", "other_filesystems", "started_utc", "finished_utc",
       "lockdown", "secure_boot", "source")
MEMORY = ("status", "file", "format", "sha256", "tool", "system_map", "note")
VOLUME = ("name", "type", "cipher", "key_location", "device", "header_backup", "route", "verdict",
          "key_sha256_16", "note", "uuid", "digest", "ground_truth")
NUMBERS = ("key_bits", "attempts", "adjacent_places")

# The verdicts of keytriage.sh and vkverify.py, and the class the page gives each of them.
VERDICTS = {
    "captured and proven": "ok",
    "proven": "ok",
    "captured, in use": "ok",
    "found in memory": "ok",
    "captured, not proven": "warn",
    "needs a memory read": "warn",
    "live copy only": "bad",
    "not proven": "bad",
    "not found": "bad",
    "unreadable header": "bad",
}


def text(value, limit=300):
    """A field as a short string, or None. Line breaks and control characters become spaces."""
    if value is None or isinstance(value, (dict, list)):
        return None
    s = "".join(c if c.isprintable() else " " for c in str(value))
    return s[:limit]


def number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**9 else None


def number10(value):
    """A byte count: a whole number below 2**50."""
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**50 else None


def load(path):
    """Read one report and return only the fields the page shows."""
    raw = open(path, "rb").read()
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError(f"not a report of the schema {SCHEMA}")
    label = os.path.splitext(os.path.basename(path))[0]
    if label == "verdict":                      # keytriage.sh: the folder carries host and time
        label = os.path.basename(os.path.dirname(os.path.abspath(path))) or label
    report = {k: text(data.get(k)) for k in TOP}
    report.update(label=text(label, 80), file=text(os.path.basename(path), 120),
                  file_sha256=hashlib.sha256(raw).hexdigest(), volumes=[], binaries=[])
    mem = data.get("memory")
    if isinstance(mem, dict):                   # keytriage.sh -m: the memory image, if one was asked for
        report["memory"] = {k: text(mem.get(k)) for k in MEMORY}
        report["memory"].update(bytes=number10(mem.get("bytes")), seconds=number(mem.get("seconds")))
    cand = data.get("candidates")
    if isinstance(cand, dict):
        report["candidates"] = {k: number(cand.get(k)) for k in ("schedules", "keys", "aes128", "aes256")}
    for b in data.get("binaries") or []:
        if isinstance(b, dict):
            report["binaries"].append({k: text(b.get(k)) for k in ("name", "path", "sha256")})
    for v in data.get("volumes") or []:
        if not isinstance(v, dict):
            continue
        vol = {k: text(v.get(k)) for k in VOLUME}
        vol.update({k: number(v.get(k)) for k in NUMBERS})
        vol["class"] = VERDICTS.get(vol["verdict"], "unknown")
        report["volumes"].append(vol)
    return report


PAGE = r"""<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keep</title>
<style>
:root {
  --bg: #f4f6f8; --surface: #ffffff; --ink: #15202b; --muted: #586574; --line: #dde3ea;
  --accent: #1f3a5f; --ok: #17794a; --ok-bg: #e4f4ec; --warn: #9a5b00; --warn-bg: #fdf1dc;
  --bad: #b3261e; --bad-bg: #fbe7e5; --unknown: #586574; --unknown-bg: #e9edf1;
  --mono: ui-monospace, "JetBrains Mono", "DejaVu Sans Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", "Noto Sans", "Liberation Sans", sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1319; --surface: #161d25; --ink: #e7ecf1; --muted: #9ba8b5; --line: #29333f;
    --accent: #9cc2f0; --ok: #56c990; --ok-bg: #12301f; --warn: #f0b354; --warn-bg: #35280f;
    --bad: #f47c73; --bad-bg: #3a1917; --unknown: #9ba8b5; --unknown-bg: #222b35;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 var(--sans); }
header.top { background: var(--surface); border-bottom: 1px solid var(--line); }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 20px; }
header.top .wrap { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; padding-top: 16px; padding-bottom: 14px; }
h1 { margin: 0; font-size: 22px; font-weight: 650; letter-spacing: -0.01em; color: var(--accent); }
.sub { color: var(--muted); }
.nokey { margin-left: auto; color: var(--muted); font-size: 13px; }
nav { display: flex; gap: 6px; flex-wrap: wrap; padding: 14px 0 0; }
nav button {
  font: inherit; color: var(--muted); background: transparent; border: 1px solid transparent;
  border-radius: 8px; padding: 6px 12px; cursor: pointer;
}
nav button:hover { color: var(--ink); }
nav button[aria-selected="true"] { color: var(--ink); background: var(--surface); border-color: var(--line); font-weight: 600; }
nav button:focus-visible, .card a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
main { padding: 16px 0 40px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; margin-top: 14px; }
h2 { margin: 0 0 12px; font-size: 13px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
dl.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px 24px; margin: 0; }
dl.meta dt { color: var(--muted); font-size: 12.5px; }
dl.meta dd { margin: 0; overflow-wrap: anywhere; }
.hint { color: var(--muted); font-size: 12.5px; }
.tally { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }
.tally div { border-radius: 10px; padding: 12px 14px; }
.tally b { display: block; font-size: 28px; line-height: 1.1; font-variant-numeric: tabular-nums; }
.ok { color: var(--ok); } .warn { color: var(--warn); } .bad { color: var(--bad); } .unknown { color: var(--unknown); }
.tally .ok, .pill.ok { background: var(--ok-bg); } .tally .warn, .pill.warn { background: var(--warn-bg); }
.tally .bad, .pill.bad { background: var(--bad-bg); } .pill.unknown { background: var(--unknown-bg); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 760px; }
th { text-align: left; font-size: 12.5px; font-weight: 600; color: var(--muted); padding: 6px 12px 8px 0; border-bottom: 1px solid var(--line); white-space: nowrap; }
td { padding: 11px 12px 11px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.name { font-weight: 600; }
.note { color: var(--muted); font-size: 13px; font-weight: 400; }
.mono { font-family: var(--mono); font-size: 13px; }
.nowrap { white-space: nowrap; }
.pill { display: inline-flex; align-items: center; gap: 8px; border-radius: 999px; padding: 3px 11px 3px 9px; font-weight: 600; font-size: 13.5px; white-space: nowrap; }
.pill::before { content: ""; width: 10px; height: 10px; background: currentColor; flex: none; }
.pill.ok::before { border-radius: 50%; }
.pill.warn::before { transform: rotate(45deg) scale(0.86); }
.pill.unknown::before { border-radius: 50%; opacity: 0.5; }
.legend { display: flex; gap: 18px 26px; flex-wrap: wrap; color: var(--muted); font-size: 13px; }
.legend span { display: inline-flex; gap: 8px; align-items: center; }
.empty { color: var(--muted); }
footer { color: var(--muted); font-size: 12.5px; padding-bottom: 30px; overflow-wrap: anywhere; }
</style>
</head>
<body>
<header class="top"><div class="wrap">
  <h1>Keep</h1><span class="sub">Decryption readiness of an unlocked Linux system</span>
  <span class="nokey">Keys are named by SHA-256. No key is on this page.</span>
</div></header>
<div class="wrap">
  <nav id="tabs" role="tablist" aria-label="Reports"></nav>
  <main id="view"></main>
  <footer id="foot"></footer>
</div>
<script>
"use strict";
const el = (tag, attrs, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (v != null) n.setAttribute(k, v); }
  for (const k of kids) { if (k != null) n.append(k); }
  return n;
};
const dash = v => (v == null || v === "") ? "–" : String(v);
const LOCKDOWN = {
  none: "memory routes open", integrity: "memory routes open",
  confidentiality: "memory routes refused by the kernel",
};
const MEANING = {
  ok: "The volume key is held and opens the volume.",
  warn: "A memory image is needed before power-off, or the proof is still open.",
  bad: "No key from this source. On scene, only a live copy of the mounted files keeps the data.",
};
const pill = v => el("span", {class: "pill " + v.class}, dash(v.verdict));

function tally(vols) {
  const n = {ok: 0, warn: 0, bad: 0};
  for (const v of vols) { if (v.class in n) n[v.class]++; }
  const names = {ok: "key held", warn: "action needed", bad: "no key"};
  return el("div", {class: "tally"}, ...Object.keys(n).map(c =>
    el("div", {class: c}, el("b", null, String(n[c])), names[c])));
}

function meta(r) {
  const rows = [
    ["Host", r.host], ["System", r.os], ["Kernel", r.kernel], ["Started (UTC)", r.started_utc],
    ["Finished (UTC)", r.finished_utc], ["Tool", r.tool], ["cryptsetup", r.cryptsetup],
    ["Key source", r.source], ["Not examined", r.other_filesystems],
  ].filter(x => x[1] != null);
  const dl = el("dl", {class: "meta"});
  for (const [k, v] of rows) dl.append(el("div", null, el("dt", null, k), el("dd", null, v)));
  if (r.lockdown != null) dl.append(el("div", null, el("dt", null, "Kernel lockdown"),
    el("dd", null, r.lockdown, " ", el("span", {class: "hint"}, LOCKDOWN[r.lockdown] ? "(" + LOCKDOWN[r.lockdown] + ")" : ""))));
  if (r.secure_boot != null) dl.append(el("div", null, el("dt", null, "Secure Boot"),
    el("dd", null, r.secure_boot === "1" ? "on" : r.secure_boot === "0" ? "off" : r.secure_boot)));
  if (r.memory) {
    const m = r.memory;
    const size = m.bytes == null ? null : m.bytes >= 1073741824
      ? (m.bytes / 1073741824).toFixed(2) + " GiB" : (m.bytes / 1048576).toFixed(1) + " MiB";
    const parts = [m.status, m.format === "lime" ? "LiME format" : m.format, size,
      m.seconds != null ? m.seconds + " s" : null, m.tool].filter(x => x != null);
    dl.append(el("div", null, el("dt", null, "Memory image"), el("dd", null, parts.join(", "),
      m.sha256 ? el("div", {class: "hint"}, "SHA-256 " + m.sha256) : "",
      m.note ? el("div", {class: "hint"}, m.note) : "")));
  }
  if (r.candidates) dl.append(el("div", null, el("dt", null, "Key schedules in the source"),
    el("dd", null, dash(r.candidates.schedules) + " (" + dash(r.candidates.aes128) + " keys AES-128, "
      + dash(r.candidates.aes256) + " keys AES-256)")));
  return dl;
}

function volumes(r) {
  if (!r.volumes.length) return el("p", {class: "empty"}, "The report lists no volume.");
  const head = ["Verdict", "Volume", "Type and cipher", "Key", "Route", "Key SHA-256 (16)", "Header"];
  const body = r.volumes.map(v => el("tr", null,
    el("td", null, pill(v)),
    el("td", {class: "name"}, dash(v.name), v.note ? el("div", {class: "note"}, v.note) : null),
    el("td", null, dash(v.type), el("div", {class: "note"}, dash(v.cipher))),
    el("td", null, v.key_bits != null ? v.key_bits + " bits" : "–",
      v.key_location ? el("div", {class: "note"}, "in " + v.key_location) : null),
    el("td", {class: "nowrap"}, dash(v.route)),
    el("td", {class: "mono"}, dash(v.key_sha256_16),
      v.ground_truth ? el("div", {class: "note"}, v.ground_truth + " to the ground truth") : null),
    el("td", null, v.header_backup ? "backed up" : v.digest ? dash(v.digest) : "–",
      v.header_backup ? el("div", {class: "note mono"}, v.header_backup) : null)));
  return el("div", {class: "scroll"}, el("table", null,
    el("thead", null, el("tr", null, ...head.map(h => el("th", {scope: "col"}, h)))),
    el("tbody", null, ...body)));
}

function binaries(r) {
  if (!r.binaries.length) return null;
  return el("section", {class: "card"}, el("h2", null, "Programs of the examined system used for the table route"),
    el("div", {class: "scroll"}, el("table", null, el("tbody", null, ...r.binaries.map(b => el("tr", null,
      el("td", {class: "name"}, dash(b.name)), el("td", {class: "mono"}, dash(b.path)),
      el("td", {class: "mono"}, dash(b.sha256))))))),
    el("p", {class: "hint"}, "Their hashes are to be compared with the distribution's packages."));
}

function legend() {
  return el("section", {class: "card"}, el("h2", null, "Reading the verdicts"),
    el("div", {class: "legend"}, ...["ok", "warn", "bad"].map(c =>
      el("span", null, el("span", {class: "pill " + c}, {ok: "key held", warn: "action needed", bad: "no key"}[c]), MEANING[c]))));
}

function reportView(r) {
  return [
    el("section", {class: "card"}, el("h2", null, "Verdicts"), tally(r.volumes)),
    el("section", {class: "card"}, el("h2", null, "Volumes"), volumes(r)),
    el("section", {class: "card"}, el("h2", null, "Run"), meta(r)),
    binaries(r), legend(),
  ];
}

function compareView(reports) {
  const names = [];
  for (const r of reports) for (const v of r.volumes) if (!names.includes(v.name)) names.push(v.name);
  const body = names.map(n => el("tr", null, el("td", {class: "name"}, dash(n)),
    ...reports.map(r => {
      const v = r.volumes.find(x => x.name === n);
      return el("td", null, v ? pill(v) : "–", v && v.key_sha256_16 ? el("div", {class: "note mono"}, v.key_sha256_16) : null);
    })));
  return [
    el("section", {class: "card"}, el("h2", null, "Each volume across the reports"),
      el("div", {class: "scroll"}, el("table", null,
        el("thead", null, el("tr", null, el("th", {scope: "col"}, "Volume"), ...reports.map(r => el("th", {scope: "col"}, r.label)))),
        el("tbody", null, ...body)))),
    legend(),
  ];
}

fetch("reports.json").then(r => r.json()).then(reports => {
  const tabs = document.getElementById("tabs"), view = document.getElementById("view");
  const views = reports.map(r => ({label: r.label, make: () => reportView(r)}));
  if (reports.length > 1) views.unshift({label: "Compare", make: () => compareView(reports)});
  const show = i => {
    [...tabs.children].forEach((b, j) => b.setAttribute("aria-selected", String(i === j)));
    view.replaceChildren(...views[i].make().filter(Boolean));
  };
  views.forEach((v, i) => {
    const b = el("button", {role: "tab", type: "button"}, v.label);
    b.addEventListener("click", () => show(i));
    tabs.append(b);
  });
  if (views.length < 2) tabs.hidden = true;
  show(0);
  document.getElementById("foot").replaceChildren(el("p", null, "Report files, with the SHA-256 of each as it was read:"),
    ...reports.map(r => el("div", {class: "mono"}, r.file_sha256 + "  " + r.file)));
}).catch(e => {
  document.getElementById("view").replaceChildren(el("p", {class: "empty"}, "The reports could not be loaded: " + e));
});
</script>
</body>
</html>
"""

HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def handler(reports):
    body = {"/": ("text/html; charset=utf-8", PAGE.encode()),
            "/reports.json": ("application/json", json.dumps(reports).encode())}

    class Handler(BaseHTTPRequestHandler):
        server_version = "keep-gui"
        sys_version = ""

        def do_GET(self):
            # Only a request addressed to the loopback name of this server is answered, so a page
            # of another site cannot read the reports through a name that points here.
            port = self.server.server_address[1]
            if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
                return self.send_error(403)
            if self.path not in body:
                return self.send_error(404)
            kind, data = body[self.path]
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("report", nargs="+")
    ap.add_argument("--port", type=int, default=8377)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()

    reports = []
    for path in a.report:
        try:
            reports.append(load(path))
        except (OSError, ValueError) as e:
            sys.exit(f"keep-gui.py: {path}: {e}")
    if a.check:
        for r in reports:
            print(f"{r['label']}: {r['tool']}, {len(r['volumes'])} volume(s), sha256 {r['file_sha256'][:16]}")
            for v in r["volumes"]:
                print(f"  {v['class']:8} {v['name']}: {v['verdict']}")
            m = r.get("memory")
            if m:
                size = f", {m['bytes']} bytes, sha256 {(m['sha256'] or '')[:16]}" if m["bytes"] is not None else ""
                print(f"  memory image: {m['status']}{size}")
        return 0

    try:
        server = ThreadingHTTPServer(("127.0.0.1", a.port), handler(reports))
    except OSError:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(reports))
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Keep viewer: {url}   ({len(reports)} report(s), Ctrl+C to stop)")
    if not a.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
