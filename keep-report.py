#!/usr/bin/env python3
"""keep-report.py: print the verdict reports of Keep as text, in the manner of ewfinfo.

    python3 -I keep-report.py REPORT.json [REPORT.json ...] [--brief]

REPORT.json is a file of the schema keep-report/1: the verdict.json that keytriage.sh and
offline-keyscan.sh write, or the file that "vkverify.py --json" writes. Each report is printed as
labelled lines: the run, the memory image if one was asked for, every volume with its verdict,
and the count of the verdicts. With more than one report a table follows that shows each volume
across the reports, for example the memory images taken before and after an event.

It runs on the investigator's workstation, on collected reports, and not on the system under
examination. It reads the files named on the command line and writes to standard output only.

What it shows and what it cannot show. A report names a key by the first 16 digits of its
SHA-256 and holds no key. Only a fixed list of fields is printed, every other field is dropped,
and control characters in a value are replaced by spaces, so a file that is not a report cannot
put an escape sequence on the terminal.

--brief   one line per volume and nothing else

Exit status 0 when every file was read as a report, otherwise 1. Python standard library only.
"""
import argparse
import hashlib
import json
import os
import sys

VERSION = "1.3"
SCHEMA = "keep-report/1"
TOP = ("tool", "host", "kernel", "os", "cryptsetup", "other_filesystems", "started_utc", "finished_utc",
       "lockdown", "secure_boot", "source", "evidence_medium")
MEMORY = ("status", "file", "format", "sha256", "tool", "system_map", "note")
VOLUME = ("name", "type", "cipher", "key_location", "device", "in_use", "header_backup", "route", "verdict",
          "key_sha256_16", "note", "uuid", "digest", "ground_truth")
NUMBERS = ("key_bits", "attempts", "adjacent_places")

# The verdicts of keytriage.sh and vkverify.py, and the class each of them falls in.
VERDICTS = {
    "captured and proven": "ok",
    "proven": "ok",
    "captured, in use": "ok",
    "found in memory": "ok",
    "no key needed": "none",
    "captured, not proven": "warn",
    "needs a memory read": "warn",
    "live copy only": "bad",
    "not proven": "bad",
    "not found": "bad",
    "unreadable header": "bad",
}
CLASSES = (("ok", "key held", "the volume key is held and opens the volume"),
           ("none", "no key needed", "the mapping has no key, the device holds the data as they are"),
           ("warn", "action needed", "a memory image is needed before power-off, or the proof is open"),
           ("bad", "no key", "no key from this source, on scene only a live copy keeps the data"),
           ("unknown", "unknown verdict", "a verdict this version does not know"))
LOCKDOWN = {"none": "memory routes open", "integrity": "memory routes open",
            "confidentiality": "memory routes refused by the kernel"}


def text(value, limit=300):
    """A field as a short string, or None. Line breaks and control characters become spaces."""
    if value is None or isinstance(value, (dict, list)):
        return None
    s = "".join(c if c.isprintable() else " " for c in str(value))
    return s[:limit]


def number(value, below=10**9):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < below else None


def load(path):
    """Read one report and return only the fields that are printed."""
    raw = open(path, "rb").read()
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError(f"not a report of the schema {SCHEMA}")
    label = os.path.splitext(os.path.basename(path))[0]
    if label == "verdict":                      # the folder carries the host or the dump, and the time
        label = os.path.basename(os.path.dirname(os.path.abspath(path))) or label
    report = {k: text(data.get(k)) for k in TOP}
    report.update(label=text(label, 80), file=text(path, 200),
                  file_sha256=hashlib.sha256(raw).hexdigest(), volumes=[], binaries=[])
    mem = data.get("memory")
    if isinstance(mem, dict):                   # keytriage.sh -m
        report["memory"] = {k: text(mem.get(k)) for k in MEMORY}
        report["memory"].update(bytes=number(mem.get("bytes"), 2**50), seconds=number(mem.get("seconds")))
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


def row(label, value, indent=1):
    """One labelled line. A field the report does not have is not printed."""
    if value is not None and value != "":
        print(f"{'    ' * indent}{label + ':':<{28 - 4 * indent}}{value}")


def size(n):
    return f"{n / 2**30:.2f} GiB" if n >= 2**30 else f"{n / 2**20:.1f} MiB"


def class_name(c):
    return next(name for key, name, _ in CLASSES if key == c)


def print_report(r):
    print(f"Report: {r['label']}")
    row("File", r["file"])
    row("SHA-256", r["file_sha256"])
    print("\nRun information:")
    row("Tool", r["tool"])
    row("Host", r["host"])
    row("System", r["os"])
    row("Kernel", r["kernel"])
    row("cryptsetup", r["cryptsetup"])
    if r["lockdown"] is not None:
        hint = LOCKDOWN.get(r["lockdown"])
        row("Kernel lockdown", r["lockdown"] + (f" ({hint})" if hint else ""))
    row("Secure Boot", {"1": "on", "0": "off"}.get(r["secure_boot"], r["secure_boot"]))
    row("Started (UTC)", r["started_utc"])
    row("Finished (UTC)", r["finished_utc"])
    row("Key source", r["source"])
    row("Destination", r["evidence_medium"])
    row("Not examined", r["other_filesystems"])
    c = r.get("candidates")
    if c:
        dash = lambda v: "-" if v is None else v
        row("Key schedules", f"{dash(c['schedules'])} ({dash(c['aes128'])} keys AES-128, "
                             f"{dash(c['aes256'])} keys AES-256)")
    m = r.get("memory")
    if m:
        print("\nMemory image:")
        row("Status", m["status"])
        row("File", m["file"])
        row("Format", "LiME" if m["format"] == "lime" else m["format"])
        row("Size", None if m["bytes"] is None else f"{size(m['bytes'])} ({m['bytes']} bytes)")
        row("Written in", None if m["seconds"] is None else f"{m['seconds']} s")
        row("SHA-256", m["sha256"])
        row("Tool", m["tool"])
        row("System.map from", m["system_map"])
        row("Note", m["note"])
    print(f"\nVolumes: {len(r['volumes'])}")
    for v in r["volumes"]:
        print(f"    {v['name'] or '-'}")
        row("Verdict", f"{v['verdict'] or '-'} [{class_name(v['class'])}]", 2)
        row("Type", v["type"], 2)
        row("Cipher", v["cipher"], 2)
        row("Key size", None if v["key_bits"] is None else f"{v['key_bits']} bits", 2)
        row("Key location", v["key_location"], 2)
        row("Route", v["route"], 2)
        row("Key SHA-256 (16)", v["key_sha256_16"], 2)
        row("Ground truth", v["ground_truth"], 2)
        row("Device", v["device"], 2)
        row("In use", v["in_use"], 2)
        row("UUID", v["uuid"], 2)
        row("Header backup", v["header_backup"], 2)
        row("Header digest", v["digest"], 2)
        row("Proof attempts", v["attempts"], 2)
        row("Adjacent places", v["adjacent_places"], 2)
        row("Note", v["note"], 2)
    if r["binaries"]:
        print("\nPrograms of the examined system used for the table route:")
        for b in r["binaries"]:
            print(f"    {b['name'] or '-'}")
            row("Path", b["path"], 2)
            row("SHA-256", b["sha256"], 2)
    print("\nVerdicts:")
    for key, name, meaning in CLASSES:
        n = sum(v["class"] == key for v in r["volumes"])
        if n or key not in ("none", "unknown"):
            row(name.capitalize(), f"{n}  ({meaning})")


def print_comparison(reports):
    names = []
    for r in reports:
        for v in r["volumes"]:
            if v["name"] not in names:
                names.append(v["name"])
    table = [["Volume"] + [r["label"] for r in reports]]
    for n in names:
        line = [n or "-"]
        for r in reports:
            v = next((x for x in r["volumes"] if x["name"] == n), None)
            if v is None:
                line.append("-")
            else:
                line.append((v["verdict"] or "-") + (f" {v['key_sha256_16']}" if v["key_sha256_16"] else ""))
        table.append(line)
    widths = [max(len(line[i]) for line in table) for i in range(len(table[0]))]
    print("Each volume across the reports:")
    for line in table:
        print("    " + "  ".join(cell.ljust(w) for cell, w in zip(line, widths)).rstrip())


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("report", nargs="+")
    ap.add_argument("--brief", action="store_true")
    a = ap.parse_args()

    reports, bad = [], 0
    for path in a.report:
        try:
            reports.append(load(path))
        except (OSError, ValueError) as e:
            print(f"keep-report.py: {text(path, 200)}: {text(e)}", file=sys.stderr)
            bad += 1
    if a.brief:
        for r in reports:
            print(f"{r['label']}: {r['tool']}, {len(r['volumes'])} volume(s), sha256 {r['file_sha256'][:16]}")
            for v in r["volumes"]:
                print(f"  {class_name(v['class']):15} {v['name']}: {v['verdict']}")
            m = r.get("memory")
            if m:
                extra = f", {m['bytes']} bytes, sha256 {(m['sha256'] or '')[:16]}" if m["bytes"] is not None else ""
                print(f"  memory image: {m['status']}{extra}")
        return 1 if bad else 0

    print(f"keep-report.py {VERSION}\n")
    for r in reports:
        print_report(r)
        print()
    if len(reports) > 1:
        print_comparison(reports)
        print()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
