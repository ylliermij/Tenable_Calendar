#!/usr/bin/env python3
"""
Parse a Tenable `scan_results` output (Tenable MCP tool) and sum severity
findings across the whole scan.

Handles two shapes of input file:
  1. Raw JSON like {"result": "...markdown text..."} - what gets written to
     disk when the tool output is too large to return inline.
  2. Plain markdown text - what you get if you copy/pasted an inline result
     into a file yourself.

The markdown format looks like:

    **Host Count:** 549
    ...
    ### Vulnerability Hosts (549)
    - **some.host** (ID: 123) | Score: 8705
      - Vulns: [Crit: 0 | High: 0 | Med: 80 | Low: 5]
      - Progress: 100-100/200-200
    ...
    ### Identified Vulnerabilities (182)
    - [11002] **DNS Server Detection** (Sev: 0)
      - Count: 1050 | Family: DNS
    ...

Critical/High/Medium/Low totals are summed from the per-host lines (this
matches how Tenable computes host severity scores). Informational findings
don't factor into host scores, so the Informational total is summed
separately from "Identified Vulnerabilities" entries marked (Sev: 0).

Usage:
    python3 parse_severity.py <path-to-file>
"""
import sys
import json
import re


def load_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "result" in data:
            return data["result"]
    except (json.JSONDecodeError, ValueError):
        pass
    return raw


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parse_severity.py <path-to-file>", file=sys.stderr)
        sys.exit(1)

    text = load_text(sys.argv[1])

    host_pattern = re.compile(
        r"Vulns:\s*\[Crit:\s*(\d+)\s*\|\s*High:\s*(\d+)\s*\|\s*Med:\s*(\d+)\s*\|\s*Low:\s*(\d+)\]"
    )
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    host_count = 0
    for m in host_pattern.finditer(text):
        c, h, me, l = (int(x) for x in m.groups())
        totals["critical"] += c
        totals["high"] += h
        totals["medium"] += me
        totals["low"] += l
        host_count += 1

    # Informational findings: sum "Count:" for entries marked (Sev: 0) inside
    # the "Identified Vulnerabilities" section only (avoid bleeding into other
    # sections that might mention "Sev: 0" out of context).
    section_match = re.search(
        r"Identified Vulnerabilities.*?(?=\n###|\Z)", text, re.DOTALL
    )
    section = section_match.group(0) if section_match else text
    info_pattern = re.compile(r"\(Sev:\s*0\).*?Count:\s*(\d+)", re.DOTALL)
    for m in info_pattern.finditer(section):
        totals["info"] += int(m.group(1))

    declared_host_count = None
    dh_match = re.search(r"\*\*Host Count:\*\*\s*(\d+)", text)
    if dh_match:
        declared_host_count = int(dh_match.group(1))

    print(
        json.dumps(
            {
                "totals": totals,
                "host_count": host_count,
                "declared_host_count": declared_host_count,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
