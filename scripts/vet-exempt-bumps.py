#!/usr/bin/env python3
"""Exempt the crate versions a Dependabot bump brought in, so `cargo vet --locked` passes again.

Reads `cargo vet --locked --output-format json` on stdin and edits supply-chain/config.toml:
a crate with one exemption has that exemption moved to the new version, unless the exempted
version is still in Cargo.lock beside the new one (a second major version, for example), and a
crate with none (a new transitive dependency) gets one. This is the edit `cargo vet regenerate
exemptions` would make for these crates, without touching any other exemption. Anything other
than missing criteria, a violation for example, is left for a person and fails the run.
"""
import json
import re
import sys

CONFIG = "supply-chain/config.toml"

report = json.load(sys.stdin)
if report.get("conclusion") == "success":
    print("cargo vet already passes; nothing to exempt.")
    sys.exit(0)
failures = report.get("failures") or []
if report.get("conclusion") != "fail (vetting)" and not failures:
    sys.exit(f"cargo vet failed in a way this script does not handle: {report.get('conclusion')}")

text = open(CONFIG).read()
locked = set(re.findall(r'^name = "([^"]+)"\nversion = "([^"]+)"$', open("Cargo.lock").read(), re.M))


def criteria_line(criteria):
    if len(criteria) == 1:
        return f'criteria = "{criteria[0]}"'
    return "criteria = [" + ", ".join(f'"{c}"' for c in criteria) + "]"


for f in failures:
    name, version, criteria = f["name"], f["version"], f["missing_criteria"]
    block = re.compile(
        r'^\[\[exemptions\.' + re.escape(name) + r'\]\]\nversion = "[^"]+"\ncriteria = [^\n]+\n', re.M
    )
    found = block.findall(text)
    new = f'[[exemptions.{name}]]\nversion = "{version}"\n{criteria_line(criteria)}\n'
    still_locked = any((name, re.search(r'version = "([^"]+)"', b)[1]) in locked for b in found)
    if len(found) == 1 and not still_locked:
        text = block.sub(lambda _m: new, text, count=1)
        print(f"moved   {name} exemption to {version}")
    elif not found:
        names = re.findall(r'^\[\[exemptions\.([^\]]+)\]\]', text, re.M)
        after = next((n for n in names if n > name), None)
        if after is None:
            text = text.rstrip("\n") + "\n\n" + new
        else:
            anchor = f"[[exemptions.{after}]]"
            text = text.replace(anchor, new + "\n" + anchor, 1)
        print(f"added   {name} {version} exemption")
    else:
        # Several versions of one crate are exempted, or the exempted one is still locked; add this
        # one rather than guess which to move.
        text = text.replace(found[-1], found[-1] + "\n" + new, 1)
        print(f"added   {name} {version} beside its {len(found)} other exemptions")

open(CONFIG, "w").write(text)
