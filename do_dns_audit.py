#!/usr/bin/env python3
"""
do_dns_audit.py

DigitalOcean DNS audit (non-grouped): fetch every domain and every DNS record, then
summarize email-related posture per domain.

This script is intentionally "flat" and prints one domain at a time (unlike the grouped
audit script). It's great when you want:
- a full per-domain record dump you can inspect
- a simple per-domain summary printed to stdout
- a single pretty text report with everything in one place

What it checks (high-level):
- Root/apex MX records (name '@' in DigitalOcean)
  - Flags a domain as:
    - "dead"  if root MX targets are all mail.invalid (used as a dead-end)
    - "active" if it has MX records but not the dead-end pattern
    - "none" if it has no MX records
- Root/apex SPF TXT records (TXT at '@' that begin with 'v=spf1')
- DMARC TXT record at _dmarc
- DKIM-ish records (anything containing '_domainkey' in TXT/CNAME names)
- Wildcard records (any record with name starting with '*')

Optional mail allowlist:
- Provide a file of domains that SHOULD process mail.
- Then the script flags:
  - ERROR(mail expected) if allowlisted domain is "dead" or "none"
  - WARN(unexpected mail) if a non-allowlisted domain is "active"

Outputs:
- Per-domain JSON record dumps:
    /tmp/do_dns_audit_<timestamp>/<domain>.records.json   (default)
- Pretty one-file report:
    /tmp/do_dns_audit_report_<timestamp>.txt              (default)
- Optional JSON summaries if --dump-json:
    summary.json, summary.ndjson

Requirements:
  pip install requests

Auth:
  export DO_TOKEN="dop_v1_..."

Examples:
  python3 do_dns_audit.py
  python3 do_dns_audit.py --mail-domains-file mail_domains.txt
  python3 do_dns_audit.py --outdir /tmp/my_audit --report-file ./dns_audit.txt
  python3 do_dns_audit.py --dump-json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

API_BASE = "https://api.digitalocean.com/v2"


# ----------------------------
# Normalization helpers
# ----------------------------

def normalize_txt_value(s: Optional[str]) -> str:
    """
    Normalize a TXT record value for comparisons.

    DNS provider UIs sometimes show quotes and people paste them, resulting in literal quote
    characters being stored. This function strips wrapping quotes repeatedly and collapses
    whitespace so the same value compares equal across minor formatting differences.

    Example:
      '"v=spf1 -all"'  -> 'v=spf1 -all'
      'v=DMARC1;  p=reject' -> 'v=DMARC1; p=reject'
    """
    if s is None:
        return ""
    s = str(s).strip()
    while len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()
    return " ".join(s.split())


def normalize_host(s: Optional[str]) -> str:
    """
    Normalize hostnames for comparisons:
    - lowercase
    - remove trailing dot if present (FQDN notation)
    """
    s = (s or "").strip().lower()
    if s.endswith("."):
        s = s[:-1]
    return s


def parse_tag_value(semi_colon_kv: str, tag: str) -> Optional[str]:
    """
    Parse a tag=value out of a semicolon-separated string (e.g., DMARC).

    This is not a full DMARC parser; it's "good enough" for extracting common tags like:
      p=, rua=, adkim=, aspf=, sp=, pct=
    """
    m = re.search(rf"(?:^|;\s*){re.escape(tag)}\s*=\s*([^;]+)", semi_colon_kv, flags=re.IGNORECASE)
    return m.group(1).strip() if m else None


# ----------------------------
# Default output locations (avoid cluttering working dir)
# ----------------------------

def default_outdir() -> Path:
    """
    Default directory for per-domain record dumps.
    Uses /tmp so running from a repo doesn't create noisy folders/files.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("/tmp") / f"do_dns_audit_{ts}"


def default_report_path() -> Path:
    """
    Default pretty report location. Also in /tmp by default.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("/tmp") / f"do_dns_audit_report_{ts}.txt"


# ----------------------------
# DigitalOcean API client (Domains + DNS records)
# ----------------------------

class DOClient:
    """
    Minimal DigitalOcean API wrapper for listing domains and DNS records.
    """

    def __init__(self, token: str, timeout: int = 30):
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self.timeout = timeout

    def req(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a request with small retry behavior for:
        - rate limiting (429)
        - transient 5xx errors
        """
        url = f"{API_BASE}{path}"
        for attempt in range(1, 6):
            r = self.s.request(method, url, timeout=self.timeout, **kwargs)

            # Retry on rate limit or server errors
            if r.status_code == 429 or (500 <= r.status_code < 600):
                wait = min(2 ** attempt, 20)
                time.sleep(wait)
                continue

            if r.status_code >= 400:
                raise RuntimeError(f"{method} {path} failed: {r.status_code} {r.text}")

            return r.json() if r.text.strip() else {}

        raise RuntimeError(f"{method} {path} failed after retries")

    def list_domains(self) -> List[str]:
        """
        List all domains in the DigitalOcean account.
        Handles pagination.
        """
        domains: List[str] = []
        page = 1
        while True:
            data = self.req("GET", f"/domains?page={page}&per_page=200")
            chunk = data.get("domains", [])
            domains.extend([d["name"].lower() for d in chunk if "name" in d])

            pages = (data.get("links") or {}).get("pages") or {}
            if not pages.get("next"):
                break
            page += 1

        return sorted(set(domains))

    def list_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        List all DNS records for a domain zone.
        Handles pagination.
        """
        recs: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = self.req("GET", f"/domains/{domain}/records?page={page}&per_page=200")
            recs.extend(data.get("domain_records", []))

            pages = (data.get("links") or {}).get("pages") or {}
            if not pages.get("next"):
                break
            page += 1

        return recs


# ----------------------------
# Allowlist support (which domains should process mail)
# ----------------------------

def load_allowlist(path: Optional[str]) -> Optional[set]:
    """
    Load a newline-delimited list of domains. Lines starting with '#' are comments.
    """
    if not path:
        return None

    allowed = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip().lower()
            if not s or s.startswith("#"):
                continue
            allowed.add(s)
    return allowed


# ----------------------------
# Domain summarization logic
# ----------------------------

def summarize_domain(domain: str, recs: List[Dict[str, Any]], dead_mx_host: str) -> Dict[str, Any]:
    """
    Build a compact summary of email-related DNS state for a domain.

    dead_mx_host:
      Hostname used to indicate mail is intentionally disabled (e.g., 'mail.invalid').
      We normalize hosts, so 'mail.invalid.' and 'mail.invalid' compare equal.
    """
    mx = [r for r in recs if r.get("type") == "MX"]
    txt = [r for r in recs if r.get("type") == "TXT"]
    cname = [r for r in recs if r.get("type") == "CNAME"]

    # DigitalOcean uses '@' for the zone apex/root.
    mx_root = [r for r in mx if (r.get("name") in ("@", ""))]

    posture = "none"
    if mx:
        posture = "active"
        if mx_root:
            targets = [normalize_host(r.get("data") or "") for r in mx_root]
            dead = normalize_host(dead_mx_host)
            if targets and all(t == dead for t in targets):
                posture = "dead"

    # SPF TXT at apex: we only list TXT strings that start with v=spf1
    spf_txts: List[str] = []
    for r in txt:
        if r.get("name") in ("@", ""):
            val = normalize_txt_value(r.get("data") or "")
            if val.lower().startswith("v=spf1"):
                spf_txts.append(val)

    # DMARC TXT at _dmarc
    dmarc_txts: List[str] = []
    for r in txt:
        if r.get("name") == "_dmarc":
            dmarc_txts.append(normalize_txt_value(r.get("data") or ""))

    dmarc_p = None
    dmarc_rua = None
    if dmarc_txts:
        dmarc_p = parse_tag_value(dmarc_txts[0], "p")
        dmarc_rua = parse_tag_value(dmarc_txts[0], "rua")

    # DKIM-ish records: anything containing '_domainkey' in TXT or CNAME names
    dkim_like = [r for r in (txt + cname) if "_domainkey" in (r.get("name") or "")]

    # Wildcards: records that begin with '*'
    wildcards = [r for r in recs if (r.get("name") or "").startswith("*")]

    # Compact list of up to 5 root MX entries for printing
    mx_compact: List[str] = []
    for r in mx_root[:5]:
        pr = r.get("priority")
        mx_compact.append(f"{r.get('data')}({pr})")
    if len(mx_root) > 5:
        mx_compact.append(f"+{len(mx_root)-5} more")

    return {
        "domain": domain,
        "posture": posture,
        "mx_root": mx_compact,
        "mx_root_count": len(mx_root),
        "mx_total_count": len(mx),
        "spf": spf_txts[:3],
        "spf_count": len(spf_txts),
        "dmarc": dmarc_txts[:1],
        "dmarc_p": dmarc_p,
        "dmarc_rua": dmarc_rua,
        "dkim_like_count": len(dkim_like),
        "wildcard_count": len(wildcards),
    }


def status_for(domain: str, posture: str, allow_mail: Optional[set]) -> str:
    """
    Return OK/WARN/ERROR based on allowlist expectations.
    """
    if allow_mail is None:
        return "OK"
    if domain in allow_mail and posture in ("dead", "none"):
        return "ERROR(mail expected)"
    if domain not in allow_mail and posture == "active":
        return "WARN(unexpected mail)"
    return "OK"


# ----------------------------
# Report writing (human-friendly)
# ----------------------------

def write_pretty_report(path: Path, outdir: Path, summaries: List[Dict[str, Any]], allow_mail: Optional[set]) -> None:
    """
    Write a single readable TXT report summarizing every domain.

    This is meant for humans, not machines.
    """
    lines: List[str] = []
    lines.append(f"DigitalOcean DNS Audit Report - {datetime.now().isoformat()}")
    lines.append(f"Per-domain record dumps: {outdir}")
    lines.append("")

    for s in summaries:
        d = s["domain"]
        st = status_for(d, s["posture"], allow_mail)

        mx_str = ", ".join(s["mx_root"]) if s["mx_root"] else "(none)"
        spf_str = s["spf"][0] if s["spf"] else "(none)"

        dmarc_p = s["dmarc_p"] or "(none)"
        dmarc_rua = s["dmarc_rua"] or "(none)"

        lines.append(f"[{st}] {d}")
        lines.append(f"  posture: {s['posture']}")
        lines.append(f"  MX(@):   {mx_str}")
        lines.append(f"  SPF(@):  {spf_str}")
        lines.append(f"  DMARC:   p={dmarc_p} rua={dmarc_rua}")
        lines.append(f"  DKIM-ish records: {s['dkim_like_count']}")
        lines.append(f"  Wildcards: {s['wildcard_count']}")
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ----------------------------
# CLI
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Audit all DigitalOcean DNS zones for email-related records.")
    ap.add_argument("--token", default=os.getenv("DO_TOKEN"), help="DigitalOcean API token (or set DO_TOKEN)")

    # Output paths (default to /tmp to avoid clutter)
    ap.add_argument("--outdir", default="", help="Directory for per-domain JSON record dumps (default: /tmp/do_dns_audit_<ts>/)")
    ap.add_argument("--report-file", default="", help="Pretty TXT report path (default: /tmp/do_dns_audit_report_<ts>.txt)")

    # Mail expectations
    ap.add_argument("--mail-domains-file", default="", help="Allowlist of domains that SHOULD process mail (one per line)")

    # Dead-mail heuristic: what MX host indicates inbound mail is intentionally disabled?
    ap.add_argument(
        "--dead-mx-host",
        default="mail.invalid",
        help="Hostname used as dead-end MX target when mail is disabled (default: mail.invalid)"
    )

    # Optional JSON summaries
    ap.add_argument("--dump-json", "--dump_json", dest="dump_json", action="store_true",
                    help="Also write summary.json and summary.ndjson to outdir")
    ap.set_defaults(dump_json=False)

    args = ap.parse_args()

    if not args.token:
        print("Missing token. Set DO_TOKEN or pass --token.")
        sys.exit(2)

    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else default_outdir()
    outdir.mkdir(parents=True, exist_ok=True)

    report_path = Path(args.report_file).expanduser().resolve() if args.report_file else default_report_path()

    allow_mail = load_allowlist(args.mail_domains_file) if args.mail_domains_file else None

    client = DOClient(args.token)
    domains = client.list_domains()

    print(f"Found {len(domains)} domains.")
    print(f"Writing per-domain record dumps to: {outdir}\n")

    summaries: List[Dict[str, Any]] = []

    for d in domains:
        try:
            recs = client.list_records(d)
        except Exception as e:
            # Keep going so one bad zone doesn't kill the whole run
            print(f"[ERROR] {d}: {e}")
            continue

        # Always dump full records for inspection/debugging
        (outdir / f"{d}.records.json").write_text(
            json.dumps(recs, indent=2, sort_keys=True),
            encoding="utf-8"
        )

        # Build summary and print it
        s = summarize_domain(d, recs, dead_mx_host=args.dead_mx_host)
        summaries.append(s)

        st = status_for(d, s["posture"], allow_mail)

        mx_str = ", ".join(s["mx_root"]) if s["mx_root"] else "(none)"
        spf_str = s["spf"][0] if s["spf"] else "(none)"
        dmarc_p = s["dmarc_p"] or "(none)"

        print(f"[{st:18}] {d:30} posture={s['posture']:6}  MX@={mx_str}")
        print(f"                  SPF={spf_str}")
        print(f"                  DMARC p={dmarc_p}  DKIM_like={s['dkim_like_count']}  wildcards={s['wildcard_count']}")
        print()

    # Sort report by domain for readability
    summaries.sort(key=lambda x: x["domain"])

    # Write a single pretty report for humans
    write_pretty_report(report_path, outdir, summaries, allow_mail)
    print(f"Wrote pretty report: {report_path}")

    # Optional: machine-friendly summaries
    if args.dump_json:
        (outdir / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        (outdir / "summary.ndjson").write_text("\n".join(json.dumps(s) for s in summaries) + "\n", encoding="utf-8")
        print(f"Wrote summary.json and summary.ndjson to: {outdir}")

    print("Done.")


if __name__ == "__main__":
    main()
