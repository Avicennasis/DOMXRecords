#!/usr/bin/env python3
"""
do_dns_audit_grouped.py

DigitalOcean DNS audit (grouped): fetch all domains and records, summarize email-related posture,
then GROUP domains that share the same settings.

Use case:
- You manage many domains with mostly identical DNS posture.
- You want to quickly see "the big herd" (e.g., 50 domains with dead-end MX + SPF -all + DMARC reject),
  plus the outliers (the few that legitimately process mail).

What it groups by (the "signature"):
- posture:    none / dead / active
- root MX:    normalized targets + priorities at the apex (@)
- SPF:        the first root SPF TXT (TXT @ starting with v=spf1), normalized
- DMARC:      a normalized *template* of the DMARC TXT (_dmarc)
             (so per-domain rua addresses can still group together)
- DKIM-ish:   count of records containing "_domainkey" (TXT/CNAME)
- wildcards:  count of records whose name starts with "*"

Optional mail allowlist:
- Provide a file listing domains that SHOULD process mail.
- Then group blocks are flagged:
  - ERROR(mail expected) if any allowlisted domain falls into posture dead/none
  - WARN(unexpected mail) if any non-allowlisted domain is in posture active

Outputs:
- By default:
  - prints grouped summary to stdout
  - writes a full "pretty" TXT report to /tmp (includes full domain lists)
- Optional:
  - --dump-json writes summary.json, summary.ndjson, groups.json to --outdir
  - --dump-records writes per-domain <domain>.records.json to --outdir

Requirements:
  pip install requests

Auth:
  export DO_TOKEN="dop_v1_..."

Examples:
  python3 do_dns_audit_grouped.py
  python3 do_dns_audit_grouped.py --show-all
  python3 do_dns_audit_grouped.py --mail-domains-file mail_domains.txt
  python3 do_dns_audit_grouped.py --dump-json --dump-records --outdir ./audit_out
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
from typing import Any, Dict, List, Optional, Tuple

import requests

API_BASE = "https://api.digitalocean.com/v2"


# ----------------------------
# Normalization helpers
# ----------------------------

def normalize_txt_value(s: Optional[str]) -> str:
    """
    Normalize TXT data for comparison:
    - trim whitespace
    - strip wrapping quotes repeatedly (DNS UI copy/paste issue)
    - collapse internal whitespace

    This helps treat these as equivalent:
      v=spf1 -all
      "v=spf1 -all"
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
    - strip trailing dot
    """
    s = (s or "").strip().lower()
    if s.endswith("."):
        s = s[:-1]
    return s


def parse_tag_value(semi_colon_kv: str, tag: str) -> Optional[str]:
    """
    Parse a tag=value from a semicolon-separated policy string, like DMARC.
    """
    m = re.search(rf"(?:^|;\s*){re.escape(tag)}\s*=\s*([^;]+)", semi_colon_kv, flags=re.IGNORECASE)
    return m.group(1).strip() if m else None


# ----------------------------
# Defaults to keep repos clean
# ----------------------------

def default_tmp_outdir(prefix: str) -> Path:
    """
    Create a timestamped folder path in /tmp.
    Used when dumping JSON/records so the working directory isn't cluttered.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("/tmp") / f"{prefix}_{ts}"


def default_report_path() -> Path:
    """
    Default grouped TXT report path in /tmp.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("/tmp") / f"do_dns_audit_grouped_report_{ts}.txt"


# ----------------------------
# DigitalOcean API client
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
        List all domains in the DigitalOcean account (paginated).
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
        List all DNS records for a domain zone (paginated).
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
# Allowlist support (mail domains)
# ----------------------------

def load_allowlist(path: Optional[str]) -> Optional[set]:
    """
    Load a newline-delimited list of domains. Lines starting with '#' are ignored.
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
# DMARC normalization for grouping
# ----------------------------

def dmarc_template(domain: str, dmarc_value: str) -> str:
    """
    Normalize a DMARC record into a template so domains group together even if
    their rua local-part embeds the domain name via plus-tagging.

    Example:
      rua=mailto:DMARC+example.com@reports.tld
      rua=mailto:DMARC+example.net@reports.tld

    Both become:
      rua=mailto:DMARC+<DOMAIN>@reports.tld

    This is a best-effort normalization, not a full DMARC parser.
    """
    v = normalize_txt_value(dmarc_value)
    d = domain.lower()

    # Replace "+<domain>@" occurrences with "+<DOMAIN>@"
    v = re.sub(rf"\+{re.escape(d)}@", "+<DOMAIN>@", v, flags=re.IGNORECASE)

    return " ".join(v.split())


# ----------------------------
# Domain summarization
# ----------------------------

def summarize_domain(domain: str, recs: List[Dict[str, Any]], dead_mx_host: str) -> Dict[str, Any]:
    """
    Build a compact summary of email-related DNS state for a domain.

    dead_mx_host:
      Hostname used to indicate mail is intentionally disabled (e.g., 'mail.invalid').
      Normalization removes trailing dots so 'mail.invalid.' and 'mail.invalid' match.
    """
    mx = [r for r in recs if r.get("type") == "MX"]
    txt = [r for r in recs if r.get("type") == "TXT"]
    cname = [r for r in recs if r.get("type") == "CNAME"]

    # Root/apex MX records (DigitalOcean uses '@' for the apex)
    mx_root = [r for r in mx if (r.get("name") in ("@", ""))]

    posture = "none"
    if mx:
        posture = "active"
        if mx_root:
            dead = normalize_host(dead_mx_host)
            targets = [normalize_host(r.get("data") or "") for r in mx_root]
            if targets and all(t == dead for t in targets):
                posture = "dead"

    # SPF TXT at apex: list those that look like SPF
    spf_txts: List[str] = []
    for r in txt:
        if r.get("name") in ("@", ""):
            val = normalize_txt_value(r.get("data") or "")
            if val.lower().startswith("v=spf1"):
                spf_txts.append(val)

    # DMARC at _dmarc: keep first; compute template for grouping
    dmarc_txts: List[str] = []
    for r in txt:
        if r.get("name") == "_dmarc":
            dmarc_txts.append(normalize_txt_value(r.get("data") or ""))

    dmarc_p = None
    dmarc_rua = None
    dmarc_tpl = None
    if dmarc_txts:
        dmarc_p = parse_tag_value(dmarc_txts[0], "p")
        dmarc_rua = parse_tag_value(dmarc_txts[0], "rua")
        dmarc_tpl = dmarc_template(domain, dmarc_txts[0])

    # DKIM-ish records: anything with _domainkey (TXT or CNAME)
    dkim_like = [r for r in (txt + cname) if "_domainkey" in (r.get("name") or "")]

    # Wildcards: records starting with "*"
    wildcards = [r for r in recs if (r.get("name") or "").startswith("*")]

    # Normalize root MX list for grouping (target + priority, sorted)
    mx_root_norm: List[Tuple[str, int]] = []
    for r in mx_root:
        mx_root_norm.append((normalize_host(r.get("data") or ""), int(r.get("priority") or 0)))
    mx_root_norm.sort()

    return {
        "domain": domain,
        "posture": posture,
        "mx_root_norm": mx_root_norm,
        "mx_root_count": len(mx_root),
        "mx_total_count": len(mx),
        "spf": spf_txts,
        "spf_count": len(spf_txts),
        "dmarc": dmarc_txts[:1],
        "dmarc_p": dmarc_p,
        "dmarc_rua": dmarc_rua,
        "dmarc_template": dmarc_tpl,
        "dkim_like_count": len(dkim_like),
        "wildcard_count": len(wildcards),
    }


# ----------------------------
# Grouping/signature logic
# ----------------------------

def signature(summary: Dict[str, Any]) -> str:
    """
    Convert a summary dict to a stable JSON string signature.
    Domains with identical signatures are grouped together.

    You can tweak this signature definition if you want "looser" or "stricter" grouping.
    """
    spf_main = summary["spf"][0] if summary.get("spf") else ""
    dmarc_tpl = summary.get("dmarc_template") or ""
    mx = tuple(summary.get("mx_root_norm") or [])

    sig_obj = {
        "posture": summary.get("posture"),
        "mx_root": mx,
        "spf": normalize_txt_value(spf_main),
        "dmarc": normalize_txt_value(dmarc_tpl),
        "dkim_like_count": int(summary.get("dkim_like_count") or 0),
        "wildcard_count": int(summary.get("wildcard_count") or 0),
    }
    return json.dumps(sig_obj, sort_keys=True)


def pretty_signature(sig_json: str) -> str:
    """
    Human-friendly signature string for printing.
    """
    obj = json.loads(sig_json)
    mx = obj.get("mx_root") or []
    mx_str = ", ".join([f"{t}({p})" for (t, p) in mx]) if mx else "(none)"
    return (
        f"posture={obj.get('posture')}  "
        f"MX@={mx_str}  "
        f"SPF={obj.get('spf') or '(none)'}  "
        f"DMARC={obj.get('dmarc') or '(none)'}  "
        f"DKIM_like={obj.get('dkim_like_count')}  "
        f"wildcards={obj.get('wildcard_count')}"
    )


def group_status(domains: List[str], sig_json: str, allow_mail: Optional[set]) -> str:
    """
    Determine OK/WARN/ERROR for a group based on allowlist expectations.
    """
    if allow_mail is None:
        return "OK"

    posture = json.loads(sig_json).get("posture")
    any_mail_expected = any(d in allow_mail for d in domains)
    any_mail_unexpected = any(d not in allow_mail for d in domains)

    if any_mail_expected and posture in ("dead", "none"):
        return "ERROR(mail expected)"
    if any_mail_unexpected and posture == "active":
        return "WARN(unexpected mail)"
    return "OK"


# ----------------------------
# Pretty report writing (full domain lists)
# ----------------------------

def write_text_report(report_path: Path, group_items: List[Tuple[str, List[str]]], allow_mail: Optional[set]) -> None:
    """
    Write a grouped report to a TXT file, including full domain lists for each group.
    """
    lines: List[str] = []
    lines.append(f"DigitalOcean DNS Grouped Audit Report - {datetime.now().isoformat()}")
    lines.append("")

    for idx, (sig, doms) in enumerate(group_items, start=1):
        doms_sorted = sorted(doms)
        status = group_status(doms_sorted, sig, allow_mail)

        lines.append(f"=== Group {idx} | {len(doms_sorted)} domains | {status} ===")
        lines.append(pretty_signature(sig))
        lines.append("Domains:")
        for d in doms_sorted:
            lines.append(f"  - {d}")
        lines.append("")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ----------------------------
# CLI
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Audit all DigitalOcean DNS zones and group domains by mail-related posture.")
    ap.add_argument("--token", default=os.getenv("DO_TOKEN"), help="DigitalOcean API token (or set DO_TOKEN)")

    # Allowlist of domains that should process mail
    ap.add_argument("--mail-domains-file", default="", help="Domains that SHOULD process mail (one per line)")

    # "Dead mail" heuristic: what MX host indicates inbound mail is disabled?
    ap.add_argument(
        "--dead-mx-host",
        default="mail.invalid",
        help="Hostname used as dead-end MX target when mail is disabled (default: mail.invalid)"
    )

    # Output controls
    ap.add_argument("--show-all", action="store_true", help="Print all domains per group to stdout (no truncation).")
    ap.add_argument("--show-domains-per-group", type=int, default=12,
                    help="How many domains to print per group (ignored with --show-all).")

    ap.add_argument("--report-file", default="",
                    help="Write grouped TXT report to this path (default: /tmp/do_dns_audit_grouped_report_<ts>.txt).")

    # JSON/record dump controls (opt-in)
    ap.add_argument("--outdir", default="",
                    help="Directory for JSON outputs (default: /tmp/do_dns_audit_grouped_<ts>/ when dumping).")
    ap.add_argument("--dump-records", action="store_true",
                    help="Write <domain>.records.json files to --outdir.")
    ap.add_argument("--dump-json", "--dump_json", dest="dump_json", action="store_true",
                    help="Write summary.json, summary.ndjson, groups.json to --outdir.")
    ap.set_defaults(dump_json=False)

    args = ap.parse_args()

    if not args.token:
        print("Missing token. Set DO_TOKEN or pass --token.")
        sys.exit(2)

    allow_mail = load_allowlist(args.mail_domains_file) if args.mail_domains_file else None

    client = DOClient(args.token)
    domains = client.list_domains()
    print(f"Found {len(domains)} domains.\n")

    # Decide whether we need an output directory for dumps
    need_outdir = args.dump_json or args.dump_records
    outdir: Optional[Path] = None
    if need_outdir:
        outdir = Path(args.outdir).expanduser().resolve() if args.outdir else default_tmp_outdir("do_dns_audit_grouped")
        outdir.mkdir(parents=True, exist_ok=True)

    # Summaries in memory; groups are signature -> list(domains)
    summaries: List[Dict[str, Any]] = []
    groups: Dict[str, List[str]] = {}

    # Fetch records and build summaries
    for d in domains:
        try:
            recs = client.list_records(d)
        except Exception as e:
            # Keep going; one bad zone shouldn't stop the run
            print(f"[ERROR] Failed to fetch records for {d}: {e}")
            continue

        # Optional: write raw record dumps per domain
        if args.dump_records and outdir is not None:
            (outdir / f"{d}.records.json").write_text(json.dumps(recs, indent=2, sort_keys=True), encoding="utf-8")

        s = summarize_domain(d, recs, dead_mx_host=args.dead_mx_host)
        summaries.append(s)

        sig = signature(s)
        groups.setdefault(sig, []).append(d)

    # Sort groups by size (largest first)
    group_items: List[Tuple[str, List[str]]] = sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)

    # Print grouped report to stdout
    for idx, (sig, doms) in enumerate(group_items, start=1):
        doms_sorted = sorted(doms)
        status = group_status(doms_sorted, sig, allow_mail)

        print(f"=== Group {idx} | {len(doms_sorted)} domains | {status} ===")
        print(pretty_signature(sig))

        if args.show_all:
            print("Domains:", ", ".join(doms_sorted))
        else:
            show_n = max(0, int(args.show_domains_per_group))
            preview = doms_sorted[:show_n]
            tail = len(doms_sorted) - len(preview)

            if preview:
                print("Domains:", ", ".join(preview))
            if tail > 0:
                print(f"... +{tail} more")
        print()

    # Always write a human-friendly report file (defaults to /tmp)
    report_path = Path(args.report_file).expanduser().resolve() if args.report_file else default_report_path()
    write_text_report(report_path, group_items, allow_mail)
    print(f"Wrote text report: {report_path}")

    # Optional: write machine-readable JSON summaries/groups
    if args.dump_json and outdir is not None:
        (outdir / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        (outdir / "summary.ndjson").write_text("\n".join(json.dumps(s) for s in summaries) + "\n", encoding="utf-8")
        (outdir / "groups.json").write_text(json.dumps(groups, indent=2, sort_keys=True), encoding="utf-8")
        print(f"Wrote JSON outputs to: {outdir}")

    print("Done.")


if __name__ == "__main__":
    main()
