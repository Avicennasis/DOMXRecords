#!/usr/bin/env python3
"""
lockdown_mail.py

Bulk "no-mail" hardening for domains hosted on DigitalOcean DNS.

Use case:
- You own many domains that should NEVER send or receive email.
- You want to:
  1) Remove DKIM records (anything under *_domainkey)
  2) Enforce DMARC reject with strict alignment
  3) Enforce SPF "-all" (authorize nobody)
  4) Replace MX with a dead-end target (mail.invalid.)
  5) Optionally remove wildcard DNS records ("*")
  6) Optionally authorize a third-party DMARC report destination domain:
     Publish: <domain>._report._dmarc.<DMARCReportDomain> TXT "v=DMARC1"
     This helps some receivers send aggregate DMARC reports (rua) to another domain.

Notes:
- DigitalOcean's DNS API expects MX "data" to be a FQDN ending with a trailing dot.
  So we write "mail.invalid." not "mail.invalid".
- DNS UIs sometimes store literal quotes inside TXT values. This script normalizes
  (strips wrapping quotes/whitespace) for comparisons, but writes clean unquoted values.
- By design, SPF handling is careful: it only touches root TXT records that start with "v=spf1"
  so it won't clobber unrelated verification TXT records at the zone apex.

Requirements:
  pip install requests

Auth:
  Export a DigitalOcean personal access token:
    export DO_TOKEN="dop_v1_..."

Example:
  python3 lockdown_mail.py --domains-file domains.txt --dry-run
  python3 lockdown_mail.py --domains-file domains.txt --delete-wildcards
  python3 lockdown_mail.py --domains-file domains.txt \
      --dmarc-report-domain example-report-domain.tld \
      --dmarc-localpart-prefix DMARC \
      --report-auth-zone example-report-domain.tld
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional

import requests

API_BASE = "https://api.digitalocean.com/v2"


# ----------------------------
# Helpers: normalization
# ----------------------------

def normalize_txt_value(s: Optional[str]) -> str:
    """
    Normalize TXT data for comparisons:
    - trim whitespace
    - strip wrapping single/double quotes repeatedly
    - collapse internal whitespace
    """
    if s is None:
        return ""
    s = str(s).strip()
    while len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()
    return " ".join(s.split())


def ensure_fqdn_dot(host: str) -> str:
    """
    Ensure a hostname is a FQDN ending with a trailing dot, as required by DO DNS API for MX targets.
    """
    host = (host or "").strip()
    if host and host != "." and not host.endswith("."):
        host += "."
    return host


def read_domains_file(path: str) -> List[str]:
    """
    Read domains from a text file (one per line). Lines beginning with '#' are ignored.
    """
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s.lower())
    return out


# ----------------------------
# DigitalOcean API client
# ----------------------------

class DOClient:
    """
    Small DigitalOcean API wrapper for Domains + DNS records.
    """

    def __init__(self, token: str, dry_run: bool = False, timeout: int = 30):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self.dry_run = dry_run
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """
        Make an API request with basic retries for rate limiting / transient errors.
        """
        url = f"{API_BASE}{path}"

        # In dry-run, never mutate DNS; just print what would happen.
        if self.dry_run and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            payload = kwargs.get("json")
            print(f"[DRY-RUN] {method} {url}" + (f" {payload}" if payload else ""))
            return {}

        for attempt in range(1, 6):
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)

            # Retry on rate limit or server errors.
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                wait = min(2 ** attempt, 30)
                print(f"Retry {attempt}/5: {method} {path} -> {resp.status_code}; sleeping {wait}s")
                time.sleep(wait)
                continue

            if resp.status_code >= 400:
                raise RuntimeError(f"{method} {path} failed: {resp.status_code} {resp.text}")

            if resp.text.strip():
                return resp.json()
            return {}

        raise RuntimeError(f"{method} {path} failed after retries")

    def list_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        List all DNS records in a domain zone. Handles pagination.
        """
        records: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = self._request("GET", f"/domains/{domain}/records?page={page}&per_page=200")
            records.extend(data.get("domain_records", []))

            pages = (data.get("links") or {}).get("pages") or {}
            if not pages.get("next"):
                break
            page += 1
        return records

    def delete_record(self, domain: str, record_id: int) -> None:
        self._request("DELETE", f"/domains/{domain}/records/{record_id}")

    def create_record(self, domain: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", f"/domains/{domain}/records", json=payload)

    def update_record(self, domain: str, record_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("PUT", f"/domains/{domain}/records/{record_id}", json=payload)


# ----------------------------
# DNS operations
# ----------------------------

def delete_matching_records(client: DOClient, zone: str, predicate, label: str) -> int:
    """
    Delete all records in `zone` matching predicate(record) -> bool.
    """
    records = client.list_records(zone)
    to_delete = [r for r in records if predicate(r)]
    for r in to_delete:
        client.delete_record(zone, r["id"])
    if to_delete:
        print(f"  - Deleted {len(to_delete)} {label}")
    else:
        print(f"  = No {label} found")
    return len(to_delete)


def upsert_single_txt(
    client: DOClient,
    zone: str,
    name: str,
    value: str,
    match_prefix: Optional[str] = None,
) -> None:
    """
    Ensure exactly one TXT record exists at (name) that matches `value`.

    - If match_prefix is provided, only consider TXT records whose normalized data startswith match_prefix.
      This is used for SPF so we don't touch unrelated root TXT verification records.
    - Normalizes existing TXT values for comparison (strips quotes, collapses whitespace).
    - Writes the desired value exactly as provided (clean, unquoted).
    """
    desired_norm = normalize_txt_value(value)
    prefix_norm = normalize_txt_value(match_prefix) if match_prefix else None

    records = client.list_records(zone)
    candidates: List[Dict[str, Any]] = []
    for r in records:
        if r.get("type") != "TXT":
            continue
        if r.get("name") != name:
            continue
        data_norm = normalize_txt_value(r.get("data") or "")
        if prefix_norm and not data_norm.lower().startswith(prefix_norm.lower()):
            continue
        candidates.append(r)

    if not candidates:
        client.create_record(zone, {"type": "TXT", "name": name, "data": value})
        print(f"  + TXT {name} = {value}")
        return

    # Keep the first candidate; delete any extras (even if they only differ by quotes/spaces).
    keep = candidates[0]
    keep_norm = normalize_txt_value(keep.get("data") or "")

    if keep_norm != desired_norm:
        client.update_record(zone, keep["id"], {"type": "TXT", "name": name, "data": value})
        print(f"  ~ TXT {name} updated")
    else:
        print(f"  = TXT {name} already correct")

    for extra in candidates[1:]:
        client.delete_record(zone, extra["id"])
        print(f"  - TXT {name} duplicate removed (id={extra['id']})")


def ensure_deadend_mx(client: DOClient, zone: str, mx_target: str, priority: int = 0) -> None:
    """
    Delete all MX records and create a single apex MX pointing at `mx_target`.
    """
    delete_matching_records(client, zone, lambda r: r.get("type") == "MX", "MX records")

    mx_target = ensure_fqdn_dot(mx_target)
    client.create_record(zone, {"type": "MX", "name": "@", "data": mx_target, "priority": priority})
    print(f"  + MX @ -> {mx_target} (priority {priority})")


# ----------------------------
# Domain lockdown routine
# ----------------------------

def lockdown_domain(
    client: DOClient,
    domain: str,
    dmarc_report_domain: str,
    dmarc_localpart_prefix: str,
    delete_wildcards: bool,
    add_report_auth_zone: Optional[str],
    deadend_mx_target: str,
    continue_on_error: bool,
) -> None:
    """
    Apply "no-mail" hardening to a single domain zone.
    """
    print(f"\n== {domain} ==")

    try:
        # 1) Delete DKIM records: anything under *_domainkey (TXT or CNAME)
        delete_matching_records(
            client,
            domain,
            lambda r: (r.get("type") in ("TXT", "CNAME")) and ("_domainkey" in (r.get("name") or "")),
            "DKIM (_domainkey) records"
        )

        # Optional: remove wildcard records like *.domain (DO usually stores wildcard label as "*")
        if delete_wildcards:
            delete_matching_records(
                client,
                domain,
                lambda r: (r.get("name") or "").startswith("*"),
                "wildcard records (name startswith '*')"
            )

        # 2) DMARC: reject + strict alignment + aggregate report destination.
        # rua local-part uses plus-tagging: <prefix>+<domain>@<dmarc_report_domain>
        rua = f"mailto:{dmarc_localpart_prefix}+{domain}@{dmarc_report_domain}"
        dmarc_value = f"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua={rua}"
        upsert_single_txt(client, domain, "_dmarc", dmarc_value)

        # 3) SPF: authorize nobody (and remove duplicate SPF TXT records at apex)
        upsert_single_txt(client, domain, "@", "v=spf1 -all", match_prefix="v=spf1")

        # 4) MX: delete and replace with a dead-end target (default: mail.invalid.)
        ensure_deadend_mx(client, domain, mx_target=deadend_mx_target, priority=0)

        # 5) Optional: authorize third-party report destination in that destination zone.
        # This publishes:
        #   <domain>._report._dmarc.<add_report_auth_zone> TXT "v=DMARC1"
        # so some receivers will send aggregate reports there.
        if add_report_auth_zone:
            auth_name = f"{domain}._report._dmarc"
            upsert_single_txt(client, add_report_auth_zone, auth_name, "v=DMARC1")
            print(f"  + Report auth TXT in {add_report_auth_zone}: {auth_name} = v=DMARC1")

    except Exception as e:
        print(f"[ERROR] {domain}: {e}")
        if not continue_on_error:
            raise


# ----------------------------
# CLI
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Lock down domains in DigitalOcean DNS to send/receive no email.")
    ap.add_argument("--domains-file", required=True, help="Text file of domains, one per line")
    ap.add_argument("--token", default=os.getenv("DO_TOKEN"), help="DigitalOcean API token (or set DO_TOKEN)")
    ap.add_argument("--dry-run", action="store_true", help="Print changes without modifying DNS")

    # DMARC aggregate report destination domain (no hard-coded personal domain)
    ap.add_argument(
        "--dmarc-report-domain",
        default="example-report-domain.tld",
        help="Domain that receives DMARC aggregate reports (rua mailto:...)"
    )
    ap.add_argument(
        "--dmarc-localpart-prefix",
        default="DMARC",
        help="Local-part prefix for plus-tagged DMARC mailbox (e.g. DMARC+<domain>@<dmarc-report-domain>)"
    )

    # Optional: add authorization record into the DMARC report destination domain's DNS zone
    ap.add_argument(
        "--report-auth-zone",
        default="",
        help='If set, also upsert TXT "<domain>._report._dmarc" = "v=DMARC1" into this zone'
    )

    # Dead-end MX target for disabling inbound mail
    ap.add_argument(
        "--deadend-mx-target",
        default="mail.invalid.",
        help="MX target used to blackhole inbound mail (will be forced to FQDN with trailing dot)"
    )

    ap.add_argument("--delete-wildcards", action="store_true", help="Delete wildcard records (name starts with '*')")
    ap.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue processing remaining domains if one fails"
    )

    args = ap.parse_args()

    if not args.token:
        print("Error: Provide --token or set DO_TOKEN environment variable.")
        sys.exit(2)

    domains = read_domains_file(args.domains_file)
    if not domains:
        print("No domains found in domains file.")
        return

    report_auth_zone = args.report_auth_zone.strip() or None

    client = DOClient(args.token, dry_run=args.dry_run)

    for d in domains:
        lockdown_domain(
            client=client,
            domain=d,
            dmarc_report_domain=args.dmarc_report_domain,
            dmarc_localpart_prefix=args.dmarc_localpart_prefix,
            delete_wildcards=args.delete_wildcards,
            add_report_auth_zone=report_auth_zone,
            deadend_mx_target=args.deadend_mx_target,
            continue_on_error=args.continue_on_error,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
