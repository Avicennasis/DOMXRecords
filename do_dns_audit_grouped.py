#!/usr/bin/env python3
"""
================================================================================
do_dns_audit_grouped.py - DigitalOcean DNS Email Posture Audit Tool (Grouped)
================================================================================

OVERVIEW:
---------
This script performs a comprehensive audit of all DNS zones (domains) managed
in your DigitalOcean account, focusing on email-related DNS records. Unlike
do_dns_audit.py which lists domains one-by-one, this script GROUPS domains
that share identical email security configurations.

This grouping approach is ideal when you manage many domains with mostly
identical DNS posture and want to quickly identify:
  - "The big herd": e.g., 50 domains with dead-end MX + SPF -all + DMARC reject
  - "The outliers": The few domains that legitimately process mail, or
    domains with misconfigured/unexpected settings

PURPOSE:
--------
Email spoofing is a significant security concern. When managing dozens or
hundreds of domains, it's impractical to review each one individually. This
tool clusters domains by their email "signature" so you can verify that:
  1. Most domains have your standard "no-mail" configuration
  2. Mail-processing domains are correctly identified
  3. Outliers are investigated and addressed

WHAT THIS SCRIPT GROUPS BY (THE "SIGNATURE"):
---------------------------------------------
Each domain is assigned a signature based on these normalized attributes:

1. POSTURE: none / dead / active
   - "none"   = No MX records exist
   - "dead"   = All root MX targets point to dead-end host (e.g., mail.invalid)
   - "active" = MX records exist but don't match dead-end pattern

2. ROOT MX: Normalized targets + priorities at the apex (@)
   - Sorted for consistent comparison

3. SPF: The first root SPF TXT record (starting with v=spf1), normalized
   - Whitespace collapsed, quotes stripped

4. DMARC: A normalized *template* of the DMARC TXT record at _dmarc
   - Per-domain rua addresses are templated so domains can group together
     even if their rua uses plus-tagging like DMARC+<domain>@reports.tld

5. DKIM-ISH: Count of records containing "_domainkey" in TXT/CNAME names
   - For comparison purposes, we just count them (0, 1, 2, etc.)

6. WILDCARDS: Count of records whose name starts with "*"
   - Flagged for review as wildcards can have security implications

GROUPING LOGIC:
---------------
Domains with identical signatures are grouped together. This means:
  - Two domains with the same MX, SPF, DMARC template, DKIM count, and
    wildcard count will appear in the same group
  - Even small differences (like one extra DKIM record) create separate groups
  - This precision helps identify exactly which domains differ and how

DMARC TEMPLATE NORMALIZATION:
-----------------------------
DMARC records often embed the domain name in the rua (aggregate report) address
using plus-tagging:
  rua=mailto:DMARC+example.com@reports.tld
  rua=mailto:DMARC+example.net@reports.tld

Without normalization, these would create separate groups. This script replaces
the domain name with a placeholder (<DOMAIN>) so they group together:
  rua=mailto:DMARC+<DOMAIN>@reports.tld

OPTIONAL MAIL ALLOWLIST:
------------------------
You can provide a file listing domains that SHOULD legitimately process mail.
With an allowlist, groups are flagged with status indicators:
  - ERROR(mail expected): Group contains allowlisted domain with dead/none posture
  - WARN(unexpected mail): Group contains non-allowlisted domain with active posture

This helps catch both:
  - Mail domains that were accidentally broken
  - Non-mail domains that unexpectedly have active mail configuration

OUTPUT:
-------
1. STDOUT (always):
   - Grouped summary with configurable domain list truncation
   - Shows signature details (MX, SPF, DMARC, counts) for each group
   - Groups are sorted by size (largest first)

2. TEXT REPORT (always):
   - Location: /tmp/do_dns_audit_grouped_report_<timestamp>.txt
   - Contains full domain lists for each group (no truncation)
   - Human-readable format for review and sharing

3. JSON OUTPUTS (optional, with --dump-json):
   - summary.json: Array of all domain summaries
   - summary.ndjson: Newline-delimited JSON (one summary per line)
   - groups.json: Mapping of signature -> list of domains

4. PER-DOMAIN RECORDS (optional, with --dump-records):
   - <domain>.records.json: Raw DNS records for each domain

AUTHENTICATION:
---------------
The script requires a DigitalOcean API token with read access to domains and
DNS records. Authentication is checked in this order:

1. .env file in the current directory (DO_TOKEN=your_token_here)
2. Environment variable: export DO_TOKEN="dop_v1_..."
3. Command-line argument: --token "dop_v1_..."

SECURITY NOTE: Store your token securely. Use the .env file approach and ensure
the file has restrictive permissions (chmod 600 .env).

REQUIREMENTS:
-------------
  pip install requests

EXAMPLES:
---------
  # Basic grouped audit
  python3 do_dns_audit_grouped.py

  # Show all domains per group (no truncation in stdout)
  python3 do_dns_audit_grouped.py --show-all

  # Audit with mail domain allowlist
  python3 do_dns_audit_grouped.py --mail-domains-file mail_domains.txt

  # Dump JSON summaries and per-domain records
  python3 do_dns_audit_grouped.py --dump-json --dump-records --outdir ./audit_out

AUTHOR:
-------
  Léon "Avic" Simmons (@Avicennasis)
================================================================================
"""

# =============================================================================
# IMPORTS
# =============================================================================
# __future__ import ensures consistent behavior across Python versions
# for type hint annotations
from __future__ import annotations

# Standard library imports for core functionality
import argparse      # Command-line argument parsing
import json          # JSON serialization for output files and signature creation
import os            # Environment variable access and file operations
import re            # Regular expressions for parsing DNS record values
import sys           # System exit codes
import time          # Sleep/retry timing for API rate limiting
from datetime import datetime  # Timestamps for output file naming
from pathlib import Path       # Modern, cross-platform file path handling
from typing import Any, Dict, List, Optional, Tuple  # Type hints for clarity

# Third-party HTTP library for API communication
import requests

# =============================================================================
# CONSTANTS
# =============================================================================

# Base URL for all DigitalOcean API v2 endpoints
# All API requests are constructed by appending paths to this base URL
API_BASE = "https://api.digitalocean.com/v2"


# =============================================================================
# ENVIRONMENT / CONFIGURATION LOADING
# =============================================================================

def load_env_file(env_path: str = ".env") -> Dict[str, str]:
    """
    Load environment variables from a .env file.

    This function provides a simple, dependency-free way to load configuration
    from a .env file without requiring the python-dotenv package. It's designed
    to be a drop-in solution for small scripts that need basic .env support.

    The .env file format supported:
      - KEY=value           (basic assignment)
      - KEY="quoted value"  (quoted values, quotes are stripped)
      - KEY='quoted value'  (single quotes also supported)
      - # comment           (lines starting with # are ignored)
      - Empty lines         (ignored)
      - KEY=                (empty value is valid)

    Parameters:
    -----------
    env_path : str
        Path to the .env file. Defaults to ".env" in the current directory.

    Returns:
    --------
    Dict[str, str]
        Dictionary mapping environment variable names to their values.
        Returns an empty dictionary if the file doesn't exist.

    Notes:
    ------
    - This function does NOT automatically set os.environ; it just returns
      the parsed values. The caller decides what to do with them.
    - Values are stripped of surrounding whitespace and quotes.
    - This is intentionally simple and doesn't handle all edge cases that
      python-dotenv does (like multi-line values or escape sequences).
    """
    env_vars = {}

    # Check if the .env file exists before attempting to read
    if not os.path.isfile(env_path):
        return env_vars

    # Read and parse the .env file line by line
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            # Strip whitespace from both ends of the line
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Split on the first '=' only (values can contain '=')
            if "=" in line:
                key, value = line.split("=", 1)

                # Clean up the key (remove whitespace)
                key = key.strip()

                # Clean up the value (remove whitespace and surrounding quotes)
                value = value.strip()

                # Remove surrounding quotes if present (both single and double)
                if len(value) >= 2:
                    if (value[0] == value[-1]) and value[0] in ('"', "'"):
                        value = value[1:-1]

                env_vars[key] = value

    return env_vars


def get_token(args_token: Optional[str]) -> Optional[str]:
    """
    Retrieve the DigitalOcean API token from available sources.

    This function implements a priority-based token retrieval system that
    checks multiple sources in order, allowing flexible configuration:

    Priority Order:
    1. .env file (DO_TOKEN=...)     - Most secure for local development
    2. Environment variable         - Standard for CI/CD and containers
    3. Command-line argument        - Convenient for one-off runs

    Parameters:
    -----------
    args_token : Optional[str]
        Token value from command-line arguments (--token flag).
        May be None if not provided on command line.

    Returns:
    --------
    Optional[str]
        The API token if found in any source, None otherwise.

    Security Considerations:
    ------------------------
    - .env file: Should have restrictive permissions (chmod 600)
    - Environment variable: Visible in process listings, less secure
    - Command-line: Visible in shell history, least secure

    The .env file approach is recommended for local development because:
    - Not visible in shell history
    - Not visible in process listings
    - Can be excluded from version control via .gitignore
    """
    # Priority 1: Check .env file first (most secure option)
    env_vars = load_env_file()
    if "DO_TOKEN" in env_vars and env_vars["DO_TOKEN"]:
        return env_vars["DO_TOKEN"]

    # Priority 2: Check shell environment variable
    env_token = os.getenv("DO_TOKEN")
    if env_token:
        return env_token

    # Priority 3: Use command-line argument as fallback
    if args_token:
        return args_token

    # No token found in any source
    return None


# =============================================================================
# NORMALIZATION HELPER FUNCTIONS
# =============================================================================
# These functions handle the messy reality of DNS data: inconsistent formatting,
# quoted values from copy-paste, trailing dots on hostnames, etc.

def normalize_txt_value(s: Optional[str]) -> str:
    """
    Normalize a TXT record value for reliable comparisons.

    Problem:
    --------
    DNS provider UIs and tools often display TXT records with surrounding
    quotes, and users frequently copy-paste these quoted values back into
    DNS management interfaces. This results in literal quote characters
    being stored as part of the record value. Additionally, whitespace
    handling varies between providers.

    For example, these should all be treated as equivalent:
      - v=spf1 -all
      - "v=spf1 -all"
      - 'v=spf1 -all'
      - "v=spf1  -all"  (extra internal space)

    Solution:
    ---------
    This function:
    1. Handles None input gracefully
    2. Strips leading/trailing whitespace
    3. Removes wrapping quote characters (repeatedly, to handle nested quotes)
    4. Collapses multiple internal whitespace to single spaces

    Parameters:
    -----------
    s : Optional[str]
        The raw TXT record value from the DNS API. May be None.

    Returns:
    --------
    str
        Normalized string suitable for comparison. Returns empty string for None.

    Examples:
    ---------
    >>> normalize_txt_value('"v=spf1 -all"')
    'v=spf1 -all'

    >>> normalize_txt_value("v=DMARC1;  p=reject")
    'v=DMARC1; p=reject'

    >>> normalize_txt_value(None)
    ''
    """
    # Handle None input - common when accessing optional dict keys
    if s is None:
        return ""

    # Convert to string and strip outer whitespace
    s = str(s).strip()

    # Repeatedly strip matching quote pairs from both ends
    # This handles cases like: '"value"' or ""value"" (yes, people do this)
    while len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()

    # Collapse all runs of whitespace to single spaces
    # This normalizes "v=spf1   -all" to "v=spf1 -all"
    return " ".join(s.split())


def normalize_host(s: Optional[str]) -> str:
    """
    Normalize hostnames for reliable comparisons.

    Problem:
    --------
    Hostnames in DNS can appear in different formats:
      - Fully Qualified Domain Name (FQDN): mail.example.com.
      - Non-FQDN: mail.example.com
      - Mixed case: Mail.Example.COM

    For comparison purposes, we need a canonical form.

    Solution:
    ---------
    This function:
    1. Handles None input gracefully
    2. Strips whitespace
    3. Converts to lowercase (DNS is case-insensitive)
    4. Removes trailing dot (FQDN notation)

    Parameters:
    -----------
    s : Optional[str]
        The hostname string, possibly in FQDN format. May be None.

    Returns:
    --------
    str
        Normalized lowercase hostname without trailing dot.

    Examples:
    ---------
    >>> normalize_host("mail.invalid.")
    'mail.invalid'

    >>> normalize_host("MAIL.INVALID")
    'mail.invalid'

    >>> normalize_host(None)
    ''
    """
    # Handle None and convert to lowercase
    s = (s or "").strip().lower()

    # Remove trailing dot if present (FQDN notation)
    if s.endswith("."):
        s = s[:-1]

    return s


def parse_tag_value(semi_colon_kv: str, tag: str) -> Optional[str]:
    """
    Parse a tag=value pair from a semicolon-separated policy string.

    Problem:
    --------
    DMARC and other DNS-based policy records use a semicolon-separated
    tag=value format. For example:

      v=DMARC1; p=reject; sp=reject; rua=mailto:reports@example.com

    We need to extract specific tag values (like the 'p' policy or 'rua'
    report address) for analysis.

    Solution:
    ---------
    Uses a regex to find the specified tag anywhere in the string,
    accounting for:
    - Tag at the start of the string
    - Tag after a semicolon (with optional whitespace)
    - Case-insensitive matching
    - Values that may contain various characters (up to the next semicolon)

    Parameters:
    -----------
    semi_colon_kv : str
        The full policy string (e.g., DMARC record value)

    tag : str
        The tag name to search for (e.g., "p", "rua", "adkim")

    Returns:
    --------
    Optional[str]
        The tag's value if found, None otherwise.

    Notes:
    ------
    This is not a full DMARC/SPF parser. It's a "good enough" extractor
    for common tags. Edge cases (like malformed records) may not parse
    correctly, but that's acceptable for audit purposes.

    Examples:
    ---------
    >>> parse_tag_value("v=DMARC1; p=reject; rua=mailto:x@y.com", "p")
    'reject'

    >>> parse_tag_value("v=DMARC1; p=reject", "rua")
    None
    """
    # Build regex pattern:
    # - (?:^|;\s*) matches either start of string OR semicolon with optional whitespace
    # - {tag}\s*=\s* matches the tag name with optional whitespace around '='
    # - ([^;]+) captures the value (everything up to the next semicolon)
    m = re.search(
        rf"(?:^|;\s*){re.escape(tag)}\s*=\s*([^;]+)",
        semi_colon_kv,
        flags=re.IGNORECASE
    )

    # Return the captured group (trimmed) if found, None otherwise
    return m.group(1).strip() if m else None


# =============================================================================
# DEFAULT OUTPUT LOCATION HELPERS
# =============================================================================
# These functions generate default paths in /tmp to avoid cluttering the
# working directory with output files. Users can override via CLI arguments.

def default_tmp_outdir(prefix: str) -> Path:
    """
    Generate a timestamped output directory path in /tmp.

    Rationale:
    ----------
    When running from a git repository or project directory, we don't want
    to create noisy folders that might accidentally get committed or clutter
    the workspace. Using /tmp is ideal because:
    - It's a standard temporary location on Unix-like systems
    - Files are typically cleaned up on reboot
    - It keeps the working directory clean

    Parameters:
    -----------
    prefix : str
        Prefix for the directory name (e.g., "do_dns_audit_grouped")

    Returns:
    --------
    Path
        A Path object pointing to the timestamped directory.
        Format: /tmp/{prefix}_YYYYMMDD_HHMMSS/

    Notes:
    ------
    - This function does NOT create the directory; that's done later.
    - The timestamp ensures multiple runs don't overwrite each other.
    """
    # Generate timestamp in a filename-safe format
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Construct and return the path
    return Path("/tmp") / f"{prefix}_{ts}"


def default_report_path() -> Path:
    """
    Generate the default path for the grouped audit report.

    Rationale:
    ----------
    Similar to default_tmp_outdir(), this places the report in /tmp to avoid
    cluttering the working directory. The report is a single consolidated
    text file containing all groups with their domain lists.

    Returns:
    --------
    Path
        A Path object pointing to the timestamped report file.
        Format: /tmp/do_dns_audit_grouped_report_YYYYMMDD_HHMMSS.txt
    """
    # Generate timestamp matching the outdir format for consistency
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Construct and return the path
    return Path("/tmp") / f"do_dns_audit_grouped_report_{ts}.txt"


# =============================================================================
# DIGITALOCEAN API CLIENT CLASS
# =============================================================================

class DOClient:
    """
    A minimal DigitalOcean API wrapper for DNS operations.

    Purpose:
    --------
    This class encapsulates all communication with the DigitalOcean API,
    providing a clean interface for listing domains and their DNS records.
    It handles common concerns like:
    - Authentication (Bearer token)
    - Rate limiting (HTTP 429 responses)
    - Transient errors (5xx responses)
    - Pagination (domains and records)

    Design Decisions:
    -----------------
    1. Uses requests.Session for connection reuse (performance)
    2. Implements automatic retry with exponential backoff
    3. Handles pagination transparently (caller gets complete lists)
    4. Raises RuntimeError on unrecoverable failures (clean error handling)

    Attributes:
    -----------
    s : requests.Session
        Persistent HTTP session with authentication headers configured.

    timeout : int
        Request timeout in seconds. Prevents hanging on network issues.

    Usage:
    ------
        client = DOClient("dop_v1_your_token_here")
        domains = client.list_domains()
        for domain in domains:
            records = client.list_records(domain)
    """

    def __init__(self, token: str, timeout: int = 30):
        """
        Initialize the DigitalOcean API client.

        Parameters:
        -----------
        token : str
            DigitalOcean personal access token (starts with "dop_v1_").
            Must have read permissions for Domains.

        timeout : int
            HTTP request timeout in seconds. Default 30s is reasonable for
            API calls but can be increased for slow networks.
        """
        # Create a persistent session for connection reuse
        # This improves performance by reusing TCP connections
        self.s = requests.Session()

        # Configure default headers for all requests
        self.s.headers.update({
            "Authorization": f"Bearer {token}",  # Bearer auth per DO API spec
            "Content-Type": "application/json",   # All responses are JSON
        })

        # Store timeout for use in requests
        self.timeout = timeout

    def req(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """
        Perform an HTTP request to the DigitalOcean API with retry logic.

        This method handles the low-level API communication, including:
        - URL construction from path
        - Automatic retry on transient failures
        - Error handling and propagation

        Parameters:
        -----------
        method : str
            HTTP method (GET, POST, PUT, DELETE, etc.)

        path : str
            API endpoint path (e.g., "/domains" or "/domains/example.com/records")
            Will be appended to API_BASE.

        **kwargs : dict
            Additional arguments passed to requests (json=, params=, etc.)

        Returns:
        --------
        Dict[str, Any]
            Parsed JSON response. Returns empty dict for empty responses.

        Raises:
        -------
        RuntimeError
            On HTTP 4xx errors (except 429) or after max retries exhausted.

        Retry Logic:
        ------------
        - Retries on HTTP 429 (rate limit) and 5xx (server errors)
        - Uses exponential backoff: 2, 4, 8, 16, 20 seconds (capped at 20)
        - Maximum 5 attempts before giving up
        """
        # Construct full URL from base and path
        url = f"{API_BASE}{path}"

        # Retry loop with exponential backoff
        for attempt in range(1, 6):  # Attempts 1 through 5
            # Make the HTTP request
            r = self.s.request(method, url, timeout=self.timeout, **kwargs)

            # Check for retryable conditions
            if r.status_code == 429 or (500 <= r.status_code < 600):
                # Calculate wait time with exponential backoff, capped at 20 seconds
                wait = min(2 ** attempt, 20)
                time.sleep(wait)
                continue  # Retry the request

            # Check for non-retryable errors
            if r.status_code >= 400:
                # Raise an exception with details for debugging
                raise RuntimeError(f"{method} {path} failed: {r.status_code} {r.text}")

            # Success! Parse and return the JSON response
            # Handle empty responses (some DELETE endpoints return nothing)
            return r.json() if r.text.strip() else {}

        # All retry attempts exhausted
        raise RuntimeError(f"{method} {path} failed after retries")

    def list_domains(self) -> List[str]:
        """
        Retrieve all domains managed in the DigitalOcean account.

        This method fetches domain names from the Domains API, handling
        pagination automatically. DigitalOcean returns domains in pages
        of up to 200 items.

        Returns:
        --------
        List[str]
            Sorted list of unique domain names (lowercase).
            Empty list if no domains exist.

        Notes:
        ------
        - Domain names are normalized to lowercase for consistency
        - Duplicates are removed (shouldn't happen, but defensive coding)
        - Results are sorted alphabetically for predictable output
        """
        domains: List[str] = []
        page = 1

        # Paginate through all results
        while True:
            # Request current page of domains
            data = self.req("GET", f"/domains?page={page}&per_page=200")

            # Extract domain names from response
            chunk = data.get("domains", [])
            domains.extend([d["name"].lower() for d in chunk if "name" in d])

            # Check for more pages using the links.pages.next field
            pages = (data.get("links") or {}).get("pages") or {}
            if not pages.get("next"):
                break  # No more pages

            page += 1

        # Return sorted, deduplicated list
        return sorted(set(domains))

    def list_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Retrieve all DNS records for a specific domain zone.

        This method fetches all records from the Domain Records API,
        handling pagination automatically.

        Parameters:
        -----------
        domain : str
            The domain name (e.g., "example.com")

        Returns:
        --------
        List[Dict[str, Any]]
            List of record dictionaries. Each record contains:
            - id: Unique record identifier
            - type: Record type (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA)
            - name: Record name (@ for apex, or subdomain)
            - data: Record value
            - priority: Priority (for MX and SRV records)
            - port, weight: Additional fields for SRV records
            - ttl: Time to live in seconds

        Notes:
        ------
        DigitalOcean uses '@' to represent the zone apex (root domain).
        """
        recs: List[Dict[str, Any]] = []
        page = 1

        # Paginate through all results
        while True:
            # Request current page of records
            data = self.req("GET", f"/domains/{domain}/records?page={page}&per_page=200")

            # Add records to our list
            recs.extend(data.get("domain_records", []))

            # Check for more pages
            pages = (data.get("links") or {}).get("pages") or {}
            if not pages.get("next"):
                break  # No more pages

            page += 1

        return recs


# =============================================================================
# MAIL DOMAIN ALLOWLIST SUPPORT
# =============================================================================

def load_allowlist(path: Optional[str]) -> Optional[set]:
    """
    Load a list of domains that should legitimately process email.

    Purpose:
    --------
    In many organizations, most domains should NOT send or receive email.
    They exist for web hosting, redirects, brand protection, etc. Only a
    small subset actually needs mail capability.

    This allowlist lets you specify which domains SHOULD have active mail,
    enabling the audit to flag:
    - Groups containing allowlisted domains that are incorrectly locked down (ERROR)
    - Groups containing non-allowlisted domains that unexpectedly have mail enabled (WARN)

    File Format:
    ------------
    Simple text file with one domain per line:

        # Mail domains allowlist
        # Lines starting with # are comments

        mail.example.com
        support.example.com
        example.org

    Parameters:
    -----------
    path : Optional[str]
        Path to the allowlist file. If None or empty, returns None
        (meaning all domains are treated equally, no WARN/ERROR flags).

    Returns:
    --------
    Optional[set]
        Set of lowercase domain names from the file, or None if no path.
        Returns empty set if file exists but is empty/all comments.

    Raises:
    -------
    FileNotFoundError
        If the specified file doesn't exist.
    """
    # If no path provided, return None to indicate no allowlist
    if not path:
        return None

    allowed = set()

    # Read and parse the allowlist file
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # Clean up the line
            s = line.strip().lower()

            # Skip empty lines and comments
            if not s or s.startswith("#"):
                continue

            # Add to the set
            allowed.add(s)

    return allowed


# =============================================================================
# DMARC TEMPLATE NORMALIZATION
# =============================================================================

def dmarc_template(domain: str, dmarc_value: str) -> str:
    """
    Normalize a DMARC record into a template for grouping purposes.

    Problem:
    --------
    DMARC records often embed the domain name in the rua (aggregate report)
    address using plus-tagging for organization. For example:

      Domain: example.com
      rua=mailto:DMARC+example.com@reports.tld

      Domain: example.net
      rua=mailto:DMARC+example.net@reports.tld

    These are essentially the same DMARC configuration, but without
    normalization they would create separate groups because the strings
    are different.

    Solution:
    ---------
    Replace occurrences of "+<domain>@" with "+<DOMAIN>@" to create a
    template. This way, domains sharing the same DMARC configuration
    (except for the plus-tagged domain name) will group together:

      rua=mailto:DMARC+<DOMAIN>@reports.tld

    Parameters:
    -----------
    domain : str
        The domain name being processed (used for replacement)

    dmarc_value : str
        The raw DMARC record value

    Returns:
    --------
    str
        Normalized DMARC template with domain placeholders

    Notes:
    ------
    - This is a best-effort normalization, not a full DMARC parser.
    - The replacement is case-insensitive.
    - Multiple occurrences of the domain name are all replaced.
    - Whitespace is collapsed for additional normalization.

    Examples:
    ---------
    >>> dmarc_template("example.com", "v=DMARC1; p=reject; rua=mailto:DMARC+example.com@reports.tld")
    'v=DMARC1; p=reject; rua=mailto:DMARC+<DOMAIN>@reports.tld'
    """
    # First, normalize the DMARC value (strip quotes, collapse whitespace)
    v = normalize_txt_value(dmarc_value)

    # Get the domain in lowercase for case-insensitive matching
    d = domain.lower()

    # Replace "+<domain>@" occurrences with "+<DOMAIN>@"
    # This pattern matches the common plus-tagging format in rua/ruf addresses
    v = re.sub(rf"\+{re.escape(d)}@", "+<DOMAIN>@", v, flags=re.IGNORECASE)

    # Additional whitespace normalization
    return " ".join(v.split())


# =============================================================================
# DOMAIN ANALYSIS AND SUMMARIZATION
# =============================================================================

def summarize_domain(domain: str, recs: List[Dict[str, Any]], dead_mx_host: str) -> Dict[str, Any]:
    """
    Build a compact summary of email-related DNS state for a domain.

    This is the core analysis function that examines all DNS records for
    a domain and extracts email-relevant information into a structured
    summary suitable for grouping.

    Parameters:
    -----------
    domain : str
        The domain name being analyzed (e.g., "example.com")

    recs : List[Dict[str, Any]]
        Complete list of DNS records from the DigitalOcean API

    dead_mx_host : str
        Hostname used to indicate intentionally disabled mail (e.g., "mail.invalid").
        When all MX records point to this host, the domain is considered "dead"
        for mail purposes.

    Returns:
    --------
    Dict[str, Any]
        Summary dictionary containing:
        - domain: The domain name
        - posture: "dead", "active", or "none"
        - mx_root_norm: List of (target, priority) tuples, sorted
        - mx_root_count: Number of root MX records
        - mx_total_count: Total MX records (including subdomains)
        - spf: List of SPF record values
        - spf_count: Total number of SPF records found
        - dmarc: List with first DMARC value (or empty)
        - dmarc_p: DMARC policy (p=) value or None
        - dmarc_rua: DMARC aggregate report address (rua=) or None
        - dmarc_template: Normalized DMARC template for grouping
        - dkim_like_count: Count of DKIM-ish records
        - wildcard_count: Count of wildcard records

    Analysis Logic:
    ---------------
    1. POSTURE DETERMINATION:
       - Start with "none" (no MX)
       - If any MX exists, mark as "active"
       - If all root MX point to dead_mx_host, mark as "dead"

    2. SPF ANALYSIS:
       - Look for TXT records at apex (@) starting with "v=spf1"
       - There should typically be exactly one SPF record

    3. DMARC ANALYSIS:
       - Look for TXT record at "_dmarc"
       - Extract p= policy and rua= report address
       - Create template for grouping

    4. DKIM ANALYSIS:
       - Count records with "_domainkey" in the name
       - Both TXT (actual keys) and CNAME (delegated signing) count

    5. WILDCARD ANALYSIS:
       - Count any records with names starting with "*"

    6. MX NORMALIZATION:
       - For grouping, MX records are normalized and sorted by (target, priority)
    """
    # Categorize records by type for easier processing
    mx = [r for r in recs if r.get("type") == "MX"]
    txt = [r for r in recs if r.get("type") == "TXT"]
    cname = [r for r in recs if r.get("type") == "CNAME"]

    # -------------------------------------------------------------------------
    # POSTURE DETERMINATION
    # -------------------------------------------------------------------------
    # DigitalOcean uses '@' for the zone apex (root domain).
    # Some APIs might use empty string, so we check both.
    mx_root = [r for r in mx if (r.get("name") in ("@", ""))]

    # Default posture is "none" (no MX records)
    posture = "none"

    if mx:
        # MX exists somewhere in the zone, so mail is potentially active
        posture = "active"

        if mx_root:
            # Check if all root MX targets point to the dead-end host
            dead = normalize_host(dead_mx_host)
            targets = [normalize_host(r.get("data") or "") for r in mx_root]

            # If ALL targets are the dead host, mail is intentionally disabled
            if targets and all(t == dead for t in targets):
                posture = "dead"

    # -------------------------------------------------------------------------
    # SPF ANALYSIS
    # -------------------------------------------------------------------------
    # SPF records are TXT records at the apex that start with "v=spf1"
    # Note: Multiple SPF records is a misconfiguration but we capture it
    spf_txts: List[str] = []
    for r in txt:
        if r.get("name") in ("@", ""):
            val = normalize_txt_value(r.get("data") or "")
            if val.lower().startswith("v=spf1"):
                spf_txts.append(val)

    # -------------------------------------------------------------------------
    # DMARC ANALYSIS
    # -------------------------------------------------------------------------
    # DMARC is a TXT record specifically at the "_dmarc" subdomain
    dmarc_txts: List[str] = []
    for r in txt:
        if r.get("name") == "_dmarc":
            dmarc_txts.append(normalize_txt_value(r.get("data") or ""))

    # Extract key DMARC policy values and create template from the first record
    dmarc_p = None
    dmarc_rua = None
    dmarc_tpl = None
    if dmarc_txts:
        dmarc_p = parse_tag_value(dmarc_txts[0], "p")      # Policy: none/quarantine/reject
        dmarc_rua = parse_tag_value(dmarc_txts[0], "rua")  # Aggregate report address
        dmarc_tpl = dmarc_template(domain, dmarc_txts[0])  # Template for grouping

    # -------------------------------------------------------------------------
    # DKIM ANALYSIS
    # -------------------------------------------------------------------------
    # DKIM records have "_domainkey" in their name (e.g., "selector._domainkey")
    # Can be TXT (actual public key) or CNAME (delegated to another domain)
    dkim_like = [r for r in (txt + cname) if "_domainkey" in (r.get("name") or "")]

    # -------------------------------------------------------------------------
    # WILDCARD ANALYSIS
    # -------------------------------------------------------------------------
    # Wildcard records have names starting with "*" (e.g., "*.example.com")
    wildcards = [r for r in recs if (r.get("name") or "").startswith("*")]

    # -------------------------------------------------------------------------
    # NORMALIZE ROOT MX FOR GROUPING
    # -------------------------------------------------------------------------
    # Create a sorted list of (target, priority) tuples for signature creation
    # Sorting ensures consistent ordering for comparison
    mx_root_norm: List[Tuple[str, int]] = []
    for r in mx_root:
        target = normalize_host(r.get("data") or "")
        priority = int(r.get("priority") or 0)
        mx_root_norm.append((target, priority))
    mx_root_norm.sort()  # Sort for consistent comparison

    # -------------------------------------------------------------------------
    # BUILD AND RETURN SUMMARY
    # -------------------------------------------------------------------------
    return {
        "domain": domain,
        "posture": posture,
        "mx_root_norm": mx_root_norm,      # For signature/grouping
        "mx_root_count": len(mx_root),
        "mx_total_count": len(mx),
        "spf": spf_txts,
        "spf_count": len(spf_txts),
        "dmarc": dmarc_txts[:1],           # Only first DMARC matters
        "dmarc_p": dmarc_p,
        "dmarc_rua": dmarc_rua,
        "dmarc_template": dmarc_tpl,       # Template for grouping
        "dkim_like_count": len(dkim_like),
        "wildcard_count": len(wildcards),
    }


# =============================================================================
# SIGNATURE AND GROUPING LOGIC
# =============================================================================

def signature(summary: Dict[str, Any]) -> str:
    """
    Convert a domain summary to a stable JSON string signature for grouping.

    Purpose:
    --------
    Domains with identical signatures are grouped together. The signature
    captures the essential email-related DNS configuration so that domains
    sharing the same configuration appear in the same group.

    Parameters:
    -----------
    summary : Dict[str, Any]
        A domain summary dictionary from summarize_domain()

    Returns:
    --------
    str
        A JSON string representing the signature. This is deterministic
        (sorted keys) so identical configurations produce identical strings.

    Signature Components:
    ---------------------
    - posture: The mail posture (none/dead/active)
    - mx_root: Tuple of (target, priority) pairs (sorted)
    - spf: The first (normalized) SPF record value
    - dmarc: The DMARC template (with domain placeholder)
    - dkim_like_count: Number of DKIM-ish records
    - wildcard_count: Number of wildcard records

    Notes:
    ------
    - You can modify this function to create "looser" grouping (fewer
      attributes) or "stricter" grouping (more attributes).
    - The JSON is sorted for deterministic output.
    """
    # Get the first SPF value (or empty string)
    spf_main = summary["spf"][0] if summary.get("spf") else ""

    # Get the DMARC template (or empty string)
    dmarc_tpl = summary.get("dmarc_template") or ""

    # Get the normalized MX list as a tuple (for JSON serialization)
    mx = tuple(summary.get("mx_root_norm") or [])

    # Build the signature object
    sig_obj = {
        "posture": summary.get("posture"),
        "mx_root": mx,
        "spf": normalize_txt_value(spf_main),
        "dmarc": normalize_txt_value(dmarc_tpl),
        "dkim_like_count": int(summary.get("dkim_like_count") or 0),
        "wildcard_count": int(summary.get("wildcard_count") or 0),
    }

    # Return as deterministic JSON string
    return json.dumps(sig_obj, sort_keys=True)


def pretty_signature(sig_json: str) -> str:
    """
    Convert a JSON signature to a human-readable string for display.

    Parameters:
    -----------
    sig_json : str
        The JSON signature string from signature()

    Returns:
    --------
    str
        A formatted string showing the signature components in a
        readable format suitable for terminal output.

    Format:
    -------
    posture=X  MX@=target(priority), ...  SPF=...  DMARC=...  DKIM_like=N  wildcards=N
    """
    # Parse the JSON signature back into an object
    obj = json.loads(sig_json)

    # Format the MX list as "target(priority), target(priority), ..."
    mx = obj.get("mx_root") or []
    mx_str = ", ".join([f"{t}({p})" for (t, p) in mx]) if mx else "(none)"

    # Build the formatted string
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
    Determine the status for a group based on allowlist expectations.

    This function evaluates a group of domains against the mail allowlist
    to identify potential issues. Unlike per-domain status, this looks at
    the group as a whole.

    Parameters:
    -----------
    domains : List[str]
        List of domain names in the group

    sig_json : str
        The JSON signature for the group

    allow_mail : Optional[set]
        Set of domains that should legitimately process mail.
        If None, no allowlist is in use.

    Returns:
    --------
    str
        Status string:
        - "OK": No issues detected
        - "ERROR(mail expected)": Group contains allowlisted domain but has dead/none posture
        - "WARN(unexpected mail)": Group contains non-allowlisted domain but has active posture

    Logic:
    ------
    The function checks if ANY domain in the group triggers an error/warning:
    - If any allowlisted domain is in a dead/none posture group -> ERROR
    - If any non-allowlisted domain is in an active posture group -> WARN
    - Otherwise -> OK
    """
    # If no allowlist, we can't determine expected behavior
    if allow_mail is None:
        return "OK"

    # Extract posture from the signature
    posture = json.loads(sig_json).get("posture")

    # Check if any domain in this group triggers an error/warning
    any_mail_expected = any(d in allow_mail for d in domains)
    any_mail_unexpected = any(d not in allow_mail for d in domains)

    # Check for ERROR: allowlisted domain in a non-mail group
    if any_mail_expected and posture in ("dead", "none"):
        return "ERROR(mail expected)"

    # Check for WARN: non-allowlisted domain in an active mail group
    if any_mail_unexpected and posture == "active":
        return "WARN(unexpected mail)"

    # No issues detected
    return "OK"


# =============================================================================
# REPORT GENERATION
# =============================================================================

def write_text_report(report_path: Path, group_items: List[Tuple[str, List[str]]], allow_mail: Optional[set]) -> None:
    """
    Write a grouped audit report to a text file.

    This function generates a formatted text file showing each group with
    its signature details and complete domain list. Unlike the stdout output,
    this report includes ALL domains per group (no truncation).

    Parameters:
    -----------
    report_path : Path
        Output file path for the report

    group_items : List[Tuple[str, List[str]]]
        List of (signature_json, domain_list) tuples, sorted by group size

    allow_mail : Optional[set]
        Mail domain allowlist for status determination

    Report Format:
    --------------
    Header:
      - Timestamp

    Per Group:
      - Group number, domain count, status indicator
      - Signature details (posture, MX, SPF, DMARC, counts)
      - Complete list of domains in the group
    """
    lines: List[str] = []

    # Write report header with timestamp
    lines.append(f"DigitalOcean DNS Grouped Audit Report - {datetime.now().isoformat()}")
    lines.append("")

    # Write each group
    for idx, (sig, doms) in enumerate(group_items, start=1):
        # Sort domains alphabetically for consistent output
        doms_sorted = sorted(doms)

        # Determine group status based on allowlist
        status = group_status(doms_sorted, sig, allow_mail)

        # Write group header
        lines.append(f"=== Group {idx} | {len(doms_sorted)} domains | {status} ===")

        # Write signature details
        lines.append(pretty_signature(sig))

        # Write complete domain list
        lines.append("Domains:")
        for d in doms_sorted:
            lines.append(f"  - {d}")

        lines.append("")  # Blank line between groups

    # Ensure parent directory exists and write the file
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================

def main() -> None:
    """
    Main entry point for the grouped DNS audit script.

    This function:
    1. Parses command-line arguments
    2. Validates authentication
    3. Fetches all domains and their records
    4. Computes signatures and groups domains
    5. Generates reports (stdout and text file)
    6. Optionally writes JSON outputs and record dumps

    Exit Codes:
    -----------
    0: Success
    2: Missing authentication token
    """
    # -------------------------------------------------------------------------
    # ARGUMENT PARSING
    # -------------------------------------------------------------------------
    ap = argparse.ArgumentParser(
        description="Audit all DigitalOcean DNS zones and group domains by mail-related posture.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication priority:
  1. .env file (DO_TOKEN=...)
  2. Environment variable (export DO_TOKEN=...)
  3. Command-line (--token ...)

Security tip: Use the .env file approach and set permissions with:
  chmod 600 .env
        """
    )

    # Authentication argument
    ap.add_argument(
        "--token",
        default=None,
        help="DigitalOcean API token. Prefer using .env file or DO_TOKEN env var for security."
    )

    # Allowlist of domains that should process mail
    ap.add_argument(
        "--mail-domains-file",
        default="",
        help="Domains that SHOULD process mail (one per line)"
    )

    # "Dead mail" heuristic: what MX host indicates inbound mail is disabled?
    ap.add_argument(
        "--dead-mx-host",
        default="mail.invalid",
        help="Hostname used as dead-end MX target when mail is disabled (default: mail.invalid)"
    )

    # Output display controls
    ap.add_argument(
        "--show-all",
        action="store_true",
        help="Print all domains per group to stdout (no truncation)."
    )
    ap.add_argument(
        "--show-domains-per-group",
        type=int,
        default=12,
        help="How many domains to print per group (ignored with --show-all)."
    )

    # Report file location
    ap.add_argument(
        "--report-file",
        default="",
        help="Write grouped TXT report to this path (default: /tmp/do_dns_audit_grouped_report_<ts>.txt)."
    )

    # JSON/record dump controls (opt-in)
    ap.add_argument(
        "--outdir",
        default="",
        help="Directory for JSON outputs (default: /tmp/do_dns_audit_grouped_<ts>/ when dumping)."
    )
    ap.add_argument(
        "--dump-records",
        action="store_true",
        help="Write <domain>.records.json files to --outdir."
    )
    ap.add_argument(
        "--dump-json", "--dump_json",
        dest="dump_json",
        action="store_true",
        help="Write summary.json, summary.ndjson, groups.json to --outdir."
    )
    ap.set_defaults(dump_json=False)

    # Parse arguments
    args = ap.parse_args()

    # -------------------------------------------------------------------------
    # TOKEN VALIDATION
    # -------------------------------------------------------------------------
    # Get token using priority: .env file > environment variable > CLI argument
    token = get_token(args.token)

    if not token:
        print("Missing token. Provide via .env file (DO_TOKEN=...), environment variable, or --token.")
        print("See --help for details on authentication options.")
        sys.exit(2)

    # -------------------------------------------------------------------------
    # LOAD OPTIONAL ALLOWLIST
    # -------------------------------------------------------------------------
    allow_mail = load_allowlist(args.mail_domains_file) if args.mail_domains_file else None

    # -------------------------------------------------------------------------
    # INITIALIZE API CLIENT AND FETCH DOMAINS
    # -------------------------------------------------------------------------
    client = DOClient(token)
    domains = client.list_domains()
    print(f"Found {len(domains)} domains.\n")

    # -------------------------------------------------------------------------
    # OUTPUT DIRECTORY SETUP (if needed)
    # -------------------------------------------------------------------------
    # Only create output directory if we're dumping JSON or records
    need_outdir = args.dump_json or args.dump_records
    outdir: Optional[Path] = None
    if need_outdir:
        outdir = Path(args.outdir).expanduser().resolve() if args.outdir else default_tmp_outdir("do_dns_audit_grouped")
        outdir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # FETCH RECORDS AND BUILD SUMMARIES/GROUPS
    # -------------------------------------------------------------------------
    # Store summaries for optional JSON export
    summaries: List[Dict[str, Any]] = []

    # Groups: signature -> list of domains with that signature
    groups: Dict[str, List[str]] = {}

    # Process each domain
    for d in domains:
        try:
            # Fetch all DNS records for this domain
            recs = client.list_records(d)
        except Exception as e:
            # Log error but continue with other domains
            # One bad zone shouldn't stop the whole audit
            print(f"[ERROR] Failed to fetch records for {d}: {e}")
            continue

        # Optional: write raw record dumps per domain
        if args.dump_records and outdir is not None:
            (outdir / f"{d}.records.json").write_text(
                json.dumps(recs, indent=2, sort_keys=True),
                encoding="utf-8"
            )

        # Build summary for this domain
        s = summarize_domain(d, recs, dead_mx_host=args.dead_mx_host)
        summaries.append(s)

        # Compute signature and add to appropriate group
        sig = signature(s)
        groups.setdefault(sig, []).append(d)

    # -------------------------------------------------------------------------
    # SORT GROUPS BY SIZE (largest first)
    # -------------------------------------------------------------------------
    group_items: List[Tuple[str, List[str]]] = sorted(
        groups.items(),
        key=lambda kv: len(kv[1]),
        reverse=True
    )

    # -------------------------------------------------------------------------
    # PRINT GROUPED REPORT TO STDOUT
    # -------------------------------------------------------------------------
    for idx, (sig, doms) in enumerate(group_items, start=1):
        # Sort domains alphabetically
        doms_sorted = sorted(doms)

        # Determine group status based on allowlist
        status = group_status(doms_sorted, sig, allow_mail)

        # Print group header
        print(f"=== Group {idx} | {len(doms_sorted)} domains | {status} ===")
        print(pretty_signature(sig))

        # Print domain list (with optional truncation)
        if args.show_all:
            # Show all domains
            print("Domains:", ", ".join(doms_sorted))
        else:
            # Truncate to show_domains_per_group
            show_n = max(0, int(args.show_domains_per_group))
            preview = doms_sorted[:show_n]
            tail = len(doms_sorted) - len(preview)

            if preview:
                print("Domains:", ", ".join(preview))
            if tail > 0:
                print(f"... +{tail} more")

        print()  # Blank line between groups

    # -------------------------------------------------------------------------
    # WRITE TEXT REPORT (always)
    # -------------------------------------------------------------------------
    report_path = Path(args.report_file).expanduser().resolve() if args.report_file else default_report_path()
    write_text_report(report_path, group_items, allow_mail)
    print(f"Wrote text report: {report_path}")

    # -------------------------------------------------------------------------
    # OPTIONAL: WRITE JSON OUTPUTS
    # -------------------------------------------------------------------------
    if args.dump_json and outdir is not None:
        # Standard JSON (array of all summaries)
        (outdir / "summary.json").write_text(
            json.dumps(summaries, indent=2),
            encoding="utf-8"
        )

        # Newline-delimited JSON (one summary per line, better for streaming)
        (outdir / "summary.ndjson").write_text(
            "\n".join(json.dumps(s) for s in summaries) + "\n",
            encoding="utf-8"
        )

        # Groups mapping (signature -> list of domains)
        (outdir / "groups.json").write_text(
            json.dumps(groups, indent=2, sort_keys=True),
            encoding="utf-8"
        )

        print(f"Wrote JSON outputs to: {outdir}")

    print("Done.")


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
