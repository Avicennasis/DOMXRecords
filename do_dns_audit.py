#!/usr/bin/env python3
"""
================================================================================
do_dns_audit.py - DigitalOcean DNS Email Posture Audit Tool (Non-Grouped)
================================================================================

OVERVIEW:
---------
This script performs a comprehensive audit of all DNS zones (domains) managed
in your DigitalOcean account, focusing specifically on email-related DNS records.
It fetches every domain and every DNS record, then generates a detailed summary
of the email security posture for each domain.

This script is intentionally "flat" and processes one domain at a time (unlike
the grouped audit script do_dns_audit_grouped.py). This makes it ideal when you
need:
  - A complete per-domain record dump for inspection and debugging
  - A simple per-domain summary printed directly to stdout
  - A single consolidated text report containing all audit results

PURPOSE:
--------
Email spoofing is a significant security concern. Attackers frequently spoof
email addresses from domains that don't actively send email. Properly configured
DNS records (SPF, DKIM, DMARC, MX) help prevent unauthorized email use. This
audit tool helps you:
  1. Identify domains with missing or misconfigured email security records
  2. Verify that domains not intended for email are properly locked down
  3. Confirm that mail-processing domains have appropriate records in place

WHAT THIS SCRIPT CHECKS:
------------------------
For each domain, the script examines:

1. ROOT/APEX MX RECORDS (name '@' in DigitalOcean):
   - Determines the domain's mail "posture":
     * "dead"   - All root MX targets point to a dead-end host (e.g., mail.invalid)
                  This indicates mail is intentionally disabled.
     * "active" - MX records exist but don't match the dead-end pattern.
                  This domain likely processes email.
     * "none"   - No MX records exist at all.
                  Inbound mail delivery behavior is undefined.

2. ROOT/APEX SPF TXT RECORDS:
   - Looks for TXT records at '@' that begin with 'v=spf1'
   - SPF (Sender Policy Framework) specifies which servers can send email
     for the domain. A restrictive policy like "v=spf1 -all" means no servers
     are authorized (ideal for domains that don't send email).

3. DMARC TXT RECORD AT _dmarc:
   - DMARC (Domain-based Message Authentication, Reporting & Conformance)
     tells receivers what to do with unauthenticated email.
   - Extracts key policy tags: p= (policy) and rua= (aggregate report address)

4. DKIM-ISH RECORDS:
   - Counts TXT and CNAME records containing '_domainkey' in their name
   - DKIM (DomainKeys Identified Mail) provides cryptographic email signing
   - For domains that shouldn't send email, DKIM records should be removed

5. WILDCARD RECORDS:
   - Counts any records with names starting with '*'
   - Wildcard DNS can have security implications and is flagged for review

OPTIONAL MAIL ALLOWLIST:
------------------------
You can provide a file listing domains that SHOULD legitimately process mail.
With an allowlist, the script will flag:
  - ERROR(mail expected): Allowlisted domain has posture "dead" or "none"
  - WARN(unexpected mail): Non-allowlisted domain has posture "active"

This helps catch both:
  - Mail domains that were accidentally broken
  - Non-mail domains that unexpectedly have active mail configuration

OUTPUT FILES:
-------------
The script produces several outputs:

1. Per-domain JSON record dumps (always created):
   Location: /tmp/do_dns_audit_<timestamp>/<domain>.records.json
   Contains: Complete raw DNS record data from the DigitalOcean API
   Purpose: Debugging, manual inspection, archival

2. Human-readable text report (always created):
   Location: /tmp/do_dns_audit_report_<timestamp>.txt
   Contains: Formatted summary for each domain with posture and key records
   Purpose: Quick review, sharing with team members

3. Machine-readable summaries (optional, with --dump-json):
   Location: <outdir>/summary.json and <outdir>/summary.ndjson
   Contains: Structured data for all domain summaries
   Purpose: Integration with other tools, programmatic analysis

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
  # Basic audit (outputs to /tmp)
  python3 do_dns_audit.py

  # Audit with mail domain allowlist
  python3 do_dns_audit.py --mail-domains-file mail_domains.txt

  # Custom output locations
  python3 do_dns_audit.py --outdir /tmp/my_audit --report-file ./dns_audit.txt

  # Include machine-readable JSON summaries
  python3 do_dns_audit.py --dump-json

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
import json          # JSON serialization for output files
import os            # Environment variable access and file operations
import re            # Regular expressions for parsing DNS record values
import sys           # System exit codes and stderr
import time          # Sleep/retry timing for API rate limiting
from datetime import datetime  # Timestamps for output file naming
from pathlib import Path       # Modern, cross-platform file path handling
from typing import Any, Dict, List, Optional  # Type hints for better code clarity

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
    correctly, but that's acceptable for audit purposes - we just want
    to flag records that exist and extract basic info.

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

def default_outdir() -> Path:
    """
    Generate the default output directory path for per-domain record dumps.

    Rationale:
    ----------
    When running from a git repository or project directory, we don't want
    to create noisy folders and files that might accidentally get committed
    or clutter the workspace. Using /tmp is ideal because:
    - It's a standard temporary location on Unix-like systems
    - Files are typically cleaned up on reboot
    - It keeps the working directory clean

    Format:
    -------
    /tmp/do_dns_audit_YYYYMMDD_HHMMSS/

    The timestamp ensures:
    - Multiple runs don't overwrite each other
    - Easy identification of when an audit was performed
    - Natural sorting by date

    Returns:
    --------
    Path
        A Path object pointing to the timestamped directory in /tmp.
        Note: This function does NOT create the directory; that's done later.
    """
    # Generate timestamp in a filename-safe format
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Construct and return the path
    return Path("/tmp") / f"do_dns_audit_{ts}"


def default_report_path() -> Path:
    """
    Generate the default path for the human-readable audit report.

    Rationale:
    ----------
    Similar to default_outdir(), this places the report in /tmp to avoid
    cluttering the working directory. The report is a single consolidated
    text file containing summaries for all domains.

    Format:
    -------
    /tmp/do_dns_audit_report_YYYYMMDD_HHMMSS.txt

    Returns:
    --------
    Path
        A Path object pointing to the timestamped report file in /tmp.
    """
    # Generate timestamp matching the outdir format for consistency
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Construct and return the path
    return Path("/tmp") / f"do_dns_audit_report_{ts}.txt"


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
    - Allowlisted domains that are incorrectly locked down (ERROR)
    - Non-allowlisted domains that unexpectedly have mail enabled (WARN)

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
# DOMAIN ANALYSIS AND SUMMARIZATION
# =============================================================================

def summarize_domain(domain: str, recs: List[Dict[str, Any]], dead_mx_host: str) -> Dict[str, Any]:
    """
    Build a compact summary of email-related DNS state for a domain.

    This is the core analysis function that examines all DNS records for
    a domain and extracts email-relevant information into a structured
    summary.

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
        - mx_root: List of compact MX strings for display
        - mx_root_count: Number of root MX records
        - mx_total_count: Total MX records (including subdomains)
        - spf: List of SPF record values (up to 3)
        - spf_count: Total number of SPF records found
        - dmarc: List with first DMARC value (or empty)
        - dmarc_p: DMARC policy (p=) value or None
        - dmarc_rua: DMARC aggregate report address (rua=) or None
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

    4. DKIM ANALYSIS:
       - Count records with "_domainkey" in the name
       - Both TXT (actual keys) and CNAME (delegated signing) count

    5. WILDCARD ANALYSIS:
       - Count any records with names starting with "*"
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
            targets = [normalize_host(r.get("data") or "") for r in mx_root]
            dead = normalize_host(dead_mx_host)

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

    # Extract key DMARC policy values from the first record
    dmarc_p = None
    dmarc_rua = None
    if dmarc_txts:
        dmarc_p = parse_tag_value(dmarc_txts[0], "p")      # Policy: none/quarantine/reject
        dmarc_rua = parse_tag_value(dmarc_txts[0], "rua")  # Aggregate report address

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
    # FORMAT MX FOR DISPLAY
    # -------------------------------------------------------------------------
    # Create a compact list of MX entries for printing (target with priority)
    mx_compact: List[str] = []
    for r in mx_root[:5]:  # Limit to first 5 for readability
        pr = r.get("priority")
        mx_compact.append(f"{r.get('data')}({pr})")

    # Indicate if there are more MX records than shown
    if len(mx_root) > 5:
        mx_compact.append(f"+{len(mx_root)-5} more")

    # -------------------------------------------------------------------------
    # BUILD AND RETURN SUMMARY
    # -------------------------------------------------------------------------
    return {
        "domain": domain,
        "posture": posture,
        "mx_root": mx_compact,          # Formatted for display
        "mx_root_count": len(mx_root),
        "mx_total_count": len(mx),
        "spf": spf_txts[:3],            # Cap at 3 (more would be misconfiguration)
        "spf_count": len(spf_txts),
        "dmarc": dmarc_txts[:1],        # Only first DMARC matters
        "dmarc_p": dmarc_p,
        "dmarc_rua": dmarc_rua,
        "dkim_like_count": len(dkim_like),
        "wildcard_count": len(wildcards),
    }


def status_for(domain: str, posture: str, allow_mail: Optional[set]) -> str:
    """
    Determine the audit status for a domain based on allowlist expectations.

    This function compares the domain's actual posture against expectations
    from the optional mail domains allowlist to identify misconfigurations.

    Parameters:
    -----------
    domain : str
        The domain name being evaluated

    posture : str
        The domain's determined mail posture: "dead", "active", or "none"

    allow_mail : Optional[set]
        Set of domains that should legitimately process mail.
        If None, no allowlist is in use and all domains get "OK".

    Returns:
    --------
    str
        Status string:
        - "OK": No issues detected
        - "ERROR(mail expected)": Domain should process mail but is dead/none
        - "WARN(unexpected mail)": Domain shouldn't process mail but is active

    Logic:
    ------
    With allowlist:
      - Allowlisted + (dead/none) = ERROR - mail was expected but disabled
      - Not allowlisted + active = WARN - mail wasn't expected but enabled
      - Everything else = OK

    Without allowlist:
      - All domains = OK (no expectations to compare against)
    """
    # If no allowlist, we can't determine expected behavior
    if allow_mail is None:
        return "OK"

    # Check for ERROR: allowlisted domain that can't receive mail
    if domain in allow_mail and posture in ("dead", "none"):
        return "ERROR(mail expected)"

    # Check for WARN: non-allowlisted domain that has active mail
    if domain not in allow_mail and posture == "active":
        return "WARN(unexpected mail)"

    # No issues detected
    return "OK"


# =============================================================================
# REPORT GENERATION
# =============================================================================

def write_pretty_report(path: Path, outdir: Path, summaries: List[Dict[str, Any]], allow_mail: Optional[set]) -> None:
    """
    Write a human-readable text report summarizing all domains.

    This function generates a formatted text file designed for humans to
    read and review. It includes all audit results in a consistent,
    scannable format.

    Parameters:
    -----------
    path : Path
        Output file path for the report

    outdir : Path
        Directory containing per-domain record dumps (included in report header)

    summaries : List[Dict[str, Any]]
        List of domain summary dictionaries from summarize_domain()

    allow_mail : Optional[set]
        Mail domain allowlist for status determination

    Report Format:
    --------------
    Header:
      - Timestamp
      - Location of record dumps

    Per Domain:
      - Status indicator: [OK], [WARN(...)], or [ERROR(...)]
      - Domain name
      - Posture: dead/active/none
      - MX records at root
      - SPF record
      - DMARC policy and report address
      - DKIM record count
      - Wildcard record count
    """
    lines: List[str] = []

    # Write report header with timestamp and reference to record dumps
    lines.append(f"DigitalOcean DNS Audit Report - {datetime.now().isoformat()}")
    lines.append(f"Per-domain record dumps: {outdir}")
    lines.append("")

    # Write summary for each domain
    for s in summaries:
        d = s["domain"]
        st = status_for(d, s["posture"], allow_mail)

        # Format MX, SPF, and DMARC for display
        mx_str = ", ".join(s["mx_root"]) if s["mx_root"] else "(none)"
        spf_str = s["spf"][0] if s["spf"] else "(none)"

        dmarc_p = s["dmarc_p"] or "(none)"
        dmarc_rua = s["dmarc_rua"] or "(none)"

        # Write domain section
        lines.append(f"[{st}] {d}")
        lines.append(f"  posture: {s['posture']}")
        lines.append(f"  MX(@):   {mx_str}")
        lines.append(f"  SPF(@):  {spf_str}")
        lines.append(f"  DMARC:   p={dmarc_p} rua={dmarc_rua}")
        lines.append(f"  DKIM-ish records: {s['dkim_like_count']}")
        lines.append(f"  Wildcards: {s['wildcard_count']}")
        lines.append("")  # Blank line between domains

    # Ensure parent directory exists and write the file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================

def main() -> None:
    """
    Main entry point for the DNS audit script.

    This function:
    1. Parses command-line arguments
    2. Validates authentication
    3. Fetches all domains and their records
    4. Generates summaries and reports
    5. Writes output files

    Exit Codes:
    -----------
    0: Success
    2: Missing authentication token
    """
    # -------------------------------------------------------------------------
    # ARGUMENT PARSING
    # -------------------------------------------------------------------------
    ap = argparse.ArgumentParser(
        description="Audit all DigitalOcean DNS zones for email-related records.",
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

    # Output path arguments (default to /tmp to avoid clutter)
    ap.add_argument(
        "--outdir",
        default="",
        help="Directory for per-domain JSON record dumps (default: /tmp/do_dns_audit_<ts>/)"
    )
    ap.add_argument(
        "--report-file",
        default="",
        help="Pretty TXT report path (default: /tmp/do_dns_audit_report_<ts>.txt)"
    )

    # Mail expectation arguments
    ap.add_argument(
        "--mail-domains-file",
        default="",
        help="Allowlist of domains that SHOULD process mail (one per line)"
    )

    # Dead-mail heuristic configuration
    ap.add_argument(
        "--dead-mx-host",
        default="mail.invalid",
        help="Hostname used as dead-end MX target when mail is disabled (default: mail.invalid)"
    )

    # Optional JSON output
    ap.add_argument(
        "--dump-json", "--dump_json",
        dest="dump_json",
        action="store_true",
        help="Also write summary.json and summary.ndjson to outdir"
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
    # OUTPUT PATH SETUP
    # -------------------------------------------------------------------------
    # Determine output directory (use user-provided or generate default)
    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else default_outdir()
    outdir.mkdir(parents=True, exist_ok=True)

    # Determine report file path
    report_path = Path(args.report_file).expanduser().resolve() if args.report_file else default_report_path()

    # -------------------------------------------------------------------------
    # LOAD OPTIONAL ALLOWLIST
    # -------------------------------------------------------------------------
    allow_mail = load_allowlist(args.mail_domains_file) if args.mail_domains_file else None

    # -------------------------------------------------------------------------
    # FETCH DATA AND PERFORM AUDIT
    # -------------------------------------------------------------------------
    # Initialize API client and fetch domain list
    client = DOClient(token)
    domains = client.list_domains()

    print(f"Found {len(domains)} domains.")
    print(f"Writing per-domain record dumps to: {outdir}\n")

    # Process each domain
    summaries: List[Dict[str, Any]] = []

    for d in domains:
        try:
            # Fetch all DNS records for this domain
            recs = client.list_records(d)
        except Exception as e:
            # Log error but continue with other domains
            # One bad zone shouldn't kill the whole audit
            print(f"[ERROR] {d}: {e}")
            continue

        # Always dump full records for inspection/debugging
        # This is useful for manual review or debugging issues
        (outdir / f"{d}.records.json").write_text(
            json.dumps(recs, indent=2, sort_keys=True),
            encoding="utf-8"
        )

        # Build summary and add to list
        s = summarize_domain(d, recs, dead_mx_host=args.dead_mx_host)
        summaries.append(s)

        # Print real-time progress to stdout
        st = status_for(d, s["posture"], allow_mail)

        mx_str = ", ".join(s["mx_root"]) if s["mx_root"] else "(none)"
        spf_str = s["spf"][0] if s["spf"] else "(none)"
        dmarc_p = s["dmarc_p"] or "(none)"

        # Formatted output for terminal
        print(f"[{st:18}] {d:30} posture={s['posture']:6}  MX@={mx_str}")
        print(f"                  SPF={spf_str}")
        print(f"                  DMARC p={dmarc_p}  DKIM_like={s['dkim_like_count']}  wildcards={s['wildcard_count']}")
        print()

    # -------------------------------------------------------------------------
    # GENERATE REPORTS
    # -------------------------------------------------------------------------
    # Sort summaries by domain for consistent report ordering
    summaries.sort(key=lambda x: x["domain"])

    # Write the human-readable report
    write_pretty_report(report_path, outdir, summaries, allow_mail)
    print(f"Wrote pretty report: {report_path}")

    # Optional: write machine-readable JSON summaries
    if args.dump_json:
        # Standard JSON (array of objects)
        (outdir / "summary.json").write_text(
            json.dumps(summaries, indent=2),
            encoding="utf-8"
        )
        # Newline-delimited JSON (one object per line, better for streaming)
        (outdir / "summary.ndjson").write_text(
            "\n".join(json.dumps(s) for s in summaries) + "\n",
            encoding="utf-8"
        )
        print(f"Wrote summary.json and summary.ndjson to: {outdir}")

    print("Done.")


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
