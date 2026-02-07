#!/usr/bin/env python3
"""
================================================================================
lockdown_mail.py - DigitalOcean DNS Mail Lockdown Tool
================================================================================

OVERVIEW:
---------
This script performs bulk "no-mail" hardening for domains hosted on DigitalOcean
DNS. It is designed for organizations that own many domains which should NEVER
send or receive email, and want to prevent email spoofing and abuse.

For each domain in your input file, the script configures DNS records to:
  1. Reject all unauthenticated email (DMARC p=reject)
  2. Authorize no mail servers (SPF v=spf1 -all)
  3. Disable inbound mail (MX pointing to mail.invalid)
  4. Remove DKIM records (no keys to verify against)
  5. Optionally remove wildcard DNS records
  6. Optionally authorize a DMARC report destination domain

PURPOSE:
--------
Email spoofing is a serious security and reputation concern. Attackers frequently
forge email addresses using domains that don't actually send email. Without proper
DNS configuration, these spoofed emails may be delivered to victims.

By enforcing strict email policies on unused domains, you:
  - Protect your brand reputation from phishing attacks
  - Help email receivers identify and reject spoofed messages
  - Maintain a consistent security posture across all owned domains
  - Receive aggregate DMARC reports about attempted abuse

WHAT THIS SCRIPT DOES:
----------------------
For each domain specified in the domains file:

1. DELETES DKIM RECORDS:
   - Removes any TXT or CNAME records containing '_domainkey' in their name
   - DKIM (DomainKeys Identified Mail) provides cryptographic signing for email
   - For domains that don't send email, DKIM records are unnecessary and could
     be abused if private keys were compromised

2. SETS DMARC TO REJECT:
   - Creates/updates the _dmarc TXT record with a strict policy:
     v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=...
   - p=reject: Tell receivers to reject unauthenticated mail
   - sp=reject: Apply same policy to subdomains
   - adkim=s: Strict DKIM alignment (exact domain match required)
   - aspf=s: Strict SPF alignment (exact domain match required)
   - pct=100: Apply policy to 100% of messages
   - rua=: Send aggregate reports to the specified address

3. SETS SPF TO DENY ALL:
   - Creates/updates the root TXT SPF record: v=spf1 -all
   - This explicitly tells receivers that NO servers are authorized to send
     email for this domain
   - Only touches TXT records at '@' that start with 'v=spf1' to avoid
     clobbering other verification TXT records (domain verification, etc.)

4. REPLACES MX WITH DEAD-END:
   - Deletes ALL existing MX records for the domain
   - Creates a single MX record at '@' pointing to mail.invalid.
   - mail.invalid is a special RFC 2606 reserved domain that doesn't resolve
   - Any mail server trying to deliver to this domain will fail

5. OPTIONAL: DELETES WILDCARD RECORDS:
   - With --delete-wildcards, removes any records whose name starts with '*'
   - Wildcard DNS can have security implications and may conflict with
     subdomain-specific policies

6. OPTIONAL: ADDS DMARC REPORT AUTHORIZATION:
   - With --report-auth-zone, publishes an authorization record in the report
     destination domain's zone
   - Format: <domain>._report._dmarc.<report-domain> TXT "v=DMARC1"
   - This tells receivers that the report domain is authorized to receive
     DMARC aggregate reports for the specified domain

DIGITALOCEAN DNS NOTES:
-----------------------
- DigitalOcean's DNS API requires MX targets to be FQDNs with trailing dots
  (e.g., "mail.invalid." not "mail.invalid"). This script handles this.
- DigitalOcean uses '@' to represent the zone apex (root domain).
- TXT records may include literal quote characters if users copy-pasted from
  DNS tools. This script normalizes values for comparison but writes clean
  unquoted values.

AUTHENTICATION:
---------------
The script requires a DigitalOcean API token with read/write access to domains
and DNS records. Authentication is checked in this order:

1. .env file in the current directory (DO_TOKEN=your_token_here)
2. Environment variable: export DO_TOKEN="dop_v1_..."
3. Command-line argument: --token "dop_v1_..."

SECURITY NOTE: Store your token securely. Use the .env file approach and ensure
the file has restrictive permissions (chmod 600 .env).

SAFETY FEATURES:
----------------
- DRY-RUN MODE: Use --dry-run to preview all changes without modifying DNS.
  This is HIGHLY RECOMMENDED for first runs.
- CONTINUE ON ERROR: Use --continue-on-error to process remaining domains if
  one domain fails (e.g., due to API errors).
- TXT RECORD SAFETY: SPF modifications only target records starting with
  'v=spf1', preserving other TXT records at the apex.

REQUIREMENTS:
-------------
  pip install requests

EXAMPLES:
---------
  # Dry-run first (RECOMMENDED)
  python3 lockdown_mail.py --domains-file domains.txt --dry-run

  # Apply changes
  python3 lockdown_mail.py --domains-file domains.txt

  # Also delete wildcard records
  python3 lockdown_mail.py --domains-file domains.txt --delete-wildcards

  # Send DMARC reports to a different domain and add authorization
  python3 lockdown_mail.py --domains-file domains.txt \
      --dmarc-report-domain dmarc-reports.example \
      --dmarc-localpart-prefix DMARC \
      --report-auth-zone dmarc-reports.example

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
import os            # Environment variable access and file operations
import sys           # System exit codes
import time          # Sleep/retry timing for API rate limiting
from typing import Any, Dict, List, Optional  # Type hints for clarity

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


def ensure_fqdn_dot(host: str) -> str:
    """
    Ensure a hostname is a Fully Qualified Domain Name (FQDN) with trailing dot.

    Problem:
    --------
    DigitalOcean's DNS API requires MX record targets to be FQDNs ending with
    a trailing dot. This is standard DNS notation indicating the hostname is
    absolute (not relative to the zone).

    For example:
      - "mail.invalid" should become "mail.invalid."
      - "mx.example.com" should become "mx.example.com."

    Solution:
    ---------
    This function checks if the hostname already ends with a dot and adds one
    if not.

    Parameters:
    -----------
    host : str
        The hostname to normalize

    Returns:
    --------
    str
        The hostname with a trailing dot (FQDN format)

    Edge Cases:
    -----------
    - Empty string: Returns as-is
    - Single dot ".": Returns as-is (don't create "..")
    - Already has dot: Returns as-is (don't create double dots)

    Examples:
    ---------
    >>> ensure_fqdn_dot("mail.invalid")
    'mail.invalid.'

    >>> ensure_fqdn_dot("mail.invalid.")
    'mail.invalid.'

    >>> ensure_fqdn_dot("")
    ''
    """
    # Strip whitespace
    host = (host or "").strip()

    # Add trailing dot if:
    # - host is not empty
    # - host is not just a dot
    # - host doesn't already end with a dot
    if host and host != "." and not host.endswith("."):
        host += "."

    return host


# =============================================================================
# DOMAINS FILE READER
# =============================================================================

def read_domains_file(path: str) -> List[str]:
    """
    Read a list of domains from a text file.

    File Format:
    ------------
    Simple text file with one domain per line:

        # My domains to lock down
        # Lines starting with # are comments

        example.com
        example.net
        example.org
        mysite.io

    Parameters:
    -----------
    path : str
        Path to the domains file

    Returns:
    --------
    List[str]
        List of domain names (lowercase, stripped of whitespace).
        Empty list if file contains no valid domains.

    Notes:
    ------
    - Domain names are normalized to lowercase
    - Blank lines are skipped
    - Lines starting with '#' are treated as comments
    - Whitespace is stripped from each line

    Raises:
    -------
    FileNotFoundError
        If the specified file doesn't exist
    """
    out: List[str] = []

    # Read and parse the domains file
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            # Strip whitespace
            s = line.strip()

            # Skip empty lines and comments
            if not s or s.startswith("#"):
                continue

            # Normalize to lowercase and add to list
            out.append(s.lower())

    return out


# =============================================================================
# DIGITALOCEAN API CLIENT CLASS
# =============================================================================

class DOClient:
    """
    A DigitalOcean API wrapper for DNS record management.

    Purpose:
    --------
    This class encapsulates all communication with the DigitalOcean API,
    providing methods for listing, creating, updating, and deleting DNS
    records. It handles common concerns like:
    - Authentication (Bearer token)
    - Rate limiting (HTTP 429 responses)
    - Transient errors (5xx responses)
    - Pagination (records)
    - Dry-run mode (preview changes without modifying)

    Design Decisions:
    -----------------
    1. Uses requests.Session for connection reuse (performance)
    2. Implements automatic retry with exponential backoff
    3. Handles pagination transparently (caller gets complete lists)
    4. Raises RuntimeError on unrecoverable failures
    5. Supports dry-run mode for safe previews

    Attributes:
    -----------
    session : requests.Session
        Persistent HTTP session with authentication headers configured.

    dry_run : bool
        If True, mutating operations (POST, PUT, DELETE) only print what
        would happen without actually making API calls.

    timeout : int
        Request timeout in seconds. Prevents hanging on network issues.

    Usage:
    ------
        # Normal mode
        client = DOClient("dop_v1_your_token_here")
        records = client.list_records("example.com")
        client.delete_record("example.com", record_id)

        # Dry-run mode
        client = DOClient("dop_v1_your_token_here", dry_run=True)
        client.delete_record("example.com", record_id)  # Only prints, no delete
    """

    def __init__(self, token: str, dry_run: bool = False, timeout: int = 30):
        """
        Initialize the DigitalOcean API client.

        Parameters:
        -----------
        token : str
            DigitalOcean personal access token (starts with "dop_v1_").
            Must have read/write permissions for Domains.

        dry_run : bool
            If True, mutating API calls will only print what would happen
            without actually executing. Useful for previewing changes.

        timeout : int
            HTTP request timeout in seconds. Default 30s is reasonable for
            API calls but can be increased for slow networks.
        """
        # Create a persistent session for connection reuse
        # This improves performance by reusing TCP connections
        self.session = requests.Session()

        # Configure default headers for all requests
        self.session.headers.update({
            "Authorization": f"Bearer {token}",  # Bearer auth per DO API spec
            "Content-Type": "application/json",   # All requests/responses are JSON
        })

        # Store configuration
        self.dry_run = dry_run
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """
        Perform an HTTP request to the DigitalOcean API with retry logic.

        This method handles the low-level API communication, including:
        - URL construction from path
        - Dry-run handling for mutating operations
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
            Parsed JSON response. Returns empty dict for empty responses
            or dry-run operations.

        Raises:
        -------
        RuntimeError
            On HTTP 4xx errors (except 429) or after max retries exhausted.

        Dry-Run Behavior:
        -----------------
        In dry-run mode, mutating operations (POST, PUT, PATCH, DELETE) will
        print what would happen and return an empty dictionary without making
        the actual API call. GET operations are always executed.

        Retry Logic:
        ------------
        - Retries on HTTP 429 (rate limit) and 5xx (server errors)
        - Uses exponential backoff: 2, 4, 8, 16, 30 seconds (capped at 30)
        - Maximum 5 attempts before giving up
        """
        # Construct full URL from base and path
        url = f"{API_BASE}{path}"

        # In dry-run mode, don't execute mutating operations
        if self.dry_run and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            payload = kwargs.get("json")
            print(f"[DRY-RUN] {method} {url}" + (f" {payload}" if payload else ""))
            return {}

        # Retry loop with exponential backoff
        for attempt in range(1, 6):  # Attempts 1 through 5
            # Make the HTTP request
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)

            # Check for retryable conditions
            if resp.status_code == 429 or (500 <= resp.status_code < 600):
                # Calculate wait time with exponential backoff, capped at 30 seconds
                wait = min(2 ** attempt, 30)
                print(f"Retry {attempt}/5: {method} {path} -> {resp.status_code}; sleeping {wait}s")
                time.sleep(wait)
                continue  # Retry the request

            # Check for non-retryable errors
            if resp.status_code >= 400:
                # Raise an exception with details for debugging
                raise RuntimeError(f"{method} {path} failed: {resp.status_code} {resp.text}")

            # Success! Parse and return the JSON response
            # Handle empty responses (DELETE endpoints often return nothing)
            if resp.text.strip():
                return resp.json()
            return {}

        # All retry attempts exhausted
        raise RuntimeError(f"{method} {path} failed after retries")

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
            - id: Unique record identifier (needed for update/delete)
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
        records: List[Dict[str, Any]] = []
        page = 1

        # Paginate through all results
        while True:
            # Request current page of records
            data = self._request("GET", f"/domains/{domain}/records?page={page}&per_page=200")

            # Add records to our list
            records.extend(data.get("domain_records", []))

            # Check for more pages using the links.pages.next field
            pages = (data.get("links") or {}).get("pages") or {}
            if not pages.get("next"):
                break  # No more pages

            page += 1

        return records

    def delete_record(self, domain: str, record_id: int) -> None:
        """
        Delete a specific DNS record.

        Parameters:
        -----------
        domain : str
            The domain name (e.g., "example.com")

        record_id : int
            The unique identifier of the record to delete.
            Obtained from list_records().

        Notes:
        ------
        In dry-run mode, this prints what would be deleted without
        actually deleting anything.
        """
        self._request("DELETE", f"/domains/{domain}/records/{record_id}")

    def create_record(self, domain: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new DNS record.

        Parameters:
        -----------
        domain : str
            The domain name (e.g., "example.com")

        payload : Dict[str, Any]
            Record data. Required fields depend on record type:
            - type: Record type (MX, TXT, A, AAAA, CNAME, etc.)
            - name: Record name (@ for apex, or subdomain)
            - data: Record value
            - priority: Required for MX records
            - ttl: Optional, time to live

        Returns:
        --------
        Dict[str, Any]
            The created record data from the API response.
            Empty dict in dry-run mode.

        Notes:
        ------
        In dry-run mode, this prints what would be created without
        actually creating anything.
        """
        return self._request("POST", f"/domains/{domain}/records", json=payload)

    def update_record(self, domain: str, record_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing DNS record.

        Parameters:
        -----------
        domain : str
            The domain name (e.g., "example.com")

        record_id : int
            The unique identifier of the record to update.
            Obtained from list_records().

        payload : Dict[str, Any]
            Updated record data. Include only fields to change:
            - type: Record type
            - name: Record name
            - data: New record value
            - priority: New priority (for MX)
            - ttl: New TTL

        Returns:
        --------
        Dict[str, Any]
            The updated record data from the API response.
            Empty dict in dry-run mode.

        Notes:
        ------
        In dry-run mode, this prints what would be updated without
        actually updating anything.
        """
        return self._request("PUT", f"/domains/{domain}/records/{record_id}", json=payload)


# =============================================================================
# DNS RECORD OPERATIONS
# =============================================================================

def delete_matching_records(client: DOClient, zone: str, predicate, label: str) -> int:
    """
    Delete all DNS records in a zone that match a predicate function.

    This is a helper function for bulk-deleting records based on custom
    criteria (e.g., all DKIM records, all wildcard records, all MX records).

    Parameters:
    -----------
    client : DOClient
        The API client to use for fetching and deleting records

    zone : str
        The domain zone name (e.g., "example.com")

    predicate : Callable[[Dict], bool]
        A function that takes a record dict and returns True if the record
        should be deleted, False otherwise.

        Example predicates:
          - lambda r: r.get("type") == "MX"  # All MX records
          - lambda r: "_domainkey" in (r.get("name") or "")  # DKIM records
          - lambda r: (r.get("name") or "").startswith("*")  # Wildcards

    label : str
        Human-readable description of what's being deleted. Used in output
        messages (e.g., "DKIM records", "MX records", "wildcard records").

    Returns:
    --------
    int
        Number of records deleted

    Output:
    -------
    Prints status messages:
      - "  - Deleted N {label}" if records were deleted
      - "  = No {label} found" if no matching records existed
    """
    # Fetch current records
    records = client.list_records(zone)

    # Filter to records matching the predicate
    to_delete = [r for r in records if predicate(r)]

    # Delete each matching record
    for r in to_delete:
        client.delete_record(zone, r["id"])

    # Print status message
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
    Ensure exactly one TXT record exists with the specified name and value.

    This function implements an "upsert" (update or insert) operation for TXT
    records. It handles the complexity of:
    - Checking if a matching record already exists
    - Creating a new record if none exists
    - Updating an existing record if the value differs
    - Removing duplicate records if multiple exist
    - Optionally filtering by value prefix (e.g., only SPF records)

    Parameters:
    -----------
    client : DOClient
        The API client to use

    zone : str
        The domain zone name (e.g., "example.com")

    name : str
        The record name (e.g., "@" for apex, "_dmarc" for DMARC)

    value : str
        The desired TXT record value (written as-is, without quotes)

    match_prefix : Optional[str]
        If provided, only consider existing TXT records whose normalized
        data starts with this prefix (case-insensitive).

        This is important for SPF: we want to update/replace existing SPF
        records but NOT touch other TXT records at the apex (like domain
        verification records).

        Example: match_prefix="v=spf1" will only match records like:
          - "v=spf1 -all"
          - "v=spf1 include:example.com -all"
        And will ignore records like:
          - "google-site-verification=..."
          - "MS=..."

    Behavior:
    ---------
    1. If no matching record exists: Create a new TXT record
    2. If one record exists with correct value: Do nothing
    3. If one record exists with different value: Update it
    4. If multiple records exist: Keep the first, update if needed, delete extras

    Output:
    -------
    Prints status messages:
      - "  + TXT {name} = {value}" - Created new record
      - "  ~ TXT {name} updated" - Updated existing record
      - "  = TXT {name} already correct" - No change needed
      - "  - TXT {name} duplicate removed (id=N)" - Removed extra records
    """
    # Normalize the desired value for comparison
    desired_norm = normalize_txt_value(value)

    # Normalize the prefix for matching (if provided)
    prefix_norm = normalize_txt_value(match_prefix) if match_prefix else None

    # Fetch current records and find candidates
    records = client.list_records(zone)
    candidates: List[Dict[str, Any]] = []

    for r in records:
        # Must be a TXT record
        if r.get("type") != "TXT":
            continue

        # Must match the requested name
        if r.get("name") != name:
            continue

        # If prefix filtering is enabled, check the prefix
        data_norm = normalize_txt_value(r.get("data") or "")
        if prefix_norm and not data_norm.lower().startswith(prefix_norm.lower()):
            continue

        # This record is a candidate for update/delete
        candidates.append(r)

    # Case 1: No existing record - create new
    if not candidates:
        client.create_record(zone, {"type": "TXT", "name": name, "data": value})
        print(f"  + TXT {name} = {value}")
        return

    # Case 2+: At least one record exists
    # Keep the first candidate as the authoritative record
    keep = candidates[0]
    keep_norm = normalize_txt_value(keep.get("data") or "")

    # Update if the value differs
    if keep_norm != desired_norm:
        client.update_record(zone, keep["id"], {"type": "TXT", "name": name, "data": value})
        print(f"  ~ TXT {name} updated")
    else:
        print(f"  = TXT {name} already correct")

    # Delete any duplicate records (extras beyond the first)
    for extra in candidates[1:]:
        client.delete_record(zone, extra["id"])
        print(f"  - TXT {name} duplicate removed (id={extra['id']})")


def ensure_deadend_mx(client: DOClient, zone: str, mx_target: str, priority: int = 0) -> None:
    """
    Delete all MX records and create a single dead-end MX at the apex.

    This function ensures that a domain's inbound mail is directed to a
    non-functional destination, effectively disabling email delivery.

    Parameters:
    -----------
    client : DOClient
        The API client to use

    zone : str
        The domain zone name (e.g., "example.com")

    mx_target : str
        The hostname to use as the MX target. This should be a non-resolving
        or blackhole destination. Common choices:
          - "mail.invalid." (RFC 2606 reserved, recommended)
          - "." (null MX, RFC 7505)

    priority : int
        MX priority value. Default 0 (highest priority).
        Since we only have one MX, the priority doesn't matter much.

    Process:
    --------
    1. Delete ALL existing MX records (root and subdomains)
    2. Create a single MX record at '@' pointing to mx_target

    Why Delete All MX:
    ------------------
    We delete all MX records (not just root) because:
    - Subdomain MX records could still receive mail
    - A clean slate ensures predictable behavior
    - Leftover MX records could cause confusion

    Output:
    -------
    Prints status messages about deleted and created MX records.
    """
    # Step 1: Delete all existing MX records
    delete_matching_records(
        client,
        zone,
        lambda r: r.get("type") == "MX",
        "MX records"
    )

    # Step 2: Ensure the target has a trailing dot (FQDN format)
    mx_target = ensure_fqdn_dot(mx_target)

    # Step 3: Create the new dead-end MX record
    client.create_record(zone, {
        "type": "MX",
        "name": "@",
        "data": mx_target,
        "priority": priority
    })
    print(f"  + MX @ -> {mx_target} (priority {priority})")


# =============================================================================
# DOMAIN LOCKDOWN ROUTINE
# =============================================================================

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
    Apply comprehensive "no-mail" hardening to a single domain zone.

    This is the main operation function that orchestrates all the DNS changes
    needed to lock down a domain against email abuse.

    Parameters:
    -----------
    client : DOClient
        The API client to use

    domain : str
        The domain to lock down (e.g., "example.com")

    dmarc_report_domain : str
        Domain to receive DMARC aggregate reports.
        Used in the rua= tag of the DMARC record.

    dmarc_localpart_prefix : str
        Prefix for the plus-tagged email address receiving reports.
        Example: "DMARC" creates addresses like DMARC+domain@reports.tld

    delete_wildcards : bool
        If True, delete any DNS records whose name starts with '*'

    add_report_auth_zone : Optional[str]
        If provided, also create a DMARC report authorization record in
        this zone. This publishes:
          <domain>._report._dmarc.<add_report_auth_zone> TXT "v=DMARC1"

    deadend_mx_target : str
        Hostname to use as the dead-end MX target (e.g., "mail.invalid.")

    continue_on_error : bool
        If True, catch and log exceptions without re-raising, allowing
        the caller to continue with other domains.

    Steps Performed:
    ----------------
    1. Delete DKIM records (TXT/CNAME containing '_domainkey')
    2. Optionally delete wildcard records (names starting with '*')
    3. Set DMARC to strict reject policy with reporting
    4. Set SPF to deny all (v=spf1 -all)
    5. Replace MX with dead-end target
    6. Optionally add report authorization record in separate zone

    Output:
    -------
    Prints progress messages for each step, prefixed with the domain name.
    """
    print(f"\n== {domain} ==")

    try:
        # ---------------------------------------------------------------------
        # STEP 1: DELETE DKIM RECORDS
        # ---------------------------------------------------------------------
        # DKIM records contain '_domainkey' in their name (e.g., selector._domainkey)
        # They can be TXT (actual public keys) or CNAME (delegation to another domain)
        # For domains that don't send email, these should be removed
        delete_matching_records(
            client,
            domain,
            lambda r: (r.get("type") in ("TXT", "CNAME")) and ("_domainkey" in (r.get("name") or "")),
            "DKIM (_domainkey) records"
        )

        # ---------------------------------------------------------------------
        # STEP 2: OPTIONALLY DELETE WILDCARD RECORDS
        # ---------------------------------------------------------------------
        # Wildcard records have names starting with '*' (e.g., '*' or '*.sub')
        # These can have security implications and may interfere with subdomain policies
        if delete_wildcards:
            delete_matching_records(
                client,
                domain,
                lambda r: (r.get("name") or "").startswith("*"),
                "wildcard records (name startswith '*')"
            )

        # ---------------------------------------------------------------------
        # STEP 3: SET DMARC POLICY
        # ---------------------------------------------------------------------
        # DMARC tells receivers what to do with unauthenticated mail
        # We use the strictest settings:
        #   - p=reject: Reject unauthenticated mail at root domain
        #   - sp=reject: Same policy for subdomains
        #   - adkim=s: Strict DKIM alignment (exact domain match)
        #   - aspf=s: Strict SPF alignment (exact domain match)
        #   - pct=100: Apply to 100% of messages
        #   - rua: Where to send aggregate reports (using plus-tagging)
        rua = f"mailto:{dmarc_localpart_prefix}+{domain}@{dmarc_report_domain}"
        dmarc_value = f"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua={rua}"
        upsert_single_txt(client, domain, "_dmarc", dmarc_value)

        # ---------------------------------------------------------------------
        # STEP 4: SET SPF TO DENY ALL
        # ---------------------------------------------------------------------
        # SPF specifies which servers can send email for the domain
        # "v=spf1 -all" means NO servers are authorized (-all = hard fail)
        # We use match_prefix to only touch SPF records, not other TXT records
        upsert_single_txt(client, domain, "@", "v=spf1 -all", match_prefix="v=spf1")

        # ---------------------------------------------------------------------
        # STEP 5: REPLACE MX WITH DEAD-END
        # ---------------------------------------------------------------------
        # MX records tell senders where to deliver mail
        # By pointing to a non-resolving host, mail delivery will fail
        ensure_deadend_mx(client, domain, mx_target=deadend_mx_target, priority=0)

        # ---------------------------------------------------------------------
        # STEP 6: OPTIONALLY ADD DMARC REPORT AUTHORIZATION
        # ---------------------------------------------------------------------
        # For DMARC aggregate reports to be sent to a different domain,
        # some receivers require an authorization record in that domain's zone.
        # Format: <source-domain>._report._dmarc.<report-domain> TXT "v=DMARC1"
        if add_report_auth_zone:
            auth_name = f"{domain}._report._dmarc"
            upsert_single_txt(client, add_report_auth_zone, auth_name, "v=DMARC1")
            print(f"  + Report auth TXT in {add_report_auth_zone}: {auth_name} = v=DMARC1")

    except Exception as e:
        # Handle errors based on continue_on_error setting
        print(f"[ERROR] {domain}: {e}")
        if not continue_on_error:
            raise


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================

def main() -> None:
    """
    Main entry point for the mail lockdown script.

    This function:
    1. Parses command-line arguments
    2. Validates authentication
    3. Reads the domains file
    4. Processes each domain with lockdown operations

    Exit Codes:
    -----------
    0: Success (all domains processed)
    2: Missing authentication token
    """
    # -------------------------------------------------------------------------
    # ARGUMENT PARSING
    # -------------------------------------------------------------------------
    ap = argparse.ArgumentParser(
        description="Lock down domains in DigitalOcean DNS to send/receive no email.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication priority:
  1. .env file (DO_TOKEN=...)
  2. Environment variable (export DO_TOKEN=...)
  3. Command-line (--token ...)

Security tip: Use the .env file approach and set permissions with:
  chmod 600 .env

IMPORTANT: Always run with --dry-run first to preview changes!
        """
    )

    # Required: domains file
    ap.add_argument(
        "--domains-file",
        required=True,
        help="Text file of domains to lock down, one per line"
    )

    # Authentication
    ap.add_argument(
        "--token",
        default=None,
        help="DigitalOcean API token. Prefer using .env file or DO_TOKEN env var for security."
    )

    # Dry-run mode (HIGHLY RECOMMENDED for first runs)
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print intended API calls without making changes (RECOMMENDED for first run)"
    )

    # DMARC configuration
    ap.add_argument(
        "--dmarc-report-domain",
        default="example-report-domain.tld",
        help="Domain that receives DMARC aggregate reports (rua mailto:...)"
    )
    ap.add_argument(
        "--dmarc-localpart-prefix",
        default="DMARC",
        help="Local-part prefix for plus-tagged DMARC mailbox (e.g., DMARC+<domain>@<dmarc-report-domain>)"
    )

    # Optional: add authorization record in report destination zone
    ap.add_argument(
        "--report-auth-zone",
        default="",
        help='If set, also upsert TXT "<domain>._report._dmarc" = "v=DMARC1" into this zone'
    )

    # MX configuration
    ap.add_argument(
        "--deadend-mx-target",
        default="mail.invalid.",
        help="MX target used to blackhole inbound mail (will be forced to FQDN with trailing dot)"
    )

    # Optional: delete wildcard records
    ap.add_argument(
        "--delete-wildcards",
        action="store_true",
        help="Delete wildcard DNS records (names starting with '*')"
    )

    # Error handling
    ap.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue processing remaining domains if one fails"
    )

    # Parse arguments
    args = ap.parse_args()

    # -------------------------------------------------------------------------
    # TOKEN VALIDATION
    # -------------------------------------------------------------------------
    # Get token using priority: .env file > environment variable > CLI argument
    token = get_token(args.token)

    if not token:
        print("Error: Provide --token, set DO_TOKEN environment variable, or create .env file with DO_TOKEN=...")
        print("See --help for details on authentication options.")
        sys.exit(2)

    # -------------------------------------------------------------------------
    # READ DOMAINS FILE
    # -------------------------------------------------------------------------
    domains = read_domains_file(args.domains_file)
    if not domains:
        print("No domains found in domains file.")
        return

    print(f"Processing {len(domains)} domain(s)...")
    if args.dry_run:
        print("[DRY-RUN MODE] No changes will be made.\n")

    # -------------------------------------------------------------------------
    # PROCESS EACH DOMAIN
    # -------------------------------------------------------------------------
    # Normalize the report auth zone (empty string -> None)
    report_auth_zone = args.report_auth_zone.strip() or None

    # Initialize the API client
    client = DOClient(token, dry_run=args.dry_run)

    # Process each domain
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


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
