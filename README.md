# DigitalOcean DNS Mail Lockdown + Audit Tools

A small set of scripts for managing email-related DNS posture across many domains hosted on **DigitalOcean DNS**.

These tools are designed for two common scenarios:

1. **Most domains should never send or receive email**  
   You want to prevent spoofing and disable inbound mail by enforcing:
   - SPF: `v=spf1 -all`
   - DMARC: `p=reject` with strict alignment
   - MX: dead-end mail target (default `mail.invalid.`)
   - Remove DKIM records and (optionally) wildcard DNS records

2. **A small subset of domains legitimately process mail**  
   You want to audit all domains and quickly identify outliers and misconfigurations.

---

## Contents

- [`lockdown_mail.py`](#lockdown_mailpy) — Apply "no-mail" hardening to a list of domains
- [`do_dns_audit.py`](#do_dns_auditpy) — Per-domain audit (flat, detailed) with record dumps + a text report
- [`do_dns_audit_grouped.py`](#do_dns_audit_groupedpy) — Grouped audit (cluster domains with identical posture) + a text report
- [Prerequisites](#prerequisites)
- [Authentication](#authentication)
- [Quick Start](#quick-start)
- [Common Issues](#common-issues)
- [License](#license)

---

## Prerequisites

### 1) DigitalOcean DNS
These scripts use the DigitalOcean Domains API and assume your DNS zones are managed in DigitalOcean.

### 2) Python
- Python 3.9+ recommended (3.8 may work, but 3.9+ is a safer baseline).

### 3) Python dependency
Install `requests`:

```bash
python3 -m pip install requests
```


---

## Authentication

Create a **DigitalOcean Personal Access Token** with sufficient permissions to read/write DNS records.

### Authentication Priority

All scripts check for authentication credentials in this order:

1. **`.env` file (recommended)** - Most secure for local development
2. **Environment variable** - Good for CI/CD and containers
3. **Command-line `--token`** - Convenient for one-off runs, but visible in shell history

### Option 1: `.env` File (Recommended)

Create a `.env` file in the project directory:

```bash
# Create the file
echo 'DO_TOKEN="dop_v1_your_token_here"' > .env

# Set restrictive permissions (IMPORTANT!)
chmod 600 .env
```

**Why use `.env`?**
- Token is not visible in shell history
- Token is not visible in process listings (`ps aux`)
- File is automatically excluded from git via `.gitignore`
- Easy to manage across development sessions

**Security Note:** Always set restrictive permissions on your `.env` file:
```bash
chmod 600 .env   # Only owner can read/write
```

Verify permissions:
```bash
ls -la .env
# Should show: -rw-------
```

### Option 2: Environment Variable

Export the token in your shell:

```bash
export DO_TOKEN="dop_v1_..."
```

Add to your shell profile (`~/.bashrc`, `~/.zshrc`) for persistence:

```bash
echo 'export DO_TOKEN="dop_v1_..."' >> ~/.bashrc
source ~/.bashrc
```

### Option 3: Command-Line Argument

Pass the token directly (least secure - visible in shell history):

```bash
python3 do_dns_audit.py --token "dop_v1_..."
```

**Warning:** Command-line arguments are visible in `ps aux` output and shell history. Avoid this method for production use.

---

## Script: `lockdown_mail.py`

Bulk hardening for domains that should **never send or receive email**.

### What it does

For each domain you provide:

1. **Deletes DKIM records**

   * Removes TXT and CNAME records whose `name` contains `_domainkey`

2. **Sets DMARC to enforce rejection**

   * Writes a DMARC record at `_dmarc`:

     ```
     v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:<PREFIX>+<DOMAIN>@<DMARC_REPORT_DOMAIN>
     ```
   * Uses strict alignment (`adkim=s`, `aspf=s`)

3. **Sets SPF to authorize nobody**

   * Ensures there is exactly one SPF record at `@`:

     ```
     v=spf1 -all
     ```
   * It only targets TXT records at `@` that begin with `v=spf1` to avoid clobbering unrelated verification TXT records.

4. **Replaces MX records with a dead-end**

   * Deletes all MX records, then creates:

     * `MX @ -> mail.invalid.` (priority 0 by default)

5. Optional: **Deletes wildcard records**

   * Removes any record whose `name` begins with `*`

6. Optional: **Adds DMARC report receiver authorization**

   * Writes a TXT record in a separate zone (the DMARC report receiving domain):

     * `<DOMAIN>._report._dmarc` = `v=DMARC1`
   * This helps some receivers send aggregate DMARC reports (rua) to a different domain.

### Inputs

Create a domains file, one per line:

```txt
# domains.txt
example.com
example.net
example.org
```

### Flags

* `--domains-file PATH` (required)
  File containing domains to lock down.

* `--token TOKEN`
  DigitalOcean API token (or use `DO_TOKEN`).

* `--dry-run`
  Print intended API calls without making changes.

* `--dmarc-report-domain DOMAIN`
  The domain that receives DMARC aggregate reports (rua).

* `--dmarc-localpart-prefix PREFIX`
  Prefix used for plus-tagged DMARC mailbox local-part (default `DMARC`):
  `DMARC+<domain>@<dmarc-report-domain>`

* `--report-auth-zone ZONE`
  If set, also upserts `<domain>._report._dmarc` TXT `v=DMARC1` into this zone.

* `--deadend-mx-target HOST`
  MX target used to disable inbound mail (default `mail.invalid.`).
  DigitalOcean requires a trailing dot for MX targets; the script enforces this.

* `--delete-wildcards`
  Delete wildcard records (`*`).

* `--continue-on-error`
  Continue processing remaining domains if one domain fails.

### Examples

**Dry-run first (recommended):**

```bash
python3 lockdown_mail.py --domains-file domains.txt --dry-run
```

**Apply changes:**

```bash
python3 lockdown_mail.py --domains-file domains.txt
```

**Send DMARC reports to a separate domain and add report authorization records:**

```bash
python3 lockdown_mail.py \
  --domains-file domains.txt \
  --dmarc-report-domain dmarc-reports.example \
  --dmarc-localpart-prefix DMARC \
  --report-auth-zone dmarc-reports.example
```

**Delete wildcard records too:**

```bash
python3 lockdown_mail.py --domains-file domains.txt --delete-wildcards
```

---

## Script: `do_dns_audit.py`

A detailed, per-domain audit that:

* Lists every domain
* Fetches all DNS records for each domain
* Writes a JSON dump of each domain’s records
* Prints a per-domain summary to stdout
* Writes a single consolidated, human-friendly text report

### What it checks

* Root MX records and posture:

  * `dead` if root MX targets are all `--dead-mx-host`
  * `active` if MX exists and not dead-end
  * `none` if no MX exists

* Root SPF TXT records (TXT at `@` that begins with `v=spf1`)

* DMARC TXT (`_dmarc`)

* DKIM-ish record count (`_domainkey` in TXT/CNAME names)

* Wildcard record count (`*`)

### Flags

* `--token TOKEN`
  DigitalOcean token (or `DO_TOKEN`)

* `--outdir DIR`
  Where record dump JSON files are written
  Default: `/tmp/do_dns_audit_<timestamp>/`

* `--report-file PATH`
  Where to write the pretty text report
  Default: `/tmp/do_dns_audit_report_<timestamp>.txt`

* `--mail-domains-file PATH`
  Allowlist of domains expected to process mail
  Used to flag WARN/ERROR

* `--dead-mx-host HOST`
  Hostname treated as the “dead mail” MX target (default `mail.invalid`)

* `--dump-json` / `--dump_json`
  Also write `summary.json` and `summary.ndjson` to `--outdir`

### Examples

**Run an audit (outputs default to `/tmp`):**

```bash
python3 do_dns_audit.py
```

**Audit and flag unexpected/incorrect mail posture:**

```bash
python3 do_dns_audit.py --mail-domains-file mail_domains.txt
```

**Specify report output:**

```bash
python3 do_dns_audit.py --report-file ./dns_audit_report.txt
```

---

## Script: `do_dns_audit_grouped.py`

A grouped audit that clusters domains by an “email posture signature,” so you can instantly see:

* The large group of domains that match your standard
* Small groups of outliers (e.g., mail-processing domains, or misconfigured domains)

### Output behavior

By default:

* Prints grouped summary to stdout (with truncated domain lists)
* Writes a full grouped TXT report (with every domain listed) to `/tmp`

Optional JSON outputs and record dumps are opt-in.

### Flags

* `--token TOKEN`
  DigitalOcean token (or `DO_TOKEN`)

* `--mail-domains-file PATH`
  Allowlist of domains expected to process mail (WARN/ERROR grouping)

* `--dead-mx-host HOST`
  Hostname treated as the “dead mail” MX target (default `mail.invalid`)

* `--show-all`
  Print all domains per group to stdout (no truncation)

* `--show-domains-per-group N`
  How many domains to show per group in stdout (ignored if `--show-all`)

* `--report-file PATH`
  Where to write the grouped TXT report
  Default: `/tmp/do_dns_audit_grouped_report_<timestamp>.txt`

* `--dump-records`
  Write `<domain>.records.json` for each domain to `--outdir`

* `--dump-json` / `--dump_json`
  Write `summary.json`, `summary.ndjson`, and `groups.json` to `--outdir`

* `--outdir DIR`
  Where JSON outputs go
  Default when dumping: `/tmp/do_dns_audit_grouped_<timestamp>/`

### Examples

**Grouped audit:**

```bash
python3 do_dns_audit_grouped.py
```

**Show every domain under each group in stdout:**

```bash
python3 do_dns_audit_grouped.py --show-all
```

**Use allowlist for mail-processing domains:**

```bash
python3 do_dns_audit_grouped.py --mail-domains-file mail_domains.txt
```

**Dump JSON summaries and per-domain records:**

```bash
python3 do_dns_audit_grouped.py --dump-json --dump-records --outdir ./audit_out
```

---

## Allowlist File Format (`--mail-domains-file`)

A plain text file, one domain per line:

```txt
# mail_domains.txt
mail-primary.example
support.example
example.com
```

* Blank lines are ignored
* Lines starting with `#` are comments

---

## Common Issues

### 1) "I'm getting 401 Unauthorized"

**Cause:** Missing/invalid DigitalOcean token, or token lacks permissions.
**Fix:**

* If using `.env` file, verify it exists and has the correct format:

  ```bash
  cat .env
  # Should show: DO_TOKEN="dop_v1_..."
  ```
* If using environment variable, confirm you exported the token:

  ```bash
  echo "$DO_TOKEN"
  ```
* Verify your token has the correct permissions in DigitalOcean dashboard.
* Create a new token in DigitalOcean with appropriate permissions if needed.

---

### 1.5) "Token not being read from .env file"

**Cause:** `.env` file format issues or wrong location.
**Fix:**

* Ensure the `.env` file is in the same directory where you run the script
* Verify the format is correct (no extra spaces around `=`):

  ```bash
  # Correct format:
  DO_TOKEN="dop_v1_abc123..."

  # Also valid:
  DO_TOKEN=dop_v1_abc123...
  DO_TOKEN='dop_v1_abc123...'
  ```
* Check file permissions allow reading:

  ```bash
  ls -la .env
  chmod 600 .env  # Fix if needed
  ```

---

### 2) “MX record creation fails / Data needs to end with a dot (.)”

DigitalOcean requires MX targets to be a fully-qualified domain name ending in `.`.

**Fix:**

* Use `mail.invalid.` (with trailing dot) as the MX target.
* `lockdown_mail.py` already enforces the trailing dot automatically for MX targets.

---

### 3) “TXT records look quoted / my values don’t match”

DNS dashboards often display quotes around TXT values, but different systems store them differently.

**Fix:**

* The scripts normalize TXT values by stripping wrapping quotes for comparisons.
* Prefer storing values without quotes in DNS UIs.

---

### 4) “DMARC reports aren’t arriving at my report inbox”

Some receivers require that the destination domain explicitly authorize report receipt.

**Fix:**

* Use `lockdown_mail.py` with `--report-auth-zone <DMARC_REPORT_DOMAIN>` to publish:

  ```
  <DOMAIN>._report._dmarc.<DMARC_REPORT_DOMAIN> TXT "v=DMARC1"
  ```
* Ensure your `rua=` address points to an inbox that exists and can receive mail.

---

### 5) “A few domains really DO send/receive mail. How do I avoid breaking them?”

**Fix:**

* Do **not** include those domains in `lockdown_mail.py` input.
* Use the audit scripts with `--mail-domains-file` to verify posture:

  * allowlisted domains should be `active`
  * non-allowlisted domains should be `dead` or `none` (depending on your standard)

---

### 6) “The scripts are writing files but I can’t find them”

By default, outputs are written under `/tmp` with timestamped names.

**Fix:**

* Look in `/tmp`:

  ```bash
  ls -la /tmp | grep do_dns_audit
  ```
* Or set explicit paths with `--outdir` and `--report-file`.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
## Credits
**Author:** Léon "Avic" Simmons ([@Avicennasis](https://github.com/Avicennasis))
