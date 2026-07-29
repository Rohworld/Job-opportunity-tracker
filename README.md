# Job Opportunity Tracker

A small Python system that watches a company's job postings, detects what's genuinely
*new* since the last check, and drafts a ready-to-send outreach message — with the
resulting data automatically PII-scanned, encrypted, and backed up.

Originally built to track roles at Razorpay, but the tracking logic is company-agnostic:
point it at any employer by editing `config.json`.

## Why this exists

Most people manually re-check a careers page every few days and lose track of what
they've already seen. This script keeps a persistent baseline of every posting it has
ever encountered, so each run only surfaces the delta — the postings that are actually
new — instead of re-reporting the same 20 roles every time.

## How it works

```
jobs_input.json  (you paste today's listing here)
        │
        ▼
   tracker.py  ──diff against──▶  data/history.json  (persistent baseline)
        │
        ├──▶ data/daily_new_jobs.json        (structured delta, machine-readable)
        ├──▶ data/daily_outreach_list.txt     (human-readable, ready to send)
        │
        ▼ (if auto_encrypt is on)
   security.py ──▶ PII scan ──▶ Fernet-encrypt ──▶ timestamped encrypted backup
```

1. **You paste today's job listing** into `jobs_input.json` (manually, or from
   whatever free/paid source you use to pull listings).
2. **`tracker.py`** deduplicates it, compares every posting's `job_id` against the
   saved history, and reports only what's new.
3. **New postings** get written to a structured JSON file and appended to a
   plain-text, outreach-ready message using the template in `config.json`.
4. **`security.py`** (optional, on by default off) scans the output for PII patterns,
   encrypts it in place with a password-derived key, and writes a rotating encrypted
   backup — automatically, at the end of every tracker run.

## Setup

```bash
git clone <this-repo>
cd razorpay-job-tracker
pip install -r requirements.txt
```

## Usage

1. Open `jobs_input.json` and replace the `jobs` array with today's full listing.
   Each entry needs at minimum: `job_id`, `title`, `location`, `posted`, `url`.
2. Run it:
   ```bash
   python tracker.py
   ```
3. Check what's new:
   - `data/daily_new_jobs.json` — structured, for feeding into another script/pipeline
   - `data/daily_outreach_list.txt` — plain text, ready to copy into an email

On the very first run there's no history yet, so everything in `jobs_input.json` will
be reported as new — that's expected, it's establishing the baseline. From the second
run onward, only genuinely new postings show up.

### Flags

```bash
python tracker.py --config other_company.json   # track a different company
python tracker.py --encrypt                     # force auto-encryption on for this run
python tracker.py --no-encrypt                  # force it off, overriding config.json
```

### Automating it

So you don't have to remember to run it:

**macOS/Linux** — `crontab -e`, run daily at 9am:
```
0 9 * * *  cd /path/to/razorpay-job-tracker && /usr/bin/python3 tracker.py
```

**Windows** — Task Scheduler:
- Program/script: `python`
- Arguments: `tracker.py`
- Start in: `C:\path\to\razorpay-job-tracker`
- Trigger: Daily, 9:00 AM

## Tracking a different company

1. Copy `config.json` to e.g. `acme.json` and edit `company_name` and the
   `outreach_template` fields.
2. Copy `jobs_input.json` to a matching input file and update `input_file` in your
   new config to point at it.
3. Run with `python tracker.py --config acme.json`.

Each config can point at its own `data_dir`, so multiple companies can be tracked
independently without their histories colliding.

## Security

- **PII scanning** runs before any encryption and flags emails, Indian mobile
  numbers, Aadhaar/PAN patterns, street addresses, and PIN codes — read-only, no
  files are modified by the scan itself.
- **Encryption** uses Fernet (AES-128 in CBC mode with HMAC authentication) with a
  key derived via PBKDF2-HMAC-SHA256 (390,000 iterations) from a master password —
  never store the password in code or version control.
- **Backups** are zipped, then the zip itself is encrypted; the last 7 are kept and
  older ones are pruned automatically.

Set your master password as an environment variable, never hard-code it:

```bash
export GTM_MASTER_PASS="your_password"      # macOS/Linux
$Env:GTM_MASTER_PASS = "your_password"      # Windows PowerShell
```

If `GTM_MASTER_PASS` isn't set, the tracker's auto-encrypt step logs a warning and
skips encryption for that run rather than failing or blocking on a prompt — you can
always run `python security.py` afterward to encrypt manually.

### Key rotation (recommended every ~90 days)

```bash
python security.py --decrypt          # with the OLD password
# confirm the plaintext looks right, update your password manager
rm data/gtm_key.salt                  # a new one is generated automatically
python security.py                    # with the NEW password
```

## Testing

```bash
pytest
```

Covers deduplication and new-job-detection logic against edge cases (empty history,
no changes, missing unique keys, duplicate IDs).

## Project structure

```
razorpay-job-tracker/
├── tracker.py           # core tracking logic + CLI
├── security.py          # PII scan / encrypt / decrypt / backup + CLI
├── config.json           # company name, file paths, outreach template
├── jobs_input.json        # today's listing (you edit this)
├── requirements.txt
├── tests/
│   └── test_tracker.py
└── data/                   # generated at runtime (gitignored)
    ├── history.json
    ├── daily_new_jobs.json
    ├── daily_outreach_list.txt
    ├── pii_scan_report.txt
    ├── gtm_key.salt
    └── secure_backups/
```

## Tech stack

Python 3.10+, `cryptography` (Fernet + PBKDF2), `pytest`. No external services or
paid APIs required to run the core tracker — see the project notes for how this
was adapted from a paid Clay.com-based GTM workflow into a zero-cost, self-hosted
version.
