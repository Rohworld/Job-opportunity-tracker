r"""
============================================================
  Job Opportunity Tracker
============================================================
  A generic job-posting change tracker. Point it at any company
  by editing config.json -- it diffs today's listings against a
  saved history file, reports only what's new, and generates a
  ready-to-send outreach message. Sensitive output can be
  auto-encrypted at the end of every run via security.py.

  HOW TO RUN:
  -----------
  1. Paste today's full job listing into jobs_input.json
     (replace the "jobs" array; keep the same field names).
  2. Run:
         python tracker.py
  3. Check data/daily_new_jobs.json and data/daily_outreach_list.txt
     for anything new.

  On the very first run there is no history yet, so every job in
  jobs_input.json will be reported as "new" -- that's expected,
  it's establishing the baseline.

  OPTIONAL FLAGS:
  ---------------
      python tracker.py --config other_company.json
      python tracker.py --encrypt        # force auto-encryption on
      python tracker.py --no-encrypt     # force it off, even if config says on

  SCHEDULING (so you don't have to remember to run it):
  ------------------------------------------------------
  macOS/Linux (crontab -e), run every morning at 9am:
      0 9 * * *  cd /path/to/razorpay-job-tracker && /usr/bin/python3 tracker.py

  Windows (Task Scheduler):
      Program/script : python
      Arguments      : tracker.py
      Start in       : C:\path\to\razorpay-job-tracker
      Trigger        : Daily, 9:00 AM
============================================================
"""

from __future__ import annotations

import json
import logging
import argparse
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("tracker")

DEFAULT_CONFIG_FILE = "config.json"


# ==================================================================
# CONFIG + I/O HELPERS
# ==================================================================

def load_config(path: str = DEFAULT_CONFIG_FILE) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}. "
            "Copy config.json and edit company_name / file paths for your use case."
        )
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_job_list(path: Path) -> list:
    """Reads a job list from either {'jobs': [...]} or a bare [...] JSON file."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("jobs", []) if isinstance(data, dict) else data


def dedupe(jobs: list, unique_key: str) -> tuple[list, int]:
    """Removes duplicate postings (LinkedIn sometimes surfaces the same one twice)."""
    seen = set()
    unique = []
    for job in jobs:
        jid = job.get(unique_key)
        if jid and jid not in seen:
            seen.add(jid)
            unique.append(job)
    return unique, len(jobs) - len(unique)


def find_new_jobs(current: list, historical: list, unique_key: str) -> list:
    """Returns jobs present in `current` but not in `historical`, matched by unique_key."""
    seen_ids = {job[unique_key] for job in historical if unique_key in job}
    return [job for job in current if job.get(unique_key) not in seen_ids]


def load_history(path: Path) -> list:
    if not path.exists():
        logger.warning("No history file found at %s -- starting fresh.", path)
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    jobs = data.get("jobs", [])
    logger.info(
        "History loaded <- %s (%d jobs, last updated: %s)",
        path, len(jobs), data.get("last_updated", "unknown"),
    )
    return jobs


def save_history(jobs: list, path: Path) -> None:
    payload = {
        "last_updated": datetime.now().isoformat(),
        "total_jobs": len(jobs),
        "jobs": jobs,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info("History saved -> %s (%d jobs recorded)", path, len(jobs))


def save_new_jobs(new_jobs: list, json_path: Path, txt_path: Path, config: dict) -> None:
    # Part A: structured JSON delta
    payload = {
        "run_date": datetime.now().isoformat(),
        "new_opportunities": len(new_jobs),
        "jobs": new_jobs,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info("New jobs saved -> %s (%d new opportunities)", json_path, len(new_jobs))

    # Part B: append email-ready plain text (accumulates a daily log)
    company = config.get("company_name", "Company")
    template = config.get("outreach_template", {})
    greeting = template.get("greeting", "Hi [Hiring Manager / Recruiter Name],")
    intro = template.get("intro", f"I noticed the following new openings at {company}.")
    closing = template.get("closing", "Please let me know if any of these roles could be a good fit.")
    signoff = template.get("signoff", "Best regards,\n[Your Name]")

    run_date_str = datetime.now().strftime("%d %B %Y, %I:%M %p")
    lines = [
        "=" * 60,
        f"  {company} -- New Job Openings",
        f"  Tracked on: {run_date_str}",
        "=" * 60,
        "",
    ]

    if new_jobs:
        lines += [greeting, "", intro, ""]
        for i, job in enumerate(new_jobs, start=1):
            lines.append(f"  {i}. {job.get('title', '(untitled)')}")
            lines.append(f"     Location : {job.get('location', 'n/a')}")
            lines.append(f"     Posted   : {job.get('posted', 'n/a')}")
            lines.append(f"     Link     : {job.get('url', 'n/a')}")
            lines.append("")
        lines += [closing, "", signoff]
    else:
        lines.append("  No new openings detected in this run.")

    lines += ["", "-" * 60, ""]

    with open(txt_path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    logger.info("Outreach text appended -> %s", txt_path)

    if new_jobs:
        preview = new_jobs[:3]
        logger.info("--- Email preview (first %d role(s)) ---", len(preview))
        for job in preview:
            logger.info("  * %s | %s", job.get("title"), job.get("url"))
        if len(new_jobs) > 3:
            logger.info("  ... and %d more (see %s)", len(new_jobs) - 3, txt_path)


# ==================================================================
# MAIN RUN
# ==================================================================

def run(config_path: str = DEFAULT_CONFIG_FILE, encrypt: bool | None = None) -> int:
    """Runs one full tracking cycle. Returns the number of new jobs found."""
    config = load_config(config_path)

    data_dir = Path(config.get("data_dir", "data"))
    data_dir.mkdir(exist_ok=True)

    input_file = Path(config["input_file"])
    history_file = data_dir / config.get("history_file", "history.json")
    new_jobs_file = data_dir / config.get("new_jobs_file", "daily_new_jobs.json")
    outreach_file = data_dir / config.get("outreach_file", "daily_outreach_list.txt")
    unique_key = config.get("unique_key", "job_id")

    logger.info(
        "=== %s Job Tracker | %s ===",
        config.get("company_name", "Job"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    logger.info("[1] Loading today's job list from %s ...", input_file)
    current_jobs = load_job_list(input_file)
    if not current_jobs:
        logger.warning(
            "No jobs found in %s -- did you paste today's listing in yet?", input_file
        )

    logger.info("[2] Deduplicating...")
    unique_current, dupes_removed = dedupe(current_jobs, unique_key)
    logger.info("%d unique job(s) (%d duplicate(s) removed)", len(unique_current), dupes_removed)

    logger.info("[3] Loading history and comparing...")
    historical = load_history(history_file)
    new_jobs = find_new_jobs(unique_current, historical, unique_key)

    logger.info("*** New opportunities found: %d ***", len(new_jobs))
    for i, job in enumerate(new_jobs, start=1):
        logger.info(
            "  %2d. [%s] %s -- %s",
            i, job.get("posted", "?"), job.get("title", "?"), job.get("url", "?"),
        )

    logger.info("[4] Saving results...")
    save_new_jobs(new_jobs, new_jobs_file, outreach_file, config)
    save_history(unique_current, history_file)

    should_encrypt = config.get("auto_encrypt", False) if encrypt is None else encrypt
    if should_encrypt:
        logger.info("[5] Auto-encryption is ON -- securing output...")
        try:
            from security import secure_run
            secure_run(target_dir=data_dir)
        except ImportError as e:
            logger.error(
                "Could not run security.py (%s). Make sure it's in the same folder "
                "and `pip install cryptography` has been run.", e,
            )
    else:
        logger.info("[5] Auto-encryption is OFF (enable in config.json or pass --encrypt).")

    logger.info("Done.")
    return len(new_jobs)


def main():
    parser = argparse.ArgumentParser(
        description="Track new job postings for any company by diffing against a saved history file."
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="Path to config.json (default: config.json)")
    parser.add_argument("--encrypt", action="store_true", help="Force auto-encryption on, overriding config.json")
    parser.add_argument("--no-encrypt", action="store_true", help="Force auto-encryption off, overriding config.json")
    args = parser.parse_args()

    encrypt = None
    if args.encrypt and args.no_encrypt:
        parser.error("--encrypt and --no-encrypt are mutually exclusive")
    elif args.encrypt:
        encrypt = True
    elif args.no_encrypt:
        encrypt = False

    run(config_path=args.config, encrypt=encrypt)


if __name__ == "__main__":
    main()
