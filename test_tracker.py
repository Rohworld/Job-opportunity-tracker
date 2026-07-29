"""
Unit tests for tracker.py's core logic (no filesystem, no network).
Run with:  pytest
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tracker import dedupe, find_new_jobs  # noqa: E402


def make_job(job_id, title="Test Role"):
    return {"job_id": job_id, "title": title, "location": "Remote", "posted": "2026-01-01", "url": "http://x"}


def test_dedupe_removes_duplicates():
    jobs = [make_job("1"), make_job("1"), make_job("2")]
    unique, removed = dedupe(jobs, "job_id")
    assert len(unique) == 2
    assert removed == 1


def test_dedupe_no_duplicates():
    jobs = [make_job("1"), make_job("2"), make_job("3")]
    unique, removed = dedupe(jobs, "job_id")
    assert len(unique) == 3
    assert removed == 0


def test_dedupe_handles_missing_key():
    jobs = [make_job("1"), {"title": "No ID field"}]
    unique, removed = dedupe(jobs, "job_id")
    # job with no job_id is dropped, not counted as a "kept" unique row
    assert len(unique) == 1
    assert removed == 1


def test_find_new_jobs_detects_new_entries():
    historical = [make_job("1"), make_job("2")]
    current = [make_job("1"), make_job("2"), make_job("3")]
    new = find_new_jobs(current, historical, "job_id")
    assert len(new) == 1
    assert new[0]["job_id"] == "3"


def test_find_new_jobs_empty_history_means_all_new():
    current = [make_job("1"), make_job("2")]
    new = find_new_jobs(current, [], "job_id")
    assert len(new) == 2


def test_find_new_jobs_no_changes_means_nothing_new():
    jobs = [make_job("1"), make_job("2")]
    new = find_new_jobs(jobs, jobs, "job_id")
    assert new == []
