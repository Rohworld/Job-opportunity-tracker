"""
============================================================
  Data Security Utility
============================================================
  Provides:
    scan_for_pii()         -- read-only PII scan of .json/.txt files
    encrypt_data_folder()  -- Fernet-encrypts files in place
    decrypt_data_folder()  -- reverses encryption (key rotation / access)
    create_secure_backup() -- zips + encrypts a timestamped backup
    secure_run()           -- convenience wrapper called automatically
                               by tracker.py at the end of each run

  Install:  pip install cryptography

  ------------------------------------------------------------
  MASTER PASSWORD GUIDANCE
  ------------------------------------------------------------
  Set it as an environment variable before running -- never
  hard-code it here, and never commit it to version control:

      macOS/Linux :  export GTM_MASTER_PASS="your_password"
      Windows PS  :  $Env:GTM_MASTER_PASS = "your_password"

  If GTM_MASTER_PASS isn't set, secure_run() (used by tracker.py's
  auto-encrypt step) logs a warning and skips encryption instead
  of failing the whole tracker run or blocking on an interactive
  prompt. Running this file directly (`python security.py`) will
  still prompt for a password if the env var isn't set.

  ------------------------------------------------------------
  KEY ROTATION (every ~90 days, or if the password was exposed)
  ------------------------------------------------------------
    1. python security.py --decrypt          (with the OLD password)
    2. Confirm the plaintext files look correct.
    3. Update GTM_MASTER_PASS / your password manager.
    4. Delete data/gtm_key.salt (a fresh one is generated automatically).
    5. python security.py                    (with the NEW password)
============================================================
"""

from __future__ import annotations

import os
import re
import json
import zipfile
import secrets
import getpass
import logging
import argparse
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("security")

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


SENSITIVE_EXTENSIONS = {".json", ".txt"}
ENC_SUFFIX = ".enc"

# Add or remove patterns to tune the scanner. Each entry: (label, compiled_regex)
PII_PATTERNS = [
    ("Personal Email", re.compile(
        r"[a-zA-Z0-9._%+\-]+@(?!linkedin\.com|gmail\.com$)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        re.IGNORECASE,
    )),
    ("Email Address", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)),
    ("Phone (IN)", re.compile(r"(?:\+91[\s\-]?)?[6-9]\d{9}")),
    ("Phone (Intl)", re.compile(r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4}")),
    ("Aadhaar", re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")),
    ("PAN Card", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("Street Address", re.compile(
        r"(?:flat|plot|house|no\.?|door|block|sector|h\.?no\.?)\s*[\#\-]?\s*\d+", re.IGNORECASE,
    )),
    ("PIN Code", re.compile(r"\b[1-9]\d{5}\b")),
]


def _require_crypto() -> bool:
    if not CRYPTO_AVAILABLE:
        logger.error("The 'cryptography' package isn't installed. Run: pip install cryptography")
        return False
    return True


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=390_000, backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# ==================================================================
# SCAN
# ==================================================================

def scan_for_pii(
    target_dir: Path,
    extensions: set = SENSITIVE_EXTENSIONS,
    report_file: Path | None = None,
) -> dict:
    """Read-only PII scan. Writes a report and returns {filepath: [findings]}."""
    target_dir = Path(target_dir)
    report_file = report_file or target_dir / "pii_scan_report.txt"

    all_findings: dict[str, list] = {}
    for fpath in sorted(target_dir.rglob("*")):
        if not fpath.is_file():
            continue
        if fpath.suffix == ENC_SUFFIX or fpath.suffix not in extensions:
            continue
        if fpath.name == report_file.name:
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        findings = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, pattern in PII_PATTERNS:
                for match in pattern.finditer(line):
                    findings.append({"line": line_no, "type": label, "match": match.group(0)[:40]})
        if findings:
            all_findings[str(fpath)] = findings

    lines = [f"PII Scan Report -- {datetime.now().isoformat()}", "=" * 60]
    if all_findings:
        for fpath, findings in all_findings.items():
            lines.append(f"\n{fpath}")
            for f in findings:
                lines.append(f"  line {f['line']:>4} | {f['type']:<16} | {f['match']}")
    else:
        lines.append("No PII patterns detected.")
    report_file.write_text("\n".join(lines), encoding="utf-8")

    logger.info("PII scan complete: %d file(s) flagged -> %s", len(all_findings), report_file)
    return all_findings


# ==================================================================
# ENCRYPT / DECRYPT
# ==================================================================

def encrypt_data_folder(password: str, target_dir: Path, salt_file: Path | None = None) -> int:
    """Fernet-encrypts every sensitive file in target_dir in place. Returns count encrypted."""
    if not _require_crypto():
        return 0
    target_dir = Path(target_dir)
    salt_file = salt_file or target_dir / "gtm_key.salt"

    if salt_file.exists():
        salt = salt_file.read_bytes()
    else:
        salt = secrets.token_bytes(16)
        salt_file.write_bytes(salt)
        logger.info("New salt generated -> %s", salt_file)

    fern = Fernet(_derive_key(password, salt))

    count = 0
    for fpath in sorted(target_dir.rglob("*")):
        if not fpath.is_file() or fpath.suffix == ENC_SUFFIX or fpath.suffix not in SENSITIVE_EXTENSIONS:
            continue
        if fpath.name == salt_file.name:
            continue
        try:
            enc = fern.encrypt(fpath.read_bytes())
            fpath.with_suffix(fpath.suffix + ENC_SUFFIX).write_bytes(enc)
            fpath.unlink()
            count += 1
        except Exception as e:
            logger.error("Could not encrypt %s: %s", fpath.name, e)

    logger.info("%d file(s) encrypted in %s", count, target_dir)
    return count


def decrypt_data_folder(password: str, target_dir: Path, salt_file: Path | None = None) -> int:
    """Reverses encrypt_data_folder(). Use before rotating the master password."""
    if not _require_crypto():
        return 0
    target_dir = Path(target_dir)
    salt_file = salt_file or target_dir / "gtm_key.salt"

    if not salt_file.exists():
        logger.error("Salt file not found at %s -- cannot decrypt without it.", salt_file)
        return 0

    fern = Fernet(_derive_key(password, salt_file.read_bytes()))

    count = 0
    for fpath in sorted(target_dir.rglob(f"*{ENC_SUFFIX}")):
        original = fpath.with_suffix("")
        try:
            plaintext = fern.decrypt(fpath.read_bytes())
            original.write_bytes(plaintext)
            fpath.unlink()
            count += 1
        except InvalidToken:
            logger.error("%s: wrong password or corrupted file. Skipped.", fpath.name)
        except Exception as e:
            logger.error("%s: %s", fpath.name, e)

    logger.info("%d file(s) decrypted in %s", count, target_dir)
    return count


# ==================================================================
# BACKUP
# ==================================================================

def create_secure_backup(
    password: str,
    target_dir: Path,
    backup_dir: Path | None = None,
    keep: int = 7,
) -> Path | None:
    """Zips target_dir, Fernet-encrypts the archive, and prunes old backups."""
    if not _require_crypto():
        return None
    target_dir = Path(target_dir)
    backup_dir = backup_dir or target_dir / "secure_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = backup_dir / f"gtm_backup_{timestamp}.zip"
    enc_path = backup_dir / f"gtm_backup_{timestamp}.zip.enc"

    files = [
        f for f in sorted(target_dir.rglob("*"))
        if f.is_file() and backup_dir not in f.parents
    ]
    if not files:
        logger.warning("No files found to back up in %s", target_dir)
        return None

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, f.relative_to(target_dir))

    salt_file = target_dir / "gtm_key.salt"
    if salt_file.exists():
        salt = salt_file.read_bytes()
    else:
        salt = secrets.token_bytes(16)
        salt_file.write_bytes(salt)

    fern = Fernet(_derive_key(password, salt))
    zip_bytes = zip_path.read_bytes()
    enc_path.write_bytes(fern.encrypt(zip_bytes))

    # Overwrite the intermediate plaintext zip before deleting it
    zip_path.write_bytes(b"\x00" * len(zip_bytes))
    zip_path.unlink()

    archives = sorted(backup_dir.glob("gtm_backup_*.zip.enc"), reverse=True)
    for old in archives[keep:]:
        old.unlink()
        logger.info("Pruned old backup: %s", old.name)

    logger.info("Encrypted backup created -> %s", enc_path)
    return enc_path


# ==================================================================
# CONVENIENCE WRAPPER (used automatically by tracker.py)
# ==================================================================

def secure_run(target_dir: Path, backup: bool = True) -> bool:
    """
    Scans, encrypts, and backs up target_dir using GTM_MASTER_PASS from
    the environment. Designed to run unattended -- if no password is
    set, it logs a warning and returns False instead of prompting or
    raising, so it never blocks an automated tracker.py run.
    """
    if not _require_crypto():
        return False

    password = os.environ.get("GTM_MASTER_PASS")
    if not password:
        logger.warning(
            "GTM_MASTER_PASS not set -- skipping auto-encryption this run. "
            "Set it with: export GTM_MASTER_PASS='yourpassword' "
            "(or run `python security.py` manually to be prompted)."
        )
        return False

    scan_for_pii(target_dir)
    encrypt_data_folder(password, target_dir)
    if backup:
        create_secure_backup(password, target_dir)
    return True


# ==================================================================
# STANDALONE CLI
# ==================================================================

def main():
    parser = argparse.ArgumentParser(description="Scan, encrypt, decrypt, or back up sensitive tracker output.")
    parser.add_argument("--dir", default="data", help="Target directory (default: data)")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt instead of encrypt")
    parser.add_argument("--scan-only", action="store_true", help="Only run the PII scan, no encryption")
    parser.add_argument("--no-backup", action="store_true", help="Skip creating a backup archive")
    args = parser.parse_args()

    target_dir = Path(args.dir)
    target_dir.mkdir(exist_ok=True)

    findings = scan_for_pii(target_dir)
    if findings:
        print(f"\n[!] PII detected in {len(findings)} file(s) -- review pii_scan_report.txt")
        answer = input("Continue anyway? [y/N]: ").strip().lower()
        if answer != "y":
            print("Exiting. No files were modified.")
            return

    if args.scan_only:
        return

    password = os.environ.get("GTM_MASTER_PASS") or getpass.getpass("Password: ")
    if not password:
        print("No password provided. Exiting.")
        return

    if args.decrypt:
        decrypt_data_folder(password, target_dir)
        return

    salt_file = target_dir / "gtm_key.salt"
    if not salt_file.exists():
        confirm = os.environ.get("GTM_MASTER_PASS") or getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Exiting.")
            return

    encrypt_data_folder(password, target_dir)
    if not args.no_backup:
        create_secure_backup(password, target_dir)


if __name__ == "__main__":
    main()
