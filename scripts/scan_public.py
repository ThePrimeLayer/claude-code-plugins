#!/usr/bin/env python3
"""Scan files bound for this public repository for personal data.

Generic checks (always on): home-directory paths with a username, email
addresses, and private or tailnet IPv4 addresses. Secrets are gitleaks' job.
Extra terms come from blocklist files given with --blocklist: one term per
line, '#' starts a comment, matched case-insensitively as a whole word.

Usage:
  python scripts/scan_public.py [PATH ...] [--blocklist FILE ...]
With no PATH, scans the files git tracks in the current repository.
Exits 1 and prints file:line for every hit.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".woff", ".woff2"}

# Placeholders like <you>, %USERNAME%, $USER and CI runners are fine.
GENERIC = {
    "windows home path": re.compile(r"[A-Za-z]:\\{1,2}Users\\{1,2}(?!Public\b|Default\b|<|%|\$|\{)[^\\/\s\"'<>`]+", re.I),
    "unix home path": re.compile(r"/(?:Users|home)/(?!<|\$|\{|runner\b|user\b|you\b|me\b|username\b)[A-Za-z0-9._-]+"),
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
    "private IPv4": re.compile(
        r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}\.\d{1,3}\b"
    ),
}

ALLOWED_EMAILS = re.compile(
    r"(?:^noreply@anthropic\.com$|@users\.noreply\.github\.com$|@example\.(?:com|org|net)$|^git@github\.com$)",
    re.I,
)


def load_blocklist(files: list[Path]) -> list[tuple[str, re.Pattern[str]]]:
    terms = []
    for file in files:
        if not file.exists():
            continue
        for line in file.read_text(encoding="utf-8").splitlines():
            term = line.split("#", 1)[0].strip()
            if term:
                terms.append((term, re.compile(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", re.I)))
    return terms


def files_to_scan(paths: list[str]) -> list[Path]:
    if not paths:
        out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True)
        return [Path(p) for p in out.stdout.decode().split("\0") if p]
    found: list[Path] = []
    for p in map(Path, paths):
        found.extend(f for f in p.rglob("*") if f.is_file() and ".git" not in f.parts) if p.is_dir() else found.append(p)
    return found


def scan(files: list[Path], blocklist: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    hits = []
    for file in files:
        if file.suffix.lower() in BINARY_SUFFIXES or not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in GENERIC.items():
                for match in pattern.finditer(line):
                    if label == "email address" and ALLOWED_EMAILS.search(match.group()):
                        continue
                    hits.append(f"{file}:{number}: {label}: {match.group()}")
            for term, pattern in blocklist:
                if pattern.search(line):
                    hits.append(f"{file}:{number}: blocklisted term: {term}")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--blocklist", action="append", type=Path, default=[])
    args = parser.parse_args()
    files = [f for f in files_to_scan(args.paths) if f.name != "scan_public.py"]
    hits = scan(files, load_blocklist(args.blocklist))
    for hit in hits:
        print(hit)
    if hits:
        print(f"\n{len(hits)} possible personal-data hit(s). Remove them, or use a placeholder like <you>.")
        return 1
    print(f"Clean: {len(files)} file(s) scanned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
