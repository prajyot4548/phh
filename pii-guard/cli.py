"""
Command-line interface for PII Guard — useful for scripting or for PCs without a browser handy.

Examples:
    python cli.py scan "C:\\Users\\You\\Documents"
    python cli.py lock "C:\\path\\file.pdf"
    python cli.py unlock "C:\\path\\file.pdf.enc"
    python cli.py list
"""
import argparse
import getpass
import os
import sys

from detector import detect, risk_level
from extractor import extract_text, SUPPORTED
from crypto_utils import encrypt_file, decrypt_file, WrongPassword, password_strength
import config
from logger_setup import get_logger

log = get_logger("cli")


def cmd_scan(args):
    folder = os.path.abspath(args.folder)
    if not os.path.isdir(folder):
        print(f"Folder not found: {folder}")
        sys.exit(1)

    found, scanned, skipped = [], 0, 0
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in config.SKIP_DIR_NAMES]
        for name in files:
            path = os.path.join(root, name)
            if os.path.splitext(name)[1].lower() not in SUPPORTED:
                continue
            try:
                if os.path.getsize(path) > config.MAX_FILE_BYTES:
                    skipped += 1
                    continue
                scanned += 1
                hits = detect(extract_text(path))
                if hits:
                    found.append((path, hits))
            except Exception as e:
                log.warning("Skipping %s: %s", path, e)
                skipped += 1

    print(f"\nScanned {scanned} file(s), skipped {skipped}.")
    if not found:
        print("No personal ID numbers found. This folder looks clean.")
        return
    print(f"{len(found)} file(s) contain personal information:\n")
    for path, hits in found:
        print(f"  [{risk_level(hits).upper()}] {path}")
        for k, v in hits.items():
            print(f"      {k}: {', '.join(v)}")
    if args.lock:
        pw = getpass.getpass("\nEnter a password to lock all of these: ")
        confirm = getpass.getpass("Repeat password: ")
        if pw != confirm:
            print("Passwords did not match. Nothing was locked.")
            return
        for path, hits in found:
            try:
                encrypt_file(path, pw)
                print(f"Locked: {path}")
            except Exception as e:
                print(f"Could not lock {path}: {e}")


def cmd_lock(args):
    if not os.path.isfile(args.file):
        print("File not found."); sys.exit(1)
    pw = getpass.getpass("Password: ")
    confirm = getpass.getpass("Repeat password: ")
    if pw != confirm:
        print("Passwords did not match."); sys.exit(1)
    strength = password_strength(pw)
    print(f"Password strength: {strength['label']}")
    info = encrypt_file(args.file, pw)
    print(f"Locked -> {info['enc_path']}")


def cmd_unlock(args):
    if not os.path.isfile(args.file):
        print("File not found."); sys.exit(1)
    pw = getpass.getpass("Password: ")
    try:
        out = decrypt_file(args.file, pw)
        print(f"Unlocked -> {out}")
    except WrongPassword:
        print("Wrong password.")
        sys.exit(1)


def cmd_list(args):
    import db
    data = db.list_files(status="ENCRYPTED", page=1, page_size=200)
    if not data["rows"]:
        print("No locked files.")
        return
    for r in data["rows"]:
        print(f"#{r['id']:<5} {r['original_path']}  [{r['pii_types']}]")


def main():
    parser = argparse.ArgumentParser(prog="pii-guard", description=config.APP_NAME + " command-line tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a folder for personal ID numbers")
    p_scan.add_argument("folder")
    p_scan.add_argument("--lock", action="store_true", help="lock everything found, after confirming a password")
    p_scan.set_defaults(func=cmd_scan)

    p_lock = sub.add_parser("lock", help="encrypt a single file")
    p_lock.add_argument("file")
    p_lock.set_defaults(func=cmd_lock)

    p_unlock = sub.add_parser("unlock", help="decrypt a single .enc file")
    p_unlock.add_argument("file")
    p_unlock.set_defaults(func=cmd_unlock)

    p_list = sub.add_parser("list", help="list locked files recorded in the database")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
