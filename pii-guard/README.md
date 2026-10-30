# PII Guard

Finds personal ID numbers sitting in plain files on a PC — PAN, Aadhaar, Voter ID,
Driving Licence, Passport, bank account numbers, IFSC, GSTIN, UPI IDs, card numbers,
phone numbers, emails — and locks the files that contain them with a password you choose.

## What's in this project

```
pii-guard/
├── app.py              Flask web server + JSON API
├── config.py            all limits/paths/settings in one place
├── db.py                 Oracle database layer (vault, activity log, settings)
├── detector.py           the regex + checksum rules that find PII
├── extractor.py          reads text out of pdf/docx/xlsx/pptx/rtf/images/text
├── crypto_utils.py       AES (Fernet) encryption, password strength, checksums
├── logger_setup.py       shared rotating log file
├── cli.py                command-line tool (scan/lock/unlock without the browser)
├── schema.sql            reference copy of the table definitions
├── requirements.txt
├── .env.example
├── tests/                25 unit tests (detector, crypto, extractor)
└── static/
    ├── index.html
    ├── style.css
    └── app.js
```

## Setup

1. Install Python 3.10+ and (for images / scanned PDFs) [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki).
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and fill in your Oracle user, password and DSN
   (Oracle XE default DSN: `localhost:1521/XEPDB1`). The user needs `CREATE TABLE` rights.
4. `python app.py`, then open **http://127.0.0.1:5000**

Tables are created automatically on first start.

## Using it

- **Scan tab** — click **Protect this PC** to check Desktop, Documents, Downloads, Pictures
  and OneDrive across every drive, or scan one specific folder instead.
- Each result shows a **risk badge** (high / medium / low) and which ID types were found.
- Tick the files you want and click **Lock selected files** — set a password (a live strength
  meter shows how good it is) and the files are encrypted in place.
- **Locked files tab** — search, filter by status, and unlock a file with its password.
  Unlocking checks a stored SHA-256 fingerprint, so a damaged or tampered file is caught.
- **Activity tab** — every scan, lock, unlock and failed attempt, with CSV export.
- **Settings tab** — see exactly which folders get scanned, a chart of what's locked by
  type, and a password-strength tester with a one-click strong-password suggestion.

## Command line

```
python cli.py scan "C:\Users\You\Documents"        # just report what it finds
python cli.py scan "C:\Users\You\Documents" --lock   # report, then lock everything found
python cli.py lock "C:\path\file.pdf"                # lock one file
python cli.py unlock "C:\path\file.pdf.enc"          # unlock one file
python cli.py list                                   # list what's currently locked
```

## Running the tests

```
python -m unittest discover -s tests -v
```
25 tests cover the Verhoeff/Luhn checksums, PII pattern matching, the full encrypt →
verify → decrypt round trip, wrong-password handling, and text extraction.

## Auto-start on login (optional)

A web app can't switch itself on the moment Windows finishes installing it, but you can
make it start automatically: press `Win + R`, type `shell:startup`, and put a shortcut
to a `start.bat` (containing `python app.py`) in that folder. The same panel is explained
in-app under the Scan tab.

## How the security works

- Files are encrypted with **AES (via Fernet)**; the key is derived from your password
  with **PBKDF2-HMAC-SHA256, 480,000 iterations** — your password is never written to disk.
- Before deleting the original, the app re-decrypts the new `.enc` file and compares it
  byte-for-byte (and by SHA-256) to the original. If that check fails, the original is kept.
- Only **masked** values (`••••••1234`) ever reach the browser, the database or the logs —
  never a full ID number.
- The server listens on `127.0.0.1` only — nothing is exposed to your network.

## Known limits

- A lost password cannot be recovered — there is no backdoor, by design.
- Deleting the original file does not securely wipe it from an SSD.
- Files over 25 MB are skipped (change `MAX_FILE_BYTES` in `config.py`).
- `openpyxl`, `python-pptx` and `striprtf` are optional — without them, `.xlsx`, `.pptx`
  and `.rtf` files are simply skipped rather than causing an error.
