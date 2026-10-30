"""Central configuration for PII Guard. Change limits and folders here, nowhere else."""
import os

APP_NAME = "PII Guard"
HOST = "127.0.0.1"
PORT = 5000

# --- Scanning limits ---
MAX_FILE_BYTES = 25 * 1024 * 1024          # skip anything bigger than this
MAX_OCR_PAGES = 5                          # pages of a scanned PDF to OCR before giving up
RESULTS_PAGE_SIZE = 50

SKIP_DIR_NAMES = {
    "windows", "program files", "program files (x86)", "programdata", "appdata",
    "node_modules", ".git", "$recycle.bin", "system volume information", "__pycache__",
    "library", "system", "snap", "proc", "sys", ".cache", "venv", ".venv", "env",
}

PERSONAL_SUBFOLDERS = [
    "", "Desktop", "Documents", "Downloads", "Pictures",
    "OneDrive", "OneDrive/Desktop", "OneDrive/Documents",
    "Documents/Scans", "Documents/ID Proofs", "Documents/KYC",
]

# --- Password policy ---
MIN_PASSWORD_LEN = 6
RECOMMENDED_PASSWORD_LEN = 10

# --- Database ---
DEFAULT_DSN = "localhost:1521/XEPDB1"

# --- Logging ---
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pii_guard.log")
LOG_MAX_BYTES = 1_000_000
LOG_BACKUPS = 3

# --- PII type -> short description shown in the UI ---
PII_DESCRIPTIONS = {
    "PAN": "Income Tax PAN card number",
    "Aadhaar": "UIDAI Aadhaar number",
    "Voter ID": "Election Commission EPIC number",
    "Driving Licence": "RTO driving licence number",
    "Passport": "Indian passport number",
    "Bank Account": "Bank account number",
    "IFSC": "Bank branch IFSC code",
    "GSTIN": "GST registration number",
    "UPI ID": "UPI payment address",
    "Credit/Debit Card": "Payment card number",
    "Phone": "Mobile phone number",
    "Email": "Email address",
}
