"""
Password-based file encryption.
AES-128 (Fernet, which is AES-CBC + HMAC) with a key derived from the user's
password via PBKDF2-HMAC-SHA256 (480,000 iterations). The password itself is
never written to disk anywhere — only a random salt travels with the file.
"""
import os
import re
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"PIIG1"          # format marker so we can tell our files apart from anything else
EXT = ".enc"
PBKDF2_ITERATIONS = 480_000


class WrongPassword(Exception):
    """Raised when decryption is attempted with the wrong password."""


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_file(path: str, password: str) -> dict:
    """
    Encrypt `path` in place: writes `path + '.enc'`, verifies it decrypts back
    to the exact original bytes, then deletes the original.
    Returns {"enc_path": ..., "sha256": ...} — sha256 is the ORIGINAL file's hash,
    so a restore can later be checked for integrity.
    """
    with open(path, "rb") as f:
        data = f.read()
    digest = sha256_of(data)

    salt = os.urandom(16)
    fernet = Fernet(_derive_key(password, salt))
    token = fernet.encrypt(data)
    blob = MAGIC + salt + token

    out_path = path + EXT
    with open(out_path, "wb") as f:
        f.write(blob)

    # verify before destroying the original — never trust-and-delete blindly
    restored = fernet.decrypt(token)
    if restored != data or sha256_of(restored) != digest:
        os.remove(out_path)
        raise RuntimeError("Could not verify the encrypted copy; original file was kept.")

    os.remove(path)
    return {"enc_path": out_path, "sha256": digest}


def decrypt_file(enc_path: str, password: str, expected_sha256: str | None = None) -> str:
    """Decrypt `enc_path`, write the original back, delete the .enc file, return its path."""
    with open(enc_path, "rb") as f:
        raw = f.read()
    if not raw.startswith(MAGIC):
        raise ValueError("This isn't a PII Guard encrypted file.")

    salt = raw[len(MAGIC): len(MAGIC) + 16]
    token = raw[len(MAGIC) + 16:]
    try:
        data = Fernet(_derive_key(password, salt)).decrypt(token)
    except InvalidToken:
        raise WrongPassword()

    if expected_sha256 and sha256_of(data) != expected_sha256:
        raise RuntimeError("Decrypted file doesn't match its original fingerprint.")

    out_path = enc_path[: -len(EXT)] if enc_path.endswith(EXT) else enc_path + ".restored"
    with open(out_path, "wb") as f:
        f.write(data)
    os.remove(enc_path)
    return out_path


# ---------------------------------------------------------------- password helpers
_COMMON_WEAK = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "111111"}


def password_strength(password: str) -> dict:
    """Simple, dependency-free strength check used by both the API and the UI hint."""
    if not password:
        return {"score": 0, "label": "empty", "tips": ["Enter a password."]}

    score = 0
    tips = []
    length = len(password)

    if length >= 6:
        score += 1
    if length >= 10:
        score += 1
    else:
        tips.append("Use at least 10 characters for a stronger lock.")
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("Mix uppercase and lowercase letters.")
    if re.search(r"\d", password):
        score += 1
    else:
        tips.append("Add a number.")
    if re.search(r"[^\w\s]", password):
        score += 1
    else:
        tips.append("Add a symbol like ! or #.")
    if password.lower() in _COMMON_WEAK:
        score = 0
        tips = ["That password is too common. Choose something unique to you."]

    label = ["very weak", "weak", "fair", "good", "strong", "very strong"][min(score, 5)]
    return {"score": min(score, 5), "label": label, "tips": tips[:2]}


def suggest_password() -> str:
    """A random, readable-ish strong password the user can copy if they want one."""
    import secrets, string
    words = ["Mint", "River", "Cedar", "Orbit", "Delta", "Pine", "Comet", "Lotus", "Amber", "Falcon"]
    w = secrets.choice(words) + secrets.choice(words)
    digits = "".join(secrets.choice(string.digits) for _ in range(3))
    symbol = secrets.choice("!@#$%*")
    return f"{w}{digits}{symbol}"
