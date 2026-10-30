"""
PII detection for Indian identity and financial documents.
Every function here returns only MASKED values — the raw number never leaves this module.
"""
import re

# ---------------------------------------------------------------- Verhoeff (Aadhaar checksum)
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]

def verhoeff_ok(num: str) -> bool:
    """True if a 12-digit string passes the Aadhaar Verhoeff checksum."""
    if not num.isdigit() or len(num) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0

def luhn_ok(num: str) -> bool:
    """True if a digit string passes the Luhn checksum (bank/credit cards)."""
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 12:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

# ---------------------------------------------------------------- Patterns
PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b")
AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)")
VOTER = re.compile(r"\b[A-Z]{3}[0-9]{7}\b")
DL = re.compile(r"\b[A-Z]{2}[0-9]{2}[\s-]?(?:19|20)[0-9]{2}[0-9]{7}\b")
PASSPORT = re.compile(r"\b[A-PR-WY][1-9]\d{6}[1-9]\b")
GSTIN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")
IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
UPI = re.compile(r"\b[\w.+-]{2,256}@(?:ok[a-z]+|ybl|ibl|axl|upi|paytm|apl|sbi|hdfcbank|icici|axisbank)\b", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b")
PHONE_IN = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
BANK_ACCOUNT = re.compile(r"\b\d{9,18}\b")

# context words that must appear near a weak/generic pattern before we trust it
_CTX = {
    "Bank Account": re.compile(r"account\s*(no|number|#)?|a/c|bank", re.I),
    "Phone": re.compile(r"phone|mobile|contact|cell|whatsapp", re.I),
    "Credit/Debit Card": re.compile(r"card|visa|mastercard|rupay|credit|debit", re.I),
    "Passport": re.compile(r"passport|republic of india", re.I),
}

def _near(text: str, match: re.Match, pattern: re.Pattern, window: int = 60) -> bool:
    lo, hi = max(0, match.start() - window), min(len(text), match.end() + window)
    return bool(pattern.search(text[lo:hi]))

def _mask(v: str) -> str:
    v = re.sub(r"\s", "", v)
    if "@" in v:                                   # email / UPI: keep first char + domain
        name, _, domain = v.partition("@")
        return (name[:1] or "•") + "•" * max(1, len(name) - 1) + "@" + domain
    return "•" * max(0, len(v) - 4) + v[-4:]

def detect(text: str) -> dict:
    """Scan one document's extracted text. Returns {type: [masked values, ...]}."""
    found = {}

    def add(key, values):
        vals = sorted({_mask(v) for v in values if v})
        if vals:
            found[key] = vals

    add("PAN", PAN.findall(text))
    add("Aadhaar", [m for m in AADHAAR.findall(text) if verhoeff_ok(re.sub(r"\s", "", m))])
    add("Voter ID", VOTER.findall(text))
    add("Driving Licence", DL.findall(text))
    add("GSTIN", GSTIN.findall(text))
    add("IFSC", IFSC.findall(text))
    add("UPI ID", UPI.findall(text))
    add("Email", EMAIL.findall(text))

    if _CTX["Passport"].search(text):
        add("Passport", PASSPORT.findall(text))

    phone_hits = [m for m in PHONE_IN.findall(text) if _near(text, re.search(re.escape(m), text), _CTX["Phone"])]
    add("Phone", phone_hits)

    card_hits = [re.sub(r"[ -]", "", m) for m in CARD.findall(text)]
    card_hits = [m for m in card_hits if luhn_ok(m) and
                 _near(text, re.search(re.escape(m[:4]), text) or re.search(m, text) or re.match(".", text), _CTX["Credit/Debit Card"])]
    add("Credit/Debit Card", card_hits)

    taken = set()
    for vals in found.values():
        taken.update(vals)
    bank_hits = []
    for m in BANK_ACCOUNT.finditer(text):
        val = m.group()
        if _mask(val) in taken:
            continue
        if _near(text, m, _CTX["Bank Account"]):
            bank_hits.append(val)
    add("Bank Account", bank_hits)

    return found

def risk_level(found: dict) -> str:
    """A simple severity label for the UI: high / medium / low."""
    high = {"Aadhaar", "PAN", "Passport", "Credit/Debit Card", "Bank Account"}
    if any(k in found for k in high):
        return "high"
    return "medium" if found else "low"
