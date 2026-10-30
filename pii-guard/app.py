"""
PII Guard backend.
Run:  python app.py   ->   http://127.0.0.1:5000
Serves the frontend in static/, and a JSON API the frontend (and cli.py) both use.
"""
import os
import string
import platform
from flask import Flask, jsonify, request, send_from_directory, Response

import config
import db
from detector import detect, risk_level
from extractor import extract_text, SUPPORTED
from crypto_utils import encrypt_file, decrypt_file, WrongPassword, password_strength, suggest_password, EXT
from logger_setup import get_logger

log = get_logger("app")
app = Flask(__name__, static_folder="static", static_url_path="")


def err(msg, code=400):
    log.warning("400 response: %s", msg)
    return jsonify({"error": msg}), code


# ---------------------------------------------------------------- folder discovery
def personal_folders():
    """Every personal folder worth checking: this PC's home dir subfolders,
    plus the same subfolders on every other drive that has a user profile."""
    results = []
    home = os.path.expanduser("~")
    for sub in config.PERSONAL_SUBFOLDERS:
        p = os.path.join(home, sub) if sub else home
        if os.path.isdir(p):
            results.append(p)

    if platform.system() == "Windows":
        user = os.path.basename(home)
        home_drive = os.path.splitdrive(home)[0].upper()
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if f"{letter}:" == home_drive or not os.path.isdir(root):
                continue
            for base in (os.path.join(root, "Users", user), root):
                for sub in config.PERSONAL_SUBFOLDERS:
                    if not sub:
                        continue
                    p = os.path.join(base, sub)
                    if os.path.isdir(p):
                        results.append(p)

    uniq = []
    for p in results:
        if not any(os.path.commonpath([p, u]) == u for u in uniq):
            uniq.append(p)
    return uniq


def _walk_scan(folders):
    results, scanned, skipped = [], 0, 0
    for folder in folders:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d.lower() not in config.SKIP_DIR_NAMES and not d.startswith(".")]
            for name in files:
                path = os.path.join(root, name)
                if os.path.splitext(name)[1].lower() not in SUPPORTED:
                    continue
                try:
                    size = os.path.getsize(path)
                    if size > config.MAX_FILE_BYTES:
                        skipped += 1
                        continue
                    scanned += 1
                    hits = detect(extract_text(path))
                    if hits:
                        results.append({
                            "path": path, "name": name, "found": hits, "size": size,
                            "risk": risk_level(hits),
                        })
                except Exception as e:
                    log.warning("Skip %s: %s", path, e)
                    skipped += 1
    results.sort(key=lambda r: {"high": 0, "medium": 1, "low": 2}[r["risk"]])
    return results, scanned, skipped


# ---------------------------------------------------------------- static / pages
@app.get("/")
def index():
    return send_from_directory("static", "index.html")


# ---------------------------------------------------------------- scanning
@app.post("/api/scan")
def scan():
    folder = os.path.abspath((request.json or {}).get("folder", "").strip().strip('"'))
    if not os.path.isdir(folder):
        return err("That folder doesn't exist. Check the path and try again.")
    results, scanned, skipped = _walk_scan([folder])
    db.log("SCAN", f"{folder}: {scanned} scanned, {len(results)} with personal info")
    return jsonify({"scanned": scanned, "skipped": skipped, "results": results, "folders": [folder]})


@app.post("/api/scan-system")
def scan_system():
    folders = personal_folders()
    if not folders:
        return err("Couldn't find a personal folder on this PC to scan.")
    results, scanned, skipped = _walk_scan(folders)
    db.log("SYSTEM_SCAN", f"{len(folders)} folder(s): {scanned} scanned, {len(results)} with personal info")
    return jsonify({"scanned": scanned, "skipped": skipped, "results": results, "folders": folders})


# ---------------------------------------------------------------- locking / unlocking
@app.post("/api/password-strength")
def api_password_strength():
    return jsonify(password_strength((request.json or {}).get("password", "")))


@app.get("/api/suggest-password")
def api_suggest_password():
    return jsonify({"password": suggest_password()})


@app.post("/api/encrypt")
def encrypt():
    body = request.json or {}
    items, pw = body.get("files", []), body.get("password", "")
    if len(pw) < config.MIN_PASSWORD_LEN:
        return err(f"Use a password with at least {config.MIN_PASSWORD_LEN} characters.")

    done, failed = 0, []
    for item in items:
        path = item.get("path", "")
        try:
            if not os.path.isfile(path):
                raise FileNotFoundError("File not found")
            size = os.path.getsize(path)
            types = item.get("types", [])
            risk = item.get("risk", "medium")
            info = encrypt_file(path, pw)
            db.add_file(path, info["enc_path"], ", ".join(types), risk, size, info["sha256"])
            done += 1
        except Exception as e:
            log.error("Encrypt failed for %s: %s", path, e)
            failed.append({"path": path, "reason": str(e)})

    db.log("ENCRYPT", f"{done} file(s) locked, {len(failed)} failed")
    return jsonify({"encrypted": done, "failed": failed})


@app.post("/api/decrypt")
def decrypt():
    body = request.json or {}
    rec = db.get_file(body.get("id"))
    if not rec or rec["status"] != "ENCRYPTED":
        return err("This file is not in the vault.", 404)
    if not rec["enc_path"].endswith(EXT) or not os.path.isfile(rec["enc_path"]):
        return err("The locked file was moved or deleted from your PC.", 404)
    try:
        out = decrypt_file(rec["enc_path"], body.get("password", ""), rec.get("sha256"))
    except WrongPassword:
        db.log("DECRYPT_FAILED", rec["original_path"])
        return err("Wrong password. Try again.", 403)
    except RuntimeError as e:
        return err(str(e), 500)
    db.mark_restored(rec["id"])
    db.log("DECRYPT", out)
    return jsonify({"restored": out})


# ---------------------------------------------------------------- vault / dashboard
@app.get("/api/vault")
def vault():
    status = request.args.get("status") or None
    search = request.args.get("q") or None
    page = max(1, int(request.args.get("page", 1)))
    return jsonify(db.list_files(status=status, search=search, page=page))


@app.delete("/api/vault/<int:fid>")
def delete_vault_record(fid):
    db.delete_record(fid)
    db.log("DELETE_RECORD", f"record #{fid} removed from vault list (file on disk untouched)")
    return jsonify({"deleted": fid})


@app.get("/api/stats")
def stats():
    return jsonify(db.stats())


@app.get("/api/pii-breakdown")
def pii_breakdown():
    return jsonify(db.pii_type_breakdown())


# ---------------------------------------------------------------- activity log
@app.get("/api/logs")
def logs():
    page = max(1, int(request.args.get("page", 1)))
    return jsonify(db.list_logs(page=page))


@app.get("/api/logs/export")
def export_logs():
    csv_text = db.export_logs_csv()
    return Response(csv_text, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=pii-guard-activity.csv"})


# ---------------------------------------------------------------- settings
@app.get("/api/settings")
def get_settings():
    return jsonify({
        "scan_folders_preview": personal_folders(),
        "max_file_mb": config.MAX_FILE_BYTES // (1024 * 1024),
        "min_password_len": config.MIN_PASSWORD_LEN,
    })


if __name__ == "__main__":
    db.init_db()
    log.info("%s starting on http://%s:%s", config.APP_NAME, config.HOST, config.PORT)
    app.run(host=config.HOST, port=config.PORT, debug=False)
