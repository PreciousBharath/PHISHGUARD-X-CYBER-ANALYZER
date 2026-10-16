"""PhishGuard X — Cyber threat analyzer: explainable URL & email phishing detection, password security lab and scan history.
Run:  python app.py   →  http://127.0.0.1:5000   (demo: demo@example.com / Demo@1234)
"""
import json
import random
from datetime import datetime, timedelta

from flask import g, jsonify, render_template, request

from analyzer import analyse_email, analyse_url
from core import create_app, execute, login_required, now, query

UI = dict(
    name="PhishGuard X", short="Cyber Threat Analyzer", icon="🛡️", accent1="#00F5A0", accent2="#00B4D8", home="scanner",
    tagline="Scan suspicious links and emails before you click. Explainable risk scores, a password security lab and a full threat history.",
    hero='Stop phishing <span class="gradient-text">before the click.</span>', badge="Cybersecurity toolkit",
    features=[("bi-link-45deg", "URL threat scanner", "15 explainable checks: typosquatting, homographs, brand abuse…"),
              ("bi-envelope-exclamation", "Email analyzer", "Detects spoofing, urgency tricks, credential theft & bad links"),
              ("bi-key", "Password lab", "Entropy, crack-time & generator — computed 100% in your browser")],
    float=['🚨 <b>paypa1-secure-login.xyz</b> → <span style="color:#FF5470">Dangerous 92</span>', '✅ <b>github.com</b> → <span style="color:#00F5A0">Safe 0</span>'],
    nav=[("Threat Scanner", "scanner", "bi-radar"), ("Password Lab", "password", "bi-key"), ("Scan History", "history", "bi-clock-history")],
    search_hint="Search history…", promo_title="Privacy first", promo="Passwords never leave your browser. URLs are analysed offline — nothing is visited.",
)
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, input TEXT NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
"""
DEMO_URLS = ["https://github.com/PreciousBharath", "http://paypa1-secure-login.xyz/verify/account", "https://www.amazon.in/deals",
             "http://192.168.10.5/hdfc/netbanking/login.php", "https://bit.ly/3xYz9Qa", "https://accounts.google.com/signin",
             "http://sbi-kyc-update.top/otp?redirect=http://evil.ru", "https://www.linkedin.com/in/connectbharath",
             "https://secure.microsoft.account-verify.support/login", "https://netflix-billing-update.click/payment"]


def seed_demo(uid):
    rng = random.Random(5)
    for i in range(36):
        u = DEMO_URLS[i % len(DEMO_URLS)] if i < len(DEMO_URLS) else rng.choice(DEMO_URLS)
        r = analyse_url(u)
        ts = (datetime.now() - timedelta(days=rng.randint(0, 20), hours=rng.randint(0, 23))).strftime("%Y-%m-%d %H:%M:%S")
        execute("INSERT INTO scans(user_id,kind,input,score,verdict,details,created_at) VALUES(?,?,?,?,?,?,?)",
                (uid, "url", u, r["score"], r["verdict"], json.dumps(r), ts))
    r = analyse_email('"PayPal Support" <security@paypal-alerts.com>', "URGENT: Your account will be suspended",
                      "Dear Customer, unusual activity detected. Verify your password and OTP within 24 hours: http://paypa1-secure-login.xyz/verify")
    execute("INSERT INTO scans(user_id,kind,input,score,verdict,details,created_at) VALUES(?,?,?,?,?,?,?)",
            (uid, "email", r["input"], r["score"], r["verdict"], json.dumps(r), now()))


app = create_app(__name__, UI, SCHEMA, seed_demo=seed_demo)


def overview(uid):
    rows = query("SELECT verdict, kind, substr(created_at,1,10) d FROM scans WHERE user_id=?", (uid,))
    by_v = {v: sum(r["verdict"] == v for r in rows) for v in ("Safe", "Suspicious", "Dangerous")}
    days = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    trend = {"labels": [d[5:] for d in days],
             "threats": [sum(1 for r in rows if r["d"] == d and r["verdict"] != "Safe") for d in days],
             "safe": [sum(1 for r in rows if r["d"] == d and r["verdict"] == "Safe") for d in days]}
    return dict(total=len(rows), by_v=by_v, trend=trend, blocked=by_v["Dangerous"] + by_v["Suspicious"],
                emails=sum(r["kind"] == "email" for r in rows))


@app.route("/scanner")
@login_required
def scanner():
    recent = query("SELECT id,kind,input,score,verdict,created_at FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT 6", (g.user["id"],))
    return render_template("scanner.html", o=overview(g.user["id"]), recent=recent, page_title="Threat Scanner")


@app.route("/password")
@login_required
def password():
    return render_template("password.html", page_title="Password Lab")


@app.route("/history")
@login_required
def history():
    rows = query("SELECT id,kind,input,score,verdict,created_at FROM scans WHERE user_id=? ORDER BY created_at DESC", (g.user["id"],))
    return render_template("history.html", rows=rows, o=overview(g.user["id"]), page_title="Scan History")


@app.post("/api/scan/url")
@login_required
def api_scan_url():
    url = str(request.get_json(force=True).get("url", "")).strip()[:2048]
    if len(url) < 4 or " " in url:
        return jsonify(error="Enter a valid URL"), 400
    r = analyse_url(url)
    r["id"] = execute("INSERT INTO scans(user_id,kind,input,score,verdict,details,created_at) VALUES(?,?,?,?,?,?,?)",
                      (g.user["id"], "url", url, r["score"], r["verdict"], json.dumps(r), now()))
    return jsonify(r)


@app.post("/api/scan/email")
@login_required
def api_scan_email():
    d = request.get_json(force=True)
    body = str(d.get("body", ""))[:20000]
    if len(body.strip()) < 10:
        return jsonify(error="Paste the email body (at least a sentence)"), 400
    r = analyse_email(str(d.get("sender", ""))[:300], str(d.get("subject", ""))[:300], body)
    r["id"] = execute("INSERT INTO scans(user_id,kind,input,score,verdict,details,created_at) VALUES(?,?,?,?,?,?,?)",
                      (g.user["id"], "email", r["input"][:200] or "(no subject)", r["score"], r["verdict"], json.dumps(r), now()))
    return jsonify(r)


@app.get("/api/scan/<int:sid>")
@login_required
def api_scan_get(sid):
    row = query("SELECT details FROM scans WHERE id=? AND user_id=?", (sid, g.user["id"]), one=True)
    return (jsonify(json.loads(row["details"])), 200) if row else (jsonify(error="Not found"), 404)


@app.delete("/api/scan/<int:sid>")
@login_required
def api_scan_delete(sid):
    execute("DELETE FROM scans WHERE id=? AND user_id=?", (sid, g.user["id"]))
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=True)
