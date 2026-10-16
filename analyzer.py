"""Explainable phishing analysis engine for URLs and emails (no external calls — safe to run on suspicious input)."""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

BRANDS = {"paypal": "paypal.com", "google": "google.com", "amazon": "amazon.in", "apple": "apple.com", "microsoft": "microsoft.com",
          "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
          "sbi": "onlinesbi.sbi", "hdfc": "hdfcbank.com", "icici": "icicibank.com", "paytm": "paytm.com", "linkedin": "linkedin.com",
          "flipkart": "flipkart.com", "outlook": "outlook.com", "office365": "office.com", "github": "github.com", "irctc": "irctc.co.in"}
POPULAR = [d.split(".")[0] for d in BRANDS.values()] + ["youtube", "twitter", "yahoo", "gmail", "dropbox"]
SUS_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "country", "kim", "loan", "rest", "fit", "mov", "support", "live", "buzz", "cam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly", "ow.ly", "rb.gy", "shorturl.at", "tiny.cc"}
KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "banking", "confirm", "password", "wallet", "bonus",
            "free", "gift", "unlock", "suspend", "kyc", "reward", "otp", "billing", "recover"]
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyse_url(raw):
    url = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    reg = registered_domain(host)
    label = reg.split(".")[0]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    full = url.lower()
    checks = []

    def add(name, failed, weight, detail, icon):
        checks.append({"name": name, "failed": bool(failed), "weight": weight if failed else 0, "detail": detail, "icon": icon})

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    add("HTTPS encryption", p.scheme != "https", 10, "Uses HTTPS" if p.scheme == "https" else "Plain HTTP — traffic can be intercepted", "bi-lock")
    add("IP address as host", is_ip, 22, "Raw IP addresses hide the real owner" if is_ip else "Uses a domain name", "bi-hdd-network")
    add("URL length", len(url) > 75, 8, f"{len(url)} characters" + (" — long URLs often hide the real destination" if len(url) > 75 else ""), "bi-rulers")
    add("'@' symbol trick", "@" in p.netloc, 20, "Browser ignores everything before '@'" if "@" in p.netloc else "No '@' in host", "bi-at")
    dots = host.count(".")
    add("Subdomain depth", dots > 3, 10, f"{dots} dots in host" + (" — deep nesting mimics trusted sites" if dots > 3 else ""), "bi-diagram-3")
    add("Hyphenated domain", label.count("-") >= 2 or ("-" in label and any(b in label for b in BRANDS)), 8, f"Domain label: {label}", "bi-dash-lg")
    add("Suspicious TLD", tld in SUS_TLDS, 14, f".{tld} is frequently abused" if tld in SUS_TLDS else f".{tld or '—'}", "bi-globe2")
    add("Punycode / homograph", "xn--" in host, 18, "Unicode look-alike characters" if "xn--" in host else "ASCII only", "bi-translate")
    add("URL shortener", reg in SHORTENERS or host in SHORTENERS, 20, "Real destination is hidden" if host in SHORTENERS or reg in SHORTENERS else "Not a shortener", "bi-link-45deg")
    norm_label = label.translate(LEET)
    impersonated = [b for b in BRANDS if (b in (sub + p.path.lower()) or (b in norm_label and norm_label != b))
                    and registered_domain(BRANDS[b]) != reg]
    add("Brand impersonation", impersonated, 24, f"Mentions '{impersonated[0]}' but domain is {reg}" if impersonated else "No brand misuse detected", "bi-mask")
    norm = label.translate(LEET)
    typo = next((b for b in POPULAR if b != label and (norm == b or (len(b) > 4 and 0 < levenshtein(norm, b) <= 2))), None)
    add("Typosquatting", typo, 22, f"'{label}' looks like '{typo}'" if typo else "No look-alike of popular brands", "bi-spellcheck")
    kws = [k for k in KEYWORDS if k in full]
    add("Phishing keywords", len(kws) >= 2, 10, ", ".join(kws) if kws else "None found", "bi-chat-square-text")
    ent = entropy(label.replace("-", ""))
    add("Random-looking domain", ent > 3.7 and len(label) > 12 and not re.search(r"[aeiou]{1}[a-z]{0,3}[aeiou]", label), 10, f"Entropy {ent:.2f} bits/char", "bi-shuffle")
    add("Non-standard port", p.port not in (None, 80, 443), 8, f"Port {p.port}" if p.port else "Default port", "bi-plug")
    add("Embedded redirect", "//" in p.path or re.search(r"(redirect|url|next)=https?", full) is not None, 10,
        "Contains an open-redirect pattern" if ("//" in p.path or re.search(r"(redirect|url|next)=https?", full)) else "No redirect pattern", "bi-sign-turn-right")

    score = min(100, sum(c["weight"] for c in checks))
    verdict = "Dangerous" if score >= 45 else "Suspicious" if score >= 20 else "Safe"
    return {"input": raw.strip(), "host": host, "domain": reg, "score": score, "verdict": verdict, "checks": checks}


URGENCY = ["urgent", "immediately", "within 24 hours", "account will be", "suspended", "locked", "final notice", "act now",
           "verify your", "unusual activity", "expire", "limited time", "last warning"]
CREDS = ["password", "otp", "pin", "cvv", "card number", "login details", "bank details", "aadhaar", "pan card", "ssn"]
MONEY = ["lottery", "prize", "won", "refund", "cashback", "bitcoin", "gift card", "inheritance", "investment opportunity", "crore", "lakh"]
BAD_ATTACH = re.compile(r"\b[\w-]+\.(exe|scr|js|vbs|bat|cmd|docm|xlsm|iso|zip|rar|html?)\b", re.I)


def analyse_email(sender, subject, body):
    text = f"{subject}\n{body}".lower()
    checks = []

    def add(name, hits, weight, detail, icon):
        checks.append({"name": name, "failed": bool(hits), "weight": weight if hits else 0, "detail": detail, "icon": icon})

    u = [w for w in URGENCY if w in text]
    add("Urgency / threats", u, 18, ", ".join(u[:4]) if u else "No pressure tactics", "bi-alarm")
    c = [w for w in CREDS if w in text]
    add("Requests credentials", c, 25, ", ".join(c[:4]) if c else "No sensitive data requested", "bi-key")
    m = [w for w in MONEY if w in text]
    add("Money / prize lure", m, 15, ", ".join(m[:4]) if m else "No financial lure", "bi-cash-coin")
    generic = re.search(r"dear (customer|user|client|member|sir|madam|account holder)", text)
    add("Generic greeting", generic, 8, f"'{generic.group(0)}'" if generic else "Personalised or none", "bi-person-x")
    sm = re.match(r'\s*"?([^"<]*)"?\s*<?([\w.+-]+@([\w-]+\.)+[\w-]+)>?', sender or "")
    spoof = None
    if sm:
        display, addr = sm.group(1).lower(), sm.group(2).lower()
        dom = registered_domain(addr.split("@")[1])
        spoof = next((b for b in BRANDS if b in display + addr.split("@")[0] and registered_domain(BRANDS[b]) != dom), None)
        free = dom in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"} and any(b in display for b in BRANDS)
        spoof = spoof or ("free-mail brand" if free else None)
    add("Sender spoofing", spoof, 22, f"Claims '{spoof}' but sent from a different domain" if spoof else "Sender looks consistent", "bi-envelope-exclamation")
    att = BAD_ATTACH.findall(body or "")
    add("Risky attachment", att, 18, "Mentions ." + ", .".join(sorted(set(a.lower() for a in att))) if att else "No risky file types", "bi-paperclip")
    urls = re.findall(r"(?:https?://|www\.)[^\s<>\"')]+", body or "", re.I)
    url_results = [analyse_url(x) for x in urls[:5]]
    bad = [r for r in url_results if r["verdict"] != "Safe"]
    add("Malicious links", bad, 25, f"{len(bad)} of {len(urls)} links flagged" if urls else "No links", "bi-link")
    caps = sum(1 for w in re.findall(r"\b[A-Z]{4,}\b", body or ""))
    add("Shouting / formatting", caps >= 3 or (body or "").count("!") >= 4, 6, f"{caps} ALL-CAPS words, {(body or '').count('!')} exclamations", "bi-megaphone")
    score = min(100, sum(x["weight"] for x in checks))
    verdict = "Dangerous" if score >= 45 else "Suspicious" if score >= 20 else "Safe"
    return {"input": subject or (body or "")[:60], "score": score, "verdict": verdict, "checks": checks, "links": url_results}
