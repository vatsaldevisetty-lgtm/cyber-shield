from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from urllib.parse import urlparse
import socket, ipaddress

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

CHECKS = [
    ("Content-Security-Policy", "CSP"),
    ("Strict-Transport-Security", "HSTS"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
    ("Referrer-Policy", "Referrer-Policy"),
    ("X-Frame-Options", "X-Frame-Options"),
]

def validate_target(raw):
    raw = raw.strip()
    if len(raw) > 2048:
        raise ValueError("URL is too long.")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Enter a valid HTTP/HTTPS domain.")
    host = p.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise ValueError("Local addresses are not allowed.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Private or reserved IP addresses are not allowed.")
        raise ValueError("Enter a domain name rather than a direct IP address.")
    except ValueError as e:
        if str(e) != "Enter a domain name rather than a direct IP address." and "Private" not in str(e):
            pass
        else:
            raise
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Domain could not be resolved.")
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if not addr.is_global:
            raise ValueError("Domain resolves to a non-public address.")
    return p

@app.get("/api/scan")
def scan():
    raw = request.args.get("url", "")
    try:
        p = validate_target(raw)
        r = requests.get(
            p.geturl(), timeout=8, allow_redirects=False, verify=True,
            headers={"User-Agent": "CyberShield/1.0"}, stream=True
        )
        try:
            results = [{"name": "HTTPS", "passed": p.scheme == "https",
                        "detail": "The URL uses HTTPS." if p.scheme == "https" else "The URL uses HTTP."}]
            for header, name in CHECKS:
                present = header.lower() in {k.lower() for k in r.headers.keys()}
                results.append({"name": name, "passed": present,
                                "detail": "Header is present." if present else "Header was not observed."})
            score = round(sum(x["passed"] for x in results) / len(results) * 100)
            return jsonify({"url": p.geturl(), "status": r.status_code, "score": score, "checks": results})
        finally:
            r.close()
    except (ValueError, requests.RequestException) as e:
        return jsonify({"error": str(e) or "Unable to scan target safely."}), 400

@app.get("/")
def home():
    return jsonify({"service": "CyberShield API", "status": "online"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
