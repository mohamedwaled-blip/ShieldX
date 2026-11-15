import os

from flask import Flask, jsonify, render_template, request

import config
from checker import analyze_url, scan_file, virustotal

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024

# الصفحة بتحمّل بس الخطوط من Google Fonts، وكل الباقي من نفس السيرفر
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/info")
def info():
    """إعدادات بتحتاجها الواجهة (الحد الأقصى للملف، وهل VirusTotal مفعّل)."""
    return jsonify({
        "max_upload_mb": config.MAX_UPLOAD_MB,
        "max_url_length": config.MAX_URL_LENGTH,
        "vt_available": virustotal.available(),
    })


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    result = analyze_url(data.get("url", ""), use_vt=bool(data.get("use_vt")))
    return jsonify(result), (400 if "error" in result else 200)


@app.route("/scan-file", methods=["POST"])
def scan():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "اختار ملف الأول", "code": "no_file"}), 400
    result = scan_file(f.filename, f.read(), use_vt=request.form.get("use_vt") == "true")
    return jsonify(result), (400 if "error" in result else 200)


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": f"الملف أكبر من {config.MAX_UPLOAD_MB} ميجا", "code": "too_large",
                    "max_mb": config.MAX_UPLOAD_MB}), 413


if __name__ == "__main__":
    # الـ debugger بتاع Flask بيسمح بتنفيذ كود، فمتفعّل بس لو طلبته صراحةً: FLASK_DEBUG=1
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
