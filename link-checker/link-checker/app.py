from flask import Flask, jsonify, render_template, request

import config
from checker import analyze_url, scan_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    result = analyze_url(data.get("url", ""), use_vt=bool(data.get("use_vt")))
    return jsonify(result), (400 if "error" in result else 200)


@app.route("/scan-file", methods=["POST"])
def scan():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "اختار ملف الأول"}), 400
    result = scan_file(f.filename, f.read(), use_vt=request.form.get("use_vt") == "true")
    return jsonify(result), (400 if "error" in result else 200)


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": f"الملف أكبر من {config.MAX_UPLOAD_MB} ميجا"}), 413


if __name__ == "__main__":
    app.run(debug=True)
