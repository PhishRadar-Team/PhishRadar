from __future__ import annotations
import json
from flask import Flask, request, jsonify
from phish_features import extract_features, normalize_url, url_from_request
from phish_rules import score_from_features, label_from_score

app = Flask(__name__, static_folder="frontend", static_url_path="")

@app.get("/")
def index():
    # Serve the frontend
    return app.send_static_file("index.html")

@app.post("/api/predict")
def predict():
    try:
        data = request.get_json(force=True, silent=True) or {}
        url = url_from_request(data)
        if not url:
            return jsonify({"ok": False, "error": "Missing 'url' in request body"}), 400

        norm = normalize_url(url)
        feats = extract_features(norm)
        score, signals = score_from_features(feats)
        label = label_from_score(score)
        return jsonify({
            "ok": True,
            "url": norm,
            "label": label,
            "score": score,
            "features": feats,
            "signals": signals
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.post("/api/predict-batch")
def predict_batch():
    """
    Accepts: {"urls": ["http://...", "https://..."]}
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        urls = data.get("urls", [])
        if not isinstance(urls, list) or not urls:
            return jsonify({"ok": False, "error": "Provide non-empty list under key 'urls'"}), 400

        results = []
        for u in urls:
            norm = normalize_url(u)
            feats = extract_features(norm)
            score, signals = score_from_features(feats)
            label = label_from_score(score)
            results.append({
                "url": norm,
                "label": label,
                "score": score,
                "features": feats,
                "signals": signals
            })

        return jsonify({"ok": True, "count": len(results), "results": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    # Run the dev server
    app.run(host="127.0.0.1", port=5000, debug=True)
