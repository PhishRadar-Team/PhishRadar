# PhishRadar – Phishing URL Detector (Flask + Vanilla JS)
A ready-to-run project with a professional frontend and a Python (Flask) backend. No external ML model is required; it uses a transparent, well-tested heuristic scoring engine. You can optionally extend it with ML later.

## 🧰 Tech Stack
- **Backend:** Python 3.9+, Flask
- **Frontend:** HTML, CSS, vanilla JS (fetch API)
- **Extras:** Explanations for each signal, batch testing utility, clean UI

---

## 🚀 Quick Start
```bash
# 1) Create & activate a virtual environment (recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run the server
python app.py

# 4) Open in your browser
http://127.0.0.1:5000
```
You should see the UI. Paste a URL and click **Analyze**.

---

## 🧪 Try a few examples
- Legit: `https://www.microsoft.com/en-us/`  
- Suspicious: `http://paypal.com.login.verify-security-alert.example.com/`  
- Phishing-like: `http://192.168.0.5/secure-login?user=admin`  
- Shortener: `https://bit.ly/49Rkabc`

You can also run a small batch via:
```
# While the server is running in one terminal
# In another terminal:
curl -X POST http://127.0.0.1:5000/api/predict-batch   -H "Content-Type: application/json"   -d @tests/sample_urls.json
```

---

## 📂 Project Structure
```
phishshield/
├─ app.py
├─ phish_features.py
├─ phish_rules.py
├─ requirements.txt
├─ frontend/
│  ├─ index.html
│  ├─ app.js
│  └─ styles.css
└─ tests/
   ├─ sample_urls.json
   └─ test_api.http
```

---

## 🧠 How detection works (short version)
We compute a **risk score (0–100)** from URL-derived signals:
- Obvious red flags (e.g., IP address in host, `@` symbol, URL shorteners, suspicious TLDs)
- Structure-based signals (too many subdomains, long path/query, excessive digits, encoded characters)
- SSL usage and host length sanity checks
- Presence of classic phishing keywords (e.g., `login`, `verify`, `update`, `secure`, `bank`, …)

**Labels:**
- `Legitimate` : score < 40
- `Suspicious` : 40 ≤ score < 60
- `Phishing`   : score ≥ 60

Every decision includes an **explanation list** so you can see *why* a URL was flagged.

---

## 🧱 Extend with ML later (optional)
You can drop in a scikit-learn model if you like: export the same features from `phish_features.py`, fit a model, and use it inside `app.py`. The current engine is designed to be easily swappable.

---

## 🔐 Notes
- No external calls are made; analysis is done locally.
- `tldextract` uses a packaged Public Suffix snapshot, so it works offline.
- CORS is disabled by default because the UI is served by Flask on the same origin.
