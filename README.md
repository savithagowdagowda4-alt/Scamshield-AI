# ScamShield AI — Multi-Channel Scam Detection & Investigation Platform

**ScamShield AI** is a full-stack cybersecurity web application designed to help users and security analysts detect, analyze, correlate, and investigate suspicious digital communications across six distinct channels:
1. **SMS Smishing Analyzer**
2. **Email Phishing & BEC Analyzer**
3. **Static URL Security Inspector** (100% static lexical/structural inspection — never visits or executes submitted URLs)
4. **WhatsApp Message Analyzer**
5. **Social Media DM & Promotional Offer Analyzer**
6. **Payment Request & UPI Collect Fraud Analyzer**

> **Important Probabilistic Disclaimer:** ScamShield AI combines a local Scikit-learn TF-IDF + Soft-Voting Machine Learning Classifier with transparent channel-specific security rules. Automated threat analysis is probabilistic and **never 100% accurate**. Risk bands (`0–24 Low Risk`, `25–49 Medium Risk`, `50–74 High Risk`, `75–100 Critical Risk`) are application-defined metrics and are not a substitute for formal institutional verification or professional incident response.

---

## 1. Architecture & Project Structure

```text
ScamShield-AI/
├── app/
│   ├── __init__.py                 # Flask application factory, error handlers, DB seeding
│   ├── extensions.py               # SQLAlchemy, Flask-Login, CSRFProtect instances
│   ├── models/
│   │   └── __init__.py             # 6 ORM Models: User, Scan, ScanResult, InvestigationCase, Evidence, InvestigationNote
│   ├── ml/
│   │   ├── preprocessing.py        # Text normalization, tokenization, regex IoC extraction, numerical features
│   │   ├── training.py             # 102-sample labeled multi-channel demonstration dataset & TF-IDF + VotingClassifier trainer
│   │   └── detection.py            # Hybrid ML + Heuristic Rule Engine, static URL inspector, explanation & recommendation builder
│   ├── services/
│   │   ├── investigation_service.py # Cross-artifact entity correlation & timeline builder
│   │   └── pdf_service.py          # Local ReportLab forensic PDF generator (with URL defanging)
│   ├── routes/
│   │   ├── auth.py                 # Registration, Login, Logout, Profile & Settings routes
│   │   ├── dashboard.py            # Live database KPI & Chart.js telemetry controller
│   │   ├── analyzer.py             # 6-channel analysis routes, JSON API, History filtering & PDF export
│   │   └── investigation.py        # Investigation Case CRUD, Evidence locker, Notes & status updates
│   ├── templates/                  # Responsive Dark Navy & Electric Blue Glassmorphism Jinja2 templates
│   │   ├── base.html
│   │   ├── auth/                   # login.html, register.html, profile.html, settings.html
│   │   ├── dashboard/              # index.html
│   │   ├── analyzer/               # hub.html, result.html, reports.html
│   │   ├── history/                # index.html
│   │   ├── investigation/          # list.html, detail.html
│   │   └── errors/                 # 403.html, 404.html, 500.html
│   └── static/
│       ├── css/style.css           # Custom cybersecurity SaaS design system
│       └── js/main.js              # Interactive channel switching, sample loaders, loading overlay
├── tests/
│   └── test_scamshield.py          # 16 comprehensive pytest integration & security isolation tests
├── instance/                       # Auto-created SQLite database (scamshield.db) & serialized ML model artifacts
├── config.py                       # Development, Production & Testing configurations
├── requirements.txt                # Pinned Python dependencies
├── run.py                          # Application entrypoint
└── README.md                       # Complete documentation
```

---

## 2. Local Installation & Execution Instructions in VS Code

1. Open **VS Code** → **File** → **Open Folder...** → Select **`Desktop\ScamShield-AI`**.
2. Open a terminal in VS Code (`Ctrl + ~`) and run:
   ```powershell
   .\start_demo.bat
   ```
   Or manually:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   python run.py
   ```
3. Open your browser to **`http://127.0.0.1:5000`**.
   - **Demo Login:** `analyst` / `ScamShield@2026`
