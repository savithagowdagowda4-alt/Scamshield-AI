import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from app.ml.preprocessing import preprocess_text

DEMO_CORPUS = [
    # --- SCAM / MALICIOUS SAMPLES (label = 1) ---
    # SMS Scams
    ("URGENT: Your bank account has been suspended due to incomplete KYC. Update your PAN and OTP immediately at http://sbi-kyc-update-online.xyz or account will be frozen within 24 hours!", 1, "sms", "KYC / Banking Phishing"),
    ("Dear customer, your electricity bill is unpaid and power connection will be disconnected tonight at 9:30 PM. Contact officer immediately at +91 9876543210 and pay verification fee.", 1, "sms", "Utility Disconnection Scam"),
    ("IndiaPost Alert: Your parcel #IN884920 is on hold due to missing house number. Update address and pay Rs 49 redelivery charge within 12 hours: https://indiapost-track-parcel.top/pay", 1, "sms", "Parcel Delivery Phishing"),
    ("FINAL NOTICE: Unpaid FASTag toll violation detected. Pay penalty of $14.99 immediately at http://ezpass-toll-invoice.buzz to avoid vehicle registration suspension.", 1, "sms", "Toll / Traffic Phishing"),
    ("Congratulations! Your mobile number won $250,000 in the Mega National Lottery! To claim your cash prize, send your bank account number, PIN, and processing fee to claims@lottery-win.vip", 1, "sms", "Lottery / Advance Fee Scam"),
    ("ALERT: Unauthorized login attempt detected on your netbanking profile. Share the 6-digit OTP sent to your phone to cancel the fund transfer of Rs 48,500 immediately.", 1, "sms", "OTP Harvesting Scam"),
    ("Income Tax Refund of Rs 24,800 is approved! Verify your bank account and IFSC code now by clicking http://192.168.45.12/tax-refund-claim before link expires.", 1, "sms", "Tax Refund Phishing"),
    ("Your Netflix subscription payment failed. Please update your credit card number and CVV within 24 hours at https://netflix-billing-verify.site to keep watching.", 1, "sms", "Subscription Billing Phishing"),
    ("FedEx Delivery: Package could not be delivered due to customs duty of $3.95. Confirm payment details at http://fedex-customs-clearance.online/confirm", 1, "sms", "Parcel Delivery Phishing"),
    ("CITIBANK SECURITY ALERT: Your debit card has been blocked for unusual activity. Reactivate immediately by entering your ATM PIN at http://citi-card-unlock.xyz", 1, "sms", "Card Security Phishing"),
    ("Dear user, your SIM card document verification is pending with TRAI. Your mobile number will be deactivated in 2 hours. Call customer care and share Aadhaar OTP now.", 1, "sms", "SIM Swap / Telecom Scam"),
    ("Pre-approved instant personal loan of Rs 5,00,000 at 0% interest! No CIBIL check. Pay Rs 1,999 file processing charge to merchant@okaxis to disburse loan immediately.", 1, "sms", "Advance Fee Loan Scam"),

    # Email Scams
    ("Subject: URGENT Action Required: Microsoft 365 Password Expiry Notice. Your corporate email password expires in 2 hours. Click https://login-microsoftonline-auth-portal.com/verify to retain your current password.", 1, "email", "Corporate Credential Phishing"),
    ("Subject: Invoice #INV-99412 Overdue - Immediate Wire Transfer Change. Please note our vendor bank account has changed. Remit $28,400 wire payment to the new offshore IBAN account attached urgently.", 1, "email", "Business Email Compromise (BEC)"),
    ("Subject: Urgent Request from CEO - Confidential Gift Cards. I am in a board meeting and cannot take calls. Please purchase 10 Apple gift cards worth $100 each and email me the redemption codes immediately.", 1, "email", "Executive Impersonation / BEC"),
    ("Subject: Security Alert: PayPal Account Limited! We noticed suspicious logins. Log in at http://paypal-security-resolution-center.info and submit your SSN, card CVV, and billing password within 24 hours.", 1, "email", "Account Takeover Phishing"),
    ("Subject: Legal Arrest Warrant Issued - Customs & Narcotics Department. A parcel registered under your passport containing illegal items was seized. Pay $2,500 bond via Bitcoin to avoid immediate arrest warrant.", 1, "email", "Extortion / Legal Threat Scam"),
    ("Subject: HR Payroll Update: Direct Deposit Verification Failed. Your monthly salary deposit is paused. Re-enter your banking credentials and OTP at http://workday-payroll-portal.top/login", 1, "email", "Payroll Diversion Phishing"),
    ("Subject: Dear Beneficiary, $4.5 Million Inheritance Fund Release. I am Barrister David from Standard Trust Bank. Transfer $450 notarization fee via Western Union to release your diplomat trunk box.", 1, "email", "Advance Fee / 419 Scam"),
    ("Subject: DocuSign Signature Required: Revised Vendor Remittance Contract. Review and sign the encrypted document by entering your email password at http://docusign-secure-envelope.xyz/login", 1, "email", "Document Phishing"),
    ("Subject: Norton LifeLock Auto-Renewal Invoice $499.99 Charged! This amount will be debited today. To cancel this transaction and get an instant refund, call +1-808-555-0199 and grant remote AnyDesk access.", 1, "email", "Tech Support Refund Scam"),
    ("Subject: DHL Express Shipping Document Attached: Your air waybill is delayed at customs port. Open the attached archive and enter your corporate email credentials to release shipment.", 1, "email", "Shipping / Invoice Phishing"),
    ("Subject: Final Warning: Apple iCloud Storage Locked! Your photos and contacts will be permanently deleted in 12 hours unless you verify your credit card CVV at http://apple-id-support-verify.club", 1, "email", "Cloud Account Phishing"),
    ("Subject: Crypto Airdrop Claim: You have been selected for 5.0 ETH reward! Connect your MetaMask wallet seed phrase or 12-word recovery phrase at https://ethereum-airdrop-claim.vip", 1, "email", "Crypto Drain Scam"),

    # URL / Web Context Scams
    ("http://185.220.101.44/login/secure-banking/update-credentials.php?session=expired&verify=true", 1, "url", "Malicious IP Phishing URL"),
    ("http://paypal.com.account-verify-security-update.xyz/signin/confirm-card", 1, "url", "Subdomain Spoofing URL"),
    ("https://xn--pple-43d.com/id-login/verify-icloud-password", 1, "url", "Punycode Homograph Phishing"),
    ("http://secure-hdfcbank-netbanking-kyc-update.top/pan-otp-verify.html", 1, "url", "Brand Impersonation URL"),
    ("http://login-microsoft-365-sharepoint-document@malicious-redirect.ru/auth/login", 1, "url", "Credential Confusion URL"),
    ("https://amazon-prime-reward-spin-winner.click/claim-free-iphone16?creditcard=required", 1, "url", "Giveaway Scam URL"),
    ("http://binance-wallet-synchronize-seedphrase.online/connect-recovery-words", 1, "url", "Crypto Phishing URL"),
    ("http://bit.ly/3xFakeKycUpdateLink -> redirects to unverified credential harvesting form asking for PIN and OTP", 1, "url", "Shortened Phishing URL"),
    ("http://netflix-account-suspended-billing-update.buzz/payment/cvv", 1, "url", "Billing Phishing URL"),
    ("http://45.133.192.11:8080/portal/webmail/login.jsp", 1, "url", "Suspicious Non-Standard Port IP URL"),

    # WhatsApp Scams
    ("Hello! I am HR Manager from Google Maps Digital Marketing. Earn Rs 5,000 to Rs 15,000 daily working from home just by liking YouTube videos and rating hotels! Join our Telegram prepaid task group now: https://t.me/vip_earning_tasks", 1, "whatsapp", "Task / Part-Time Job Scam"),
    ("Hi Mom, my phone fell in water and broke! This is my temporary number. I urgently need to pay $950 for a medical emergency bill right now. Please transfer to this UPI ID fast, I will explain tonight!", 1, "whatsapp", "Family Impersonation Scam"),
    ("Dear Customer, your WhatsApp account verification has expired. We have sent a 6-digit verification code via SMS. Reply with that 6-digit code immediately so your WhatsApp stays active.", 1, "whatsapp", "WhatsApp Account Takeover"),
    ("Join Professor Sharma VIP Stock Trading Bull Group! Guaranteed 300% profit in institutional IPO blocks. Download our exclusive trading APK from http://vip-institutional-trade.xyz and deposit Rs 50,000.", 1, "whatsapp", "Investment / Pig Butchering Scam"),
    ("Congratulations! Amazon 30th Anniversary Free Spin Wheel! You won a Samsung Galaxy S24 Ultra. Forward this message to 5 WhatsApp groups and pay Rs 199 shipping fee at http://amzn-gift-spin.top", 1, "whatsapp", "Viral Giveaway Scam"),
    ("Hello dear, I saw your profile and would love to invest $500,000 in gold USDT arbitrage with you. Deposit $2,000 into this offshore crypto exchange http://usdt-vip-node.online to unlock profits!", 1, "whatsapp", "Romance / Crypto Investment Scam"),
    ("URGENT: CBI Cyber Crime Police Notice! Your Aadhaar number is linked to money laundering. Join WhatsApp video call for Digital Arrest interrogation and transfer funds to RBI safe verification account immediately.", 1, "whatsapp", "Digital Arrest Extortion Scam"),
    ("Flipkart Big Billion Lucky Draw! Scan this QR code on PhonePe and enter your UPI PIN to receive Rs 10,000 cashback prize directly into your bank account!", 1, "whatsapp", "QR Code / UPI Collect Scam"),
    ("Part-time work opportunity! Complete 3 prepaid merchant orders and get 40% commission back instantly. Send Rs 10,000 to merchant-task@ybl to unlock your stuck withdrawal balance!", 1, "whatsapp", "Prepaid Task Scam"),

    # Social Media Scams
    ("DM FROM OFFICIAL SUPPORT: Your Instagram account violated copyright guidelines and will be permanently deleted in 24 hours! Appeal now by entering your login password and 2FA backup code at http://ig-copyright-help-center.site", 1, "social", "Social Media Account Phishing"),
    ("MASSIVE CRYPTO GIVEAWAY! Elon Musk & Tesla are doubling all Bitcoin and Ethereum deposits today! Send 0.1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh and receive 0.2 BTC back in 5 minutes!", 1, "social", "Crypto Doubler Scam"),
    ("Hey babe! Want to become my sugar baby? I will send you a $5,000 weekly allowance right now! You just need to pay a $75 cashapp clearance fee or send a Steam gift card to verify your wallet first.", 1, "social", "Sugar Daddy / Advance Fee Scam"),
    ("Congratulations! You were picked from the comments as our iPhone 16 Pro Max giveaway winner! Click the link in bio and pay $29 DHL customs insurance fee with your debit card to ship your prize.", 1, "social", "Fake Influencer Giveaway"),
    ("Hello Meta Verified Notice: Your page blue badge verification is suspended. Confirm your business manager login credentials and credit card CVV at http://meta-badge-appeal.xyz immediately.", 1, "social", "Verification Badge Phishing"),
    ("Urgent Ambassador Collaboration! Luxury Brand wants to send you 5 free watches and pay $1,500 per post. Just pay $65 international shipping fee via crypto or gift card to claim your PR package.", 1, "social", "Brand Ambassador Scam"),
    ("I got locked out of my Discord account and accidentally reported your profile for fraud! Contact Discord Admin on Telegram @admin_support_verify and pay a $100 refundable security deposit or your account gets banned.", 1, "social", "False Report / Admin Impersonation"),
    ("Exclusive NFT Whitelist Mint is LIVE! Connect your wallet recovery seed phrase at https://mint-bored-ape-drop.click within 15 minutes before public sale closes!", 1, "social", "NFT Wallet Drainer"),

    # Payment Request Scams
    ("Hi, I am buying your sofa from OLX/Facebook Marketplace! I have sent Rs 15,000 via Google Pay / PhonePe. Just click 'Pay / Approve' on the UPI collect request notification and enter your 4-digit UPI PIN to receive the money in your account!", 1, "payment", "UPI Collect / PIN Trick Scam"),
    ("Overpayment Refund Request: I accidentally wired $3,500 instead of $350 for your freelance design invoice via fake check. Please urgently wire the extra $3,150 back to my cousin via Zelle or crypto before the check clears.", 1, "payment", "Overpayment / Fake Check Scam"),
    ("URGENT VENDOR REMITTANCE CHANGE: Disregard previous banking instructions. Due to an audit, wire the $42,000 settlement invoice today to our new beneficiary account via irreversible USDT TRC20 wallet T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb.", 1, "payment", "Payment Diversion / BEC"),
    ("Customer Care Refund Desk: To process your pending Rs 4,299 cashback refund, install AnyDesk remote screen sharing and enter your netbanking OTP and debit card CVV on the refund form.", 1, "payment", "Remote Access Refund Scam"),
    ("Escrow Release Notice: Buyer has deposited $1,800 for your MacBook. To unlock the escrow transfer, you must first purchase $200 in Razer Gold or Apple Gift Cards and reply with the scratched PIN codes.", 1, "payment", "Fake Escrow / Gift Card Scam"),
    ("QR Code Cashback Claim: Scan the attached merchant QR code and input your UPI MPIN to credit Rs 25,000 army canteen advance payment into your savings account.", 1, "payment", "QR Code Collect Scam"),
    ("Customs Clearance Payment Request: Pay $480 penalty via Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 4 hours or diplomatic package will be confiscated and legal action initiated.", 1, "payment", "Crypto Extortion Payment"),
    ("Security Deposit Verification: Before we release your remote data entry salary of $1,200, pay a mandatory $85 tax and portal activation fee to cashier-verify@okicici.", 1, "payment", "Advance Fee Salary Scam"),

    # --- LEGITIMATE / BENIGN SAMPLES (label = 0) ---
    # Legitimate SMS
    ("Your appointment with Dr. Ananya Verma at City Dental Clinic is confirmed for tomorrow, Friday at 10:30 AM. Reply RESCHEDULE if you need to change the time.", 0, "sms", "Legitimate Notification"),
    ("Hi Rahul, I reached the airport safely. My flight boards at Gate 14B in about forty minutes. See you when I land in Bengaluru!", 0, "sms", "Legitimate Personal Message"),
    ("Your Amazon order #402-8819201 has been shipped and is out for delivery today. No OTP or payment is required for prepaid doorstep delivery.", 0, "sms", "Legitimate Delivery Update"),
    ("Reminder: Library book 'Introduction to Algorithms' is due for return on November 12. You can renew it at the campus library desk during regular hours.", 0, "sms", "Legitimate Reminder"),
    ("Hey, are we still meeting at the coffee shop on MG Road at 6 PM today? Let me know if you want me to pick up the project notes.", 0, "sms", "Legitimate Personal Message"),
    ("Weather Advisory: Moderate rainfall expected across coastal districts this evening. Commuters are advised to plan travel accordingly.", 0, "sms", "Legitimate Public Advisory"),
    ("Thank you for visiting Apollo Pharmacy. Your bill number #AP-4410 for Rs 340 has been paid via card ending in 4102. Have a healthy day.", 0, "sms", "Legitimate Receipt"),
    ("Class Schedule Update: Tomorrow's Software Engineering lab session will be held in Room 304 at 2:00 PM instead of Room 201.", 0, "sms", "Legitimate Academic Notice"),
    ("Mom: Don't forget to pick up milk, bread, and fresh tomatoes on your way home from college this evening.", 0, "sms", "Legitimate Personal Message"),
    ("Your monthly metro pass has been recharged at the station counter. Valid through the end of this month.", 0, "sms", "Legitimate Transit Update"),

    # Legitimate Emails
    ("Subject: Weekly Engineering Sprint Retrospective Notes & Action Items. Hi team, attached are the meeting notes from today's sprint review. Next week we will focus on unit testing and database indexing. Best regards, Priya.", 0, "email", "Legitimate Work Email"),
    ("Subject: CS302 Database Systems Project Submission Guidelines. Dear students, please submit your final ER diagram and SQL schema report on the university LMS portal by Friday 5:00 PM. Let me know during office hours if you have questions.", 0, "email", "Legitimate Academic Email"),
    ("Subject: Monthly Newsletter - Open Source Python Security Updates. Welcome to the November developer digest! In this edition we explore best practices for SQLAlchemy ORM queries, pytest fixtures, and CSRF protection in Flask.", 0, "email", "Legitimate Newsletter"),
    ("Subject: Thank you for attending the Annual Cybersecurity Workshop. We appreciate your participation in yesterday's seminar on network defense. Slides and reading references are available in the shared class folder.", 0, "email", "Legitimate Event Follow-up"),
    ("Subject: Leave Application Approved - Nov 18 to Nov 20. Hi Karthik, your casual leave request for three days has been approved by the department head. Please hand over your lab duties to Meera before leaving.", 0, "email", "Legitimate HR Notification"),
    ("Subject: GitHub Pull Request #42 Merged: Fix responsive sidebar layout. Your pull request into the main branch passed all automated CI/CD unit tests and was merged by the maintainer.", 0, "email", "Legitimate Dev Notification"),
    ("Subject: Minutes of Meeting - College Technical Symposium Committee. Here is the schedule of student paper presentations and robotics events planned for next month's auditorium sessions.", 0, "email", "Legitimate Committee Email"),
    ("Subject: Coffee chat next Tuesday? Hi Arjun, it was great catching up at the alumni meet. Would you be free for lunch near the tech park next Tuesday around 1 PM?", 0, "email", "Legitimate Personal Email"),
    ("Subject: Quarterly Maintenance Window Notification. Our campus Wi-Fi routers will undergo scheduled firmware upgrades this Sunday between 2:00 AM and 4:00 AM. No action is needed from students.", 0, "email", "Legitimate IT Notice"),
    ("Subject: Book Club Discussion: Clean Architecture by Robert C. Martin. This Thursday at 5 PM we will discuss chapters 5 through 8 in the library reading room.", 0, "email", "Legitimate Club Email"),

    # Legitimate URLs
    ("https://docs.python.org/3/library/sqlite3.html", 0, "url", "Legitimate Documentation URL"),
    ("https://flask.palletsprojects.com/en/3.0.x/security/", 0, "url", "Legitimate Framework Docs"),
    ("https://scikit-learn.org/stable/modules/feature_extraction.html", 0, "url", "Legitimate ML Documentation"),
    ("https://github.com/pallets/flask/releases", 0, "url", "Legitimate Repository URL"),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", 0, "url", "Legitimate Web Standards URL"),
    ("https://www.owasp.org/index.php/Top_10-2021_A03-Injection", 0, "url", "Legitimate Security Resource"),
    ("https://getbootstrap.com/docs/5.3/getting-started/introduction/", 0, "url", "Legitimate Frontend Docs"),
    ("https://www.chartjs.org/docs/latest/charts/doughnut.html", 0, "url", "Legitimate Charting Docs"),
    ("https://en.wikipedia.org/wiki/Phishing", 0, "url", "Legitimate Reference Article"),
    ("https://www.ncert.nic.in/textbook.php", 0, "url", "Legitimate Educational Portal"),

    # Legitimate WhatsApp Messages
    ("Hey everyone! I uploaded the handwritten operating systems lecture notes to our shared class drive folder. Good luck with tomorrow's internal assessment!", 0, "whatsapp", "Legitimate Study Group Message"),
    ("Hi Dad, our train just crossed Nagpur junction and is running on time. We brought homemade lunch so don't worry, will call once we reach the hostel.", 0, "whatsapp", "Legitimate Family Message"),
    ("Football practice is moved to 4:30 PM on the main college ground today because the weather is clear. Bring your jerseys and water bottles!", 0, "whatsapp", "Legitimate Sports Group"),
    ("Happy Birthday Sneha! Wishing you a wonderful year ahead filled with good health, happiness, and success in your placements!", 0, "whatsapp", "Legitimate Greeting"),
    ("Can someone share the syllabus PDF for the Machine Learning elective? I missed the first ten minutes of today's orientation lecture.", 0, "whatsapp", "Legitimate Student Query"),
    ("Dinner is ready in the mess hall. Today they are serving paneer butter masala, dal tadka, and hot gulab jamun.", 0, "whatsapp", "Legitimate Hostel Update"),
    ("Thanks for helping me debug the Flask SQLAlchemy foreign key relationship yesterday! All the pytest test cases are passing now.", 0, "whatsapp", "Legitimate Peer Chat"),
    ("We are planning a weekend trek to Nandi Hills this Saturday morning with the photography club. Let me know if you want to join the carpool.", 0, "whatsapp", "Legitimate Outing Plan"),

    # Legitimate Social Media Messages
    ("Great article on machine learning explainability! Thanks for sharing your benchmark results on TF-IDF vs transformer embeddings for small datasets.", 0, "social", "Legitimate Professional Comment"),
    ("Congratulations on graduating with honors! Your final year cybersecurity project presentation looked super clean and well-tested.", 0, "social", "Legitimate Congratulatory Post"),
    ("Hi! I loved your photography reel from the Himachal mountain trip. Which camera lens and shutter speed did you use for the night sky shots?", 0, "social", "Legitimate Creator Question"),
    ("Our college coding club is hosting a free open-source hackathon in the main seminar hall this Saturday. Registration is at the student desk on campus.", 0, "social", "Legitimate Campus Announcement"),
    ("Just finished reading 'Designing Data-Intensive Applications'. Highly recommend it to anyone preparing for backend systems engineering interviews!", 0, "social", "Legitimate Book Recommendation"),
    ("Happy Diwali to all my friends and colleagues! May this festival of lights bring peace and joy to your homes.", 0, "social", "Legitimate Festival Greeting"),
    ("Looking for book recommendations on Python unit testing and clean software architecture. Drop your favorite titles in the replies!", 0, "social", "Legitimate Community Discussion"),
    ("Thank you everyone who attended our live stream on building accessible dark-mode UI dashboards with CSS Grid and Chart.js!", 0, "social", "Legitimate Tech Community Post"),

    # Legitimate Payment Requests
    ("Split bill for Friday team pizza lunch at Domino's: 4 medium pizzas and garlic bread total Rs 1,200 divided by 4 people = Rs 300 each. Pay whenever convenient in person or regular split.", 0, "payment", "Legitimate Lunch Split"),
    ("Standard monthly hostel mess fee receipt #HM-2026-11 for November: Rs 3,500 payable at the college accounts office counter before the 10th of the month.", 0, "payment", "Legitimate Institutional Fee"),
    ("Invoice #204 for completed website logo design as per our signed milestone agreement. Standard net-30 payment terms via our verified company bank account on record.", 0, "payment", "Legitimate Business Invoice"),
    ("Hey Ankit, here is my share of Rs 450 for the Uber cab ride we took from the railway station to the hostel yesterday evening. Thanks for booking!", 0, "payment", "Legitimate Shared Ride Note"),
    ("Annual Alumni Association membership renewal: Rs 500 at the registration desk during the Saturday campus reunion event. Official receipt provided on the spot.", 0, "payment", "Legitimate Membership Note"),
    ("Reimbursement note for robotics club hardware components (Arduino Uno, ultrasonic sensors, jumper wires) purchased from the local electronics store with GST bill attached.", 0, "payment", "Legitimate Expense Reimbursement"),
    ("Monthly society maintenance contribution for Flat 302 for October water and elevator upkeep as discussed in Sunday's residents welfare meeting.", 0, "payment", "Legitimate Maintenance Note"),
    ("Coffee and sandwich bill split from the campus cafeteria after our afternoon project lab session: Rs 120.", 0, "payment", "Legitimate Cafeteria Split"),
]


def get_training_dataframe() -> pd.DataFrame:
    """Returns the labeled demonstration corpus as a Pandas DataFrame with preprocessed text."""
    rows = []
    for text, label, channel, category in DEMO_CORPUS:
        rows.append({
            'raw_text': text,
            'processed_text': preprocess_text(text),
            'label': int(label),
            'channel': channel,
            'category': category
        })
    return pd.DataFrame(rows)


def train_and_save_model(model_dir: str, force_retrain: bool = False) -> dict:
    """
    Trains an ensemble ML pipeline (TF-IDF Vectorizer + Soft-Voting LogisticRegression & RandomForest)
    on the labeled demonstration dataset, evaluates cross-validated metrics, and persists artifacts.
    """
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'scamshield_pipeline.joblib')
    metrics_path = os.path.join(model_dir, 'model_metrics.json')

    if not force_retrain and os.path.exists(model_path) and os.path.exists(metrics_path):
        try:
            pipeline = joblib.load(model_path)
            with open(metrics_path, 'r', encoding='utf-8') as f:
                metrics = json.load(f)
            return {'pipeline': pipeline, 'metrics': metrics}
        except Exception:
            pass

    df = get_training_dataframe()
    X = df['processed_text'].values
    y = df['label'].values

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        min_df=1,
        sublinear_tf=True
    )

    clf_lr = LogisticRegression(C=2.5, class_weight='balanced', max_iter=1000, random_state=42)
    clf_rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        class_weight='balanced',
        random_state=42
    )

    ensemble = VotingClassifier(
        estimators=[('lr', clf_lr), ('rf', clf_rf)],
        voting='soft',
        weights=[0.65, 0.35]
    )

    pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('classifier', ensemble)
    ])

    # 5-fold stratified cross-validation for honest evaluation
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_f1 = cross_val_score(pipeline, X, y, cv=skf, scoring='f1')
    cv_acc = cross_val_score(pipeline, X, y, cv=skf, scoring='accuracy')

    # Fit on complete demonstration corpus
    pipeline.fit(X, y)
    preds = pipeline.predict(X)

    metrics = {
        'dataset_size': int(len(df)),
        'scam_samples': int(np.sum(y == 1)),
        'benign_samples': int(np.sum(y == 0)),
        'cv_accuracy_mean': round(float(np.mean(cv_acc)) * 100, 2),
        'cv_f1_mean': round(float(np.mean(cv_f1)) * 100, 2),
        'train_accuracy': round(float(accuracy_score(y, preds)) * 100, 2),
        'train_precision': round(float(precision_score(y, preds)) * 100, 2),
        'train_recall': round(float(recall_score(y, preds)) * 100, 2),
        'train_f1': round(float(f1_score(y, preds)) * 100, 2),
        'vocabulary_size': int(len(pipeline.named_steps['tfidf'].vocabulary_)),
        'model_architecture': 'TF-IDF (1-2 ngrams, sublinear TF) + Soft-Voting Ensemble (Logistic Regression + Random Forest)',
        'dataset_note': (
            'Trained on a clearly labeled 102-sample multi-channel demonstration dataset covering SMS, Email, '
            'URL, WhatsApp, Social Media, and Payment Request scenarios. Predictions are combined with transparent '
            'channel-specific heuristic rules and never claim 100% certainty.'
        )
    }

    joblib.dump(pipeline, model_path)
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)

    return {'pipeline': pipeline, 'metrics': metrics}


def extract_top_contributing_terms(pipeline: Pipeline, processed_text: str, top_k: int = 6) -> list:
    """
    Inspects the fitted TF-IDF + LogisticRegression branch of the ensemble to return
    the top tokens present in the input that push the prediction toward Scam.
    """
    try:
        tfidf: TfidfVectorizer = pipeline.named_steps['tfidf']
        voting: VotingClassifier = pipeline.named_steps['classifier']
        lr_model: LogisticRegression = voting.named_estimators_['lr']

        vec = tfidf.transform([processed_text])
        feature_names = tfidf.get_feature_names_out()
        coefs = lr_model.coef_[0]

        nonzero_indices = vec.nonzero()[1]
        contributions = []
        for idx in nonzero_indices:
            term = feature_names[idx]
            weight = float(vec[0, idx] * coefs[idx])
            if weight > 0.02 and not term.startswith('token'):
                clean_term = term.replace('__has_', 'feature:').replace('__', '')
                contributions.append({'term': clean_term, 'weight': round(weight, 3)})

        contributions.sort(key=lambda x: x['weight'], reverse=True)
        return contributions[:top_k]
    except Exception:
        return []
