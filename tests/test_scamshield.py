import os
import tempfile
import pytest

from config import TestingConfig
from app import create_app
from app.extensions import db
from app.models import User, Scan, ScanResult, InvestigationCase, Evidence, InvestigationNote
from app.ml.detection import classify_risk_band, inspect_url_static


@pytest.fixture
def app_instance():
    tmp_dir = tempfile.mkdtemp()
    class LocalTestConfig(TestingConfig):
        MODEL_DIR = tmp_dir

    app = create_app(LocalTestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


def register_and_login(client, username='alice', email='alice@example.com', password='Password123!'):
    return client.post('/auth/register', data={
        'username': username,
        'email': email,
        'full_name': 'Alice Analyst',
        'role_title': 'SOC Engineer',
        'organization': 'CyberLab',
        'password': password,
        'confirm_password': password
    }, follow_redirects=True)


# 1. Registration Tests
def test_01_user_registration_and_password_hashing(client, app_instance):
    resp = register_and_login(client, 'analyst_one', 'one@cyber.org', 'SecurePass99!')
    assert resp.status_code == 200
    assert b'Welcome to ScamShield AI' in resp.data

    with app_instance.app_context():
        user = User.query.filter_by(username='analyst_one').first()
        assert user is not None
        assert user.password_hash != 'SecurePass99!'
        assert user.check_password('SecurePass99!') is True


# 2. Login and Logout Tests
def test_02_login_and_logout_flow(client):
    register_and_login(client, 'bob_sec', 'bob@cyber.org', 'BobSecret123!')
    logout_resp = client.post('/auth/logout', follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b'securely logged out' in logout_resp.data

    # Invalid login attempt
    bad_login = client.post('/auth/login', data={
        'identifier': 'bob_sec',
        'password': 'WrongPassword'
    }, follow_redirects=True)
    assert bad_login.status_code == 401
    assert b'Invalid credentials' in bad_login.data

    # Valid login attempt
    good_login = client.post('/auth/login', data={
        'identifier': 'bob_sec',
        'password': 'BobSecret123!'
    }, follow_redirects=True)
    assert good_login.status_code == 200
    assert b'ScamShield AI Command Center' in good_login.data


# 3. Unauthorized Access Protection
def test_03_unauthorized_route_protection(client):
    for protected_url in ['/dashboard', '/analyzer/', '/analyzer/history', '/investigations/', '/auth/profile', '/auth/settings']:
        r = client.get(protected_url, follow_redirects=False)
        assert r.status_code == 302
        assert '/auth/login' in r.headers['Location']


# 4. All Six Analysis Channels (End-to-End Execution)
def test_04_all_six_analysis_channels(client, app_instance):
    register_and_login(client)

    channel_payloads = [
        ('sms', 'URGENT: Your bank account is suspended due to incomplete KYC. Share OTP at http://sbi-kyc-update.xyz immediately!'),
        ('email', 'Subject: Invoice Wire Change. Please wire $28,400 to our new offshore IBAN account immediately or face legal penalty.'),
        ('url', 'http://185.220.101.44/login/paypal-verify-credentials.php'),
        ('whatsapp', 'Earn Rs 10,000 daily liking YouTube videos! Join our prepaid task Telegram group and pay Rs 2,000 to merchant@ybl'),
        ('social', 'DM FROM SUPPORT: Your Instagram blue badge is suspended! Enter password and 2FA code at http://ig-appeal.site'),
        ('payment', 'I sent Rs 15,000 for your OLX sofa. Click Approve on the UPI collect notification and enter your 4-digit UPI PIN to receive money!')
    ]

    for ch, content in channel_payloads:
        resp = client.post('/analyzer/scan', data={
            'channel': ch,
            'subject_or_sender': 'test_sender@spoofed-domain.xyz',
            'content': content
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Executive Findings' in resp.data

    with app_instance.app_context():
        assert Scan.query.count() == 6
        for scan in Scan.query.all():
            assert scan.result is not None
            assert scan.result.risk_score >= 50


# 5. Valid and Invalid Input Validation
def test_05_valid_and_invalid_inputs(client):
    register_and_login(client)

    # Empty content submission
    empty_resp = client.post('/analyzer/scan', data={
        'channel': 'sms',
        'content': '   '
    })
    assert empty_resp.status_code == 400

    # Invalid registration password length
    client.post('/auth/logout')
    short_pw = client.post('/auth/register', data={
        'username': 'shortuser',
        'email': 'short@cyber.org',
        'password': '123',
        'confirm_password': '123'
    })
    assert short_pw.status_code == 400


# 6. Static URL Validation & Security Inspection
def test_06_url_static_validation():
    ip_url = inspect_url_static('http://192.168.1.99/bank-login/verify')
    assert ip_url['is_valid_format'] is True
    assert ip_url['uses_https'] is False
    assert ip_url['is_ip_hostname'] is True
    assert ip_url['url_rule_points'] >= 50

    safe_url = inspect_url_static('https://docs.python.org/3/library/unittest.html')
    assert safe_url['is_valid_format'] is True
    assert safe_url['uses_https'] is True
    assert safe_url['is_ip_hostname'] is False
    assert safe_url['url_rule_points'] == 0


# 7. AI/ML Prediction & Deterministic Scoring
def test_07_ai_ml_prediction_and_determinism(app_instance):
    engine = app_instance.extensions['scam_engine']
    scam_res = engine.analyze(
        channel='sms',
        content='URGENT: Your debit card is blocked. Enter ATM PIN and OTP at http://citi-unlock.xyz within 2 hours!'
    )
    benign_res = engine.analyze(
        channel='sms',
        content='Hi Mom, I reached the college hostel safely and had dinner at the mess hall.'
    )
    assert scam_res['ml_probability'] > 0.55
    assert scam_res['risk_score'] >= 70
    assert benign_res['risk_score'] <= 24
    assert scam_res['confidence_score'] < 100.0  # Never claims 100% certainty


# 8. Risk Classification Band Boundaries
def test_08_risk_classification_bands():
    assert classify_risk_band(0) == 'Low Risk'
    assert classify_risk_band(24) == 'Low Risk'
    assert classify_risk_band(25) == 'Medium Risk'
    assert classify_risk_band(49) == 'Medium Risk'
    assert classify_risk_band(50) == 'High Risk'
    assert classify_risk_band(74) == 'High Risk'
    assert classify_risk_band(75) == 'Critical Risk'
    assert classify_risk_band(100) == 'Critical Risk'


# 9. Database Storage & ORM Relationships
def test_09_database_storage_and_relationships(client, app_instance):
    register_and_login(client)
    client.post('/analyzer/scan', data={
        'channel': 'payment',
        'content': 'Scan this QR code and enter your UPI MPIN to receive Rs 20,000 cashback prize!'
    }, follow_redirects=True)

    with app_instance.app_context():
        scan = Scan.query.first()
        assert scan is not None
        assert scan.result is not None
        assert len(scan.result.indicators) >= 1
        assert len(scan.result.recommendations) >= 1


# 10. Scan History & Deletion
def test_10_scan_history_and_deletion(client, app_instance):
    register_and_login(client)
    client.post('/analyzer/scan', data={'channel': 'sms', 'content': 'Test SMS for history deletion'}, follow_redirects=True)

    with app_instance.app_context():
        scan_id = Scan.query.first().id

    hist_resp = client.get('/analyzer/history')
    assert hist_resp.status_code == 200
    assert b'Test SMS for history deletion' in hist_resp.data

    del_resp = client.post(f'/analyzer/history/{scan_id}/delete', follow_redirects=True)
    assert del_resp.status_code == 200
    with app_instance.app_context():
        assert db.session.get(Scan, scan_id) is None


# 11. Search and Filters in Scan History
def test_11_history_search_and_filters(client):
    register_and_login(client)
    client.post('/analyzer/scan', data={
        'channel': 'sms',
        'content': 'UNIQUE_KYCSCAM_TOKEN: Share your OTP at http://kyc-fraud.xyz immediately!'
    }, follow_redirects=True)
    client.post('/analyzer/scan', data={
        'channel': 'email',
        'content': 'UNIQUE_BENIGN_EMAIL: Meeting notes for tomorrow afternoon database lecture.'
    }, follow_redirects=True)

    sms_only = client.get('/analyzer/history?channel=sms')
    assert b'UNIQUE_KYCSCAM_TOKEN' in sms_only.data
    assert b'UNIQUE_BENIGN_EMAIL' not in sms_only.data

    search_q = client.get('/analyzer/history?q=UNIQUE_BENIGN_EMAIL')
    assert b'UNIQUE_BENIGN_EMAIL' in search_q.data
    assert b'UNIQUE_KYCSCAM_TOKEN' not in search_q.data


# 12. Investigation Creation & Status Updates
def test_12_investigation_case_lifecycle(client, app_instance):
    register_and_login(client)
    create_resp = client.post('/investigations/create', data={
        'title': 'Operation PhishNet Investigation',
        'severity': 'Critical',
        'category': 'Multi-Channel Phishing',
        'description': 'Tracking coordinated SMS and WhatsApp lures.'
    }, follow_redirects=True)
    assert create_resp.status_code == 200
    assert b'Operation PhishNet Investigation' in create_resp.data

    with app_instance.app_context():
        case = InvestigationCase.query.first()
        case_id = case.id

    status_resp = client.post(f'/investigations/{case_id}/status', data={
        'status': 'Escalated',
        'severity': 'Critical'
    }, follow_redirects=True)
    assert status_resp.status_code == 200
    assert b'Escalated' in status_resp.data


# 13. Evidence Management, Notes & Genuine Entity Correlation
def test_13_evidence_correlation_and_notes(client, app_instance):
    register_and_login(client)
    client.post('/investigations/create', data={
        'title': 'Shared UPI & Domain Correlation Test',
        'severity': 'High',
        'category': 'UPI Fraud'
    }, follow_redirects=True)

    with app_instance.app_context():
        case_id = InvestigationCase.query.first().id

    # Add two related pieces of evidence sharing a UPI handle and domain
    client.post(f'/investigations/{case_id}/evidence', data={
        'evidence_type': 'whatsapp',
        'label': 'WhatsApp Task Message',
        'content': 'Send Rs 5,000 fee to scammer-collect@ybl or visit http://task-portal-scam.xyz'
    }, follow_redirects=True)

    resp2 = client.post(f'/investigations/{case_id}/evidence', data={
        'evidence_type': 'payment',
        'label': 'UPI Collect Request',
        'content': 'Approve collect request from scammer-collect@ybl verified at http://task-portal-scam.xyz/pay'
    }, follow_redirects=True)

    assert resp2.status_code == 200
    assert b'scammer-collect@ybl' in resp2.data
    assert b'Shared in 2 Artifacts' in resp2.data

    # Add an analyst note
    note_resp = client.post(f'/investigations/{case_id}/note', data={
        'note_type': 'Correlation',
        'content': 'Confirmed shared UPI handle scammer-collect@ybl across both channels.'
    }, follow_redirects=True)
    assert note_resp.status_code == 200
    assert b'Confirmed shared UPI handle' in note_resp.data


# 14. Local PDF Report Generation
def test_14_pdf_report_generation(client, app_instance):
    register_and_login(client)
    client.post('/analyzer/scan', data={
        'channel': 'url',
        'content': 'http://paypal.com.verify-login.xyz/auth'
    }, follow_redirects=True)

    with app_instance.app_context():
        scan_id = Scan.query.first().id

    pdf_resp = client.get(f'/analyzer/result/{scan_id}/pdf')
    assert pdf_resp.status_code == 200
    assert pdf_resp.mimetype == 'application/pdf'
    assert pdf_resp.data.startswith(b'%PDF-')
    assert len(pdf_resp.data) > 1000


# 15. Dashboard Dynamic Statistics Calculation
def test_15_dashboard_dynamic_statistics(client):
    register_and_login(client)
    client.post('/analyzer/scan', data={
        'channel': 'sms',
        'content': 'URGENT: Account blocked! Share OTP and PIN immediately at http://185.220.101.44/kyc'
    }, follow_redirects=True)
    client.post('/analyzer/scan', data={
        'channel': 'sms',
        'content': 'Hey friend, see you at the library at 4 PM for our study session.'
    }, follow_redirects=True)

    dash = client.get('/dashboard')
    assert dash.status_code == 200
    assert b'Total Scans' in dash.data


# 16. Strict Multi-Tenant User Data Isolation
def test_16_user_data_isolation(client, app_instance):
    # User A creates a scan and a case
    register_and_login(client, 'user_alpha', 'alpha@cyber.org', 'AlphaPass123!')
    client.post('/analyzer/scan', data={
        'channel': 'sms',
        'content': 'Alpha private scan record'
    }, follow_redirects=True)
    client.post('/investigations/create', data={
        'title': 'Alpha Private Case',
        'severity': 'High'
    }, follow_redirects=True)

    with app_instance.app_context():
        alpha_scan_id = Scan.query.first().id
        alpha_case_id = InvestigationCase.query.first().id

    client.post('/auth/logout')

    # User B registers and tries to access User A's scan, PDF, and case
    register_and_login(client, 'user_beta', 'beta@cyber.org', 'BetaPass123!')

    assert client.get(f'/analyzer/result/{alpha_scan_id}').status_code == 403
    assert client.get(f'/analyzer/result/{alpha_scan_id}/pdf').status_code == 403
    assert client.post(f'/analyzer/history/{alpha_scan_id}/delete').status_code == 403
    assert client.get(f'/investigations/{alpha_case_id}').status_code == 403
    assert client.post(f'/investigations/{alpha_case_id}/delete').status_code == 403
