import os
import json
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template

from config import Config
from app.extensions import db, login_manager, csrf
from app.ml.detection import ScamDetectionEngine
from app.ml.preprocessing import extract_entities


def create_app(config_class=Config) -> Flask:
    """Application factory for ScamShield AI."""

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Initialize AI/ML detection engine
    scam_engine = ScamDetectionEngine(app.config['MODEL_DIR'])
    app.extensions['scam_engine'] = scam_engine

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.analyzer import analyzer_bp
    from app.routes.investigation import investigation_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analyzer_bp)
    app.register_blueprint(investigation_bp)

    # Custom error handlers
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    # Initialize database
    with app.app_context():
        db.create_all()

        # Seed demo data only when explicitly enabled
        if (
            not app.config.get('TESTING', False)
            and os.environ.get('SEED_DEMO_DATA', '').lower() == 'true'
        ):
            _seed_demo_account_if_empty(scam_engine)

    return app


def _seed_demo_account_if_empty(engine: ScamDetectionEngine) -> None:
    """Create demonstration analyst data when explicitly enabled."""

    from app.models import (
        User,
        Scan,
        ScanResult,
        InvestigationCase,
        Evidence,
        InvestigationNote
    )

    if User.query.first() is not None:
        return

    demo_user = User(
        username='analyst',
        email='analyst@scamshield.local',
        full_name='Aarav Mehta',
        role_title='Lead Cyber Threat Analyst',
        organization='ScamShield SOC Lab',
        bio='Specializing in multi-channel phishing, UPI payment fraud, and social engineering investigations.'
    )

    demo_user.set_password('ScamShield@2026')
    db.session.add(demo_user)
    db.session.flush()

    now = datetime.now(timezone.utc)

    sample_submissions = [
        (
            'sms',
            '+91-98201-55109',
            'URGENT: Your SBI Bank account has been suspended due to incomplete KYC. Update your PAN and OTP immediately at http://sbi-kyc-update-online.xyz or your account will be frozen within 24 hours!',
            now - timedelta(days=5, hours=2),
            'SS-20261031-A101F1'
        ),
        (
            'email',
            'security-alert@login-microsoftonline-auth-portal.com | Subject: URGENT Action Required: Corporate 365 Password Expiry',
            'Your corporate email password expires in 2 hours. Click http://sbi-kyc-update-online.xyz/office365-login to verify your password and 2FA code immediately or lose access.',
            now - timedelta(days=4, hours=5),
            'SS-20261101-B202E4'
        ),
        (
            'url',
            'Suspicious Banking Link',
            'http://185.220.101.44/login/secure-banking/update-credentials.php?session=expired&verify=true',
            now - timedelta(days=3, hours=1),
            'SS-20261102-C303D8'
        ),
        (
            'whatsapp',
            '+91-98201-55109',
            'Hello! Earn Rs 10,000 daily working from home by liking YouTube videos and completing prepaid merchant tasks! Deposit Rs 5,000 registration fee to merchant-task@ybl to unlock your VIP withdrawal.',
            now - timedelta(days=2, hours=4),
            'SS-20261103-D404C2'
        ),
        (
            'social',
            '@elon_crypto_giveaway_official',
            'MASSIVE CRYPTO GIVEAWAY! Send 0.1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh and receive 0.2 BTC back in 5 minutes! Connect your 12-word seed phrase now.',
            now - timedelta(days=1, hours=6),
            'SS-20261104-E505B9'
        ),
        (
            'payment',
            'OLX Buyer Collect Request (merchant-task@ybl)',
            'I am buying your dining table! I have sent Rs 18,000 via PhonePe. Just click Approve on the UPI collect request from merchant-task@ybl and enter your 4-digit UPI PIN to receive the money!',
            now - timedelta(hours=14),
            'SS-20261105-F606A3'
        ),
        (
            'email',
            'prof.sharma@university.edu | Subject: CS302 Database Project Submission Schedule',
            'Dear students, please upload your final ER diagram and SQLAlchemy ORM test report to the campus portal by Friday at 5:00 PM. No external links or payments are required.',
            now - timedelta(hours=4),
            'SS-20261105-G707B1'
        )
    ]

    created_scans = []

    for ch, sender, content, ts, uid in sample_submissions:

        analysis = engine.analyze(
            channel=ch,
            content=content,
            subject_or_sender=sender
        )

        sc = Scan(
            analysis_uid=uid,
            user_id=demo_user.id,
            channel=ch,
            subject_or_sender=sender,
            submitted_content=content,
            metadata_json='{}',
            created_at=ts
        )

        db.session.add(sc)
        db.session.flush()

        sr = ScanResult(
            scan_id=sc.id,
            risk_score=analysis['risk_score'],
            risk_category=analysis['risk_category'],
            ml_probability=analysis['ml_probability'],
            rule_score=analysis['rule_score'],
            confidence_score=analysis['confidence_score'],
            scam_type=analysis['scam_type'],
            indicators_json=json.dumps(analysis['indicators']),
            explanation=analysis['explanation'],
            recommendations_json=json.dumps(analysis['recommendations']),
            feature_breakdown_json=json.dumps(analysis['feature_breakdown']),
            created_at=ts
        )

        db.session.add(sr)
        created_scans.append((sc, sr))

    # Create investigation case
    case = InvestigationCase(
        case_uid='CASE-20261105-9F4A2',
        user_id=demo_user.id,
        title='Coordinated Smishing & UPI Collect Fraud Campaign',
        description=(
            'Investigating a linked cluster of SMS KYC phishing lures, WhatsApp task scams, '
            'and deceptive UPI collect payment requests sharing sender phone numbers, domains, and UPI handles.'
        ),
        status='In Progress',
        severity='Critical',
        category='Multi-Channel Phishing & UPI Fraud',
        created_at=now - timedelta(days=3),
        updated_at=now - timedelta(hours=2)
    )

    db.session.add(case)
    db.session.flush()

    # Attach related scans as evidence
    for idx in (0, 1, 3, 5):

        sc, sr = created_scans[idx]

        ents = extract_entities(
            f"{sc.subject_or_sender}\n{sc.submitted_content}"
        )

        ev = Evidence(
            case_id=case.id,
            scan_id=sc.id,
            evidence_type=sc.channel,
            label=f"Artifact: {sc.channel.upper()} ({sc.analysis_uid})",
            content=f"{sc.subject_or_sender}\n{sc.submitted_content}",
            extracted_entities_json=json.dumps(ents),
            risk_score=sr.risk_score,
            source_timestamp=sc.created_at.strftime('%Y-%m-%d %H:%M UTC'),
            created_at=sc.created_at + timedelta(minutes=15)
        )

        db.session.add(ev)

    # Investigation notes
    note1 = InvestigationNote(
        case_id=case.id,
        user_id=demo_user.id,
        note_type='Correlation',
        content=(
            'Cross-channel entity correlation confirmed that sender phone +91-98201-55109 was used in both the '
            'SMS KYC lure and the WhatsApp task scam, while UPI handle merchant-task@ybl is shared between '
            'the WhatsApp solicitation and the OLX UPI collect request.'
        ),
        created_at=now - timedelta(hours=3)
    )

    note2 = InvestigationNote(
        case_id=case.id,
        user_id=demo_user.id,
        note_type='Action Taken',
        content='Generated forensic PDF reports for affected users and submitted malicious domain sbi-kyc-update-online.xyz for takedown.',
        created_at=now - timedelta(hours=1)
    )

    db.session.add_all([note1, note2])
    db.session.commit()
    