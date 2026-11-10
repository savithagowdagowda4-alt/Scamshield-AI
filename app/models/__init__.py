import json
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.extensions import db, login_manager


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    """User account model with secure password hashing and preferences."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(120), nullable=False, default='')
    role_title = db.Column(db.String(100), nullable=False, default='Security Analyst')
    organization = db.Column(db.String(120), nullable=False, default='Independent')
    bio = db.Column(db.Text, nullable=False, default='')
    # Settings & preferences
    default_channel = db.Column(db.String(32), nullable=False, default='sms')
    strict_mode = db.Column(db.Boolean, nullable=False, default=False)
    email_alerts = db.Column(db.Boolean, nullable=False, default=True)
    auto_archive_days = db.Column(db.Integer, nullable=False, default=90)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime, default=utcnow, nullable=True)

    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    cases = db.relationship('InvestigationCase', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class Scan(db.Model):
    """Represents a user-submitted multi-channel security scan."""
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    analysis_uid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    channel = db.Column(db.String(32), nullable=False, index=True)  # sms, email, url, whatsapp, social, payment
    subject_or_sender = db.Column(db.String(255), nullable=True, default='')
    submitted_content = db.Column(db.Text, nullable=False)
    metadata_json = db.Column(db.Text, nullable=False, default='{}')
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    # One-to-one relationship with ScanResult
    result = db.relationship('ScanResult', backref='scan', uselist=False, cascade='all, delete-orphan')
    # Evidence links
    evidence_items = db.relationship('Evidence', backref='linked_scan', lazy='dynamic')

    @property
    def metadata_dict(self) -> dict:
        try:
            return json.loads(self.metadata_json or '{}')
        except Exception:
            return {}

    @property
    def channel_label(self) -> str:
        labels = {
            'sms': 'SMS Analyzer',
            'email': 'Email Analyzer',
            'url': 'URL Analyzer',
            'whatsapp': 'WhatsApp Analyzer',
            'social': 'Social Media Analyzer',
            'payment': 'Payment Request Analyzer'
        }
        return labels.get(self.channel, self.channel.upper())


class ScanResult(db.Model):
    """Stores the AI/ML and rule-based analysis result for a Scan."""
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), unique=True, nullable=False, index=True)
    risk_score = db.Column(db.Integer, nullable=False, index=True)  # 0 to 100
    risk_category = db.Column(db.String(32), nullable=False, index=True)  # Low Risk, Medium Risk, High Risk, Critical Risk
    ml_probability = db.Column(db.Float, nullable=False, default=0.0)  # 0.0 to 1.0
    rule_score = db.Column(db.Integer, nullable=False, default=0)  # 0 to 100
    confidence_score = db.Column(db.Float, nullable=False, default=0.0)  # 0.0 to 100.0
    scam_type = db.Column(db.String(64), nullable=False, default='General Suspicious Activity')
    indicators_json = db.Column(db.Text, nullable=False, default='[]')
    explanation = db.Column(db.Text, nullable=False, default='')
    recommendations_json = db.Column(db.Text, nullable=False, default='[]')
    feature_breakdown_json = db.Column(db.Text, nullable=False, default='{}')
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    @property
    def indicators(self) -> list:
        try:
            return json.loads(self.indicators_json or '[]')
        except Exception:
            return []

    @property
    def recommendations(self) -> list:
        try:
            return json.loads(self.recommendations_json or '[]')
        except Exception:
            return []

    @property
    def feature_breakdown(self) -> dict:
        try:
            return json.loads(self.feature_breakdown_json or '{}')
        except Exception:
            return {}


class InvestigationCase(db.Model):
    """Investigation case grouping related suspicious communications, URLs, and analyst notes."""
    __tablename__ = 'investigation_cases'

    id = db.Column(db.Integer, primary_key=True)
    case_uid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False, default='')
    status = db.Column(db.String(32), nullable=False, default='Open', index=True)  # Open, In Progress, Escalated, Resolved, Closed
    severity = db.Column(db.String(32), nullable=False, default='Medium')  # Low, Medium, High, Critical
    category = db.Column(db.String(64), nullable=False, default='Multi-Channel Phishing')
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    evidence = db.relationship('Evidence', backref='case', lazy='dynamic', cascade='all, delete-orphan')
    notes = db.relationship('InvestigationNote', backref='case', lazy='dynamic', cascade='all, delete-orphan')


class Evidence(db.Model):
    """Piece of evidence linked to an InvestigationCase (can optionally link to a saved Scan)."""
    __tablename__ = 'evidence'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('investigation_cases.id'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True, index=True)
    evidence_type = db.Column(db.String(32), nullable=False)  # sms, email, url, whatsapp, social, payment, artifact
    label = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    extracted_entities_json = db.Column(db.Text, nullable=False, default='{}')  # domains, phones, emails, handles, payment_ids
    risk_score = db.Column(db.Integer, nullable=False, default=50)
    source_timestamp = db.Column(db.String(64), nullable=True, default='')
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    @property
    def extracted_entities(self) -> dict:
        try:
            return json.loads(self.extracted_entities_json or '{}')
        except Exception:
            return {}


class InvestigationNote(db.Model):
    """Analyst note attached to an InvestigationCase."""
    __tablename__ = 'investigation_notes'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('investigation_cases.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note_type = db.Column(db.String(32), nullable=False, default='Observation')  # Observation, Action Taken, Correlation, Escalation
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    author = db.relationship('User', foreign_keys=[user_id])
