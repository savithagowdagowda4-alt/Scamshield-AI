import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration for ScamShield AI."""

    SECRET_KEY = os.environ.get(
        'SCAMSHIELD_SECRET_KEY',
        'scamshield-ai-dev-secret-key-2026'
    )

    # Vercel allows writing to /tmp
    if os.environ.get('VERCEL'):
        INSTANCE_DIR = '/tmp/scamshield-instance'
    else:
        INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')

    os.makedirs(INSTANCE_DIR, exist_ok=True)

    SQLALCHEMY_DATABASE_URI = (
        os.environ.get('DATABASE_URL')
        or f"sqlite:///{os.path.join(INSTANCE_DIR, 'scamshield.db')}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 2 * 1024 * 1024

    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    MODEL_DIR = os.path.join(INSTANCE_DIR, 'models')
    os.makedirs(MODEL_DIR, exist_ok=True)


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'scamshield-ai-testing-secret-key'