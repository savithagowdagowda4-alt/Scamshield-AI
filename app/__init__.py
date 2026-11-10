import os
from importlib import import_module
from flask import Flask
from flask import Blueprint

from config import Config
from app.extensions import db, login_manager, csrf


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register application route blueprints
    for module_name in ("auth", "dashboard", "analyzer", "investigation"):
        module = import_module(f"app.routes.{module_name}")

        for item in vars(module).values():
            if isinstance(item, Blueprint):
                app.register_blueprint(item)

    # Create database tables and demo analyst account
    with app.app_context():
        from app.models import User

        db.create_all()

        demo_user = User.query.filter_by(username="analyst").first()

        if demo_user is None:
            demo_user = User(
                username="analyst",
                email="analyst@scamshield.local",
                full_name="Demo Analyst",
                role_title="Security Analyst",
                organization="ScamShield AI"
            )
            db.session.add(demo_user)

        demo_user.set_password("ScamShield@2026")
        db.session.commit()

    return app