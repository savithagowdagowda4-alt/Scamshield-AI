from app import create_app
from app.extensions import db
from app.models import User

app = create_app()

with app.app_context():
    db.create_all()

    username = "demo_analyst"
    email = "demo@scamshield.local"
    password = "DemoShield@2026"

    user = User.query.filter_by(username=username).first()

    if not user:
        user = User(
            username=username,
            email=email,
            full_name="Demo Analyst",
            role_title="Security Analyst",
            organization="ScamShield AI"
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print("Demo account created successfully!")
    else:
        print("Demo account already exists.")