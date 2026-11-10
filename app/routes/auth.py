import re
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db
from app.models import User

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

EMAIL_SIMPLE_RE = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.-]{3,32}$')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        full_name = (request.form.get('full_name') or '').strip()
        role_title = (request.form.get('role_title') or 'Security Analyst').strip()
        organization = (request.form.get('organization') or 'Independent').strip()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        # Strict input validation
        if not USERNAME_RE.match(username):
            flash('Username must be 3–32 characters using letters, numbers, dots, hyphens, or underscores.', 'danger')
            return render_template('auth/register.html'), 400

        if not EMAIL_SIMPLE_RE.match(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('auth/register.html'), 400

        if len(password) < 8:
            flash('Password must be at least 8 characters long for security compliance.', 'danger')
            return render_template('auth/register.html'), 400

        if password != confirm_password:
            flash('Passwords do not match. Please re-enter.', 'danger')
            return render_template('auth/register.html'), 400

        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            flash('Username is already registered. Please choose another.', 'danger')
            return render_template('auth/register.html'), 400

        if User.query.filter(db.func.lower(User.email) == email).first():
            flash('Email address is already registered. Please sign in instead.', 'danger')
            return render_template('auth/register.html'), 400

        user = User(
            username=username,
            email=email,
            full_name=full_name or username,
            role_title=role_title[:100],
            organization=organization[:120]
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash(f'Welcome to ScamShield AI, {user.full_name}! Your analyst workspace is ready.', 'success')
        return redirect(url_for('dashboard.index'))

    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        password = request.form.get('password') or ''
        remember = bool(request.form.get('remember'))

        if not identifier or not password:
            flash('Please enter both your username/email and password.', 'danger')
            return render_template('auth/login.html'), 400

        user = User.query.filter(
            db.or_(
                db.func.lower(User.username) == identifier.lower(),
                db.func.lower(User.email) == identifier.lower()
            )
        ).first()

        if not user or not user.check_password(password):
            flash('Invalid credentials. Please verify your username/email and password.', 'danger')
            return render_template('auth/login.html'), 401

        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        login_user(user, remember=remember)
        flash(f'Authenticated successfully as {user.username}.', 'success')

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/') and not next_page.startswith('//'):
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html')


@auth_bp.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    flash('You have been securely logged out of ScamShield AI.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('form_action', 'update_profile')
        if action == 'update_profile':
            full_name = (request.form.get('full_name') or '').strip()
            email = (request.form.get('email') or '').strip().lower()
            role_title = (request.form.get('role_title') or '').strip()
            organization = (request.form.get('organization') or '').strip()
            bio = (request.form.get('bio') or '').strip()

            if not EMAIL_SIMPLE_RE.match(email):
                flash('Please provide a valid email address.', 'danger')
                return redirect(url_for('auth.profile'))

            existing = User.query.filter(db.func.lower(User.email) == email, User.id != current_user.id).first()
            if existing:
                flash('That email address is already in use by another account.', 'danger')
                return redirect(url_for('auth.profile'))

            current_user.full_name = full_name[:120] or current_user.username
            current_user.email = email
            current_user.role_title = role_title[:100] or 'Security Analyst'
            current_user.organization = organization[:120] or 'Independent'
            current_user.bio = bio[:1000]
            db.session.commit()
            flash('Analyst profile updated successfully.', 'success')

        elif action == 'change_password':
            current_pw = request.form.get('current_password') or ''
            new_pw = request.form.get('new_password') or ''
            confirm_pw = request.form.get('confirm_password') or ''

            if not current_user.check_password(current_pw):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('auth.profile'))

            if len(new_pw) < 8:
                flash('New password must be at least 8 characters long.', 'danger')
                return redirect(url_for('auth.profile'))

            if new_pw != confirm_pw:
                flash('New password and confirmation do not match.', 'danger')
                return redirect(url_for('auth.profile'))

            current_user.set_password(new_pw)
            db.session.commit()
            flash('Password updated successfully.', 'success')

        return redirect(url_for('auth.profile'))

    total_scans = current_user.scans.count()
    total_cases = current_user.cases.count()
    return render_template('auth/profile.html', total_scans=total_scans, total_cases=total_cases)


@auth_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        default_channel = (request.form.get('default_channel') or 'sms').lower()
        if default_channel not in ('sms', 'email', 'url', 'whatsapp', 'social', 'payment'):
            default_channel = 'sms'

        strict_mode = bool(request.form.get('strict_mode'))
        email_alerts = bool(request.form.get('email_alerts'))
        try:
            auto_archive_days = int(request.form.get('auto_archive_days', 90))
            auto_archive_days = max(7, min(365, auto_archive_days))
        except ValueError:
            auto_archive_days = 90

        current_user.default_channel = default_channel
        current_user.strict_mode = strict_mode
        current_user.email_alerts = email_alerts
        current_user.auto_archive_days = auto_archive_days
        db.session.commit()
        flash('Detection engine & workspace settings saved.', 'success')
        return redirect(url_for('auth.settings'))

    return render_template('auth/settings.html')
