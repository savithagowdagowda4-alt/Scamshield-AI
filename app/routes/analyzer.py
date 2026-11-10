import json
import uuid
from datetime import datetime
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, current_app, abort, send_file, jsonify
)
from flask_login import login_required, current_user
import io

from app.extensions import db
from app.models import Scan, ScanResult, InvestigationCase
from app.services.pdf_service import generate_scan_pdf_report

analyzer_bp = Blueprint('analyzer', __name__, url_prefix='/analyzer')

VALID_CHANNELS = {'sms', 'email', 'url', 'whatsapp', 'social', 'payment'}


def _generate_analysis_uid() -> str:
    return 'SS-' + datetime.utcnow().strftime('%Y%m%d') + '-' + uuid.uuid4().hex[:6].upper()


@analyzer_bp.route('/', methods=['GET'])
@login_required
def hub():
    active_channel = request.args.get('channel', current_user.default_channel or 'sms').lower()
    if active_channel not in VALID_CHANNELS:
        active_channel = 'sms'
    user_cases = InvestigationCase.query.filter_by(user_id=current_user.id).order_by(InvestigationCase.updated_at.desc()).all()
    return render_template('analyzer/hub.html', active_channel=active_channel, user_cases=user_cases)


@analyzer_bp.route('/scan', methods=['POST'])
@login_required
def run_scan():
    channel = (request.form.get('channel') or 'sms').lower().strip()
    if channel not in VALID_CHANNELS:
        flash('Invalid analysis channel selected.', 'danger')
        return redirect(url_for('analyzer.hub'))

    subject_or_sender = (request.form.get('subject_or_sender') or '').strip()
    content = (request.form.get('content') or '').strip()
    platform_or_method = (request.form.get('platform_or_method') or '').strip()
    amount_requested = (request.form.get('amount_requested') or '').strip()

    if not content:
        flash('Please provide content or a URL to analyze. Empty submissions cannot be scored.', 'danger')
        return redirect(url_for('analyzer.hub', channel=channel)), 400

    if len(content) > 15000:
        flash('Submitted content exceeds the 15,000 character safety limit.', 'danger')
        return redirect(url_for('analyzer.hub', channel=channel)), 400

    extra_meta = {}
    if platform_or_method:
        extra_meta['platform_or_method'] = platform_or_method[:100]
    if amount_requested:
        extra_meta['amount_requested'] = amount_requested[:64]

    # Enrich content string slightly if payment amount is provided separately
    analysis_input = content
    if channel == 'payment' and amount_requested and amount_requested not in content:
        analysis_input = f"Requested Amount: {amount_requested}\nPayment Method: {platform_or_method}\n{content}"
    elif channel == 'social' and platform_or_method:
        analysis_input = f"Platform: {platform_or_method}\n{content}"

    engine = current_app.extensions['scam_engine']
    analysis = engine.analyze(
        channel=channel,
        content=analysis_input,
        subject_or_sender=subject_or_sender,
        extra_meta=extra_meta,
        strict_mode=current_user.strict_mode
    )

    scan = Scan(
        analysis_uid=_generate_analysis_uid(),
        user_id=current_user.id,
        channel=channel,
        subject_or_sender=subject_or_sender[:255],
        submitted_content=content,
        metadata_json=json.dumps(extra_meta)
    )
    db.session.add(scan)
    db.session.flush()

    scan_result = ScanResult(
        scan_id=scan.id,
        risk_score=analysis['risk_score'],
        risk_category=analysis['risk_category'],
        ml_probability=analysis['ml_probability'],
        rule_score=analysis['rule_score'],
        confidence_score=analysis['confidence_score'],
        scam_type=analysis['scam_type'],
        indicators_json=json.dumps(analysis['indicators']),
        explanation=analysis['explanation'],
        recommendations_json=json.dumps(analysis['recommendations']),
        feature_breakdown_json=json.dumps(analysis['feature_breakdown'])
    )
    db.session.add(scan_result)
    db.session.commit()

    flash(f'Analysis {scan.analysis_uid} completed ({scan_result.risk_category}: {scan_result.risk_score}/100).', 'info')
    return redirect(url_for('analyzer.view_result', scan_id=scan.id))


@analyzer_bp.route('/api/scan', methods=['POST'])
@login_required
def api_run_scan():
    """REST JSON endpoint for programmatic multi-channel scam detection."""
    data = request.get_json(silent=True) or {}
    channel = (data.get('channel') or 'sms').lower().strip()
    content = (data.get('content') or '').strip()
    subject_or_sender = (data.get('subject_or_sender') or '').strip()

    if channel not in VALID_CHANNELS:
        return jsonify({'error': 'Invalid channel'}), 400
    if not content:
        return jsonify({'error': 'Content cannot be empty'}), 400

    engine = current_app.extensions['scam_engine']
    analysis = engine.analyze(
        channel=channel,
        content=content,
        subject_or_sender=subject_or_sender,
        strict_mode=current_user.strict_mode
    )

    scan = Scan(
        analysis_uid=_generate_analysis_uid(),
        user_id=current_user.id,
        channel=channel,
        subject_or_sender=subject_or_sender[:255],
        submitted_content=content,
        metadata_json='{}'
    )
    db.session.add(scan)
    db.session.flush()

    scan_result = ScanResult(
        scan_id=scan.id,
        risk_score=analysis['risk_score'],
        risk_category=analysis['risk_category'],
        ml_probability=analysis['ml_probability'],
        rule_score=analysis['rule_score'],
        confidence_score=analysis['confidence_score'],
        scam_type=analysis['scam_type'],
        indicators_json=json.dumps(analysis['indicators']),
        explanation=analysis['explanation'],
        recommendations_json=json.dumps(analysis['recommendations']),
        feature_breakdown_json=json.dumps(analysis['feature_breakdown'])
    )
    db.session.add(scan_result)
    db.session.commit()

    return jsonify({
        'scan_id': scan.id,
        'analysis_uid': scan.analysis_uid,
        'channel': scan.channel,
        **analysis
    }), 200


@analyzer_bp.route('/result/<int:scan_id>', methods=['GET'])
@login_required
def view_result(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        abort(403)

    user_cases = InvestigationCase.query.filter_by(user_id=current_user.id).order_by(InvestigationCase.updated_at.desc()).all()
    return render_template('analyzer/result.html', scan=scan, result=scan.result, user_cases=user_cases)


@analyzer_bp.route('/result/<int:scan_id>/pdf', methods=['GET'])
@login_required
def download_pdf(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        abort(403)

    pdf_bytes = generate_scan_pdf_report(scan)
    filename = f"ScamShield_Report_{scan.analysis_uid}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )


@analyzer_bp.route('/history', methods=['GET'])
@login_required
def history():
    q = (request.args.get('q') or '').strip()
    channel = (request.args.get('channel') or '').strip().lower()
    risk_level = (request.args.get('risk_level') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()
    page = max(1, request.args.get('page', 1, type=int))
    per_page = 10

    query = Scan.query.join(ScanResult).filter(Scan.user_id == current_user.id)

    if q:
        like_pattern = f"%{q}%"
        query = query.filter(
            db.or_(
                Scan.submitted_content.ilike(like_pattern),
                Scan.subject_or_sender.ilike(like_pattern),
                Scan.analysis_uid.ilike(like_pattern),
                ScanResult.scam_type.ilike(like_pattern)
            )
        )

    if channel in VALID_CHANNELS:
        query = query.filter(Scan.channel == channel)

    if risk_level in ('Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'):
        query = query.filter(ScanResult.risk_category == risk_level)

    if date_from:
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Scan.created_at >= dt_from)
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            query = query.filter(Scan.created_at <= dt_to)
        except ValueError:
            pass

    pagination = query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        'history/index.html',
        scans=pagination.items,
        pagination=pagination,
        filters={
            'q': q,
            'channel': channel,
            'risk_level': risk_level,
            'date_from': date_from,
            'date_to': date_to
        }
    )


@analyzer_bp.route('/reports', methods=['GET'])
@login_required
def reports():
    """Dedicated Security Reports center listing all downloadable forensic PDF reports."""
    scans = (
        Scan.query.join(ScanResult)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return render_template('analyzer/reports.html', scans=scans)


@analyzer_bp.route('/history/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)
    if scan.user_id != current_user.id:
        abort(403)

    uid = scan.analysis_uid
    db.session.delete(scan)
    db.session.commit()
    flash(f'Scan record {uid} permanently deleted.', 'success')
    return redirect(url_for('analyzer.history'))
