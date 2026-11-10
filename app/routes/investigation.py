import json
import uuid
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user

from app.extensions import db
from app.models import InvestigationCase, Evidence, InvestigationNote, Scan
from app.ml.preprocessing import extract_entities
from app.services.investigation_service import compute_evidence_correlations, build_investigation_timeline

investigation_bp = Blueprint('investigation', __name__, url_prefix='/investigations')

VALID_STATUSES = {'Open', 'In Progress', 'Escalated', 'Resolved', 'Closed'}
VALID_SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}


def _generate_case_uid() -> str:
    return 'CASE-' + datetime.now(timezone.utc).strftime('%Y%m%d') + '-' + uuid.uuid4().hex[:5].upper()


@investigation_bp.route('/', methods=['GET'])
@login_required
def list_cases():
    status_filter = (request.args.get('status') or '').strip()
    severity_filter = (request.args.get('severity') or '').strip()
    q = (request.args.get('q') or '').strip()

    query = InvestigationCase.query.filter_by(user_id=current_user.id)

    if status_filter in VALID_STATUSES:
        query = query.filter(InvestigationCase.status == status_filter)
    if severity_filter in VALID_SEVERITIES:
        query = query.filter(InvestigationCase.severity == severity_filter)
    if q:
        like_pat = f"%{q}%"
        query = query.filter(
            db.or_(
                InvestigationCase.title.ilike(like_pat),
                InvestigationCase.description.ilike(like_pat),
                InvestigationCase.case_uid.ilike(like_pat),
                InvestigationCase.category.ilike(like_pat)
            )
        )

    cases = query.order_by(InvestigationCase.updated_at.desc()).all()
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(25).all()

    return render_template(
        'investigation/list.html',
        cases=cases,
        user_scans=user_scans,
        filters={'status': status_filter, 'severity': severity_filter, 'q': q}
    )


@investigation_bp.route('/create', methods=['POST'])
@login_required
def create_case():
    title = (request.form.get('title') or '').strip()
    description = (request.form.get('description') or '').strip()
    severity = (request.form.get('severity') or 'Medium').strip()
    category = (request.form.get('category') or 'Multi-Channel Phishing').strip()
    initial_scan_id = request.form.get('initial_scan_id', type=int)

    if not title:
        flash('Investigation case title is required.', 'danger')
        return redirect(url_for('investigation.list_cases')), 400

    if severity not in VALID_SEVERITIES:
        severity = 'Medium'

    new_case = InvestigationCase(
        case_uid=_generate_case_uid(),
        user_id=current_user.id,
        title=title[:200],
        description=description[:3000],
        status='Open',
        severity=severity,
        category=category[:64]
    )
    db.session.add(new_case)
    db.session.flush()

    # Optionally attach an existing scan owned by this user right upon creation
    if initial_scan_id:
        scan = db.session.get(Scan, initial_scan_id)
        if scan and scan.user_id == current_user.id:
            entities = extract_entities(f"{scan.subject_or_sender or ''}\n{scan.submitted_content}")
            ev = Evidence(
                case_id=new_case.id,
                scan_id=scan.id,
                evidence_type=scan.channel,
                label=f"Linked Scan {scan.analysis_uid} ({scan.channel.upper()})",
                content=scan.submitted_content,
                extracted_entities_json=json.dumps(entities),
                risk_score=scan.result.risk_score if scan.result else 50,
                source_timestamp=scan.created_at.strftime('%Y-%m-%d %H:%M UTC')
            )
            db.session.add(ev)

    db.session.commit()
    flash(f'Investigation case {new_case.case_uid} ("{new_case.title}") created.', 'success')
    return redirect(url_for('investigation.case_detail', case_id=new_case.id))


@investigation_bp.route('/<int:case_id>', methods=['GET'])
@login_required
def case_detail(case_id: int):
    case = db.session.get(InvestigationCase, case_id)
    if not case:
        abort(404)
    if case.user_id != current_user.id:
        abort(403)

    evidence_items = case.evidence.order_by(Evidence.created_at.asc()).all()
    notes = case.notes.order_by(InvestigationNote.created_at.desc()).all()
    correlations = compute_evidence_correlations(evidence_items)
    timeline = build_investigation_timeline(case)
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(30).all()

    return render_template(
        'investigation/detail.html',
        case=case,
        evidence_items=evidence_items,
        notes=notes,
        correlations=correlations,
        timeline=timeline,
        user_scans=user_scans
    )


@investigation_bp.route('/<int:case_id>/evidence', methods=['POST'])
@login_required
def add_evidence(case_id: int):
    case = db.session.get(InvestigationCase, case_id)
    if not case:
        abort(404)
    if case.user_id != current_user.id:
        abort(403)

    linked_scan_id = request.form.get('scan_id', type=int)
    if linked_scan_id:
        scan = db.session.get(Scan, linked_scan_id)
        if not scan or scan.user_id != current_user.id:
            abort(403)
        entities = extract_entities(f"{scan.subject_or_sender or ''}\n{scan.submitted_content}")
        ev = Evidence(
            case_id=case.id,
            scan_id=scan.id,
            evidence_type=scan.channel,
            label=request.form.get('label', '').strip() or f"Scan {scan.analysis_uid} ({scan.channel.upper()})",
            content=scan.submitted_content,
            extracted_entities_json=json.dumps(entities),
            risk_score=scan.result.risk_score if scan.result else 50,
            source_timestamp=scan.created_at.strftime('%Y-%m-%d %H:%M UTC')
        )
        db.session.add(ev)
        case.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        flash(f'Scan {scan.analysis_uid} linked to investigation case {case.case_uid}.', 'success')
        return redirect(url_for('investigation.case_detail', case_id=case.id))

    # Manual evidence entry
    evidence_type = (request.form.get('evidence_type') or 'sms').strip().lower()
    label = (request.form.get('label') or '').strip()
    content = (request.form.get('content') or '').strip()
    source_timestamp = (request.form.get('source_timestamp') or '').strip()

    if not label or not content:
        flash('Both evidence label and content are required.', 'danger')
        return redirect(url_for('investigation.case_detail', case_id=case.id)), 400

    engine = current_app.extensions['scam_engine']
    analysis = engine.analyze(
        channel=evidence_type if evidence_type in ('sms', 'email', 'url', 'whatsapp', 'social', 'payment') else 'sms',
        content=content,
        strict_mode=current_user.strict_mode
    )
    entities = extract_entities(content)

    ev = Evidence(
        case_id=case.id,
        scan_id=None,
        evidence_type=evidence_type[:32],
        label=label[:200],
        content=content[:10000],
        extracted_entities_json=json.dumps(entities),
        risk_score=analysis['risk_score'],
        source_timestamp=source_timestamp[:64] or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    )
    db.session.add(ev)
    case.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    flash(f'Evidence artifact "{ev.label}" added and analyzed (Risk Score: {ev.risk_score}/100).', 'success')
    return redirect(url_for('investigation.case_detail', case_id=case.id))


@investigation_bp.route('/<int:case_id>/evidence/<int:evidence_id>/delete', methods=['POST'])
@login_required
def delete_evidence(case_id: int, evidence_id: int):
    case = db.session.get(InvestigationCase, case_id)
    if not case or case.user_id != current_user.id:
        abort(403)

    ev = db.session.get(Evidence, evidence_id)
    if not ev or ev.case_id != case.id:
        abort(404)

    db.session.delete(ev)
    case.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    flash('Evidence artifact removed from case.', 'info')
    return redirect(url_for('investigation.case_detail', case_id=case.id))


@investigation_bp.route('/<int:case_id>/note', methods=['POST'])
@login_required
def add_note(case_id: int):
    case = db.session.get(InvestigationCase, case_id)
    if not case:
        abort(404)
    if case.user_id != current_user.id:
        abort(403)

    note_type = (request.form.get('note_type') or 'Observation').strip()
    content = (request.form.get('content') or '').strip()

    if not content:
        flash('Investigation note content cannot be empty.', 'danger')
        return redirect(url_for('investigation.case_detail', case_id=case.id)), 400

    note = InvestigationNote(
        case_id=case.id,
        user_id=current_user.id,
        note_type=note_type[:32],
        content=content[:4000]
    )
    db.session.add(note)
    case.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    flash('Analyst investigation note logged to case timeline.', 'success')
    return redirect(url_for('investigation.case_detail', case_id=case.id))


@investigation_bp.route('/<int:case_id>/status', methods=['POST'])
@login_required
def update_status(case_id: int):
    case = db.session.get(InvestigationCase, case_id)
    if not case:
        abort(404)
    if case.user_id != current_user.id:
        abort(403)

    new_status = (request.form.get('status') or '').strip()
    new_severity = (request.form.get('severity') or '').strip()

    if new_status in VALID_STATUSES:
        case.status = new_status
    if new_severity in VALID_SEVERITIES:
        case.severity = new_severity

    case.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    flash(f'Case {case.case_uid} updated (Status: {case.status}, Severity: {case.severity}).', 'success')
    return redirect(url_for('investigation.case_detail', case_id=case.id))


@investigation_bp.route('/<int:case_id>/delete', methods=['POST'])
@login_required
def delete_case(case_id: int):
    case = db.session.get(InvestigationCase, case_id)
    if not case:
        abort(404)
    if case.user_id != current_user.id:
        abort(403)

    uid = case.case_uid
    db.session.delete(case)
    db.session.commit()
    flash(f'Investigation case {uid} deleted.', 'info')
    return redirect(url_for('investigation.list_cases'))
