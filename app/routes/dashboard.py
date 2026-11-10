from collections import Counter
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, redirect, url_for, current_app
from flask_login import login_required, current_user

from app.models import Scan, ScanResult, InvestigationCase, Evidence, InvestigationNote

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    return redirect(url_for('auth.login'))


@dashboard_bp.route('/dashboard')
@login_required
def index():
    user_scans = (
        Scan.query.join(ScanResult)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )

    total_scans = len(user_scans)
    critical_count = sum(1 for s in user_scans if s.result and s.result.risk_category == 'Critical Risk')
    high_count = sum(1 for s in user_scans if s.result and s.result.risk_category == 'High Risk')
    medium_count = sum(1 for s in user_scans if s.result and s.result.risk_category == 'Medium Risk')
    low_count = sum(1 for s in user_scans if s.result and s.result.risk_category == 'Low Risk')

    high_or_critical = critical_count + high_count
    avg_risk = round(sum(s.result.risk_score for s in user_scans if s.result) / total_scans, 1) if total_scans else 0.0

    # Channel distribution
    channel_counts = Counter(s.channel for s in user_scans)
    channel_labels = ['SMS', 'Email', 'URL', 'WhatsApp', 'Social', 'Payment']
    channel_keys = ['sms', 'email', 'url', 'whatsapp', 'social', 'payment']
    channel_series = [channel_counts.get(k, 0) for k in channel_keys]

    # Scam category distribution (top 6)
    scam_type_counts = Counter(s.result.scam_type for s in user_scans if s.result)
    top_scam_types = scam_type_counts.most_common(6)

    # Weekly scan statistics (last 7 days)
    today = datetime.now(timezone.utc).date()
    day_labels = []
    day_total_counts = []
    day_high_risk_counts = []

    for offset in range(6, -1, -1):
        d = today - timedelta(days=offset)
        day_labels.append(d.strftime('%b %d'))
        matching = [s for s in user_scans if s.created_at and s.created_at.date() == d]
        day_total_counts.append(len(matching))
        day_high_risk_counts.append(sum(1 for s in matching if s.result and s.result.risk_score >= 50))

    # Recent scans & recent investigation cases
    recent_scans = user_scans[:7]
    radar_blips = []
    for idx, s in enumerate(user_scans[:12]):
        sc = s.result.risk_score if s.result else 10
        radar_blips.append({
            'uid': s.analysis_uid,
            'channel': s.channel.upper(),
            'score': sc,
            'category': s.result.risk_category if s.result else 'Low Risk',
            'angle_deg': (idx * 53 + sc * 3) % 360,
            'radius_pct': max(18, min(88, sc))
        })
    recent_cases = (
        InvestigationCase.query
        .filter_by(user_id=current_user.id)
        .order_by(InvestigationCase.updated_at.desc())
        .limit(5)
        .all()
    )

    # Unified recent activity feed (combining scans, cases, and notes)
    activity_feed = []
    for s in user_scans[:5]:
        activity_feed.append({
            'timestamp': s.created_at,
            'icon': 'fa-radar' if s.result and s.result.risk_score >= 50 else 'fa-shield-halved',
            'color': 'danger' if s.result and s.result.risk_score >= 50 else ('warning' if s.result and s.result.risk_score >= 25 else 'success'),
            'title': f'Analyzed {s.channel_label} ({s.analysis_uid})',
            'subtitle': f'{s.result.risk_category} ({s.result.risk_score}/100) — {s.result.scam_type}',
            'url': url_for('analyzer.view_result', scan_id=s.id)
        })

    for c in recent_cases[:4]:
        activity_feed.append({
            'timestamp': c.updated_at,
            'icon': 'fa-folder-tree',
            'color': 'info',
            'title': f'Investigation Case {c.case_uid}: {c.title}',
            'subtitle': f'Status: {c.status} | Severity: {c.severity} | {c.evidence.count()} artifact(s)',
            'url': url_for('investigation.case_detail', case_id=c.id)
        })

    activity_feed.sort(key=lambda x: x['timestamp'] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    activity_feed = activity_feed[:8]

    engine = current_app.extensions.get('scam_engine')
    model_metrics = engine.metrics if engine else {}

    chart_data = {
        'risk_distribution': [low_count, medium_count, high_count, critical_count],
        'channel_labels': channel_labels,
        'channel_series': channel_series,
        'weekly_labels': day_labels,
        'weekly_totals': day_total_counts,
        'weekly_high_risk': day_high_risk_counts,
        'scam_type_labels': [item[0] for item in top_scam_types] or ['No Scans Yet'],
        'scam_type_values': [item[1] for item in top_scam_types] or [0]
    }

    return render_template(
        'dashboard/index.html',
        stats={
            'total_scans': total_scans,
            'high_or_critical': high_or_critical,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'avg_risk': avg_risk,
            'total_cases': InvestigationCase.query.filter_by(user_id=current_user.id).count()
        },
        recent_scans=recent_scans,
        radar_blips=radar_blips,
        recent_cases=recent_cases,
        activity_feed=activity_feed,
        chart_data=chart_data,
        model_metrics=model_metrics
    )
