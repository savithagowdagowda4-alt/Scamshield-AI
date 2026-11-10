from collections import defaultdict
from app.ml.preprocessing import extract_entities


def compute_evidence_correlations(evidence_list: list) -> dict:
    """
    Analyzes actual saved Evidence records in an InvestigationCase to discover genuine
    shared entities (domains, URLs, emails, phone numbers, UPI handles, crypto wallets).
    Never fabricates fake connections between unrelated evidence items.
    """
    entity_index = defaultdict(list)

    for ev in evidence_list:
        entities = ev.extracted_entities
        if not entities:
            entities = extract_entities(ev.content)

        for domain in entities.get('domains', []):
            entity_index[('Domain', domain)].append(ev)
        for email in entities.get('emails', []):
            entity_index[('Email Address', email)].append(ev)
        for phone in entities.get('phones', []):
            entity_index[('Phone Number', phone)].append(ev)
        for handle in entities.get('payment_handles', []):
            entity_index[('UPI / Payment Handle', handle)].append(ev)
        for wallet in entities.get('crypto_wallets', []):
            entity_index[('Crypto Wallet', wallet)].append(ev)

    shared_correlations = []
    all_extracted = []

    for (etype, eval_str), linked_evs in entity_index.items():
        ev_summaries = [{'id': e.id, 'label': e.label, 'type': e.evidence_type} for e in linked_evs]
        all_extracted.append({
            'entity_type': etype,
            'entity_value': eval_str,
            'count': len(linked_evs),
            'evidence_items': ev_summaries
        })
        if len(linked_evs) >= 2:
            shared_correlations.append({
                'entity_type': etype,
                'entity_value': eval_str,
                'count': len(linked_evs),
                'evidence_items': ev_summaries,
                'summary': (
                    f'{etype} "{eval_str}" appears across {len(linked_evs)} evidence artifacts: '
                    + ', '.join(f'#{e.id} ({e.label})' for e in linked_evs)
                )
            })

    shared_correlations.sort(key=lambda x: x['count'], reverse=True)
    all_extracted.sort(key=lambda x: x['count'], reverse=True)

    return {
        'shared_correlations': shared_correlations,
        'all_entities': all_extracted,
        'has_shared_links': len(shared_correlations) > 0
    }


def build_investigation_timeline(case) -> list:
    """
    Generates a unified chronological timeline combining case creation,
    evidence additions, and analyst investigation notes.
    """
    events = [{
        'timestamp': case.created_at,
        'event_type': 'Case Opened',
        'icon': 'fa-folder-plus',
        'badge_class': 'bg-info',
        'title': f'Investigation Case {case.case_uid} Created',
        'detail': f'Case "{case.title}" initialized under category {case.category} with {case.severity} severity.'
    }]

    for ev in case.evidence.order_by(None).all():
        events.append({
            'timestamp': ev.created_at,
            'event_type': 'Evidence Added',
            'icon': 'fa-microscope',
            'badge_class': 'bg-danger' if ev.risk_score >= 50 else 'bg-primary',
            'title': f'Evidence Artifact #{ev.id}: {ev.label} ({ev.evidence_type.upper()})',
            'detail': f'Risk Score: {ev.risk_score}/100 | Content snippet: {ev.content[:120]}{"..." if len(ev.content) > 120 else ""}'
        })

    for note in case.notes.order_by(None).all():
        events.append({
            'timestamp': note.created_at,
            'event_type': f'Analyst Note ({note.note_type})',
            'icon': 'fa-clipboard-check',
            'badge_class': 'bg-secondary',
            'title': f'{note.note_type} Note by {note.author.username if note.author else "Analyst"}',
            'detail': note.content
        })

    events.sort(key=lambda x: x['timestamp'])
    return events
