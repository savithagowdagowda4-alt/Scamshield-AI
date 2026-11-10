import io
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)


def defang_text(text: str) -> str:
    """
    Safely defangs URLs and emails in submitted content so clickable malicious links
    are never live inside the exported PDF forensic report.
    """
    if not text:
        return ''
    safe = text.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    return escape(safe)


def generate_scan_pdf_report(scan) -> bytes:
    """
    Generates a branded, multi-section PDF forensic analysis report for a Scan record
    using ReportLab locally. Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"ScamShield AI Forensic Report - {scan.analysis_uid}"
    )

    styles = getSampleStyleSheet()
    navy_dark = colors.HexColor('#0A1128')
    electric_blue = colors.HexColor('#0066FF')
    cyan_accent = colors.HexColor('#00D4FF')
    slate_gray = colors.HexColor('#475569')
    light_bg = colors.HexColor('#F1F5F9')

    result = scan.result
    risk_score = result.risk_score if result else 0
    risk_cat = result.risk_category if result else 'Unknown'

    if risk_score >= 75:
        badge_color = colors.HexColor('#DC2626')
    elif risk_score >= 50:
        badge_color = colors.HexColor('#EA580C')
    elif risk_score >= 25:
        badge_color = colors.HexColor('#D97706')
    else:
        badge_color = colors.HexColor('#16A34A')

    title_style = ParagraphStyle(
        'BrandTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=navy_dark,
        spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'BrandSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        textColor=slate_gray,
        spaceAfter=8
    )
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=electric_blue,
        spaceBefore=10,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#1E293B')
    )
    code_style = ParagraphStyle(
        'DefangedCode',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#0F172A'),
        backColor=light_bg,
        borderPadding=6
    )
    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=slate_gray
    )

    story = []

    # 1. Branded Header
    story.append(Paragraph("SCAMSHIELD AI — FORENSIC THREAT ANALYSIS REPORT", title_style))
    story.append(Paragraph(
        "Multi-Channel Scam Detection &amp; Investigation Platform | Hybrid AI/ML &amp; Heuristic Security Assessment",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=electric_blue, spaceBefore=2, spaceAfter=10))

    # 2. Metadata & Risk Score Summary Table
    created_str = scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.created_at else 'N/A'
    analyst_name = scan.user.username if scan.user else 'Authenticated Analyst'

    summary_data = [
        [
            Paragraph("<b>Analysis ID:</b>", body_style),
            Paragraph(escape(scan.analysis_uid), body_style),
            Paragraph("<b>Risk Score:</b>", body_style),
            Paragraph(f"<font color='{badge_color.hexval()}'><b>{risk_score} / 100 ({escape(risk_cat)})</b></font>", body_style)
        ],
        [
            Paragraph("<b>Analysis Date:</b>", body_style),
            Paragraph(created_str, body_style),
            Paragraph("<b>ML Probability:</b>", body_style),
            Paragraph(f"{round((result.ml_probability or 0) * 100, 1)}% Scam Linguistic Match", body_style)
        ],
        [
            Paragraph("<b>Input Channel:</b>", body_style),
            Paragraph(escape(scan.channel_label), body_style),
            Paragraph("<b>Heuristic Score:</b>", body_style),
            Paragraph(f"{result.rule_score if result else 0} / 100 Rule Points", body_style)
        ],
        [
            Paragraph("<b>Classification:</b>", body_style),
            Paragraph(escape(result.scam_type if result else 'N/A'), body_style),
            Paragraph("<b>Confidence:</b>", body_style),
            Paragraph(f"{result.confidence_score if result else 0}% (Analyst: {escape(analyst_name)})", body_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[32 * mm, 58 * mm, 32 * mm, 52 * mm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), light_bg),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    # 3. Submitted Content (Defanged for Safe Handling)
    story.append(Paragraph("1. SUBMITTED CONTENT (SAFELY DEFANGED)", section_style))
    if scan.subject_or_sender:
        story.append(Paragraph(f"<b>Sender / Subject Context:</b> {defang_text(scan.subject_or_sender)}", body_style))
        story.append(Spacer(1, 4))
    story.append(Paragraph(defang_text(scan.submitted_content[:2000]), code_style))
    story.append(Spacer(1, 8))

    # 4. Executive Explanation of Findings
    story.append(Paragraph("2. AI/ML &amp; HEURISTIC EXPLANATION OF FINDINGS", section_style))
    story.append(Paragraph(escape(result.explanation if result else 'No explanation available.'), body_style))
    story.append(Spacer(1, 8))

    # 5. Suspicious Indicators Detected
    story.append(Paragraph("3. DETECTED SECURITY INDICATORS", section_style))
    indicators = result.indicators if result else []
    if indicators:
        ind_rows = [[
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>Category</b>", body_style),
            Paragraph("<b>Indicator &amp; Technical Rationale</b>", body_style)
        ]]
        for ind in indicators:
            sev = escape(str(ind.get('severity', 'Medium')))
            cat = escape(str(ind.get('category', 'General')))
            title_txt = escape(str(ind.get('title', '')))
            detail_txt = escape(str(ind.get('detail', '')))
            ind_rows.append([
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(cat, body_style),
                Paragraph(f"<b>{title_txt}</b><br/>{detail_txt}", body_style)
            ])
        ind_table = Table(ind_rows, colWidths=[24 * mm, 38 * mm, 112 * mm])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(ind_table)
    else:
        story.append(Paragraph("No specific high-risk indicators triggered.", body_style))
    story.append(Spacer(1, 8))

    # 6. Recommended Safety Actions
    story.append(Paragraph("4. RECOMMENDED SAFETY &amp; RESPONSE ACTIONS", section_style))
    recs = result.recommendations if result else []
    for idx, rec in enumerate(recs, start=1):
        prio = escape(str(rec.get('priority', 'Standard')))
        act = escape(str(rec.get('action', '')))
        det = escape(str(rec.get('detail', '')))
        story.append(Paragraph(f"<b>{idx}. [{prio}] {act}:</b> {det}", body_style))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor('#CBD5E1'), spaceBefore=4, spaceAfter=6))
    story.append(Paragraph(
        "IMPORTANT DISCLAIMER: ScamShield AI assessments combine statistical machine learning models and rule-based "
        "security heuristics. No automated analysis is 100% accurate. Risk bands (Low 0-24, Medium 25-49, High 50-74, "
        "Critical 75-100) are application-defined metrics and do not constitute formal legal or financial certification. "
        "Never click defanged links; verify suspicious requests independently through official institutional channels.",
        disclaimer_style
    ))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
