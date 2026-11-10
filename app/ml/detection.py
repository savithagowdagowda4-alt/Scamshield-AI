import re
from urllib.parse import urlparse, parse_qs

from app.ml.preprocessing import preprocess_text, extract_entities, extract_numerical_features
from app.ml.training import train_and_save_model, extract_top_contributing_terms


SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.info', '.site', '.online', '.vip', '.work',
    '.click', '.link', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq', '.icu',
    '.cam', '.rest', '.monster', '.loan', '.win', '.bid'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc'
}

TARGETED_BRANDS = {
    'paypal': ['paypal.com'],
    'microsoft': ['microsoft.com', 'office.com', 'live.com', 'microsoftonline.com'],
    'apple': ['apple.com', 'icloud.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com'],
    'amazon': ['amazon.com', 'amazon.in', 'amzn.to'],
    'netflix': ['netflix.com'],
    'hdfc': ['hdfcbank.com'],
    'sbi': ['onlinesbi.sbi', 'sbi.co.in'],
    'icici': ['icicibank.com'],
    'citibank': ['citi.com', 'citibank.com'],
    'fedex': ['fedex.com'],
    'dhl': ['dhl.com'],
    'indiapost': ['indiapost.gov.in'],
    'metamask': ['metamask.io'],
    'binance': ['binance.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'docusign': ['docusign.com', 'docusign.net']
}


def classify_risk_band(score: int) -> str:
    """
    Maps a 0-100 risk score into application-defined risk bands:
    0-24: Low Risk
    25-49: Medium Risk
    50-74: High Risk
    75-100: Critical Risk
    """
    score = max(0, min(100, int(round(score))))
    if score <= 24:
        return 'Low Risk'
    elif score <= 49:
        return 'Medium Risk'
    elif score <= 74:
        return 'High Risk'
    else:
        return 'Critical Risk'


def inspect_url_static(raw_url: str) -> dict:
    """
    Performs static, non-executing URL security analysis.
    Never visits, pings, or executes the target URL.
    """
    url_str = (raw_url or '').strip()
    if not url_str:
        return {
            'is_valid_format': False,
            'normalized_url': '',
            'scheme': '',
            'hostname': '',
            'uses_https': False,
            'is_ip_hostname': False,
            'has_at_symbol': False,
            'has_punycode': False,
            'subdomain_depth': 0,
            'suspicious_tld': False,
            'is_shortener': False,
            'impersonated_brand': None,
            'url_indicators': [],
            'url_rule_points': 0
        }

    # Check if user omitted scheme
    has_explicit_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_str))
    parse_target = url_str if has_explicit_scheme else f'http://{url_str}'

    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or '').lower().strip('.')
        scheme = (parsed.scheme or 'http').lower()
        path_and_query = (parsed.path or '') + ('?' + parsed.query if parsed.query else '')
    except Exception:
        return {
            'is_valid_format': False,
            'normalized_url': url_str,
            'scheme': '',
            'hostname': '',
            'uses_https': False,
            'is_ip_hostname': False,
            'has_at_symbol': False,
            'has_punycode': False,
            'subdomain_depth': 0,
            'suspicious_tld': False,
            'is_shortener': False,
            'impersonated_brand': None,
            'url_indicators': [{
                'category': 'Malformed URL',
                'severity': 'Medium',
                'title': 'Invalid or Obfuscated URL Syntax',
                'detail': 'The submitted string could not be parsed as a standard RFC-compliant URL.'
            }],
            'url_rule_points': 35
        }

    # Basic hostname validity check
    is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', hostname))
    is_valid_domain = bool(
        hostname and (is_ip or ('.' in hostname and re.match(r'^[a-z0-9.-]+$', hostname)))
    )

    if not is_valid_domain:
        return {
            'is_valid_format': False,
            'normalized_url': url_str,
            'scheme': scheme,
            'hostname': hostname,
            'uses_https': False,
            'is_ip_hostname': False,
            'has_at_symbol': False,
            'has_punycode': False,
            'subdomain_depth': 0,
            'suspicious_tld': False,
            'is_shortener': False,
            'impersonated_brand': None,
            'url_indicators': [{
                'category': 'URL Format',
                'severity': 'Medium',
                'title': 'Unrecognized Domain Format',
                'detail': 'The URL does not contain a valid domain name or IPv4 address.'
            }],
            'url_rule_points': 30
        }

    indicators = []
    points = 0

    uses_https = (scheme == 'https')
    if not uses_https:
        points += 16
        indicators.append({
            'category': 'Transport Security',
            'severity': 'Medium',
            'title': 'Unencrypted HTTP Protocol',
            'detail': 'URL uses unencrypted HTTP (or omits HTTPS), exposing submitted credentials or session tokens in transit.'
        })

    if is_ip:
        points += 38
        indicators.append({
            'category': 'Host Obfuscation',
            'severity': 'Critical',
            'title': 'Raw IP-Address Hostname Detected',
            'detail': f'URL points directly to an IP address ({hostname}) instead of a registered domain, a common phishing evasion technique.'
        })

    has_at = '@' in url_str
    if has_at:
        points += 32
        indicators.append({
            'category': 'URL Obfuscation',
            'severity': 'High',
            'title': 'Embedded "@" Credential Redirection Symbol',
            'detail': 'The URL contains an "@" character, which browsers interpret by ignoring everything before "@" and redirecting to the host after it.'
        })

    has_punycode = 'xn--' in hostname
    if has_punycode:
        points += 34
        indicators.append({
            'category': 'Homograph Attack',
            'severity': 'High',
            'title': 'Internationalized Punycode Domain (xn--)',
            'detail': f'Hostname "{hostname}" uses Punycode encoding, often abused for look-alike homograph domain spoofing.'
        })

    host_parts = [p for p in hostname.split('.') if p]
    subdomain_depth = max(0, len(host_parts) - 2) if not is_ip else 0
    if subdomain_depth >= 3:
        points += 20
        indicators.append({
            'category': 'Domain Structure',
            'severity': 'Medium',
            'title': 'Excessive Subdomain Nesting',
            'detail': f'Hostname has {subdomain_depth} subdomain levels ({hostname}), often used to hide the true root domain on mobile screens.'
        })

    if hostname.count('-') >= 3:
        points += 18
        indicators.append({
            'category': 'Domain Structure',
            'severity': 'Medium',
            'title': 'Multi-Hyphenated Deceptive Hostname',
            'detail': f'Hostname "{hostname}" chains multiple hyphens to mimic legitimate security or login portals.'
        })

    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_tld = tld
            break
    if matched_tld:
        points += 24
        indicators.append({
            'category': 'Domain Reputation',
            'severity': 'High',
            'title': f'High-Abuse Top-Level Domain ({matched_tld})',
            'detail': f'The domain uses the "{matched_tld}" TLD, which is frequently registered in bulk for short-lived phishing campaigns.'
        })

    is_shortener = hostname in URL_SHORTENERS
    if is_shortener:
        points += 20
        indicators.append({
            'category': 'Link Masking',
            'severity': 'Medium',
            'title': 'URL Shortener Concealing Destination',
            'detail': f'"{hostname}" is a URL shortening service that masks the final landing domain from inspection.'
        })

    # Check brand impersonation in hostname or path
    impersonated_brand = None
    full_lower = (hostname + ' ' + path_and_query).lower()
    for brand, official_domains in TARGETED_BRANDS.items():
        if brand in full_lower:
            is_official = any(hostname == od or hostname.endswith('.' + od) for od in official_domains)
            if not is_official:
                impersonated_brand = brand.capitalize()
                points += 35
                indicators.append({
                    'category': 'Brand Impersonation',
                    'severity': 'Critical',
                    'title': f'Potential {impersonated_brand} Brand Spoofing',
                    'detail': f'URL references "{brand}" but is hosted on "{hostname}", which is not an official {impersonated_brand} domain ({", ".join(official_domains)}).'
                })
                break

    # Suspicious path/query tokens
    sensitive_path_terms = re.findall(
        r'\b(?:login|signin|verify|kyc|update|secure|account|password|credential|otp|cvv|wallet|seedphrase|airdrop|unlock|refund)\b',
        path_and_query.lower()
    )
    if sensitive_path_terms:
        unique_path_terms = sorted(set(sensitive_path_terms))
        if not hostname.endswith(('python.org', 'palletsprojects.com', 'scikit-learn.org', 'mozilla.org', 'owasp.org', 'github.com', 'wikipedia.org', 'getbootstrap.com', 'chartjs.org', 'nic.in')):
            points += min(24, 8 * len(unique_path_terms))
            indicators.append({
                'category': 'URL Path Structure',
                'severity': 'Medium',
                'title': 'Credential / Verification Lure Keywords in URL',
                'detail': f'URL path or query contains sensitive action tokens: {", ".join(unique_path_terms)}.'
            })

    if parsed.port and parsed.port not in (80, 443):
        points += 18
        indicators.append({
            'category': 'Network Port',
            'severity': 'Medium',
            'title': f'Non-Standard Web Port (:{parsed.port})',
            'detail': f'URL specifies port {parsed.port} instead of standard ports 80/443.'
        })

    return {
        'is_valid_format': True,
        'normalized_url': parse_target,
        'scheme': scheme,
        'hostname': hostname,
        'uses_https': uses_https,
        'is_ip_hostname': is_ip,
        'has_at_symbol': has_at,
        'has_punycode': has_punycode,
        'subdomain_depth': subdomain_depth,
        'suspicious_tld': bool(matched_tld),
        'is_shortener': is_shortener,
        'impersonated_brand': impersonated_brand,
        'url_indicators': indicators,
        'url_rule_points': min(100, points)
    }


# ---------------------------------------------------------------------------
# MULTI-CHANNEL HEURISTIC RULE DEFINITIONS
# ---------------------------------------------------------------------------
COMMON_RULES = [
    {
        'id': 'urgency_coercion',
        'category': 'Urgency & Coercion',
        'severity': 'High',
        'points': 20,
        'title': 'High-Urgency or Coercive Deadline Language',
        'pattern': re.compile(
            r'\b(?:urgent|immediately|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|final\s+notice|final\s+warning|action\s+required|act\s+now|expire[sd]?|suspended|deactivated|permanently\s+deleted|account\s+blocked|account\s+frozen|disconnected\s+tonight)\b',
            re.IGNORECASE
        ),
        'detail_tpl': 'Detected time-pressure phrasing ({matches}) designed to force hasty action before verification.'
    },
    {
        'id': 'credential_otp_harvest',
        'category': 'Credential Harvesting',
        'severity': 'Critical',
        'points': 32,
        'title': 'Request for OTP, PIN, CVV, or Secret Credentials',
        'pattern': re.compile(
            r'(?:\b(?:share|enter|submit|reply\s+with|verify|confirm|input|provide|send)\b.{0,45}\b(?:otp|pin|mpin|cvv|password|passcode|seed\s+phrase|recovery\s+phrase|2fa\s+code|6-digit\s+code)\b|\b(?:otp|cvv|upi\s+pin|atm\s+pin|seed\s+phrase|12-word\s+recovery)\b)',
            re.IGNORECASE
        ),
        'detail_tpl': 'Detected sensitive authentication or secret credential keywords ({matches}). Legitimate organizations do not ask users to share OTPs, PINs, or seed phrases.'
    },
    {
        'id': 'legal_arrest_threat',
        'category': 'Extortion & Threat',
        'severity': 'Critical',
        'points': 30,
        'title': 'Legal, Police, or Digital Arrest Intimidation',
        'pattern': re.compile(
            r'\b(?:arrest\s+warrant|digital\s+arrest|cyber\s+crime\s+police|narcotics\s+department|money\s+laundering|customs\s+seized|legal\s+action\s+initiated|cbi\s+notice|court\s+summons|rbi\s+safe\s+verification)\b',
            re.IGNORECASE
        ),
        'detail_tpl': 'Detected law-enforcement or legal intimidation terms ({matches}), a hallmark of extortion and "Digital Arrest" scams.'
    },
    {
        'id': 'advance_fee_lottery',
        'category': 'Advance Fee / Prize Lure',
        'severity': 'High',
        'points': 26,
        'title': 'Unrealistic Prize, Lottery, or Advance-Fee Lure',
        'pattern': re.compile(
            r'\b(?:won\s+[\$£€₹]?[\d,]+|mega\s+national\s+lottery|inheritance\s+fund|processing\s+fee|clearance\s+fee|notarization\s+fee|claim\s+your\s+(?:cash\s+)?prize|free\s+spin\s+wheel|lucky\s+draw|0%\s+interest.{0,25}processing\s+charge)\b',
            re.IGNORECASE
        ),
        'detail_tpl': 'Detected prize/windfall lure or upfront fee demand ({matches}).'
    },
    {
        'id': 'remote_access_tool',
        'category': 'Remote Takeover',
        'severity': 'Critical',
        'points': 34,
        'title': 'Remote Desktop / Screen-Sharing Tool Request',
        'pattern': re.compile(
            r'\b(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|remote\s+access|screen\s+sharing\s+app)\b',
            re.IGNORECASE
        ),
        'detail_tpl': 'Detected request to use remote access software ({matches}), commonly abused in tech-support and refund scams to drain bank accounts.'
    }
]

CHANNEL_SPECIFIC_RULES = {
    'sms': [
        {
            'id': 'sms_kyc_utility_parcel',
            'category': 'SMS Smishing Lure',
            'severity': 'High',
            'points': 24,
            'title': 'SMS KYC, Utility Disconnection, or Parcel Hold Lure',
            'pattern': re.compile(
                r'\b(?:incomplete\s+kyc|update\s+your\s+pan|electricity\s+bill\s+is\s+unpaid|power\s+connection\s+will\s+be\s+disconnected|parcel\s+#?[a-z0-9-]+\s+is\s+on\s+hold|redelivery\s+charge|fastag\s+toll\s+violation|sim\s+card\s+document\s+verification)\b',
                re.IGNORECASE
            ),
            'detail_tpl': 'Matches classic SMS smishing pretext ({matches}).'
        }
    ],
    'email': [
        {
            'id': 'email_bec_wire_giftcard',
            'category': 'Business Email Compromise',
            'severity': 'Critical',
            'points': 28,
            'title': 'BEC Wire Diversion or Executive Gift-Card Request',
            'pattern': re.compile(
                r'\b(?:vendor\s+bank\s+account\s+has\s+changed|new\s+offshore\s+iban|purchase\s+\d*\s*(?:apple|steam|razer|google\s+play)\s+gift\s+cards|redemption\s+codes|in\s+a\s+board\s+meeting\s+and\s+cannot\s+take\s+calls|payroll\s+update|direct\s+deposit\s+verification\s+failed)\b',
                re.IGNORECASE
            ),
            'detail_tpl': 'Detected Business Email Compromise (BEC) or executive impersonation language ({matches}).'
        },
        {
            'id': 'email_impersonation_header',
            'category': 'Impersonation Indicator',
            'severity': 'High',
            'points': 22,
            'title': 'High-Risk Security Alert or Account Limitation Pretext',
            'pattern': re.compile(
                r'\b(?:password\s+expires\s+in\s+\d+|account\s+limited|storage\s+locked|docusign\s+signature\s+required|auto-renewal\s+invoice.{0,20}charged)\b',
                re.IGNORECASE
            ),
            'detail_tpl': 'Email uses an authoritative security or billing pretext ({matches}) to induce panic.'
        }
    ],
    'whatsapp': [
        {
            'id': 'wa_task_job_investment',
            'category': 'Task & Investment Scam',
            'severity': 'Critical',
            'points': 30,
            'title': 'Prepaid Task Job, VIP Trading Group, or Family Emergency Lure',
            'pattern': re.compile(
                r'\b(?:liking\s+youtube\s+videos|rating\s+hotels|prepaid\s+task|prepaid\s+merchant\s+orders|vip\s+stock\s+trading|guaranteed\s+\d+%\s+profit|trading\s+apk|phone\s+fell\s+in\s+water|temporary\s+number.{0,30}medical\s+emergency|usdt\s+arbitrage)\b',
                re.IGNORECASE
            ),
            'detail_tpl': 'Matches known WhatsApp fraud pattern ({matches}) such as prepaid task scams, fake trading APKs, or "Hi Mom/Dad" impersonation.'
        }
    ],
    'social': [
        {
            'id': 'social_giveaway_drainer_badge',
            'category': 'Social Media Fraud',
            'severity': 'High',
            'points': 28,
            'title': 'Crypto Doubler, Fake Badge Appeal, or Influencer Giveaway Scam',
            'pattern': re.compile(
                r'\b(?:doubling\s+all\s+bitcoin|sugar\s+baby|weekly\s+allowance|violated\s+copyright\s+guidelines|blue\s+badge\s+verification\s+is\s+suspended|picked\s+from\s+the\s+comments|ambassador\s+collaboration|accidentally\s+reported\s+your\s+profile|nft\s+whitelist\s+mint)\b',
                re.IGNORECASE
            ),
            'detail_tpl': 'Matches prevalent social media DM scam pattern ({matches}).'
        }
    ],
    'payment': [
        {
            'id': 'payment_upi_pin_overpayment_escrow',
            'category': 'Payment Fraud Mechanic',
            'severity': 'Critical',
            'points': 34,
            'title': 'Deceptive UPI Collect PIN Trick, Overpayment, or Irreversible Payment Demand',
            'pattern': re.compile(
                r'\b(?:enter\s+your\s+(?:4-digit\s+)?upi\s+pin\s+to\s+receive|input\s+your\s+upi\s+mpin\s+to\s+credit|scan\s+this\s+qr\s+code.{0,35}receive|accidentally\s+wired|overpayment\s+refund|unlock\s+the\s+escrow|irreversible\s+usdt|portal\s+activation\s+fee|disregard\s+previous\s+banking\s+instructions)\b',
                re.IGNORECASE
            ),
            'detail_tpl': 'Detected deceptive payment instruction ({matches}). Entering a UPI PIN or scanning a collect QR always deducts money—it never receives money.'
        }
    ]
}


class ScamDetectionEngine:
    """
    Hybrid AI/ML + Multi-Channel Rule Engine for ScamShield AI.
    Combines TF-IDF + Soft-Voting Ensemble probabilities with transparent channel rules
    and static URL analysis. Never claims 100% certainty.
    """

    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        bundle = train_and_save_model(model_dir, force_retrain=False)
        self.pipeline = bundle['pipeline']
        self.metrics = bundle['metrics']

    def analyze(self, channel: str, content: str, subject_or_sender: str = '', extra_meta: dict = None, strict_mode: bool = False) -> dict:
        channel = (channel or 'sms').lower().strip()
        content = (content or '').strip()
        subject_or_sender = (subject_or_sender or '').strip()
        extra_meta = extra_meta or {}

        combined_text = f"{subject_or_sender}\n{content}".strip() if subject_or_sender else content

        # 1. Preprocess & Extract Entities / Numerical Features
        processed_text = preprocess_text(combined_text)
        entities = extract_entities(combined_text)
        num_features = extract_numerical_features(combined_text)

        # 2. ML Model Prediction
        if processed_text.strip():
            probs = self.pipeline.predict_proba([processed_text])[0]
            ml_scam_prob = float(probs[1])
            top_ml_terms = extract_top_contributing_terms(self.pipeline, processed_text, top_k=6)
        else:
            ml_scam_prob = 0.0
            top_ml_terms = []

        # 3. Rule-Based & Static URL Evaluation
        indicators = []
        rule_points = 0
        matched_categories = []

        # Apply common rules
        for rule in COMMON_RULES:
            matches = rule['pattern'].findall(combined_text)
            if matches:
                unique_matches = sorted(set(m.strip() for m in matches if m.strip()))[:3]
                rule_points += rule['points']
                matched_categories.append(rule['category'])
                indicators.append({
                    'category': rule['category'],
                    'severity': rule['severity'],
                    'title': rule['title'],
                    'detail': rule['detail_tpl'].format(matches='"' + '", "'.join(unique_matches) + '"')
                })

        # Apply channel-specific rules
        for rule in CHANNEL_SPECIFIC_RULES.get(channel, []):
            matches = rule['pattern'].findall(combined_text)
            if matches:
                unique_matches = sorted(set(m.strip() for m in matches if m.strip()))[:3]
                rule_points += rule['points']
                matched_categories.append(rule['category'])
                indicators.append({
                    'category': rule['category'],
                    'severity': rule['severity'],
                    'title': rule['title'],
                    'detail': rule['detail_tpl'].format(matches='"' + '", "'.join(unique_matches) + '"')
                })

        # Email sender vs body brand mismatch check
        if channel == 'email' and subject_or_sender:
            sender_emails = extract_entities(subject_or_sender)['emails']
            if sender_emails:
                sender_domain = sender_emails[0].split('@')[-1].lower()
                for brand, official_domains in TARGETED_BRANDS.items():
                    if brand in combined_text.lower():
                        if not any(sender_domain == od or sender_domain.endswith('.' + od) for od in official_domains):
                            rule_points += 26
                            matched_categories.append('Sender Spoofing')
                            indicators.append({
                                'category': 'Sender Spoofing',
                                'severity': 'High',
                                'title': f'Sender Domain Mismatch for {brand.capitalize()}',
                                'detail': f'Sender address ({sender_emails[0]}) uses domain "{sender_domain}", which does not match official {brand.capitalize()} domains ({", ".join(official_domains)}).'
                            })
                            break

        # URL inspection: primary for 'url' channel, and auxiliary for embedded URLs in other channels
        url_details = None
        if channel == 'url':
            url_details = inspect_url_static(content)
            rule_points += url_details['url_rule_points']
            for ind in url_details['url_indicators']:
                indicators.append(ind)
                matched_categories.append(ind['category'])
        elif entities['urls']:
            for embedded_url in entities['urls'][:3]:
                u_info = inspect_url_static(embedded_url)
                if u_info['url_rule_points'] >= 20:
                    rule_points += int(u_info['url_rule_points'] * 0.75)
                    for ind in u_info['url_indicators']:
                        indicators.append(ind)
                        matched_categories.append(ind['category'])

        # Entity-based indicators
        if entities['crypto_wallets']:
            rule_points += 22
            matched_categories.append('Cryptocurrency Demand')
            indicators.append({
                'category': 'Cryptocurrency Payment',
                'severity': 'High',
                'title': 'Cryptocurrency Wallet Address Detected',
                'detail': f'Detected cryptocurrency wallet address ({", ".join(entities["crypto_wallets"][:2])}). Crypto transfers are irreversible and heavily used in extortion and giveaway scams.'
            })

        if entities['payment_handles'] and (rule_points > 0 or ml_scam_prob > 0.45):
            rule_points += 16
            matched_categories.append('Unverified UPI Handle')
            indicators.append({
                'category': 'Payment Handle',
                'severity': 'Medium',
                'title': 'Direct UPI Payment Handle in Suspicious Context',
                'detail': f'Message directs payment to UPI ID ({", ".join(entities["payment_handles"])}) alongside high-risk phrasing.'
            })

        if ml_scam_prob >= 0.60:
            term_str = ', '.join(f'"{t["term"]}"' for t in top_ml_terms[:4]) if top_ml_terms else 'scam-associated phrasing'
            indicators.append({
                'category': 'AI/ML Classifier',
                'severity': 'High' if ml_scam_prob >= 0.75 else 'Medium',
                'title': f'ML Ensemble Flagged Scam Linguistic Pattern ({round(ml_scam_prob * 100, 1)}% probability)',
                'detail': f'The TF-IDF + Voting Classifier detected strong statistical similarity to known scam patterns driven by features: {term_str}.'
            })

        rule_score_capped = min(100, rule_points)

        # 4. Hybrid Risk Score Calculation
        ml_component = ml_scam_prob * 100.0
        if channel == 'url':
            raw_hybrid = (0.70 * rule_score_capped) + (0.30 * ml_component)
            if rule_score_capped >= 70:
                raw_hybrid = max(raw_hybrid, rule_score_capped * 0.92)
        else:
            raw_hybrid = (0.48 * ml_component) + (0.52 * rule_score_capped)
            if rule_score_capped >= 65 and ml_component >= 55:
                raw_hybrid = max(raw_hybrid, min(98.0, (ml_component + rule_score_capped) * 0.58))
            elif rule_score_capped >= 75:
                raw_hybrid = max(raw_hybrid, rule_score_capped * 0.88)
            elif rule_score_capped == 0 and ml_component < 42:
                raw_hybrid = min(raw_hybrid, 22.0)

        if strict_mode and raw_hybrid >= 20:
            raw_hybrid = min(100.0, raw_hybrid * 1.12)

        risk_score = max(2, min(99, int(round(raw_hybrid))))
        risk_category = classify_risk_band(risk_score)

        # 5. Meaningful Confidence Calculation (Bounded between 55% and 97% - never 100%)
        agreement = 1.0 - (abs(ml_component - rule_score_capped) / 100.0)
        extremity = abs(risk_score - 50) / 50.0
        confidence_score = round(min(96.5, max(58.0, (55.0 + 25.0 * agreement + 16.5 * extremity))), 1)

        # 6. Determine Primary Scam Type Classification
        scam_type = self._determine_scam_type(channel, risk_score, matched_categories, url_details)

        # 7. Generate Human-Readable Explanation & Tailored Safety Recommendations
        explanation = self._build_explanation(
            channel=channel,
            risk_score=risk_score,
            risk_category=risk_category,
            ml_prob=ml_scam_prob,
            rule_score=rule_score_capped,
            indicators=indicators,
            top_ml_terms=top_ml_terms,
            url_details=url_details
        )

        recommendations = self._build_recommendations(
            channel=channel,
            risk_score=risk_score,
            matched_categories=matched_categories,
            entities=entities,
            url_details=url_details
        )

        if not indicators:
            indicators.append({
                'category': 'Baseline Check',
                'severity': 'Low',
                'title': 'No Known High-Risk Phishing or Coercion Patterns Detected',
                'detail': 'Neither the heuristic rule engine nor the ML ensemble detected overt scam triggers. Always exercise standard caution with unexpected requests.'
            })

        feature_breakdown = {
            'numerical_features': num_features,
            'extracted_entities': entities,
            'top_ml_terms': top_ml_terms,
            'url_inspection': url_details,
            'ml_score_component': round(ml_component, 1),
            'rule_score_component': rule_score_capped,
            'disclaimer': (
                'Automated hybrid AI/ML and heuristic analysis is probabilistic and never 100% accurate. '
                'Risk bands (Low 0-24, Medium 25-49, High 50-74, Critical 75-100) are application-defined indicators '
                'and not a substitute for formal incident response or institutional verification.'
            )
        }

        return {
            'risk_score': risk_score,
            'risk_category': risk_category,
            'ml_probability': round(ml_scam_prob, 4),
            'rule_score': rule_score_capped,
            'confidence_score': confidence_score,
            'scam_type': scam_type,
            'indicators': indicators,
            'explanation': explanation,
            'recommendations': recommendations,
            'feature_breakdown': feature_breakdown
        }

    def _determine_scam_type(self, channel: str, risk_score: int, matched_categories: list, url_details: dict = None) -> str:
        if risk_score <= 24:
            return 'Benign / Low-Risk Communication'

        cats = set(matched_categories)
        if 'Remote Takeover' in cats:
            return 'Remote Access / Tech Support Scam'
        if 'Extortion & Threat' in cats:
            return 'Digital Arrest / Legal Extortion Scam'
        if 'Business Email Compromise' in cats:
            return 'Business Email Compromise (BEC)'
        if 'Payment Fraud Mechanic' in cats:
            return 'UPI Collect / Payment Diversion Fraud'
        if 'Task & Investment Scam' in cats:
            return 'Prepaid Task / Investment Scam'
        if 'Social Media Fraud' in cats:
            return 'Social Media Giveaway / Impersonation Scam'
        if 'Brand Impersonation' in cats or 'Sender Spoofing' in cats:
            return 'Brand Impersonation Phishing'
        if 'Homograph Attack' in cats or 'Host Obfuscation' in cats:
            return 'Deceptive URL / Infrastructure Phishing'
        if 'Credential Harvesting' in cats:
            return 'Credential / OTP Harvesting Phishing'
        if 'SMS Smishing Lure' in cats:
            return 'SMS Smishing Campaign'
        if 'Advance Fee / Prize Lure' in cats:
            return 'Advance-Fee / Lottery Scam'

        channel_defaults = {
            'sms': 'Suspicious SMS Smishing',
            'email': 'Suspicious Phishing Email',
            'url': 'Suspicious Web URL',
            'whatsapp': 'Suspicious WhatsApp Solicitation',
            'social': 'Suspicious Social Media Message',
            'payment': 'Suspicious Payment Request'
        }
        return channel_defaults.get(channel, 'General Suspicious Activity')

    def _build_explanation(self, channel: str, risk_score: int, risk_category: str, ml_prob: float,
                           rule_score: int, indicators: list, top_ml_terms: list, url_details: dict = None) -> str:
        channel_names = {
            'sms': 'SMS message',
            'email': 'email communication',
            'url': 'website URL',
            'whatsapp': 'WhatsApp message',
            'social': 'social media message',
            'payment': 'payment request'
        }
        ch_label = channel_names.get(channel, 'submission')
        ml_pct = round(ml_prob * 100, 1)

        parts = [
            f"This {ch_label} received a hybrid risk score of {risk_score}/100 ({risk_category}). "
            f"The Scikit-learn TF-IDF ensemble classifier estimated a {ml_pct}% scam linguistic probability, "
            f"while the deterministic security rule engine contributed {rule_score}/100 points across {len(indicators)} indicator(s)."
        ]

        if url_details and channel == 'url':
            if not url_details['is_valid_format']:
                parts.append("The submitted URL string did not match standard domain syntax.")
            else:
                proto = "encrypted HTTPS" if url_details['uses_https'] else "unencrypted HTTP"
                parts.append(f"Static URL parsing identified hostname '{url_details['hostname']}' using {proto} (URL was inspected safely without visiting or executing it).")

        if top_ml_terms and risk_score >= 25:
            terms_list = ', '.join(f"'{t['term']}'" for t in top_ml_terms[:4])
            parts.append(f"Key vocabulary & structural features influencing the ML score include: {terms_list}.")

        parts.append(
            "Note: This assessment combines statistical machine learning and rule-based heuristics; "
            "it is never 100% certain and should be paired with independent verification."
        )
        return ' '.join(parts)

    def _build_recommendations(self, channel: str, risk_score: int, matched_categories: list,
                               entities: dict, url_details: dict = None) -> list:
        recs = []
        cats = set(matched_categories)

        if 'Credential Harvesting' in cats or channel in ('sms', 'whatsapp'):
            recs.append({
                'priority': 'Critical',
                'action': 'Never Share OTPs, PINs, CVVs, or Recovery Phrases',
                'detail': 'No legitimate bank, telecom carrier, government agency, or support desk will ever ask you to read back an SMS OTP, ATM/UPI PIN, or crypto seed phrase.'
            })

        if 'Payment Fraud Mechanic' in cats or channel == 'payment' or entities.get('payment_handles') or entities.get('crypto_wallets'):
            recs.append({
                'priority': 'Critical',
                'action': 'Verify Payment Requests Independently & Never Enter a PIN to "Receive" Money',
                'detail': 'Entering a UPI PIN or approving a collect request always deducts funds from your account. Confirm vendor or family payment requests via a separate, known phone call.'
            })

        if channel == 'url' or entities.get('urls'):
            recs.append({
                'priority': 'High',
                'action': 'Do Not Click or Enter Credentials on Unverified Links',
                'detail': 'Navigate to banking, shopping, or corporate portals by typing the official address directly into your browser or using your bookmarked app.'
            })

        if 'Remote Takeover' in cats:
            recs.append({
                'priority': 'Critical',
                'action': 'Refuse Remote Screen-Sharing Requests (AnyDesk / TeamViewer)',
                'detail': 'Immediately disconnect if an unsolicited caller asks you to install remote desktop apps to process a refund or KYC update.'
            })

        if 'Extortion & Threat' in cats:
            recs.append({
                'priority': 'Critical',
                'action': 'Do Not Comply with "Digital Arrest" or Video-Call Interrogation Demands',
                'detail': 'Law enforcement agencies do not conduct arrests over WhatsApp/Skype video calls or demand money transfers to "safe verification accounts."'
            })

        if 'Business Email Compromise' in cats or 'Sender Spoofing' in cats or channel == 'email':
            recs.append({
                'priority': 'High',
                'action': 'Authenticate the Sender Out-of-Band',
                'detail': 'Inspect the full Reply-To header and verify any invoice bank changes or gift-card requests by calling the sender on an internal directory number.'
            })

        if risk_score >= 50:
            recs.append({
                'priority': 'Medium',
                'action': 'Preserve Evidence & Report Through Official Cybercrime Channels',
                'detail': 'Log this scan into a ScamShield Investigation Case to correlate related artifacts, block the sender, and report suspected fraud to your bank or national cybercrime portal.'
            })
        else:
            recs.append({
                'priority': 'Standard',
                'action': 'Maintain Standard Digital Hygiene',
                'detail': 'Even when automated analysis indicates low risk, verify unexpected attachments or financial changes directly with the known sender before acting.'
            })

        return recs[:5]
