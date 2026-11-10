import re
import string
from urllib.parse import urlparse

# Standard English stop words subset (preserving negation and security-relevant terms)
STOP_WORDS = {
    'the', 'is', 'at', 'which', 'on', 'and', 'a', 'an', 'in', 'to', 'of',
    'for', 'with', 'as', 'by', 'that', 'this', 'it', 'from', 'be', 'are',
    'was', 'were', 'been', 'has', 'have', 'had', 'but', 'or', 'so', 'if'
}

URL_REGEX = re.compile(
    r'((?:https?://|www\.)[^\s<>"]+|(?:[a-zA-Z0-9-]+\.)+(?:xyz|top|club|info|site|online|vip|work|click|link|buzz|tk|ml|ga|cf|gq|com|net|org|in|co|io|me|ru|cn)(?:/[^\s<>"]*)?)',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{4}')
UPI_HANDLE_REGEX = re.compile(r'[a-zA-Z0-9.\-_]{2,50}@(?:ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|apl|ibl|axl|upi|pingpay)', re.IGNORECASE)
CRYPTO_WALLET_REGEX = re.compile(r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\b0x[a-fA-F0-9]{40}\b|\bT[A-Za-z1-9]{33}\b')


def extract_entities(text: str) -> dict:
    """
    Extracts structured indicators of compromise (IoCs) and entities from raw text:
    URLs, domains, email addresses, phone numbers, UPI IDs, and crypto addresses.
    """
    if not text:
        return {
            'urls': [],
            'domains': [],
            'emails': [],
            'phones': [],
            'payment_handles': [],
            'crypto_wallets': []
        }

    # Extract emails first so we don't confuse email domains with standalone URLs
    emails = sorted(set(m.lower() for m in EMAIL_REGEX.findall(text)))
    upi_handles = sorted(set(m.lower() for m in UPI_HANDLE_REGEX.findall(text)))
    # Filter out UPI handles from generic email list
    emails = [e for e in emails if e not in upi_handles]

    # Mask emails & UPI handles temporarily before URL extraction
    text_no_emails = EMAIL_REGEX.sub(' ', text)
    raw_urls = URL_REGEX.findall(text_no_emails)
    cleaned_urls = []
    domains = set()

    for u in raw_urls:
        u_clean = u.rstrip('.,;:!?)>]\'"')
        cleaned_urls.append(u_clean)
        parsed_target = u_clean if '://' in u_clean else f'http://{u_clean}'
        try:
            parsed = urlparse(parsed_target)
            host = (parsed.hostname or '').lower()
            if host:
                domains.add(host)
        except Exception:
            pass

    phones = []
    for p in PHONE_REGEX.findall(text):
        digits = re.sub(r'\D', '', p)
        if 10 <= len(digits) <= 14:
            phones.append(p.strip())

    crypto_wallets = sorted(set(CRYPTO_WALLET_REGEX.findall(text)))

    return {
        'urls': sorted(set(cleaned_urls)),
        'domains': sorted(domains),
        'emails': emails,
        'phones': sorted(set(phones)),
        'payment_handles': upi_handles,
        'crypto_wallets': crypto_wallets
    }


def preprocess_text(text: str) -> str:
    """
    Normalizes, tokenizes, and enriches raw text with structural meta-tokens
    so the TF-IDF + ML classifier captures both semantic vocabulary and structural patterns.
    """
    if not text or not isinstance(text, str):
        return ''

    original = text
    entities = extract_entities(original)

    meta_tokens = []
    if entities['urls']:
        meta_tokens.append('__HAS_URL__')
    if entities['payment_handles']:
        meta_tokens.append('__HAS_UPI_HANDLE__')
    if entities['crypto_wallets']:
        meta_tokens.append('__HAS_CRYPTO_WALLET__')
    if entities['phones']:
        meta_tokens.append('__HAS_PHONE__')
    if re.search(r'\b(?:otp|pin|cvv|passcode|password|mpin)\b', original, re.IGNORECASE):
        meta_tokens.append('__HAS_CREDENTIAL_REQ__')
    if re.search(r'(?:[\$£€₹]\s*\d+|\b(?:rs|inr|usd|usdt)\s*\.?\s*\d+)', original, re.IGNORECASE):
        meta_tokens.append('__HAS_CURRENCY_AMOUNT__')

    # Calculate uppercase ratio
    alpha_chars = [c for c in original if c.isalpha()]
    if len(alpha_chars) > 12:
        upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if upper_ratio > 0.35:
            meta_tokens.append('__HIGH_CAPS__')

    if original.count('!') >= 2:
        meta_tokens.append('__MULTI_EXCLAMATION__')

    # Replace URLs, emails, and numbers with canonical tokens
    lowered = original.lower()
    lowered = EMAIL_REGEX.sub(' tokenemail ', lowered)
    lowered = URL_REGEX.sub(' tokenurl ', lowered)
    lowered = re.sub(r'\b\d{4,8}\b', ' tokencode ', lowered)
    lowered = re.sub(r'\d+', ' tokennum ', lowered)

    # Remove punctuation
    translator = str.maketrans(string.punctuation, ' ' * len(string.punctuation))
    cleaned = lowered.translate(translator)

    tokens = [
        tok for tok in cleaned.split()
        if len(tok) > 1 and tok not in STOP_WORDS
    ]

    all_tokens = tokens + [m.lower() for m in meta_tokens]
    return ' '.join(all_tokens)


def extract_numerical_features(text: str) -> dict:
    """
    Computes interpretable quantitative text features for explainability and reporting.
    """
    if not text:
        return {
            'char_length': 0,
            'word_count': 0,
            'uppercase_ratio': 0.0,
            'digit_ratio': 0.0,
            'exclamation_count': 0,
            'url_count': 0,
            'urgency_term_count': 0
        }

    words = text.split()
    alpha = [c for c in text if c.isalpha()]
    upper_ratio = round(sum(1 for c in alpha if c.isupper()) / len(alpha), 3) if alpha else 0.0
    digit_ratio = round(sum(1 for c in text if c.isdigit()) / max(len(text), 1), 3)

    urgency_terms = re.findall(
        r'\b(?:urgent|immediately|suspended|blocked|expire|expires|final\s+notice|warning|action\s+required|verify\s+now|within\s+24\s+hours|deactivated|unauthorized|penalty|arrest|warrant|freeze|frozen)\b',
        text,
        re.IGNORECASE
    )
    entities = extract_entities(text)

    return {
        'char_length': len(text),
        'word_count': len(words),
        'uppercase_ratio': upper_ratio,
        'digit_ratio': digit_ratio,
        'exclamation_count': text.count('!'),
        'url_count': len(entities['urls']),
        'urgency_term_count': len(urgency_terms)
    }
