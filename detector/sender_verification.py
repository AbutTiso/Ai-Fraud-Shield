# detector/sender_verification.py

# Known legitimate sender IDs in Kenya
LEGITIMATE_SENDERS = {
    'SAFARICOM',
    'Safaricom',
    'M-PESA',
    'Mpesa',
    'MPESA',
    'AIRTEL',
    'Airtel',
    'TELKOM',
    'Telkom',
    'KCB',
    'KCB Bank',
    'EQTYBK',
    'Equity Bank',
    'COOPBK',
    'Cooperative Bank',
    'ABSABANK',
    'ABSA',
    'I&M BANK',
    'DTB',
    'NIC BANK',
    'CITIBANK',
    'FAMILY BANK',
    'NCBA',
    'STANBIC',
    'Stanbic',
    'SCBK',
    'Standard Chartered',
    'BANK ABC',
    'PRIME BANK',
    'GOVT',
    'NTSA',
    'KRA',
    'NHIF',
    'NSSF',
    'HELB',
    'KPLC',
    'Kenya Power',
    'NWSC',
    'KEBS',
}

# Known scam sender patterns
SCAM_SENDER_PATTERNS = [
    (r'SAFARICOM-\d+', 'Fake Safaricom sender'),
    (r'M-PESA-\d+', 'Fake M-PESA sender'),
    (r'AIRTEL\d+', 'Fake Airtel sender'),
    (r'KCB-\w+', 'Suspicious KCB variation'),
    (r'EQUITY\d+', 'Suspicious Equity variation'),
]

def verify_sender(sender_id):
    """Verify if a sender ID is legitimate"""
    if not sender_id:
        return {'verified': False, 'reason': 'No sender ID found'}
    
    # Check if in legitimate list
    if sender_id in LEGITIMATE_SENDERS:
        return {'verified': True, 'reason': 'Verified legitimate sender'}
    
    # Check scam patterns
    for pattern, description in SCAM_SENDER_PATTERNS:
        if re.search(pattern, sender_id, re.IGNORECASE):
            return {'verified': False, 'reason': description}
    
    # Check for suspicious characteristics
    if len(sender_id) > 15:
        return {'verified': False, 'reason': 'Unusually long sender ID'}
    
    if any(char.isdigit() for char in sender_id) and len(sender_id) > 8:
        return {'verified': False, 'reason': 'Suspicious combination of letters and numbers'}
    
    return {'verified': None, 'reason': 'Unknown sender - be cautious'}

def extract_sender_id(sms_text):
    """Try to extract sender ID from SMS (for personal messages)"""
    # Pattern for phone numbers (potential scammer)
    phone_pattern = r'(07|01|2547)\d{8}'
    phones = re.findall(phone_pattern, sms_text)
    
    if phones:
        return {'type': 'phone', 'value': phones[0], 'verified': False, 'reason': 'Personal phone number - not a verified business sender'}
    
    return {'type': 'unknown', 'value': None, 'verified': None, 'reason': 'Could not determine sender'}