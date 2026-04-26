# detector/phone_lookup.py
import re
import requests
from datetime import datetime

# Known scam phone numbers reported in Kenya (sample database)
KNOWN_SCAM_NUMBERS = {
    '0712345678': {'reports': 45, 'last_seen': '2024-11-20', 'type': 'M-Pesa scam'},
    '0722000000': {'reports': 12, 'last_seen': '2024-11-15', 'type': 'Prize scam'},
    '0741000000': {'reports': 8, 'last_seen': '2024-11-10', 'type': 'Loan scam'},
    '0110000000': {'reports': 23, 'last_seen': '2024-11-18', 'type': 'Fake promotion'},
    '0700000000': {'reports': 5, 'last_seen': '2024-11-05', 'type': 'Job scam'},
}

# Network prefixes in Kenya
NETWORK_PREFIXES = {
    '07': {
        '1': 'Safaricom', '2': 'Safaricom', '3': 'Safaricom', '4': 'Safaricom', '5': 'Safaricom',
        '6': 'Safaricom', '7': 'Safaricom', '8': 'Safaricom', '9': 'Safaricom', '0': 'Safaricom'
    },
    '01': {
        '1': 'Telkom', '2': 'Telkom', '3': 'Airtel', '4': 'Airtel', '5': 'Airtel',
        '6': 'Airtel', '7': 'Airtel', '8': 'Airtel', '9': 'Airtel', '0': 'Telkom'
    }
}

def identify_network(phone_number):
    """Identify mobile network provider in Kenya"""
    if len(phone_number) >= 3:
        prefix = phone_number[:2]
        if prefix in NETWORK_PREFIXES:
            third_digit = phone_number[2] if len(phone_number) > 2 else '0'
            return NETWORK_PREFIXES[prefix].get(third_digit, 'Unknown')
    return 'Unknown'

def check_phone_risk(phone_number, risk_score=0):
    """Check if a phone number has been reported as scam"""
    # Clean phone number
    clean_number = re.sub(r'\D', '', phone_number)
    if len(clean_number) == 9:
        clean_number = '0' + clean_number
    elif len(clean_number) == 12 and clean_number.startswith('254'):
        clean_number = '0' + clean_number[3:]
    
    # Check known scam database
    if clean_number in KNOWN_SCAM_NUMBERS:
        scam_data = KNOWN_SCAM_NUMBERS[clean_number]
        return {
            'is_scam': True,
            'risk_level': 'HIGH',
            'reports': scam_data['reports'],
            'type': scam_data['type'],
            'network': identify_network(clean_number),
            'recommendation': 'This number has been reported multiple times. BLOCK immediately!'
        }
    
    # Determine risk based on pattern
    if risk_score > 50:
        return {
            'is_scam': None,
            'risk_level': 'MEDIUM',
            'reports': 0,
            'type': 'Suspicious based on message content',
            'network': identify_network(clean_number),
            'recommendation': 'Be very cautious with this number'
        }
    
    return {
        'is_scam': False,
        'risk_level': 'LOW',
        'reports': 0,
        'type': 'No reports found',
        'network': identify_network(clean_number),
        'recommendation': 'Unknown number - verify before trusting'
    }

def report_scam_number(phone_number, scam_type, reported_by='anonymous'):
    """Report a scam number (to be stored in database)"""
    clean_number = re.sub(r'\D', '', phone_number)
    if len(clean_number) == 9:
        clean_number = '0' + clean_number
    
    # This would save to database in production
    print(f"Reported scam number: {clean_number} - Type: {scam_type} - By: {reported_by}")
    return {'status': 'reported', 'number': clean_number}