# detector/ocr_detector.py
import pytesseract
from PIL import Image
import re
import os

# Configure Tesseract path (Windows)
if os.name == 'nt':  # Windows
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

def detect_fake_mpesa_receipt(image_path):
    """Detect fake M-Pesa receipts from screenshots - Enhanced with 50+ patterns"""
    
    try:
        # Open image
        image = Image.open(image_path)
        
        # Extract text using OCR with better preprocessing
        # Convert to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Extract text
        extracted_text = pytesseract.image_to_string(image)
        text_lower = extracted_text.lower()
        
        # Initialize detection
        score = 0
        reasons = []
        detected_amount = None
        detected_number = None
        detected_transaction_id = None
        detected_date = None
        detected_time = None
        
        # ============================================================
        # SECTION 1: M-PESA Keyword Detection (30+ keywords)
        # ============================================================
        mpesa_keywords = [
            'mpesa', 'm-pesa', 'safaricom', 'transaction', 'amount', 
            'received', 'sent', 'payment', 'transfer', 'funds',
            'withdrawal', 'deposit', 'send money', 'receive money',
            'buy goods', 'pay bill', 'till number', 'paybill',
            'fuliza', 'm-shwari', 'kcb mpesa', 'equity mpesa',
            'agent', 'customer', 'mpin', 'balance', 'statement'
        ]
        
        for kw in mpesa_keywords:
            if kw in text_lower:
                score += 5
                reasons.append(f"📱 Found M-Pesa keyword: '{kw}'")
                break  # Only add once
        
        # ============================================================
        # SECTION 2: Amount Detection (Enhanced patterns)
        # ============================================================
        amount_patterns = [
            # Standard patterns
            (r'ksh[\s]*:?[\s]*([\d,]+\.?\d*)', 'Ksh amount'),
            (r'amount[\s]*:?[\s]*ksh[\s]*([\d,]+\.?\d*)', 'Amount with label'),
            (r'([\d,]+\.?\d*)\s*ksh', 'Ksh suffix'),
            (r'[\s]ksh[\s]*([\d,]+\.?\d*)', 'Ksh prefix'),
            # Alternative formats
            (r'kes[\s]*([\d,]+\.?\d*)', 'KES amount'),
            (r'([\d,]+\.?\d*)\s*kes', 'KES suffix'),
            (r'total[\s]*:?[\s]*ksh[\s]*([\d,]+\.?\d*)', 'Total amount'),
            (r'value[\s]*:?[\s]*ksh[\s]*([\d,]+\.?\d*)', 'Value amount'),
            (r'credited with[\s]*ksh[\s]*([\d,]+\.?\d*)', 'Credited amount'),
            (r'debited with[\s]*ksh[\s]*([\d,]+\.?\d*)', 'Debited amount'),
            # Large amount patterns (scam indicator)
            (r'ksh[\s]*([\d,]{5,})', 'Large amount detected'),
        ]
        
        for pattern, description in amount_patterns:
            match = re.search(pattern, text_lower)
            if match:
                amount = match.group(1).replace(',', '').replace('.', '')
                detected_amount = f"Ksh {match.group(1)}"
                
                # Check for unrealistic large amounts (scam indicator)
                if len(amount) >= 6:  # 100,000+
                    score += 20
                    reasons.append(f"💰 SUSPICIOUS: Unusually large amount {detected_amount}")
                else:
                    score += 15
                    reasons.append(f"💰 Detected amount: {detected_amount}")
                break
        
        # ============================================================
        # SECTION 3: Phone Number Detection (Enhanced)
        # ============================================================
        phone_patterns = [
            # Kenyan numbers
            (r'(07\d{8})', 'Safaricom/Airtel/Telkom number'),
            (r'(01\d{8})', 'Alternative format'),
            (r'(2547\d{8})', 'International format'),
            (r'(\+2547\d{8})', 'Plus international format'),
            # Labeled patterns
            (r'from[\s]*:?[\s]*(\d{10,12})', 'Sender number'),
            (r'to[\s]*:?[\s]*(\d{10,12})', 'Recipient number'),
            (r'sent to[\s]*:?[\s]*(\d{10,12})', 'Sent to number'),
            (r'received from[\s]*:?[\s]*(\d{10,12})', 'Received from number'),
            (r'customer[\s]*:?[\s]*(\d{10,12})', 'Customer number'),
            (r'agent[\s]*:?[\s]*(\d{10,12})', 'Agent number'),
        ]
        
        for pattern, description in phone_patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                detected_number = matches[0]
                score += 10
                reasons.append(f"📞 Found phone number: {detected_number}")
                break
        
        # ============================================================
        # SECTION 4: Transaction ID Detection
        # ============================================================
        transaction_patterns = [
            (r'transaction[\s]*id[\s]*:?[\s]*([A-Z0-9]{8,})', 'Transaction ID'),
            (r'transaction[\s]*code[\s]*:?[\s]*([A-Z0-9]{8,})', 'Transaction code'),
            (r'trx[\s]*id[\s]*:?[\s]*([A-Z0-9]{8,})', 'TRX ID'),
            (r'receipt[\s]*no[\s]*:?[\s]*([A-Z0-9]{6,})', 'Receipt number'),
            (r'reference[\s]*:?[\s]*([A-Z0-9]{6,})', 'Reference number'),
            (r'order[\s]*id[\s]*:?[\s]*([A-Z0-9]{6,})', 'Order ID'),
        ]
        
        for pattern, description in transaction_patterns:
            match = re.search(pattern, text_lower)
            if match:
                detected_transaction_id = match.group(1)
                score += 12
                reasons.append(f"🔢 Found {description}: {detected_transaction_id[:10]}...")
                break
        
        # ============================================================
        # SECTION 5: Date and Time Detection
        # ============================================================
        date_patterns = [
            (r'(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', 'Date'),
            (r'(\d{1,2}\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{2,4})', 'Date with month'),
            (r'(today|yesterday)', 'Relative date'),
        ]
        
        for pattern, description in date_patterns:
            match = re.search(pattern, text_lower)
            if match:
                detected_date = match.group(1)
                score += 8
                reasons.append(f"📅 Found date: {detected_date}")
                break
        
        time_patterns = [
            (r'(\d{1,2}:\d{2}\s*(am|pm))', 'Time with am/pm'),
            (r'(\d{1,2}:\d{2}:\d{2})', 'Time with seconds'),
            (r'(\d{1,2}\.\d{2}\s*(am|pm))', 'Time with dot separator'),
        ]
        
        for pattern, description in time_patterns:
            match = re.search(pattern, text_lower)
            if match:
                detected_time = match.group(1)
                score += 8
                reasons.append(f"⏰ Found time: {detected_time}")
                break
        
        # ============================================================
        # SECTION 6: Fake Receipt Scam Indicators (20+ patterns)
        # ============================================================
        fake_receipt_indicators = [
            # Missing/Incomplete data
            (r'confirmed\.?\s*$', 'Missing transaction details (truncated)', 15),
            (r'^[^a-z]*$', 'No meaningful text extracted', 25),
            
            # Error messages (fake receipts often show errors)
            (r'error|failed|cancelled|rejected|declined', 'Transaction shows error/failure', 18),
            (r'pending|processing|waiting', 'Pending transaction shown as complete', 15),
            (r'insufficient funds', 'Shows insufficient funds - unusual for receipt', 15),
            
            # Suspicious links
            (r'http[s]?://', 'Contains suspicious link in receipt', 20),
            (r'click here|tap here|follow link', 'Asks to click/tap link', 20),
            (r'bit\.ly|tinyurl|short\.link', 'Contains URL shortener', 18),
            
            # Contact scams
            (r'call.*?customer.*?care', 'Asks to call number', 12),
            (r'whatsapp|telegram|signal', 'Contains messaging app reference', 15),
            (r'customer.*?support.*?\d{10}', 'Phone number in receipt', 12),
            
            # Unprofessional formatting
            (r'[A-Z]{10,}', 'Excessive capital letters', 10),
            (r'!{2,}', 'Multiple exclamation marks', 8),
            (r'\*{5,}', 'Star/asterisk spam', 8),
            
            # Urgency/Pressure
            (r'urgent|immediate|asap', 'Shows urgency - unusual in receipts', 12),
            (r'limited time|expires|valid until', 'Time pressure tactics', 12),
            
            # Request for action
            (r'reply|respond|text back', 'Asks to reply', 15),
            (r'send.*?confirmation|confirm.*?receipt', 'Asks for confirmation', 12),
            (r'forward.*?this.*?message', 'Asks to forward', 10),
            
            # Fake promotion indicators
            (r'bonus|reward|cashback|points', 'Promotional language in receipt', 15),
            (r'congratulations|winner|prize|jackpot', 'Prize language - not in real receipts', 20),
            (r'free.*?money|free.*?cash', 'Free money claims', 20),
            
            # Multiple transaction indicators (unusual)
            (r'(transaction|trx).*?(\d+).*?(\d+)', 'Multiple transaction references', 10),
        ]
        
        for pattern, description, points in fake_receipt_indicators:
            if re.search(pattern, text_lower):
                score += points
                reasons.append(f"⚠️ {description}")
        
        # ============================================================
        # SECTION 7: Required Elements Check (Missing = Fake)
        # ============================================================
        required_elements = {
            'amount': ['amount', 'ksh', 'kes', 'total', 'value', 'credited', 'debited'],
            'transaction': ['transaction', 'txn', 'trx', 'reference', 'receipt'],
            'time': ['time', 'at', 'am', 'pm', 'hour'],
            'date': ['date', 'today', 'yesterday', 'jan', 'feb', 'mar', 'apr', 'may', 'jun', 
                     'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
        }
        
        missing_elements = []
        for element_name, keywords in required_elements.items():
            found = False
            for keyword in keywords:
                if keyword in text_lower:
                    found = True
                    break
            if not found:
                missing_elements.append(element_name)
        
        missing_count = len(missing_elements)
        if missing_count >= 2:
            score += 15
            reasons.append(f"❌ Missing {missing_count} key receipt element(s): {', '.join(missing_elements)}")
        elif missing_count >= 1:
            score += 8
            reasons.append(f"⚠️ Missing receipt element: {missing_elements[0]}")
        
        # ============================================================
        # SECTION 8: Legitimate Receipt Indicators (Reduce Score)
        # ============================================================
        legitimate_indicators = [
            # Real M-Pesa receipt markers
            ('transaction cost', -10),
            ('balance', -12),
            ('transaction id', -12),
            ('receipt no', -10),
            ('completed on', -10),
            ('paid to', -8),
            ('paid from', -8),
            ('mpesa statement', -10),
            ('your transaction', -8),
            ('was successful', -15),
            ('new balance', -12),
            ('available balance', -10),
            
            # Professional formatting
            ('thank you for choosing', -8),
            ('safaricom transaction', -10),
            ('mpesa confirmation', -10),
            ('is your m-pesa code', -5),  # OTP message
        ]
        
        for indicator, reduction in legitimate_indicators:
            if indicator in text_lower:
                score += reduction  # reduction is negative
                reasons.append(f"✓ Found legitimate indicator: '{indicator}'")
        
        # ============================================================
        # SECTION 9: Quality & Consistency Checks
        # ============================================================
        
        # Text length check (very short text = likely fake or unreadable)
        text_length = len(extracted_text.strip())
        if text_length < 20:
            score += 20
            reasons.append("⚠️ Very short extracted text - possible fake or low-quality receipt")
        elif text_length < 50:
            score += 10
            reasons.append("⚠️ Limited text extracted - receipt may be incomplete")
        
        # Check for excessive line breaks (poor formatting)
        line_breaks = extracted_text.count('\n')
        if line_breaks > 20 and text_length < 500:
            score += 10
            reasons.append("⚠️ Unusual formatting with excessive line breaks")
        
        # Number consistency (should have some numbers)
        number_count = len(re.findall(r'\d+', extracted_text))
        if number_count < 3:
            score += 15
            reasons.append("⚠️ Too few numbers - legitimate receipts have amounts, dates, transaction IDs")
        
        # ============================================================
        # SECTION 10: Common Fake Receipt Templates (Keyword matching)
        # ============================================================
        fake_template_indicators = [
            'fake receipt generator', 'receipt maker', 'edit receipt',
            'mpesa generator', 'fake mpesa', 'receipt template',
        ]
        
        for indicator in fake_template_indicators:
            if indicator in text_lower:
                score += 35
                reasons.append(f"🔴 CRITICAL: Contains fake receipt generator reference: '{indicator}'")
                break
        
        # ============================================================
        # Normalize score to 0-100
        # ============================================================
        score = max(0, min(100, score))
        
        # ============================================================
        # Determine Risk Level with enhanced messaging
        # ============================================================
        if score >= 65:
            risk_level = "HIGH RISK - DEFINITELY FAKE"
            color = "danger"
            emoji = "🔴❌"
            message = "⚠️ This appears to be a FAKE M-Pesa receipt! DO NOT release goods or send money."
        elif score >= 50:
            risk_level = "HIGH RISK - LIKELY FAKE"
            color = "danger"
            emoji = "🔴"
            message = "This receipt shows strong indicators of being fake. Verify with M-Pesa statement first."
        elif score >= 35:
            risk_level = "MEDIUM RISK - SUSPICIOUS"
            color = "warning"
            emoji = "🟡"
            message = "This receipt has multiple suspicious elements. Verify before trusting."
        elif score >= 20:
            risk_level = "LOW RISK - CAUTION"
            color = "info"
            emoji = "🔵"
            message = "This receipt has minor inconsistencies. Still verify with official M-Pesa app."
        else:
            risk_level = "LOW RISK - LIKELY LEGITIMATE"
            color = "success"
            emoji = "🟢✅"
            message = "This receipt appears legitimate, but always confirm in your M-Pesa app."
        
        # ============================================================
        # Generate enhanced recommendations
        # ============================================================
        recommendations = []
        if score >= 35:
            recommendations = [
                "🔐 DO NOT release goods or send money based on this receipt alone",
                "📱 Check your ACTUAL M-Pesa statement via *334# or MySafaricom App",
                "⏰ Wait 5-10 minutes and refresh your M-Pesa to confirm payment",
                "🔍 Look for the official M-Pesa 'Receipt No.' format - fakes often miss this",
                "📞 Call the sender back to verify payment directly",
                "⚠️ Scammers use fake receipts to trick sellers - always verify in app!"
            ]
        else:
            recommendations = [
                "✅ Receipt appears legitimate, but still verify in your M-Pesa app",
                "📱 Check your M-Pesa balance to confirm the transaction",
                "💾 Save this receipt for your records",
                "🔍 Compare with your previous M-Pesa receipts for consistency"
            ]
        
        # ============================================================
        # Return result with all detected information
        # ============================================================
        return {
            'score': score,
            'risk_level': risk_level,
            'color': color,
            'emoji': emoji,
            'message': message,
            'reasons': reasons[:10] if reasons else ["✅ No scam indicators found"],  # Limit to 10
            'recommendations': recommendations[:5],
            'extracted_text': extracted_text[:500] + ('...' if len(extracted_text) > 500 else ''),
            'detected_amount': detected_amount,
            'detected_number': detected_number,
            'detected_transaction_id': detected_transaction_id,
            'detected_date': detected_date,
            'detected_time': detected_time,
            'text_length': text_length,
            'missing_elements': missing_elements,
            'is_fake': score >= 35,
            'type': 'SCREENSHOT',
            'analysis_time': __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except Exception as e:
        return {
            'error': f"OCR processing failed: {str(e)}",
            'score': 0,
            'risk_level': "ERROR",
            'color': "danger",
            'emoji': "❌",
            'message': "Could not process image. Please ensure it's a clear screenshot of an M-Pesa receipt.",
            'reasons': ["Image processing failed. Try a clearer screenshot."],
            'recommendations': [
                "📸 Take a clearer screenshot of the receipt",
                "💡 Ensure the text is readable in the image",
                "📱 Try the SMS detection feature instead"
            ],
            'is_fake': False,
            'type': 'SCREENSHOT_ERROR'
        }