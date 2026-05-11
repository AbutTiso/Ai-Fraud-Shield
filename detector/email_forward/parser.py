# detector/email_forward/parser.py
import re
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

class EmailParser:
    """Parse forwarded emails and extract content for analysis"""
    
    @staticmethod
    def parse_email(raw_email):
        """
        Parse raw email content
        
        Args:
            raw_email: Raw email bytes or string
        
        Returns:
            dict with parsed email data
        """
        try:
            if isinstance(raw_email, str):
                raw_email = raw_email.encode('utf-8')
            
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            # Extract headers
            result = {
                'subject': msg.get('subject', 'No Subject'),
                'from': msg.get('from', 'unknown'),
                'to': msg.get('to', 'unknown'),
                'date': msg.get('date', 'unknown'),
                'body_text': '',
                'body_html': '',
                'urls': [],
                'attachments': [],
                'forwarded': False
            }
            
            # Check if it's a forwarded email
            if result['subject'].lower().startswith(('fwd:', 'fw:')):
                result['forwarded'] = True
                result['original_subject'] = result['subject'][4:].strip()
            
            # Extract body
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    
                    if content_type == 'text/plain':
                        try:
                            result['body_text'] += part.get_content()
                        except:
                            pass
                    
                    elif content_type == 'text/html':
                        try:
                            html_content = part.get_content()
                            result['body_html'] += html_content
                            # Extract text from HTML
                            soup = BeautifulSoup(html_content, 'html.parser')
                            result['body_text'] += soup.get_text()
                        except:
                            pass
                    
                    # Check for attachments
                    filename = part.get_filename()
                    if filename:
                        result['attachments'].append(filename)
            else:
                try:
                    result['body_text'] = msg.get_content()
                except:
                    pass
            
            # Extract URLs from body
            result['urls'] = EmailParser.extract_urls(result['body_text'])
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'body_text': str(raw_email)[:5000]}
    
    @staticmethod
    def extract_urls(text):
        """Extract all URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))  # Remove duplicates
    
    @staticmethod
    def extract_original_content(text):
        """
        Extract original scam content from forwarded email
        Removes forwarding headers and signatures
        """
        # Remove common forward headers
        lines = text.split('\n')
        cleaned_lines = []
        skip_next = False
        
        for line in lines:
            stripped = line.strip()
            
            # Skip forwarding markers
            if any(marker in stripped.lower() for marker in [
                'begin forwarded message',
                'original message',
                'from:',
                'sent:',
                'to:',
                'subject:',
                'date:'
            ]):
                skip_next = True
                continue
            
            # Skip signature markers
            if stripped.startswith('--') or stripped.startswith('__'):
                break
            
            if not skip_next and stripped:
                cleaned_lines.append(line)
            
            skip_next = False
        
        return '\n'.join(cleaned_lines)