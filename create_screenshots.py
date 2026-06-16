import os
from PIL import Image, ImageDraw, ImageFont

# Create icons directory
os.makedirs('static/detector/icons', exist_ok=True)

def create_mobile_screenshot():
    """Create mobile screenshot (360x640)"""
    img = Image.new('RGB', (360, 640), color='#f8fafc')
    draw = ImageDraw.Draw(img)
    
    # Navy header
    draw.rectangle([0, 0, 360, 80], fill='#002855')
    draw.text((20, 25), '🛡️ AI Fraud Shield', fill='#F5A623')
    
    # Gold accent line
    draw.rectangle([0, 80, 360, 84], fill='#F5A623')
    
    # Main content area
    draw.text((20, 100), 'SMS Scam Detector', fill='#002855')
    
    # Text input area
    draw.rectangle([20, 130, 340, 180], fill='white', outline='#e2e8f0')
    draw.text((30, 145), 'Paste suspicious SMS here...', fill='#94a3b8')
    
    # Analyze button
    draw.rectangle([20, 190, 340, 220], fill='#002855')
    draw.text((140, 200), 'Analyze SMS', fill='white')
    
    # Stats row
    draw.text((20, 240), 'Quick Stats', fill='#002855')
    stats = [
        ('1,234', 'Total', '#002855'),
        ('89', 'High Risk', '#dc3545'),
        ('567', 'Blocked', '#F5A623'),
        ('678', 'Safe', '#10b981')
    ]
    for i, (value, label, color) in enumerate(stats):
        x = 20 + i * 80
        draw.rectangle([x, 270, x+70, 300], fill=color, outline='white')
        draw.text((x+10, 278), value, fill='white')
        draw.text((x+10, 290), label, fill='white', size=8)
    
    # Footer
    draw.rectangle([0, 600, 360, 640], fill='#001a3f')
    draw.text((80, 615), 'Protected by AI Fraud Shield', fill='#F5A623', size=10)
    
    img.save('static/detector/icons/screenshot-mobile.png')
    print('✅ Created screenshot-mobile.png')

def create_desktop_screenshot():
    """Create desktop screenshot (1280x720)"""
    img = Image.new('RGB', (1280, 720), color='#f8fafc')
    draw = ImageDraw.Draw(img)
    
    # Navy header
    draw.rectangle([0, 0, 1280, 70], fill='#002855')
    draw.text((40, 20), '🛡️ AI Fraud Shield', fill='#F5A623')
    draw.text((300, 20), 'Kenya\'s Most Advanced Scam Detection Platform', fill='#f8fafc')
    
    # Gold accent line
    draw.rectangle([0, 70, 1280, 74], fill='#F5A623')
    
    # Sidebar (left)
    draw.rectangle([0, 74, 200, 720], fill='#e8f0fe')
    draw.text((20, 100), 'Detection Tools', fill='#002855')
    
    tools = ['SMS Detection', 'Email Analysis', 'WhatsApp', 'Screenshot', 'URL Checker']
    for i, tool in enumerate(tools):
        y = 130 + i * 45
        draw.rectangle([20, y, 180, y+35], fill='white', outline='#e2e8f0')
        draw.text((30, y+10), tool, fill='#002855')
    
    # Main content
    draw.text((220, 100), 'Welcome to AI Fraud Shield', fill='#002855')
    
    # Hero card
    draw.rectangle([220, 130, 1260, 250], fill='white', outline='#e2e8f0')
    draw.text((250, 160), '🚀 Detect Scams Instantly', fill='#002855')
    draw.text((250, 190), 'Protect yourself from SMS, Email, WhatsApp, and Call scams', fill='#64748b')
    
    # Stats cards
    cards = [
        ('🛡️', 'Total Scans', '12,345', '#002855'),
        ('🚨', 'High Risk', '89', '#dc3545'),
        ('📱', 'SMS Scans', '5,678', '#F5A623'),
        ('🔗', 'URLs Checked', '3,456', '#10b981')
    ]
    for i, (icon, label, value, color) in enumerate(cards):
        x = 240 + i * 240
        draw.rectangle([x, 270, x+200, 350], fill=color, outline='white')
        draw.text((x+10, 290), icon, fill='white')
        draw.text((x+10, 310), value, fill='white')
        draw.text((x+10, 330), label, fill='white')
    
    # Footer
    draw.rectangle([0, 680, 1280, 720], fill='#001a3f')
    draw.text((500, 695), '© 2026 AI Fraud Shield Kenya - Protecting Kenyans from Digital Scams', fill='#F5A623')
    
    img.save('static/detector/icons/screenshot-wide.png')
    print('✅ Created screenshot-wide.png')

# Create both screenshots
create_mobile_screenshot()
create_desktop_screenshot()
print('✅ All screenshots created successfully!')
