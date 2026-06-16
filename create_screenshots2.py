from PIL import Image, ImageDraw

# Create mobile screenshot
def create_mobile_screenshot():
    img = Image.new('RGB', (360, 640), color='#f8fafc')
    draw = ImageDraw.Draw(img)
    
    # Navy header
    draw.rectangle([0, 0, 360, 80], fill='#002855')
    draw.text((20, 25), '🛡️ AI Fraud Shield', fill='#F5A623')
    draw.rectangle([0, 80, 360, 84], fill='#F5A623')
    
    draw.text((20, 100), 'SMS Scam Detector', fill='#002855')
    draw.rectangle([20, 130, 340, 180], fill='white', outline='#e2e8f0')
    draw.text((30, 145), 'Paste suspicious SMS here...', fill='#94a3b8')
    draw.rectangle([20, 190, 340, 220], fill='#002855')
    draw.text((140, 200), 'Analyze SMS', fill='white')
    
    img.save('static/detector/icons/screenshot-mobile.png')
    print('✅ Created screenshot-mobile.png')

# Create desktop screenshot
def create_desktop_screenshot():
    img = Image.new('RGB', (1280, 720), color='#f8fafc')
    draw = ImageDraw.Draw(img)
    
    draw.rectangle([0, 0, 1280, 70], fill='#002855')
    draw.text((40, 20), '🛡️ AI Fraud Shield', fill='#F5A623')
    draw.text((300, 20), 'Kenya\'s Most Advanced Scam Detection Platform', fill='#f8fafc')
    draw.rectangle([0, 70, 1280, 74], fill='#F5A623')
    
    draw.rectangle([0, 74, 200, 720], fill='#e8f0fe')
    draw.text((20, 100), 'Detection Tools', fill='#002855')
    
    tools = ['SMS Detection', 'Email Analysis', 'WhatsApp', 'Screenshot', 'URL Checker']
    for i, tool in enumerate(tools):
        y = 130 + i * 45
        draw.rectangle([20, y, 180, y+35], fill='white', outline='#e2e8f0')
        draw.text((30, y+10), tool, fill='#002855')
    
    draw.text((220, 100), 'Welcome to AI Fraud Shield', fill='#002855')
    draw.rectangle([220, 130, 1260, 250], fill='white', outline='#e2e8f0')
    draw.text((250, 160), '🚀 Detect Scams Instantly', fill='#002855')
    draw.text((250, 190), 'Protect yourself from SMS, Email, WhatsApp, and Call scams', fill='#64748b')
    
    img.save('static/detector/icons/screenshot-wide.png')
    print('✅ Created screenshot-wide.png')

create_mobile_screenshot()
create_desktop_screenshot()
print('✅ All screenshots created successfully!')
