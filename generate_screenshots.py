from PIL import Image, ImageDraw
import os

# Create screenshots directory
os.makedirs('static/detector/icons', exist_ok=True)

# Mobile screenshot (360x640)
img = Image.new('RGB', (360, 640), color='#002855')
draw = ImageDraw.Draw(img)

# Draw header
draw.rectangle([0, 0, 360, 80], fill='#001a3f')
draw.text((20, 25), '🛡️ AI Fraud Shield', fill='#F5A623', font=None)

# Draw main content area
draw.rectangle([10, 90, 350, 630], fill='#f8fafc', outline='#e2e8f0')

# Draw some text
draw.text((30, 110), 'SMS Scam Detector', fill='#002855', font=None)
draw.rectangle([30, 140, 330, 160], fill='#e8f0fe')
draw.text((40, 145), 'Paste suspicious SMS here...', fill='#64748b', font=None)

draw.rectangle([30, 170, 330, 200], fill='#002855')
draw.text((120, 185), 'Analyze SMS', fill='#ffffff', font=None)

# Draw some stats
draw.text((30, 220), 'Quick Stats', fill='#002855', font=None)
colors = ['#002855', '#F5A623', '#dc3545', '#10b981']
labels = ['Total: 1,234', 'High Risk: 89', 'Blocked: 567', 'Safe: 678']
for i, (color, label) in enumerate(zip(colors, labels)):
    x = 30 + (i * 75)
    draw.rectangle([x, 245, x + 70, 275], fill=color)
    draw.text((x + 10, 255), label, fill='#ffffff', font=None)

# Save
img.save('static/detector/icons/screenshot-mobile.png')
print('Created mobile screenshot')

# Wide screenshot (1280x720)
img = Image.new('RGB', (1280, 720), color='#002855')
draw = ImageDraw.Draw(img)

# Draw header
draw.rectangle([0, 0, 1280, 90], fill='#001a3f')
draw.text((40, 25), '🛡️ AI Fraud Shield - Scam Detection Platform', fill='#F5A623', font=None)

# Draw main content
draw.rectangle([10, 100, 1270, 710], fill='#f8fafc', outline='#e2e8f0')

# Draw sidebar
draw.rectangle([10, 100, 260, 710], fill='#e8f0fe')
draw.text((40, 120), 'Detection Tools', fill='#002855', font=None)
tools = ['SMS Detection', 'Email Analysis', 'WhatsApp', 'Screenshot', 'URL Checker']
for i, tool in enumerate(tools):
    draw.rectangle([30, 150 + i*40, 240, 180 + i*40], fill='#ffffff', outline='#e2e8f0')
    draw.text((50, 160 + i*40), tool, fill='#002855', font=None)

# Draw main content area
draw.text((280, 120), 'Welcome to AI Fraud Shield', fill='#002855', font=None)
draw.text((280, 150), 'Kenya\'s Most Advanced AI-Powered Scam Detection Platform', fill='#64748b', font=None)

# Draw cards
for i in range(4):
    x = 280 + (i * 240)
    draw.rectangle([x, 190, x + 220, 280], fill='#ffffff', outline='#e2e8f0')
    draw.text((x + 20, 210), f'Card {i+1}', fill='#002855', font=None)

# Save
img.save('static/detector/icons/screenshot-wide.png')
print('Created wide screenshot')
