import os
from PIL import Image, ImageDraw, ImageFont
import math

# Create icons directory
os.makedirs('static/detector/icons', exist_ok=True)

def create_icon(size, color='#002855', accent='#F5A623'):
    """Create a simple shield icon"""
    img = Image.new('RGBA', (size, size), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    
    # Navy background with rounded corners
    draw.rounded_rectangle([0, 0, size-1, size-1], radius=size//8, fill=color)
    
    # Gold shield shape
    shield_points = [
        (size//2, size//8),
        (size - size//8, size//4),
        (size - size//8, size//2),
        (size//2, size - size//8),
        (size//8, size//2),
        (size//8, size//4)
    ]
    draw.polygon(shield_points, fill=accent, outline='#e6951a', width=2)
    
    # Add a small gold border
    draw.arc([2, 2, size-3, size-3], 0, 360, fill=accent, width=2)
    
    return img

# Generate all icons
sizes = [72, 96, 128, 144, 152, 192, 384, 512]

for size in sizes:
    img = create_icon(size)
    img.save(f'static/detector/icons/icon-{size}.png')
    print(f'✅ Created icon-{size}.png')

# Create maskable icons
for size in [192, 512]:
    img = create_icon(size, color='#001a3f', accent='#e6951a')
    img.save(f'static/detector/icons/icon-{size}-maskable.png')
    print(f'✅ Created icon-{size}-maskable.png')

print('✅ All icons created successfully!')
