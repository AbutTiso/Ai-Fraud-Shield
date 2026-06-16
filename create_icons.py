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
    
    # Draw "AI" text in the center
    try:
        font_size = size // 4
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        # Draw shield icon or text
        if size >= 128:
            text = '🛡️'
            draw.text((size//2 - font_size//2, size//2 - font_size//2), text, fill=color, font=font)
        else:
            # For smaller icons, draw a star
            center = size // 2
            radius = size // 3
            points = []
            for i in range(5):
                angle = math.pi/2 + i * 2 * math.pi / 5
                x = center + radius * math.cos(angle)
                y = center - radius * math.sin(angle)
                points.append((x, y))
                angle2 = angle + math.pi/5
                x2 = center + radius * 0.4 * math.cos(angle2)
                y2 = center - radius * 0.4 * math.sin(angle2)
                points.append((x2, y2))
            draw.polygon(points, fill=color)
    except:
        pass
    
    # Add a small gold border
    draw.arc([2, 2, size-3, size-3], 0, 360, fill=accent, width=2)
    
    return img

# Generate icons for all sizes
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
print(f'📁 Location: static/detector/icons/')
