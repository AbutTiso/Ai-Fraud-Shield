from PIL import Image, ImageDraw, ImageFont
import os

# Create icons directory if it doesn't exist
os.makedirs('static/detector/icons', exist_ok=True)

# Define icon sizes
sizes = [72, 96, 128, 144, 152, 192, 384, 512]

for size in sizes:
    # Create image with Navy background
    img = Image.new('RGB', (size, size), color='#002855')
    draw = ImageDraw.Draw(img)
    
    # Draw a gold shield
    center = size // 2
    radius = size // 3
    
    # Draw circle
    draw.ellipse([center - radius, center - radius, center + radius, center + radius], 
                 fill='#F5A623', outline='#e6951a')
    
    # Draw shield text or symbol
    try:
        # Try to use a font
        font_size = size // 3
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        draw.text((center - font_size//2, center - font_size//2), '🛡️', fill='#002855', font=font)
    except:
        # If text fails, just draw a star
        draw.polygon([
            (center, center - radius//2),
            (center + radius//4, center - radius//4),
            (center + radius//2, center),
            (center + radius//4, center + radius//4),
            (center, center + radius//2),
            (center - radius//4, center + radius//4),
            (center - radius//2, center),
            (center - radius//4, center - radius//4)
        ], fill='#002855')
    
    # Save the image
    img.save(f'static/detector/icons/icon-{size}.png')
    print(f'Created icon-{size}.png')

print('All icons created successfully!')
