# test_server.py
import sys
print("Python path:", sys.path)

try:
    print("1. Importing django...")
    import django
    print("   Django version:", django.get_version())
except Exception as e:
    print(f"   Error: {e}")

try:
    print("2. Loading settings...")
    from fraudshield import settings
    print("   Settings loaded")
except Exception as e:
    print(f"   Error: {e}")

try:
    print("3. Setting up django...")
    django.setup()
    print("   Setup complete")
except Exception as e:
    print(f"   Error: {e}")

try:
    print("4. Importing detector.views...")
    from detector import views
    print("   Views imported")
except Exception as e:
    print(f"   Error: {e}")
    import traceback
    traceback.print_exc()
