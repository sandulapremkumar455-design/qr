"""
Run this script ONCE to download face-api.js model weights locally.
After running, the app will load models from your own server — no internet needed for face scan.

Usage:
    python download_models.py
"""

import urllib.request
import os

WEIGHTS_DIR = os.path.join(os.path.dirname(__file__), 'static', 'weights')
BASE_URL = 'https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights'

FILES = [
    'tiny_face_detector_model-weights_manifest.json',
    'tiny_face_detector_model-shard1',
    'face_landmark_68_tiny_model-weights_manifest.json',
    'face_landmark_68_tiny_model-shard1',
    'face_recognition_model-weights_manifest.json',
    'face_recognition_model-shard1',
    'face_recognition_model-shard2',
]

os.makedirs(WEIGHTS_DIR, exist_ok=True)

print(f"Downloading models to: {WEIGHTS_DIR}\n")

for filename in FILES:
    dest = os.path.join(WEIGHTS_DIR, filename)

    # Skip if already downloaded
    if os.path.exists(dest) and os.path.getsize(dest) > 100:
        print(f"  [SKIP] {filename} (already exists)")
        continue

    url = f"{BASE_URL}/{filename}"
    print(f"  Downloading {filename} ...", end=' ', flush=True)
    try:
        urllib.request.urlretrieve(url, dest)
        size_kb = os.path.getsize(dest) / 1024
        print(f"OK ({size_kb:.0f} KB)")
    except Exception as e:
        print(f"FAILED: {e}")

print("\n✅ Done! Models saved to static/weights/")
print("The app will now load face models locally — no CDN needed.")

# Also download face-api.js library itself
import urllib.request, os
JS_DIR = os.path.join(os.path.dirname(__file__), 'static')
JS_FILE = os.path.join(JS_DIR, 'face-api.min.js')
if not os.path.exists(JS_FILE) or os.path.getsize(JS_FILE) < 1000:
    print("\n  Downloading face-api.min.js library...", end=' ', flush=True)
    try:
        urllib.request.urlretrieve(
            'https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js',
            JS_FILE
        )
        print(f"OK ({os.path.getsize(JS_FILE)//1024} KB)")
    except Exception as e:
        print(f"FAILED: {e}")
else:
    print("  [SKIP] face-api.min.js (already exists)")

print("\n✅ All done! Run: python app.py")
