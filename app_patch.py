# This shows the key changes needed
# 1. User model needs face_image field (base64 JPEG stored in DB)
# 2. New endpoint /api/register_face_image to save image
# 3. New endpoint /api/verify_face_image (compare only that user's image)
# 4. Login page: remove upload mode, camera-only
# 5. Student info: show face images
print("patch plan done")
