FILE INTEGRITY CHECKER — IMAGE COMPARISON FIX
=============================================

These are replacement files for the project root used by render.yaml:
  FileIntegrityChecker/FileIntegrityChecker/

Replace:
  compare_tools.py
  app.py
  static/js/fic_tools.js
  requirements.txt

Do NOT replace the extra nested duplicate folder:
  FileIntegrityChecker/FileIntegrityChecker/FileIntegrityChecker/

What this patch changes:
- Normalizes EXIF rotation and common Pillow image modes (RGB, RGBA, palette,
  grayscale, CMYK, etc.).
- Handles transparent images by compositing them on a white background.
- Uses the first frame of animated GIF/WEBP and multi-page TIFF images.
- Adds explicit handling for empty/unsupported/damaged image uploads.
- Logs full backend exceptions for diagnosis instead of silently hiding them.
- Makes the frontend accept either highlight_b or the older highlight response key.

Supported formats depend on the image decoders installed with Pillow. Common
formats include JPG/JPEG, PNG, WEBP, GIF, BMP and TIFF. HEIC/HEIF and AVIF
require extra decoder packages and are not guaranteed by this patch.

Important:
This is pixel-based comparison, not AI semantic matching. It detects visible
pixel differences after normalizing the images to a common size. If two photos
are taken from different angles, heavily cropped, or substantially reframed,
a pixel-difference percentage is not a reliable measure of whether one is an
edit of the other.

After replacing files:
1. Install dependencies from requirements.txt if not already installed:
   pip install -r requirements.txt
2. Restart Flask locally.
3. Test two JPG images, then PNG with transparency, WEBP, and different image sizes.
4. Push the changed files to GitHub and redeploy Render.
