"""
compare_tools.py  -  file comparison helpers used by app.py

    image_diff(bytes_a, bytes_b)  -> % of pixels that differ + highlighted regions
    pdf_diff(bytes_a, bytes_b)    -> % different, page-wise / line / word / character counts
    byte_diff_percent(a, b)       -> % of bytes that differ (used by Verify File)

Needs: Pillow, numpy, pypdf   (see requirements.txt)
"""
import base64
import difflib
import io
from collections import deque

import numpy as np
from PIL import Image, ImageDraw, ImageOps, ImageFilter, UnidentifiedImageError

# Optional decoders extend Pillow support for modern phone/web image formats.
try:
    import pillow_heif
    pillow_heif.register_heif_opener()
except ImportError:
    pass

try:
    import pillow_avif  # noqa: F401 - importing registers the AVIF decoder
except ImportError:
    pass

MAX_SIDE = 1600
PIXEL_THRESHOLD = 40       # kitna color farak "change" maane
BLUR_RADIUS = 2            # JPEG noise hatane ke liye
MIN_REGION_PIXELS = 40     # isse chhote dhabbe ignore
MAX_REGIONS = 25
COMPLETELY_DIFFERENT = 35  # % isse upar = alag photos, box nahi
BOX_COLOR = (34, 220, 60)  # green


def _load_image(data):
    """
    Decode the first frame of a supported image and normalize it for comparison.
    Handles EXIF rotation, palette/alpha, grayscale, CMYK and other Pillow modes.
    Pillow's installed decoders determine the exact formats available at runtime.
    """
    if not data:
        raise ValueError("The uploaded image is empty.")

    try:
        with Image.open(io.BytesIO(data)) as source:
            # Animated GIF/WEBP and multi-page TIFF: compare the first frame.
            try:
                source.seek(0)
            except EOFError:
                pass

            image = ImageOps.exif_transpose(source)
            image.load()

            # Composite transparency onto a consistent white background.
            has_alpha = "A" in image.getbands() or "transparency" in image.info
            if has_alpha:
                rgba = image.convert("RGBA")
                background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                background.alpha_composite(rgba)
                image = background.convert("RGB")
            else:
                # Also normalizes palette, grayscale, CMYK, LAB and 16-bit modes.
                image = image.convert("RGB")

            if image.width < 1 or image.height < 1:
                raise ValueError("The uploaded image has invalid dimensions.")
            return image.copy()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError(
            "Unsupported or damaged image. Try PNG, JPG/JPEG, WEBP, GIF, BMP or TIFF."
        ) from exc


def _regions_from_mask(mask, cell):
    height, width = mask.shape
    rows = (height + cell - 1) // cell
    cols = (width + cell - 1) // cell
    padded = np.zeros((rows * cell, cols * cell), dtype=bool)
    padded[:height, :width] = mask
    active = padded.reshape(rows, cell, cols, cell).any(axis=(1, 3))

    seen = np.zeros_like(active, dtype=bool)
    regions = []
    for r0 in range(rows):
        for c0 in range(cols):
            if not active[r0, c0] or seen[r0, c0]:
                continue
            queue = deque([(r0, c0)])
            seen[r0, c0] = True
            members = []
            while queue:
                r, c = queue.popleft()
                members.append((r, c))
                for dr in (-1, 0, 1):
                    for dc in (-1, 0, 1):
                        rr, cc = r + dr, c + dc
                        if 0 <= rr < rows and 0 <= cc < cols and active[rr, cc] and not seen[rr, cc]:
                            seen[rr, cc] = True
                            queue.append((rr, cc))
            rs = [m[0] for m in members]
            cs = [m[1] for m in members]
            x0, y0 = min(cs) * cell, min(rs) * cell
            x1, y1 = min(width, (max(cs) + 1) * cell), min(height, (max(rs) + 1) * cell)
            part = mask[y0:y1, x0:x1]
            changed = int(part.sum())
            if changed < MIN_REGION_PIXELS:
                continue
            ys, xs = np.where(part)
            pad = 4
            bx0, by0 = max(0, x0 + int(xs.min()) - pad), max(0, y0 + int(ys.min()) - pad)
            bx1, by1 = min(width, x0 + int(xs.max()) + 1 + pad), min(height, y0 + int(ys.max()) + 1 + pad)
            regions.append({"x": bx0, "y": by0, "w": bx1 - bx0, "h": by1 - by0, "changed": changed})
    return regions


def _merge_overlapping(regions, mask):
    merged = True
    while merged:
        merged = False
        for i in range(len(regions)):
            for j in range(i + 1, len(regions)):
                a, b = regions[i], regions[j]
                if (a["x"] <= b["x"] + b["w"] and b["x"] <= a["x"] + a["w"]
                        and a["y"] <= b["y"] + b["h"] and b["y"] <= a["y"] + a["h"]):
                    x0, y0 = min(a["x"], b["x"]), min(a["y"], b["y"])
                    x1 = max(a["x"] + a["w"], b["x"] + b["w"])
                    y1 = max(a["y"] + a["h"], b["y"] + b["h"])
                    regions[i] = {"x": x0, "y": y0, "w": x1 - x0, "h": y1 - y0,
                                  "changed": int(mask[y0:y1, x0:x1].sum())}
                    del regions[j]
                    merged = True
                    break
            if merged:
                break
    return regions


def _draw_boxes(image, regions, width):
    out = image.copy()
    draw = ImageDraw.Draw(out)
    line = max(2, width // 300)
    for index, region in enumerate(regions, start=1):
        box = (region["x"], region["y"], region["x"] + region["w"], region["y"] + region["h"])
        draw.rectangle(box, outline=BOX_COLOR, width=line)
        label_y = max(0, region["y"] - 16)
        draw.rectangle((region["x"], label_y, region["x"] + 22, label_y + 15), fill=BOX_COLOR)
        draw.text((region["x"] + 6, label_y + 2), str(index), fill=(0, 0, 0))
    return out


def _to_data_url(image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def image_diff(data_a, data_b):
    a = _load_image(data_a)
    b = _load_image(data_b)
    original_a, original_b = a.size, b.size

    # Keep memory and response size predictable for large phone/AI images.
    # Image 1 defines the comparison canvas; Image 2 is normalized to it.
    scale = min(1.0, MAX_SIDE / max(a.size))
    work = (max(1, round(a.width * scale)), max(1, round(a.height * scale)))
    a = a.resize(work, Image.Resampling.LANCZOS) if work != a.size else a
    resized_b = b.size != a.size
    b = b.resize(a.size, Image.Resampling.LANCZOS) if resized_b else b

    blur_a = a.filter(ImageFilter.GaussianBlur(BLUR_RADIUS))
    blur_b = b.filter(ImageFilter.GaussianBlur(BLUR_RADIUS))
    arr_a = np.asarray(blur_a, dtype=np.int16)
    arr_b = np.asarray(blur_b, dtype=np.int16)
    mask = np.abs(arr_a - arr_b).max(axis=2) > PIXEL_THRESHOLD

    width, height = a.size
    total_pixels = width * height
    changed_pixels = int(mask.sum())
    percent = 100.0 * changed_pixels / total_pixels if total_pixels else 0.0
    completely_different = percent >= COMPLETELY_DIFFERENT

    regions = []
    if changed_pixels and not completely_different:
        grown = Image.fromarray((mask * 255).astype(np.uint8)).filter(ImageFilter.MaxFilter(7))
        grown_mask = np.asarray(grown) > 0
        cell = max(6, min(width, height) // 60)
        regions = _regions_from_mask(grown_mask, cell)
        regions = _merge_overlapping(regions, mask)
        regions = [r for r in regions if r["changed"] >= MIN_REGION_PIXELS]
        for region in regions:
            area = max(1, region["w"] * region["h"])
            region["percent_of_image"] = round(100.0 * region["changed"] / total_pixels, 3)
            region["percent_in_region"] = round(100.0 * region["changed"] / area, 1)
        regions.sort(key=lambda r: r["changed"], reverse=True)
        regions = regions[:MAX_REGIONS]
        for index, region in enumerate(regions, start=1):
            region["no"] = index

    shown_a = _draw_boxes(a, regions, width) if regions else a
    shown_b = _draw_boxes(b, regions, width) if regions else b

    return {
        "identical": changed_pixels == 0,
        "completely_different": completely_different,
        "percent_different": round(percent, 3),
        "changed_pixels": changed_pixels,
        "total_pixels": total_pixels,
        "size_a": list(original_a),
        "size_b": list(original_b),
        "resized_b": resized_b,
        "analysed_size": [width, height],
        "regions": regions,
        "highlight_a": _to_data_url(shown_a),
        "highlight_b": _to_data_url(shown_b),
        "highlight": _to_data_url(shown_b),
    }

# =========================================================================
# 2. PDF COMPARE
# =========================================================================

CHAR_DIFF_LIMIT = 6000      # exact character diff only for pages up to this size


def _pdf_pages(data):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    pages = []
    for page in reader.pages:
        try:
            pages.append(page.extract_text() or "")
        except Exception:                      # a broken page must not stop the compare
            pages.append("")
    return pages


def _clean_lines(text):
    return [" ".join(line.split()) for line in text.splitlines() if line.strip()]


def _changed(opcodes, seq_a, seq_b, weight=len):
    """Count items that are not equal. `weight` lets us count characters of words."""
    total = 0
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        total += max(sum(weight(x) for x in seq_a[i1:i2]), sum(weight(x) for x in seq_b[j1:j2]))
    return total


def _count_changed_items(opcodes):
    total = 0
    for tag, i1, i2, j1, j2 in opcodes:
        if tag != "equal":
            total += max(i2 - i1, j2 - j1)
    return total


def pdf_diff(data_a, data_b):
    pages_a = _pdf_pages(data_a)
    pages_b = _pdf_pages(data_b)
    page_count = max(len(pages_a), len(pages_b))

    rows = []
    totals = {"lines": 0, "lines_total": 0, "words": 0, "words_total": 0,
              "chars": 0, "chars_total": 0}

    for number in range(page_count):
        text_a = pages_a[number] if number < len(pages_a) else None
        text_b = pages_b[number] if number < len(pages_b) else None
        lines_a = _clean_lines(text_a or "")
        lines_b = _clean_lines(text_b or "")
        words_a = (text_a or "").split()
        words_b = (text_b or "").split()
        chars_a = " ".join(words_a)
        chars_b = " ".join(words_b)

        line_ops = difflib.SequenceMatcher(None, lines_a, lines_b, autojunk=False).get_opcodes()
        word_ops = difflib.SequenceMatcher(None, words_a, words_b, autojunk=False).get_opcodes()
        lines_changed = _count_changed_items(line_ops)
        words_changed = _count_changed_items(word_ops)

        if max(len(chars_a), len(chars_b)) <= CHAR_DIFF_LIMIT:
            char_ops = difflib.SequenceMatcher(None, chars_a, chars_b, autojunk=False).get_opcodes()
            chars_changed = _count_changed_items(char_ops)
        else:                                  # big page: derive from the changed words
            chars_changed = _changed(word_ops, words_a, words_b, weight=lambda w: len(w) + 1)

        chars_total = max(len(chars_a), len(chars_b))
        if text_a is None:
            status = "only in PDF 2"
        elif text_b is None:
            status = "only in PDF 1"
        elif chars_changed == 0 and lines_changed == 0:
            status = "same"
        else:
            status = "different"

        samples = []
        for tag, i1, i2, j1, j2 in line_ops:
            if tag == "equal" or len(samples) >= 8:
                continue
            samples.append({
                "type": {"replace": "changed", "delete": "removed", "insert": "added"}[tag],
                "pdf1": " / ".join(lines_a[i1:i2])[:220],
                "pdf2": " / ".join(lines_b[j1:j2])[:220],
            })

        percent = round(100.0 * chars_changed / chars_total, 2) if chars_total else 0.0
        if status.startswith("only"):
            percent = 100.0
        rows.append({
            "page": number + 1, "status": status, "percent": percent,
            "lines_changed": lines_changed, "lines_total": max(len(lines_a), len(lines_b)),
            "words_changed": words_changed, "words_total": max(len(words_a), len(words_b)),
            "chars_changed": chars_changed, "chars_total": chars_total,
            "samples": samples,
        })
        totals["lines"] += lines_changed
        totals["lines_total"] += max(len(lines_a), len(lines_b))
        totals["words"] += words_changed
        totals["words_total"] += max(len(words_a), len(words_b))
        totals["chars"] += chars_changed
        totals["chars_total"] += chars_total

    text_found = totals["chars_total"] > 0
    overall = round(100.0 * totals["chars"] / totals["chars_total"], 2) if text_found else 0.0
    identical_bytes = data_a == data_b
    return {
        "pages_a": len(pages_a), "pages_b": len(pages_b),
        "text_found": text_found,
        "identical_bytes": identical_bytes,
        "identical_text": text_found and totals["chars"] == 0 and len(pages_a) == len(pages_b),
        "percent_different": 0.0 if identical_bytes else overall,
        "totals": totals,
        "pages": rows,
    }


# =========================================================================
# 3. BYTE DIFFERENCE (Verify File)
# =========================================================================

def byte_diff_percent(stored, current):
    """% of bytes that differ between two byte strings (length change counts too)."""
    longest = max(len(stored), len(current))
    if longest == 0:
        return 0.0
    shortest = min(len(stored), len(current))
    if shortest:
        a = np.frombuffer(stored, dtype=np.uint8, count=shortest)
        b = np.frombuffer(current, dtype=np.uint8, count=shortest)
        differing = int(np.count_nonzero(a != b))
    else:
        differing = 0
    differing += longest - shortest
    return round(100.0 * differing / longest, 4)
