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
from PIL import Image, ImageDraw, ImageOps

MAX_SIDE = 1600            # images are analysed at most this big
PIXEL_THRESHOLD = 24       # per-channel difference (0-255) that counts as "different"
MAX_REGIONS = 25


# =========================================================================
# 1. IMAGE COMPARE
# =========================================================================

def _load_image(data):
    image = Image.open(io.BytesIO(data))
    image = ImageOps.exif_transpose(image)          # respect phone rotation
    if image.mode in ("RGBA", "LA", "P"):
        rgba = image.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        background.alpha_composite(rgba)
        image = background
    return image.convert("RGB")


def _regions_from_mask(mask, cell):
    """Group the changed pixels into rectangular regions.

    The mask is cut into cell x cell squares; squares that contain changes are
    joined with their neighbours (8-way, plus a 1-square gap) and every joined
    group becomes one region.
    """
    height, width = mask.shape
    rows = (height + cell - 1) // cell
    cols = (width + cell - 1) // cell

    padded = np.zeros((rows * cell, cols * cell), dtype=bool)
    padded[:height, :width] = mask
    cell_counts = padded.reshape(rows, cell, cols, cell).sum(axis=(1, 3))
    active = cell_counts > 0

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
                for dr in (-2, -1, 0, 1, 2):
                    for dc in (-2, -1, 0, 1, 2):
                        rr, cc = r + dr, c + dc
                        if 0 <= rr < rows and 0 <= cc < cols and active[rr, cc] and not seen[rr, cc]:
                            seen[rr, cc] = True
                            queue.append((rr, cc))
            rs = [m[0] for m in members]
            cs = [m[1] for m in members]
            x0, y0 = min(cs) * cell, min(rs) * cell
            x1, y1 = min(width, (max(cs) + 1) * cell), min(height, (max(rs) + 1) * cell)
            changed = int(mask[y0:y1, x0:x1].sum())
            regions.append({"x": x0, "y": y0, "w": x1 - x0, "h": y1 - y0, "changed": changed})
    return regions


def image_diff(data_a, data_b):
    a = _load_image(data_a)
    b = _load_image(data_b)
    original_a, original_b = a.size, b.size

    # work at a sensible size; B is stretched to A's shape if they differ
    scale = min(1.0, MAX_SIDE / max(a.size))
    work = (max(1, round(a.size[0] * scale)), max(1, round(a.size[1] * scale)))
    a = a.resize(work, Image.LANCZOS) if work != a.size else a
    resized_b = b.size != a.size
    b = b.resize(a.size, Image.LANCZOS) if resized_b else b

    arr_a = np.asarray(a, dtype=np.int16)
    arr_b = np.asarray(b, dtype=np.int16)
    mask = np.abs(arr_a - arr_b).max(axis=2) > PIXEL_THRESHOLD

    width, height = a.size
    total_pixels = width * height
    changed_pixels = int(mask.sum())
    percent = 100.0 * changed_pixels / total_pixels if total_pixels else 0.0

    cell = max(8, min(width, height) // 40)
    regions = _regions_from_mask(mask, cell) if changed_pixels else []
    for region in regions:
        area = max(1, region["w"] * region["h"])
        region["percent_of_image"] = round(100.0 * region["changed"] / total_pixels, 3)
        region["percent_in_region"] = round(100.0 * region["changed"] / area, 1)
    regions.sort(key=lambda r: r["changed"], reverse=True)
    regions = regions[:MAX_REGIONS]

    # highlighted copy of image A: changed pixels tinted red + a box per region
    overlay = np.asarray(a, dtype=np.uint8).copy()
    overlay[mask] = (0.35 * overlay[mask] + 0.65 * np.array([255, 40, 60])).astype(np.uint8)
    highlight = Image.fromarray(overlay)
    draw = ImageDraw.Draw(highlight)
    line = max(2, width // 400)
    for index, region in enumerate(regions, start=1):
        box = (region["x"], region["y"], region["x"] + region["w"], region["y"] + region["h"])
        draw.rectangle(box, outline=(255, 214, 0), width=line)
        label_y = max(0, region["y"] - 16)
        draw.rectangle((region["x"], label_y, region["x"] + 22, label_y + 15), fill=(255, 214, 0))
        draw.text((region["x"] + 5, label_y + 2), str(index), fill=(0, 0, 0))

    buffer = io.BytesIO()
    highlight.save(buffer, format="PNG", optimize=True)
    for index, region in enumerate(regions, start=1):
        region["no"] = index

    return {
        "identical": changed_pixels == 0,
        "percent_different": round(percent, 3),
        "changed_pixels": changed_pixels,
        "total_pixels": total_pixels,
        "size_a": list(original_a),
        "size_b": list(original_b),
        "resized_b": resized_b,
        "analysed_size": [width, height],
        "regions": regions,
        "highlight": "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii"),
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
