"""
report_pdf.py - builds the downloadable user report (PDF and CSV)

    build_report_data(files, history)  -> (file_rows, checks)
    build_csv(user, file_rows)         -> str
    build_pdf(user, file_rows, checks) -> bytes

`files` and `history` are the lists returned by /api/user/files and
/api/user/history.  Needs: reportlab  (see requirements.txt)
"""
import csv
import io
import re
from datetime import datetime

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

GREEN, AMBER, RED = colors.HexColor("#10b981"), colors.HexColor("#f59e0b"), colors.HexColor("#ef4444")
INDIGO, INK, MUTED = colors.HexColor("#4f46e5"), colors.HexColor("#0f1b3a"), colors.HexColor("#64748b")
STATUS_COLOR = {"safe": GREEN, "modified": AMBER, "tampered": RED}


def _size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _pct_from_remarks(text):
    match = re.search(r"([\d.]+)% bytes changed", text or "")
    return float(match.group(1)) if match else None


def build_report_data(files, history):
    """One row per file + one row per verification (history rows grouped)."""
    groups = {}
    for row in history:
        key = (row.get("file_id"), row.get("verified_at"))
        group = groups.setdefault(key, {
            "file": row.get("file") or "", "file_id": row.get("file_id"),
            "time": row.get("verified_at") or "", "status": "safe", "percent": None})
        if (row.get("result") or "safe") != "safe":
            group["status"] = row["result"]
        pct = _pct_from_remarks(row.get("remarks"))
        if pct is not None:
            group["percent"] = pct
    checks = sorted(groups.values(), key=lambda g: g["time"])

    file_rows = []
    for f in files:
        mine = [c for c in checks if c["file_id"] == f["id"]]
        percents = [c["percent"] for c in mine if c["percent"] is not None]
        file_rows.append({
            "id": f["id"], "name": f["name"], "size": f.get("size") or 0,
            "type": (f["name"].rsplit(".", 1)[-1].lower() if "." in f["name"] else ""),
            "algorithms": list((f.get("hashes") or {}).keys()),
            "status": f.get("status") or "safe",
            "uploaded": f.get("upload_date") or "", "last_checked": f.get("last_checked") or "",
            "checks": len(mine), "max_change": max(percents) if percents else None,
        })
    return file_rows, checks


def build_csv(user, file_rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "file", "type", "size_bytes", "algorithms", "status",
                     "uploaded", "last_checked", "checks", "max_percent_changed"])
    for r in file_rows:
        writer.writerow([r["id"], r["name"], r["type"], r["size"], " ".join(r["algorithms"]),
                         r["status"], r["uploaded"], r["last_checked"], r["checks"],
                         "" if r["max_change"] is None else r["max_change"]])
    return out.getvalue()


def _kpi_table(cells):
    table = Table([[Paragraph(f"<font size=17><b>{v}</b></font><br/><font size=8 color='#64748b'>{k}</font>",
                              ParagraphStyle("k", leading=20)) for k, v in cells]],
                  colWidths=[41 * mm] * len(cells))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5fd")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#dbe4f5")),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return table


def _status_pie(counts):
    drawing = Drawing(240, 130)
    total = sum(counts.values())
    if not total:
        drawing.add(String(20, 60, "No files yet", fontSize=10, fillColor=MUTED))
        return drawing
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 10, 12, 105, 105
    keys = [k for k in ("safe", "modified", "tampered") if counts.get(k)]
    pie.data = [counts[k] for k in keys]
    pie.labels = None
    for i, k in enumerate(keys):
        pie.slices[i].fillColor = STATUS_COLOR[k]
        pie.slices[i].strokeColor = colors.white
    drawing.add(pie)
    y = 95
    for k in keys:
        drawing.add(String(135, y, f"{k.capitalize()}: {counts[k]}  ({round(100 * counts[k] / total)}%)",
                           fontSize=9, fillColor=INK))
        y -= 18
    return drawing


def _size_bars(file_rows):
    top = sorted(file_rows, key=lambda r: r["size"], reverse=True)[:6]
    drawing = Drawing(250, 130)
    if not top:
        drawing.add(String(20, 60, "No files yet", fontSize=10, fillColor=MUTED))
        return drawing
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 30, 28, 205, 85
    chart.data = [[r["size"] / 1024 for r in top]]
    chart.categoryAxis.categoryNames = [(r["name"][:7] + "…") if len(r["name"]) > 8 else r["name"] for r in top]
    chart.categoryAxis.labels.fontSize = 6.5
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.bars[0].fillColor = INDIGO
    chart.bars.strokeColor = None
    drawing.add(chart)
    drawing.add(String(30, 118, "Largest files (KB)", fontSize=8, fillColor=MUTED))
    return drawing


def build_pdf(user, file_rows, checks):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="File Integrity Report", author="File Integrity Checker")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], alignment=0, fontSize=21, leading=26, textColor=INK, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12.5, textColor=INK, spaceBefore=14, spaceAfter=6)
    small = ParagraphStyle("s", parent=styles["Normal"], fontSize=8.5, textColor=MUTED)
    cell = ParagraphStyle("c", parent=styles["Normal"], fontSize=8, leading=10)

    counts = {k: sum(1 for r in file_rows if r["status"] == k) for k in ("safe", "modified", "tampered")}
    total = len(file_rows)
    score = round(100 * counts["safe"] / total) if total else 100
    now = datetime.now().strftime("%d %b %Y, %H:%M")

    story = [
        Paragraph("File Integrity Report", h1),
        Paragraph(f"{user.get('name', '')} &nbsp;·&nbsp; {user.get('email', '')} &nbsp;·&nbsp; generated {now}", small),
        Spacer(1, 10),
        _kpi_table([("Files", total), ("Integrity score", f"{score}%"),
                    ("Modified / tampered", counts["modified"] + counts["tampered"]),
                    ("Verifications", len(checks))]),
        Paragraph("Overview", h2),
        Table([[_status_pie(counts), _size_bars(file_rows)]], colWidths=[85 * mm, 90 * mm]),
        Paragraph("Files", h2),
    ]

    header = ["ID", "File", "Size", "Algorithms", "Status", "Last checked"]
    body = [[str(r["id"]), Paragraph(r["name"].replace("&", "&amp;"), cell), _size(r["size"]),
             Paragraph(", ".join(r["algorithms"]) or "-", cell), r["status"].capitalize(),
             (r["last_checked"] or "-")[:16].replace("T", " ")] for r in file_rows]
    table = Table([header] + body if body else [header, ["", "No files yet", "", "", "", ""]],
                  colWidths=[10 * mm, 52 * mm, 20 * mm, 42 * mm, 20 * mm, 31 * mm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), INDIGO), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fd")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, r in enumerate(file_rows, start=1):
        style.append(("TEXTCOLOR", (4, i), (4, i), STATUS_COLOR.get(r["status"], INK)))
        style.append(("FONTNAME", (4, i), (4, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style))
    story.append(table)

    story.append(Paragraph("Verification history", h2))
    names = {r["id"]: r["name"] for r in file_rows}
    rows = [["When", "File", "Result", "% changed"]]
    for c in reversed(checks[-40:]):
        rows.append([(c["time"] or "-")[:16].replace("T", " "),
                     Paragraph(names.get(c["file_id"], c["file"]).replace("&", "&amp;"), cell),
                     c["status"].capitalize(), "-" if c["percent"] is None else f"{c['percent']}%"])
    if len(rows) == 1:
        rows.append(["", "No verifications yet", "", ""])
    hist = Table(rows, colWidths=[36 * mm, 80 * mm, 30 * mm, 30 * mm], repeatRows=1)
    hstyle = [
        ("BACKGROUND", (0, 0), (-1, 0), INDIGO), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fd")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, c in enumerate(reversed(checks[-40:]), start=1):
        hstyle.append(("TEXTCOLOR", (2, i), (2, i), STATUS_COLOR.get(c["status"], INK)))
    hist.setStyle(TableStyle(hstyle))
    story.append(hist)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(16 * mm, 9 * mm, "File Integrity Checker · confidential")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
