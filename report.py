"""Build the JSON scan file and the PDF report from a list of findings."""
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
COLOR = {"Critical": "#7f1d1d", "High": "#b91c1c", "Medium": "#c2410c", "Low": "#a16207", "Info": "#475569"}

CANNOT_SEE = ("This is an outside-in check of public information. It is not a full penetration test. "
              "It does not log in, test passwords, or look inside your systems. It can miss problems, "
              "and a clean report does not guarantee you are safe. Each finding lists its own limit.")


def sort_findings(findings):
    return sorted(findings, key=lambda f: ORDER[f.severity])


def save_json(domain, findings, path, by=""):
    data = {"domain": domain, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "checked_by": by, "findings": [f.to_dict() for f in findings]}
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return data


def _styles():
    base = ParagraphStyle("b", fontName="Helvetica", fontSize=9.5, leading=13, wordWrap="CJK")
    return {
        "b": base,
        "small": ParagraphStyle("s", parent=base, fontSize=8, leading=10.5, textColor=colors.HexColor("#334155")),
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=18, leading=22, spaceAfter=4),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12, leading=15, spaceBefore=10, spaceAfter=4),
    }


def _tag(sev):
    return f'<font color="{COLOR[sev]}"><b>{sev.upper()}</b></font>'


def build_pdf(domain, findings, path, by="", date=None):
    st = _styles()
    date = date or datetime.now(timezone.utc).strftime("%d %B %Y")
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=15*mm, bottomMargin=14*mm, title=f"Security Check Report: {domain}")
    fs = sort_findings(findings)
    issues = [f for f in fs if f.severity != "Info"]
    good = [f for f in fs if f.severity == "Info"]
    s = [Paragraph("Security Check Report", st["h1"]),
         Paragraph(f"<b>Domain:</b> {escape(domain)} &nbsp;&nbsp; <b>Date:</b> {date}"
                   + (f" &nbsp;&nbsp; <b>Checked by:</b> {escape(by)}" if by else ""), st["b"]), Spacer(1, 6)]

    counts = {k: sum(1 for f in issues if f.severity == k) for k in ("Critical", "High", "Medium", "Low")}
    t = Table([list(counts.keys()), [str(v) for v in counts.values()]], colWidths=[40*mm]*4 if False else None)
    t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 10),
                           ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9"))]))
    s += [Paragraph("Problems found", st["h2"]), t]

    s.append(Paragraph("Fix these first", st["h2"]))
    if not issues:
        s.append(Paragraph("No problems were found by these checks.", st["b"]))
    for i, f in enumerate(issues[:5], 1):
        s.append(Paragraph(f"{_tag(f.severity)} &nbsp; <b>{escape(f.title)}</b>", st["b"]))
        s.append(Paragraph(f"<b>Why it matters:</b> {escape(f.why_it_matters)}", st["b"]))
        s.append(Paragraph(f"<b>What to do:</b> {escape(f.fix)}", st["b"]))
        s.append(Spacer(1, 6))
    if len(issues) > 5:
        s.append(Paragraph(f"{len(issues) - 5} more {'problem is' if len(issues) - 5 == 1 else 'problems are'} listed in the technical details.", st["small"]))
    if good:
        s.append(Paragraph("Already good", st["h2"]))
        for f in good:
            s.append(Paragraph("&bull; " + escape(f.title), st["b"]))

    s += [PageBreak(), Paragraph("Technical details", st["h1"])]
    for f in issues:
        s.append(Paragraph(f"{_tag(f.severity)} &nbsp; <b>{escape(f.title)}</b> &nbsp; <font size=8>({escape(f.check)})</font>", st["b"]))
        s.append(Paragraph(escape(f.detail), st["b"]))
        s.append(Paragraph(f"<b>Evidence:</b> {escape(f.evidence[:300])} <i>[{escape(f.timestamp)}]</i>", st["small"]))
        if f.limit:
            s.append(Paragraph(f"<b>Limit:</b> {escape(f.limit)}", st["small"]))
        s.append(Spacer(1, 7))
    s += [Paragraph("What this check cannot see", st["h2"]), Paragraph(CANNOT_SEE, st["b"])]
    doc.build(s)
