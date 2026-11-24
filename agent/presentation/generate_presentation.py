"""
Generate the UBADS MCA Internship Phase-I PowerPoint presentation.

This script builds a NEW presentation (UBADS_Internship_Phase_I_Presentation.pptx)
that visually matches the style of the reference template
"Internship Review Phase - I.pptx" (RV College of Engineering academic format):

  - Slide size: 10in x 5.625in (16:9)
  - Font: Times New Roman throughout
  - Palette: navy (#002060), academic blue (#005893), black body text, white background
  - Footer tagline image ("Go, change the world (r)") reused from the reference template
  - No bullet glyphs, no accent stripes, no stock imagery - plain academic layout

The reference PPTX is never modified. Re-running this script regenerates the
output PPTX from scratch, so it is safe to re-run after editing content below.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
REFERENCE_PPTX = os.path.join(HERE, "Internship Review Phase - I.pptx")  # never modified
OUTPUT_PPTX = os.path.join(HERE, "UBADS_Internship_Phase_I_Presentation.pptx")
FOOTER_IMAGE = os.path.join(HERE, "assets", "tagline_footer.png")

# ---------------------------------------------------------------------------
# Style constants (extracted from the reference template)
# ---------------------------------------------------------------------------
FONT = "Times New Roman"
NAVY = RGBColor(0x00, 0x20, 0x60)     # 002060
BLUE = RGBColor(0x00, 0x58, 0x93)     # 005893
BLACK = RGBColor(0x00, 0x00, 0x00)
GRAY = RGBColor(0x59, 0x59, 0x59)     # muted label for (Planned)/status text

SLIDE_W = Inches(10)
SLIDE_H = Inches(5.625)

MARGIN_L = Inches(0.5)
CONTENT_W = SLIDE_W - Inches(1.0)

TITLE_TOP = Inches(0.35)
TITLE_H = Inches(0.55)
BODY_TOP = Inches(1.0)
BODY_H = Inches(3.95)

# Placeholders to fill in later
USN_PLACEHOLDER = "[USN]"
GUIDE_PLACEHOLDER = "[Guide Name]"
DESIGNATION_PLACEHOLDER = "[Designation]"


def new_presentation():
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H
    return prs


def blank_slide(prs):
    layout = prs.slide_layouts[6]  # blank
    return prs.slides.add_slide(layout)


def add_footer(slide, page_num=None):
    """Reuse the reference template's tagline image + a small page number, bottom of slide."""
    if os.path.exists(FOOTER_IMAGE):
        pic_w = Inches(2.35)
        pic_h = Inches(0.34)
        left = (SLIDE_W - pic_w) / 2
        top = SLIDE_H - Inches(0.42)
        slide.shapes.add_picture(FOOTER_IMAGE, left, top, width=pic_w, height=pic_h)
    if page_num is not None:
        box = slide.shapes.add_textbox(SLIDE_W - Inches(0.7), SLIDE_H - Inches(0.42), Inches(0.55), Inches(0.32))
        tf = box.text_frame
        tf.margin_left = 0
        tf.margin_right = 0
        tf.margin_top = 0
        tf.margin_bottom = 0
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.RIGHT
        run = p.add_run()
        run.text = str(page_num)
        run.font.size = Pt(11)
        run.font.name = FONT
        run.font.color.rgb = NAVY


def add_textbox(slide, left, top, width, height, anchor=None):
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = 0
    tf.margin_right = 0
    tf.margin_top = 0
    tf.margin_bottom = 0
    if anchor:
        tf.vertical_anchor = anchor
    return box, tf


def set_para(p, text, size, color=BLACK, bold=False, italic=False, align=PP_ALIGN.LEFT,
             font=FONT, space_after=6):
    p.alignment = align
    p.space_after = Pt(space_after)
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.name = font
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    return run


def add_title(slide, text, size=28):
    box, tf = add_textbox(slide, MARGIN_L, TITLE_TOP, CONTENT_W, TITLE_H)
    p = tf.paragraphs[0]
    set_para(p, text, size, color=BLUE, bold=True, align=PP_ALIGN.LEFT)
    return box


def add_bullets(slide, items, left=MARGIN_L, top=BODY_TOP, width=CONTENT_W, height=BODY_H,
                 size=16, color=BLACK, space_after=8):
    """
    items: list of (level, text) or (level, text, style_dict)
    level 0 = main point, level 1 = sub-point (indented, smaller)
    """
    box, tf = add_textbox(slide, left, top, width, height)
    first = True
    for item in items:
        level = item[0]
        text = item[1]
        opts = item[2] if len(item) > 2 else {}
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        indent = Inches(0.3) * level
        p.level = 0
        this_size = opts.get("size", size - (2 if level else 0))
        this_bold = opts.get("bold", False)
        this_color = opts.get("color", color)
        this_italic = opts.get("italic", False)
        p.alignment = PP_ALIGN.LEFT
        p.space_after = Pt(space_after if level == 0 else 4)
        # simulate indentation with leading run since no bullet glyphs are used
        prefix = ("–  " if level else "")  # en dash for sub-points, matches plain academic look
        run = p.add_run()
        run.text = ("     " if level else "") + prefix + text
        run.font.size = Pt(this_size)
        run.font.name = FONT
        run.font.bold = this_bold
        run.font.italic = this_italic
        run.font.color.rgb = this_color
    return box


def add_flow(slide, steps, left=None, width=None, top=Inches(1.05), height=Inches(4.0),
             size=15, note=None):
    """Vertical process-flow rendered as centered text lines separated by down-arrows."""
    if left is None:
        left = MARGIN_L
    if width is None:
        width = CONTENT_W
    box, tf = add_textbox(slide, left, top, width, height, anchor=MSO_ANCHOR.TOP)
    first = True
    for i, step in enumerate(steps):
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        set_para(p, step, size, color=NAVY if i % 2 == 0 else BLUE, bold=True,
                 align=PP_ALIGN.CENTER, space_after=0)
        if i != len(steps) - 1:
            p2 = tf.add_paragraph()
            set_para(p2, "↓", max(10, size - 2), color=GRAY, align=PP_ALIGN.CENTER, space_after=0)
    if note:
        p3 = tf.add_paragraph()
        set_para(p3, note, 12, color=GRAY, italic=True, align=PP_ALIGN.CENTER, space_after=0)
    return box


def add_two_column(slide, left_title, left_items, right_title, right_items,
                    top=BODY_TOP, height=BODY_H, size=14):
    col_w = (CONTENT_W - Inches(0.4)) / 2
    left_box, ltf = add_textbox(slide, MARGIN_L, top, col_w, height)
    p = ltf.paragraphs[0]
    set_para(p, left_title, 18, color=NAVY, bold=True, align=PP_ALIGN.LEFT, space_after=8)
    for text in left_items:
        p = ltf.add_paragraph()
        set_para(p, "✓  " + text, size, color=BLACK, align=PP_ALIGN.LEFT, space_after=6)

    right_left = MARGIN_L + col_w + Inches(0.4)
    right_box, rtf = add_textbox(slide, right_left, top, col_w, height)
    p = rtf.paragraphs[0]
    set_para(p, right_title, 18, color=BLUE, bold=True, align=PP_ALIGN.LEFT, space_after=8)
    for text in right_items:
        p = rtf.add_paragraph()
        set_para(p, "→  " + text, size, color=GRAY, italic=True, align=PP_ALIGN.LEFT, space_after=6)

    return left_box, right_box


def add_status_columns(slide, left, top, width, height,
                        implemented_title, implemented_items,
                        planned_title, planned_items, size=12):
    """Compact IMPLEMENTED (checkmark) / PLANNED (arrow) stacked list in one column."""
    box, tf = add_textbox(slide, left, top, width, height)
    p = tf.paragraphs[0]
    set_para(p, implemented_title, size + 2, color=NAVY, bold=True, align=PP_ALIGN.LEFT,
             space_after=4)
    for text in implemented_items:
        p = tf.add_paragraph()
        set_para(p, "✓  " + text, size, color=BLACK, align=PP_ALIGN.LEFT, space_after=3)
    p = tf.add_paragraph()
    set_para(p, planned_title, size + 2, color=BLUE, bold=True, align=PP_ALIGN.LEFT,
             space_after=4)
    for text in planned_items:
        p = tf.add_paragraph()
        set_para(p, "→  " + text, size, color=GRAY, italic=True, align=PP_ALIGN.LEFT,
                 space_after=3)
    return box


# ---------------------------------------------------------------------------
# Build presentation
# ---------------------------------------------------------------------------

def build():
    prs = new_presentation()

    # ---------------- Slide 1: Title ----------------
    s = blank_slide(prs)
    box, tf = add_textbox(s, Inches(0.7), Inches(0.5), Inches(8.6), Inches(0.5))
    p = tf.paragraphs[0]
    set_para(p, "Department of Master of Computer Applications", 20, color=NAVY, bold=True,
             align=PP_ALIGN.RIGHT)

    box, tf = add_textbox(s, Inches(1.0), Inches(1.05), Inches(8.0), Inches(0.4))
    p = tf.paragraphs[0]
    set_para(p, "MCA Internship – Phase I", 18, color=BLUE, align=PP_ALIGN.CENTER)

    box, tf = add_textbox(s, Inches(0.7), Inches(1.55), Inches(8.6), Inches(0.5))
    p = tf.paragraphs[0]
    set_para(p, "User Behavior Anomaly Detection System", 24, color=BLUE, bold=True,
             align=PP_ALIGN.CENTER)

    box, tf = add_textbox(s, Inches(0.7), Inches(2.08), Inches(8.6), Inches(0.55))
    p = tf.paragraphs[0]
    set_para(p, "User-Specific Behavioral Anomaly Detection for Windows Endpoints "
                 "Using Machine Learning", 14, color=BLACK, italic=True, align=PP_ALIGN.CENTER)

    box, tf = add_textbox(s, Inches(0.7), Inches(2.72), Inches(8.6), Inches(0.4))
    p = tf.paragraphs[0]
    set_para(p, f"Pradeep M  ({USN_PLACEHOLDER})", 16, color=BLACK, align=PP_ALIGN.CENTER)

    box, tf = add_textbox(s, Inches(1.0), Inches(3.35), Inches(8.0), Inches(1.85))
    lines = ["Under the Guidance of", GUIDE_PLACEHOLDER, DESIGNATION_PLACEHOLDER,
             "RV College of Engineering, Bengaluru"]
    first = True
    for line in lines:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        set_para(p, line, 14, color=BLACK, align=PP_ALIGN.CENTER, space_after=3)
    add_footer(s)

    # ---------------- Slide 2: Agenda ----------------
    s = blank_slide(prs)
    add_title(s, "Agenda")
    agenda_items = [
        "1. Internship Carried Out",
        "2. Domain",
        "3. Engineering Knowledge / Operational Procedures",
        "4. Design & Development of Solutions / Product / Service Knowledge / "
        "Process Structure in the Organization",
        "5. Modern Tools / Methods Explored / Research and Technology Use",
        "6. Implementation Results / Conclusion",
        "7. Societal and Environmental Concern",
        "8. Application of Project Management Principles",
        "9. Summarization",
    ]
    add_bullets(s, [(0, t) for t in agenda_items], size=16, space_after=10)
    add_footer(s, 2)

    # ---------------- Slide 3: Internship Carried Out ----------------
    s = blank_slide(prs)
    add_title(s, "Internship Carried Out")
    items = [
        (0, "Women in Cloud Internship – a research and development oriented internship program"),
        (0, "Focus area: Cybersecurity – User Behavior Analytics"),
        (0, "Project undertaken: UBADS (User Behavior Anomaly Detection System)"),
        (0, "Centered on collecting real, authorized Windows endpoint telemetry"),
        (0, "Objective: build user-specific behavioral profiles and identify unusual "
             "user behavior on Windows endpoints"),
        (0, "Emphasis on privacy-aware, authorized data collection throughout"),
    ]
    add_bullets(s, items, size=16, space_after=14)
    add_footer(s, 3)

    # ---------------- Slide 4: Domain ----------------
    s = blank_slide(prs)
    add_title(s, "Domain")
    add_flow(s, [
        "Cybersecurity",
        "User Behavior Analytics",
        "Windows Endpoint Security",
        "Behavioral Profiling",
        "Machine Learning",
        "Anomaly Detection",
    ], top=Inches(0.98), height=Inches(3.5), size=15)
    box, tf = add_textbox(s, MARGIN_L, Inches(4.55), CONTENT_W, Inches(0.55))
    p = tf.paragraphs[0]
    set_para(p, "UBADS combines cybersecurity, user behavior analytics, Windows endpoint "
                 "monitoring, and behavioral profiling, with machine-learning-based anomaly "
                 "detection as the planned research direction.",
             12, color=GRAY, italic=True, align=PP_ALIGN.CENTER)
    add_footer(s, 4)

    # ---------------- Slide 5: Engineering Knowledge / Operational Procedures ----------------
    s = blank_slide(prs)
    add_title(s, "Engineering Knowledge / Operational Procedures")
    items = [
        (0, "Windows Event Log collection (authentication, file, process, device/USB)"),
        (0, "Authentication activity monitoring"),
        (0, "File and process activity monitoring"),
        (0, "Device / USB activity monitoring"),
        (0, "Event normalization and validation"),
        (0, "Event deduplication"),
        (0, "SQLite-based local storage"),
        (0, "REST APIs for ingestion and endpoint management"),
        (0, "Per-agent endpoint authentication"),
        (0, "Privacy and authorization controls at every collection stage"),
    ]
    add_bullets(s, items, size=14, space_after=6)
    add_footer(s, 5)

    # ---------------- Slide 6: Design & Development ----------------
    s = blank_slide(prs)
    add_title(s, "Design & Development – UBADS Architecture", size=24)
    flow_col_w = (CONTENT_W - Inches(0.4)) / 2
    add_flow(s, [
        "Authorized Windows Endpoint",
        "Windows Endpoint Agent",
        "Event Collection & Normalization",
        "Backend / SQLite Storage",
        "Behavioral Feature Engineering",
        "User-Specific Baseline",
        "Anomaly Detection",
        "Risk Scoring",
        "Dashboard",
    ], left=MARGIN_L, width=flow_col_w, top=Inches(0.95), height=Inches(3.95), size=11)
    status_left = MARGIN_L + flow_col_w + Inches(0.4)
    add_status_columns(
        s, status_left, Inches(0.95), flow_col_w, Inches(3.95),
        "IMPLEMENTED",
        ["Collection", "Normalization", "Validation", "Storage",
         "Feature Engineering", "Endpoint Authentication", "Dashboard Foundation"],
        "PLANNED",
        ["ML-based Anomaly Detection", "Risk Scoring Evaluation",
         "Explainable Alert Evaluation", "Final Research Evaluation", "Azure Deployment"],
        size=11,
    )
    add_footer(s, 6)

    # ---------------- Slide 7: Modern Tools / Research & Technology ----------------
    s = blank_slide(prs)
    add_title(s, "Modern Tools / Methods / Research & Technology", size=24)
    implemented_tech = [
        "Python", "FastAPI", "React", "Vite", "SQLite",
        "Windows Event Logs", "pywin32", "PowerShell", "REST APIs",
        "PyInstaller", "Inno Setup", "Git / GitHub",
    ]
    research_tech = [
        "Isolation Forest – planned initial anomaly detection method",
        "LOF / statistical methods – possible comparison methods",
        "Azure – planned future cloud deployment",
    ]
    add_two_column(s, "Implemented Technologies", implemented_tech,
                    "Research / Future Technologies", research_tech, size=13)
    add_footer(s, 7)

    # ---------------- Slide 8: Research Methodology ----------------
    s = blank_slide(prs)
    add_title(s, "Research Methodology")
    add_flow(s, [
        "Real Authorized Windows Activity",
        "Data Collection",
        "Normalization",
        "Feature Engineering",
        "User-Specific Baseline",
        "Anomaly Detection  [TO BE EVALUATED]",
        "Risk Scoring  [PLANNED]",
        "Explainable Alert  [PLANNED]",
        "Evaluation  [FUTURE WORK]",
    ], top=Inches(0.85), height=Inches(3.9), size=12)
    box, tf = add_textbox(s, MARGIN_L, Inches(4.85), CONTENT_W, Inches(0.3))
    p = tf.paragraphs[0]
    set_para(p, "Data and feature-engineering foundation is established; ML experiments are "
                 "the next research stage.", 11, color=GRAY, italic=True, align=PP_ALIGN.CENTER)
    add_footer(s, 8)

    # ---------------- Slide 9: Implementation Results / Conclusion ----------------
    s = blank_slide(prs)
    add_title(s, "Implementation Results / Conclusion")
    left_items = [
        "Real Windows event collection",
        "Authentication activity collection",
        "File activity collection",
        "Process activity collection",
        "Endpoint identity & secure enrollment",
        "Per-agent authentication",
        "Backend ingestion",
        "Behavioral feature engineering",
        "React dashboard foundation",
        "Windows endpoint installer",
    ]
    right_items = [
        "ML experimental evaluation – To Be Completed",
        "Isolation Forest / comparison methods – Planned",
        "Precision / Recall / F1 / ROC-AUC – To Be Evaluated",
        "Explainable anomaly detection – Planned",
        "Azure deployment – Planned",
        "Production hardening – Future Work",
    ]
    add_two_column(s, "Implemented & Verified", left_items, "Planned / Future Work", right_items,
                    size=13)
    add_footer(s, 9)

    # ---------------- Slide 10: Societal & Environmental Concerns ----------------
    s = blank_slide(prs)
    add_title(s, "Societal and Environmental Concern")
    items = [
        (0, "Collection restricted to authorized users and endpoints"),
        (0, "Privacy-aware monitoring – no passwords, keystrokes, messages, "
             "browser data, screenshots, or document contents are collected"),
        (0, "Data minimization – only security/activity metadata is captured"),
        (0, "Secure telemetry transport and per-agent authentication"),
        (0, "Supports responsible monitoring rather than covert surveillance"),
        (0, "Can help detect compromised accounts and insider misuse"),
        (0, "Event-based collection is designed to avoid unnecessary continuous "
             "monitoring overhead"),
    ]
    add_bullets(s, items, size=15, space_after=10)
    add_footer(s, 10)

    # ---------------- Slide 11: Project Management Principles ----------------
    s = blank_slide(prs)
    add_title(s, "Application of Project Management Principles")
    add_flow(s, [
        "Requirement Analysis",
        "Architecture Design",
        "Incremental Development",
        "Testing",
        "Security / Privacy Review",
        "Documentation",
        "Validation",
        "Next Phase",
    ], top=Inches(0.9), height=Inches(3.15), size=12)
    box, tf = add_textbox(s, MARGIN_L, Inches(4.15), CONTENT_W, Inches(0.9))
    p = tf.paragraphs[0]
    set_para(p, "Agile / iterative development · Modular implementation · "
                 "Phase-wise delivery · Version control · Testing after each phase · "
                 "Documentation · Risk management · Security review",
             11, color=GRAY, italic=True, align=PP_ALIGN.CENTER)
    add_footer(s, 11)

    # ---------------- Slide 12: Summarization ----------------
    s = blank_slide(prs)
    add_title(s, "Summarization")
    box, tf = add_textbox(s, MARGIN_L, BODY_TOP, CONTENT_W, BODY_H)
    entries = [
        ("Problem: ", "Difficulty identifying unusual user behavior from large volumes "
                        "of activity logs."),
        ("Solution: ", "UBADS collects authorized Windows telemetry and establishes a "
                        "foundation for user-specific behavioral anomaly detection."),
        ("Current Status: ", "Real endpoint collection, backend, feature engineering, "
                               "dashboard, endpoint enrollment, authentication, and "
                               "installer implemented."),
        ("Research Direction: ", "Machine-learning-based anomaly detection and evaluation."),
    ]
    first = True
    for label, text in entries:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.alignment = PP_ALIGN.LEFT
        p.space_after = Pt(8)
        r1 = p.add_run()
        r1.text = label
        r1.font.size = Pt(15)
        r1.font.name = FONT
        r1.font.bold = True
        r1.font.color.rgb = NAVY
        r2 = p.add_run()
        r2.text = text
        r2.font.size = Pt(15)
        r2.font.name = FONT
        r2.font.color.rgb = BLACK

    p = tf.add_paragraph()
    set_para(p, "Future Work:", 15, color=BLUE, bold=True, space_after=4)
    future = [
        "Multi-day real dataset", "Isolation Forest experiments", "Model comparison",
        "Quantitative evaluation", "Explainability", "Azure deployment",
        "Production hardening", "Code signing",
    ]
    p = tf.add_paragraph()
    set_para(p, "  •  ".join(future), 13, color=BLACK, space_after=0)
    add_footer(s, 12)

    # ---------------- Slide 13: Thank You ----------------
    s = blank_slide(prs)
    box, tf = add_textbox(s, Inches(0.5), Inches(2.0), Inches(9.0), Inches(0.9),
                           anchor=MSO_ANCHOR.MIDDLE)
    p = tf.paragraphs[0]
    set_para(p, "THANK YOU", 36, color=BLUE, bold=True, align=PP_ALIGN.CENTER)
    box, tf = add_textbox(s, Inches(0.5), Inches(2.9), Inches(9.0), Inches(0.5))
    p = tf.paragraphs[0]
    set_para(p, "Questions?", 20, color=NAVY, align=PP_ALIGN.CENTER)
    add_footer(s)

    prs.save(OUTPUT_PPTX)
    print(f"Saved: {OUTPUT_PPTX}")
    print(f"Slides: {len(prs.slides.__iter__.__self__._sldIdLst) if False else len(prs.slides._sldIdLst)}")


if __name__ == "__main__":
    build()
