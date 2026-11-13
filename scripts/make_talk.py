#!/usr/bin/env python3
"""Build the 4-minute Pebble talk.

Speaker notes on each slide are the words to say. The slide itself is the
diagram and a few labels, so the room is looking at the picture while you talk.
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

W = Inches(13.333)
H = Inches(7.5)

INK = RGBColor(0x1B, 0x24, 0x30)
MUTED = RGBColor(0x5C, 0x65, 0x70)
TEAL = RGBColor(0x1E, 0x4D, 0x5C)
TEAL_DEEP = RGBColor(0x14, 0x36, 0x42)
PAPER = RGBColor(0xF6, 0xF3, 0xEC)
CARD = RGBColor(0xFF, 0xFC, 0xF7)
LINE = RGBColor(0xD9, 0xD2, 0xC5)
GOLD = RGBColor(0x8A, 0x5A, 0x12)
GOLD_BG = RGBColor(0xF8, 0xEE, 0xD6)
RED = RGBColor(0x8E, 0x3B, 0x32)
RED_BG = RGBColor(0xF8, 0xE8, 0xE4)
GREEN = RGBColor(0x1F, 0x6B, 0x45)
GREEN_BG = RGBColor(0xE5, 0xF2, 0xEA)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)


def _set_run(run, text, size, color, bold=False, italic=False, font="Calibri"):
    run.text = text
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.bold = bold
    run.font.italic = italic
    run.font.name = font


def add_text(slide, text, x, y, w, h, size=18, color=INK, bold=False, italic=False, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.word_wrap = True
    frame.auto_size = None
    frame.margin_left = Emu(0)
    frame.margin_right = Emu(0)
    frame.margin_top = Emu(0)
    frame.margin_bottom = Emu(0)
    try:
        frame._txBody.bodyPr.set("anchor", {MSO_ANCHOR.TOP: "t", MSO_ANCHOR.MIDDLE: "ctr", MSO_ANCHOR.BOTTOM: "b"}[anchor])
    except Exception:
        pass
    p = frame.paragraphs[0]
    p.alignment = align
    p.space_before = Pt(0)
    p.space_after = Pt(0)
    _set_run(p.add_run(), text, size, color, bold, italic)
    return box


def add_lines(slide, lines, x, y, w, h, size=16, color=INK, bold=False, align=PP_ALIGN.LEFT, spacing=6):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.word_wrap = True
    frame.margin_left = Emu(0)
    frame.margin_right = Emu(0)
    frame.margin_top = Emu(0)
    frame.margin_bottom = Emu(0)
    for index, line in enumerate(lines):
        p = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        p.alignment = align
        p.space_before = Pt(0)
        p.space_after = Pt(spacing)
        text, line_bold, line_color, line_size = line if isinstance(line, tuple) else (line, bold, color, size)
        _set_run(p.add_run(), text, line_size, line_color, line_bold)
    return box


def rect(slide, x, y, w, h, fill, line=None, radius=True):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
        Inches(x), Inches(y), Inches(w), Inches(h),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    if line is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line
        shape.line.width = Pt(1.25)
    if radius:
        # Less pill-shaped than the default.
        shape.adjustments[0] = 0.08
    return shape


def label(shape, text, size, color, bold=False, align=PP_ALIGN.CENTER):
    frame = shape.text_frame
    frame.word_wrap = True
    frame.auto_size = None
    shape.text_frame.paragraphs[0].alignment = align
    try:
        frame._txBody.bodyPr.set("anchor", "ctr")
    except Exception:
        pass
    p = frame.paragraphs[0]
    p.clear()
    _set_run(p.add_run(), text, size, color, bold, align=align if False else False)
    p.alignment = align
    return shape


def box_text(slide, x, y, w, h, fill, lines, line=None):
    shape = rect(slide, x, y, w, h, fill, line)
    frame = shape.text_frame
    frame.word_wrap = True
    frame.margin_left = Inches(0.14)
    frame.margin_right = Inches(0.14)
    frame.margin_top = Inches(0.08)
    frame.margin_bottom = Inches(0.08)
    try:
        frame._txBody.bodyPr.set("anchor", "ctr")
    except Exception:
        pass
    for index, item in enumerate(lines):
        text, size, color, bold = item
        p = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        p.alignment = PP_ALIGN.CENTER
        p.space_before = Pt(0)
        p.space_after = Pt(2)
        _set_run(p.add_run(), text, size, color, bold)
    return shape


def background(slide):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = PAPER
    rect(slide, 0, 0, 13.333, 0.08, TEAL, radius=False)


def footer(slide, number, total, cue):
    add_text(slide, "Pebble  ·  LLS10 VaultFS", 0.5, 7.12, 6, 0.28, 11, MUTED)
    add_text(slide, cue, 7.2, 7.12, 4.2, 0.28, 11, MUTED, align=PP_ALIGN.RIGHT)
    add_text(slide, f"{number}  /  {total}", 11.5, 7.12, 1.3, 0.28, 11, MUTED, align=PP_ALIGN.RIGHT)


def notes(slide, speech):
    frame = slide.notes_slide.notes_text_frame
    frame.text = speech


def new(prs):
    return prs.slides.add_slide(prs.slide_layouts[6])


def build(path: Path) -> None:
    prs = Presentation()
    prs.slide_width = W
    prs.slide_height = H
    prs.core_properties.title = "Pebble — a four-minute map, then the terminal"
    prs.core_properties.subject = "LLS10 VaultFS, Low-Level Security, Synergy '26"
    total = 8

    # ----- 1 -----
    s = new(prs)
    background(s)
    add_text(s, "LOW-LEVEL SECURITY  ·  SYNERGY '26", 0.7, 1.55, 10, 0.35, 14, TEAL, bold=True)
    add_text(s, "Pebble", 0.65, 2.0, 12, 1.2, 66, INK, bold=True)
    add_text(
        s,
        "An encrypted folder that notices when the cloud\nputs an old copy back.",
        0.7, 3.35, 11, 1.2, 28, INK,
    )
    add_text(
        s,
        "Four minutes on the idea. Then the same idea, in the terminal.",
        0.7, 5.15, 10, 0.4, 18, MUTED,
    )
    add_text(s, "LLS10  ·  VaultFS", 0.7, 6.45, 6, 0.3, 14, TEAL, bold=True)
    notes(
        s,
        "SAY, about 25 seconds.\n\n"
        "We built Pebble, an encrypted folder for Linux. You unlock it with a password, "
        "and then ordinary programs use it as a normal folder. The copy that gets synced "
        "can live with a storage provider you do not trust. This talk is the map of that "
        "system. After these slides, I will show the same map happening in the terminal.",
    )

    # ----- 2 -----
    s = new(prs)
    background(s)
    add_text(s, "Who the attacker is", 0.5, 0.28, 10, 0.5, 32, INK, bold=True)
    add_text(
        s,
        "The problem gives them the stored copy. It does not give them the running laptop.",
        0.5, 0.9, 12, 0.4, 16, MUTED,
    )
    box_text(
        s, 0.5, 1.6, 5.9, 5.05, CARD,
        [
            ("The laptop", 22, TEAL, True),
            ("", 8, INK, False),
            ("The password", 18, INK, True),
            ("Which saves this computer has accepted", 16, INK, False),
            ("A notebook of saves it has seen", 16, INK, False),
            ("", 10, INK, False),
            ("The attacker does not have these.", 16, GREEN, True),
        ],
        LINE,
    )
    box_text(
        s, 6.9, 1.6, 5.9, 5.05, RGBColor(0x2A, 0x1C, 0x1A),
        [
            ("The synced folder", 22, RGBColor(0xF6, 0xD7, 0xC8), True),
            ("", 8, WHITE, False),
            ("Every stored byte", 18, WHITE, True),
            ("They can read, edit, delete, and copy it", 16, WHITE, False),
            ("They can keep old snapshots", 16, WHITE, False),
            ("They can put yesterday’s folder back", 16, WHITE, False),
            ("", 10, WHITE, False),
            ("This is the attacker.", 16, RGBColor(0xF0, 0xB4, 0xA2), True),
        ],
    )
    footer(s, 2, total, "about 40 seconds")
    notes(
        s,
        "SAY, about 40 seconds.\n\n"
        "The attacker in this problem is the storage provider, or anyone who breaks into "
        "that provider. They can read every stored byte, edit it, delete it, and keep old "
        "copies. They can put yesterday’s whole folder back. They do not have the password, "
        "and they are not logged into the laptop. So the question is not a second user on "
        "the same machine. The question is what the laptop can still notice, when the only "
        "thing the attacker owns is the folder in the cloud.",
    )

    # ----- 3 -----
    s = new(prs)
    background(s)
    add_text(s, "Encryption stops reading. It does not stop rewind.", 0.5, 0.26, 12, 0.5, 30, INK, bold=True)
    add_text(s, "Tuesday’s ciphertext was also encrypted correctly.", 0.5, 0.88, 12, 0.35, 16, MUTED)
    # timeline
    rect(s, 1.3, 2.55, 10.6, 0.045, TEAL, radius=False)
    for i, (name, sub) in enumerate((("Monday", "first save"), ("Tuesday", "still valid"), ("Wednesday", "latest save"))):
        x = 1.55 + i * 3.7
        circ = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(2.35), Inches(0.42), Inches(0.42))
        circ.fill.solid()
        circ.fill.fore_color.rgb = TEAL if i < 2 else GREEN
        circ.line.fill.background()
        add_text(s, name, x - 0.5, 2.9, 1.5, 0.35, 16, INK, bold=True, align=PP_ALIGN.CENTER)
        add_text(s, sub, x - 0.7, 3.25, 1.9, 0.3, 13, MUTED, align=PP_ALIGN.CENTER)
    # restore arrow
    arrow = s.shapes.add_shape(MSO_SHAPE.LEFT_ARROW, Inches(6.15), Inches(1.55), Inches(2.3), Inches(0.38))
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = RED
    arrow.line.fill.background()
    add_text(s, "cloud puts Tuesday back", 5.7, 1.15, 3.3, 0.35, 14, RED, bold=True, align=PP_ALIGN.CENTER)

    box_text(
        s, 0.5, 4.15, 6.0, 2.55, RED_BG,
        [
            ("If the laptop trusts the cloud", 18, RED, True),
            ("Tuesday opens. The tag checks.", 16, INK, False),
            ("The files are real files, from yesterday.", 16, INK, False),
            ("Nothing looks broken.", 16, INK, True),
        ],
        RGBColor(0xE4, 0xC8, 0xC2),
    )
    box_text(
        s, 6.8, 4.15, 6.0, 2.55, GREEN_BG,
        [
            ("Fork consistency", 18, GREEN, True),
            ("The store may hide an update.", 16, INK, False),
            ("The two histories then split.", 16, INK, False),
            ("That split can be shown.", 16, INK, True),
        ],
        RGBColor(0xC5, 0xDE, 0xCE),
    )
    footer(s, 3, total, "about 40 seconds")
    notes(
        s,
        "SAY, about 40 seconds.\n\n"
        "Scrambling the files stops them from reading. It does not stop them from rolling "
        "the folder backwards, because Tuesday’s ciphertext was also encrypted correctly. "
        "Mazières and Shasha named this fork consistency. An untrusted store can hide an "
        "update, but then the two histories split, and that split can be shown. SUNDR built "
        "that idea for a server. Pebble does it for an ordinary synced folder, with no "
        "special server protocol.",
    )

    # ----- 4 -----
    s = new(prs)
    background(s)
    add_text(s, "Four places. Only one is in the cloud.", 0.5, 0.26, 12, 0.5, 30, INK, bold=True)
    cols = [
        (0.45, TEAL_DEEP, WHITE, "Mount", "What you see", ["Ordinary files", "ls, vim, cp", "Gone on unmount"]),
        (3.7, RGBColor(0x3A, 0x24, 0x22), WHITE, "Cipher directory", "The attacker’s pile", ["Scrambled file pieces", "Scrambled listings", "Signed saves and HEAD", "Password keybag"]),
        (6.95, TEAL, WHITE, "state", "On the laptop", ["Save ids this computer", "has already accepted", "A fork receipt,", "if the histories split"]),
        (10.15, GOLD, WHITE, "witness", "On the laptop", ["A notebook that", "only grows", "“I have seen", "this save.”"]),
    ]
    for x, fill, fg, title, sub, lines in cols:
        shape = rect(s, x, 1.15, 2.95, 4.55, fill)
        frame = shape.text_frame
        frame.word_wrap = True
        frame.margin_left = Inches(0.16)
        frame.margin_right = Inches(0.16)
        frame.margin_top = Inches(0.2)
        items = [(title, 20, fg, True), (sub, 13, fg, False), ("", 10, fg, False)]
        items += [(line, 15, fg, False) for line in lines]
        for index, (text, size, color, bold) in enumerate(items):
            p = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
            p.alignment = PP_ALIGN.LEFT
            p.space_after = Pt(3)
            _set_run(p.add_run(), text, size, color, bold)
    add_text(
        s,
        "Copying the cipher directory does not copy state or witness. That is why a restored snapshot can be caught.",
        0.5, 5.9, 12.3, 0.7, 16, INK,
    )
    footer(s, 4, total, "about 35 seconds")
    notes(
        s,
        "SAY, about 35 seconds.\n\n"
        "Only one of these places is in the cloud. The mount is a view, and it disappears "
        "when you unmount. The cipher directory is the synced pile: scrambled file pieces, "
        "scrambled folder listings, and a chain of signed saves. Beside it, on the laptop, "
        "state is the list of saves this computer has accepted. Witness is a notebook that "
        "only grows, one signed line for each save we have seen. Copying the cloud folder "
        "does not copy that notebook.",
    )

    # ----- 5 -----
    s = new(prs)
    background(s)
    add_text(s, "On open, where does the cloud’s save sit?", 0.5, 0.24, 12, 0.48, 30, INK, bold=True)
    add_text(s, "Each save points at the one before it, and the record is signed.", 0.5, 0.78, 12, 0.32, 16, MUTED)

    box_text(s, 0.4, 1.3, 3.55, 1.2, CARD, [("1", 14, TEAL, True), ("Password opens the keybag?", 16, INK, True)], LINE)
    arrow = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(4.05), Inches(1.72), Inches(0.42), Inches(0.32))
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = TEAL
    arrow.line.fill.background()
    box_text(s, 4.55, 1.3, 3.7, 1.2, CARD, [("2", 14, TEAL, True), ("Keybag matches this laptop’s note?", 15, INK, True)], LINE)
    arrow = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(8.35), Inches(1.72), Inches(0.42), Inches(0.32))
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = TEAL
    arrow.line.fill.background()
    box_text(s, 8.85, 1.3, 4.0, 1.2, CARD, [("3", 14, TEAL, True), ("Walk the parent links.", 16, INK, True)], LINE)
    add_text(s, "then exactly one of these", 4.6, 2.52, 4, 0.28, 13, MUTED, align=PP_ALIGN.CENTER)

    outcomes = [
        (0.45, GREEN_BG, GREEN, "Update", "A later save.", "Take it. Remember it. Show it."),
        (4.7, RED_BG, RED, "Rewind", "An earlier save.", "Refuse. Name the newer one the notebook still has."),
        (8.95, GOLD_BG, GOLD, "Split", "Neither comes after the other.", "Stay on the last trusted save. Write a receipt."),
    ]
    for x, fill, accent, title, a, b in outcomes:
        box_text(
            s, x, 2.85, 3.9, 2.55, fill,
            [(title, 22, accent, True), (a, 16, INK, True), (b, 15, INK, False)],
            LINE,
        )
    add_text(
        s,
        "The receipt checks with no password. It shows that the histories diverged. It does not decide who was dishonest.",
        0.5, 5.6, 12.3, 0.85, 16, INK,
    )
    footer(s, 5, total, "about 50 seconds")
    notes(
        s,
        "SAY, about 50 seconds.\n\n"
        "A save points at the previous save, and it is signed, so a changed byte is not "
        "history. When we open, we compare the cloud’s current save with what this laptop "
        "has accepted. A later save is an update, and we take it. An earlier save is a "
        "rewind. We refuse to open, and we name the newer save, because the notebook still "
        "remembers it even if the cloud deleted the files. If neither save comes after the "
        "other, we do not pick a winner. We stay on the last save we trust, and we write a "
        "receipt. Anyone can check that receipt without the password. It shows the split. "
        "It does not say who was dishonest, because two honest offline edits look the same.",
    )

    # ----- 6 -----
    s = new(prs)
    background(s)
    add_text(s, "Share one folder. Take it back without rewriting the files.", 0.45, 0.24, 12.4, 0.5, 28, INK, bold=True)
    add_text(s, "Lazy revocation, from Plutus. The old bytes stay. The new listing key does not.", 0.5, 0.82, 12, 0.35, 16, MUTED)

    box_text(
        s, 0.45, 1.4, 4.0, 4.35, CARD,
        [
            ("Given", 14, TEAL, True),
            ("Their own password", 18, INK, True),
            ("home/their-name", 16, INK, False),
            ("and any folder you share", 16, INK, False),
            ("", 8, INK, False),
            ("A neighbor folder was never", 15, MUTED, False),
            ("sealed to them, so the stored", 15, MUTED, False),
            ("bytes do not let them in.", 15, MUTED, False),
        ],
        LINE,
    )
    box_text(
        s, 4.7, 1.4, 4.0, 4.35, GOLD_BG,
        [
            ("Removed", 14, GOLD, True),
            ("New key for that listing", 18, INK, True),
            ("Old files still open", 16, INK, False),
            ("New files do not", 16, INK, True),
            ("", 8, INK, False),
            ("The file bodies on disk", 15, INK, False),
            ("are not encrypted again.", 15, INK, False),
        ],
        RGBColor(0xE4, 0xD2, 0xA8),
    )
    box_text(
        s, 8.95, 1.4, 3.9, 4.35, RED_BG,
        [
            ("If they paste it back", 14, RED, True),
            ("The old permission list", 18, INK, True),
            ("inside a later save", 16, INK, False),
            ("", 8, INK, False),
            ("The chain remembers", 16, INK, False),
            ("that the seal was dropped.", 16, INK, False),
            ("That save is refused.", 16, RED, True),
        ],
        RGBColor(0xE4, 0xC8, 0xC2),
    )
    footer(s, 6, total, "about 40 seconds")
    notes(
        s,
        "SAY, about 40 seconds.\n\n"
        "A second person gets their own password, and one folder, not the whole volume. "
        "The person who created the volume still holds the top key, so they can read the "
        "tree. The second person sees only the folders sealed to them. Removing them "
        "follows lazy revocation, from Plutus. We make a new key for that folder’s listing, "
        "and we leave the old file bodies as they are. What they could already read stays "
        "readable. What is written afterwards sits in a listing their old key cannot open. "
        "If the cloud pastes the old permission list into a later save, that save is refused.",
    )

    # ----- 7 -----
    s = new(prs)
    background(s)
    add_text(s, "Then the terminal. Six beats.", 0.5, 0.26, 12, 0.5, 32, INK, bold=True)
    add_text(s, "Same laptop. The attacker is a copied folder.", 0.5, 0.86, 12, 0.35, 16, MUTED)
    beats = [
        ("1", "Write a file", "The stored bytes are not the text."),
        ("2", "A second copy", "It takes the new save."),
        ("3", "Yesterday’s folder", "The open is refused."),
        ("4", "Two histories", "The receipt checks with no password."),
        ("5", "A hidden save", "The notebook still names it."),
        ("6", "Share, then revoke", "The old share list does not come back."),
    ]
    for i, (n, title, line) in enumerate(beats):
        col = i % 2
        row = i // 2
        x = 0.5 + col * 6.4
        y = 1.5 + row * 1.7
        circ = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y + 0.25), Inches(0.62), Inches(0.62))
        circ.fill.solid()
        circ.fill.fore_color.rgb = TEAL
        circ.line.fill.background()
        tf = circ.text_frame
        tf.paragraphs[0].alignment = PP_ALIGN.CENTER
        try:
            tf._txBody.bodyPr.set("anchor", "ctr")
        except Exception:
            pass
        _set_run(tf.paragraphs[0].add_run(), n, 20, WHITE, True)
        add_text(s, title, x + 0.85, y + 0.12, 5.2, 0.4, 22, INK, bold=True)
        add_text(s, line, x + 0.85, y + 0.58, 5.2, 0.4, 16, MUTED)
    footer(s, 7, total, "about 25 seconds")
    notes(
        s,
        "SAY, about 25 seconds.\n\n"
        "The terminal has six beats. First, ciphertext instead of the file. Then a second "
        "copy taking the new save. Then yesterday’s folder, and the open refuses. Then two "
        "histories, and a receipt that checks with no password. Then a hidden save, which "
        "the notebook still names. Then one shared folder, a revoke, and the old share list "
        "pasted back, which fails. I will switch to the terminal now.",
    )

    # ----- 8 -----
    s = new(prs)
    background(s)
    add_text(s, "References", 0.5, 0.22, 8, 0.45, 32, INK, bold=True)
    add_text(s, "The first three are the ones this build follows.", 0.5, 0.72, 12, 0.3, 15, MUTED)
    refs = [
        "1   David Mazières and Dennis Shasha. Building Secure File Systems out of Byzantine Storage. PODC, 2002.  Fork consistency.",
        "2   Jinyuan Li, Maxwell Krohn, David Mazières, and Dennis Shasha. Secure Untrusted Data Repository (SUNDR). OSDI, 2004.",
        "3   Mahesh Kallahalla, Erik Riedel, Ram Swaminathan, Qian Wang, and Kevin Fu. Plutus: Scalable Secure File Sharing on Untrusted Storage. FAST, 2003.  Lazy revocation.",
        "4   Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich. Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications. IEEE EuroS&P, 2016.",
        "5   Daniel J. Bernstein. ChaCha, a variant of Salsa20. SASC, 2008.  And The Poly1305-AES message-authentication code. FSE, 2005.",
        "6   Prince Mahajan, Srinath Setty, Sangmin Lee, Allen Clement, Lorenzo Alvisi, Mike Dahlin, and Michael Walfish. Depot: Cloud Storage with Minimal Trust. OSDI, 2010.",
        "7   Alexander Shraer, Christian Cachin, Asaf Cidon, Idit Keidar, Yan Michalevsky, and Dani Shaket. Venus: Verification for Untrusted Cloud Storage. CCSW, 2010.",
    ]
    box = s.shapes.add_textbox(Inches(0.5), Inches(1.15), Inches(12.3), Inches(5.7))
    frame = box.text_frame
    frame.word_wrap = True
    for index, ref in enumerate(refs):
        p = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        p.space_after = Pt(10)
        p.level = 0
        _set_run(p.add_run(), ref, 15, INK, False)
    footer(s, 8, total, "about 15 seconds, then the terminal")
    notes(
        s,
        "SAY, about 15 seconds, then switch to the terminal.\n\n"
        "These are the papers. Fork consistency is Mazières and Shasha, and SUNDR is the "
        "system that followed it. Lazy revocation is Plutus. Argon2 is how the password is "
        "stretched, and ChaCha with Poly1305 is the seal on the file pieces. Depot and Venus "
        "are the nearby cloud systems. I will leave this up for a moment, and then go to "
        "the terminal.",
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(path)


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "docs" / "Pebble-4min.pptx"
    build(out)
    print(out)
