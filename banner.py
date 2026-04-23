#!/usr/bin/env python3
"""ElJuez Cybersecurity — animated intro banner."""
import sys
import time
import re
import os

# ANSI codes
BR  = '\033[1;31m'   # bold red
R   = '\033[31m'     # red
BLK = '\033[5m'      # blink
Y   = '\033[33m'     # amber (beer liquid)
BY  = '\033[1;33m'   # bright yellow (foam)
DIM = '\033[2;31m'   # dim red (cat "off" state)
RS  = '\033[0m'      # reset
HC  = '\033[?25l'    # hide cursor
SC  = '\033[?25h'    # show cursor
HM  = '\033[H'       # cursor home

# Cycling palette for "By Viernez13" multicolor blink
RAINBOW = [
    '\033[1;31m',  # bold red
    '\033[1;33m',  # bold yellow
    '\033[1;32m',  # bold green
    '\033[1;36m',  # bold cyan
    '\033[1;34m',  # bold blue
    '\033[1;35m',  # bold magenta
]

def multicolor_blink(text):
    """Return text with each character in a cycling rainbow color + blink."""
    out = ''
    color_idx = 0
    for ch in text:
        if ch == ' ':
            out += ch
        else:
            out += BLK + RAINBOW[color_idx % len(RAINBOW)] + ch + RS
            color_idx += 1
    return out

FW = 74  # total frame width

def vl(s):
    """Visible length — strip all ANSI CSI sequences."""
    return len(re.sub(r'\033\[[^a-zA-Z]*[a-zA-Z]', '', s))

# ── Chess border ──────────────────────────────────────────────────────────────
_CHESS_PIECES = '♜♞♝♛♚♝♞♜'   # black back-rank pieces, 8 chars

def chess_border(row_idx):
    if row_idx % 2 == 0:
        # Outer rows: cycling chess pieces
        pat = (_CHESS_PIECES * (FW // len(_CHESS_PIECES) + 1))[:FW]
    else:
        # Inner rows: classic alternating chessboard squares
        pat = ''.join('█' if i % 2 == 0 else '░' for i in range(FW))
    return BR + pat + RS

def frow(row_idx, content=''):
    """Wrap content in alternating chess-pawn side borders, padding to fill FW."""
    iw = FW - 2
    lc = '♟' if row_idx % 2 == 0 else '♙'
    rc = '♙' if row_idx % 2 == 0 else '♟'
    pad = max(0, iw - vl(content))
    return BR + lc + RS + content + ' ' * pad + BR + rc + RS

# ── Cat ASCII art ─────────────────────────────────────────────────────────────
CAT_LINES = [
    r"             uu$$$$$$$$$$$uu",
    r"          uu$$$$$$$$$$$$$$$$$uu",
    r"         u$$$$$$$$$$$$$$$$$$$$$u",
    r"        u$$$$$$$$$$$$$$$$$$$$$$$u",
    r"       u$$$$$$$$$$$$$$$$$$$$$$$$$u",
    r"       u$$$$$$*   *$$$*   *$$$$$$u",
    r"       *$$$$*      u$u       $$$$*",
    r"        $$$u       u$u       u$$$",
    r"        $$$u      u$$$u      u$$$",
    r"         *$$$$uu$$$   $$$uu$$$$*",
    r"          *$$$$$$$*   *$$$$$$$*",
    r"            u$$$$$$$u$$$$$$$u",
    r"             u$*$*$*$*$*$*$u",
    r"  uuu        $$u$ $ $ $ $u$$       uuu",
    r"  u$$$$       $$$$$u$u$u$$$       u$$$$",
    r"  $$$$$uu      *$$$$$$$$$*     uu$$$$$$",
    r"u$$$$$$$$$$$uu    *****    uuuu$$$$$$$$$",
    r"$$$$***$$$$$$$$$$uuu   uu$$$$$$$$$***$$$*",
    r" ***      **$$$$$$$$$$$uu **$***",
    r"          uuuu **$$$$$$$$$$uuu",
    r" u$$$uuu$$$$$$$$$uu **$$$$$$$$$$$uuu$$$",
    r" $$$$$$$$$$****           **$$$$$$$$$$$*",
    r"   *$$$$$*                      **$$$$**",
    r"     $$$*                         $$$$*",
]
CAT_W = max(len(l) for l in CAT_LINES)

# ── Beer mug ─────────────────────────────────────────────────────────────────
_INNER = "##########"   # 10 hash chars (liquid)
_EMPTY = "          "   # 10 spaces
_FROTH = "~~~~~~~~~~"   # 10 tilde chars (foam)
_LEVELS = 5             # fillable rows

def beer_art(fill, foam=False):
    lines = []
    lines.append("  .----------.  ")
    lines.append("  |          |] ")
    for i in range(_LEVELS - 1, -1, -1):
        if i < fill:
            if i == _LEVELS - 1 and foam:
                lines.append(f"  |{BY}{_FROTH}{RS}|] ")
            else:
                lines.append(f"  |{Y}{_INNER}{RS}|] ")
        else:
            lines.append(f"  |{_EMPTY}|] ")
    lines.append("  '----------'  ")
    return lines

BEER_W = max(len(l) for l in beer_art(0))

# ── Render a single frame ────────────────────────────────────────────────────
def render_frame(skull_on, fill, foam):
    IW = FW - 2
    rows = []
    r = 0

    # Two rows of chess border on top
    rows.append(chess_border(r)); r += 1
    rows.append(chess_border(r)); r += 1

    # Blank row
    rows.append(frow(r)); r += 1

    # ── Main title (blink + bold red) ──
    title = ' ☠  E L J U E Z   C Y B E R S E C U R I T Y  ☠ '
    colored = BLK + BR + title + RS
    lp = max(0, (IW - len(title)) // 2)
    rows.append(frow(r, ' ' * lp + colored)); r += 1

    # ── "By Viernez13" multicolor blinking subtitle ──
    byline_plain = 'B y   V i e r n e z 1 3'
    byline_colored = multicolor_blink(byline_plain)
    lp_by = max(0, (IW - len(byline_plain)) // 2)
    rows.append(frow(r, ' ' * lp_by + byline_colored)); r += 1

    # Blank row
    rows.append(frow(r)); r += 1

    # ── Cat + beer side by side ──
    cat_color = BR if skull_on else DIM
    cat  = [cat_color + l.ljust(CAT_W) + RS for l in CAT_LINES]
    beer = beer_art(fill, foam)

    mh = max(len(cat), len(beer))
    cat  += [' ' * CAT_W] * (mh - len(cat))
    beer += [' ' * BEER_W] * (mh - len(beer))

    gap   = 4
    art_w = CAT_W + gap + BEER_W
    lp2   = max(0, (IW - art_w) // 2)

    for cl, bl in zip(cat, beer):
        line = ' ' * lp2 + cl + ' ' * gap + bl
        rows.append(frow(r, line)); r += 1

    # Blank row
    rows.append(frow(r)); r += 1

    # Two rows of chess border on bottom
    rows.append(chess_border(r)); r += 1
    rows.append(chess_border(r)); r += 1

    return '\n'.join(rows)


# ── Public entry point ────────────────────────────────────────────────────────
def show_banner():
    """Run the full animated intro banner, then return."""
    sys.stdout.write(HC)
    sys.stdout.flush()
    try:
        os.system('clear')

        # Initial: cat visible, beer empty
        print(render_frame(True, 0, False))
        sys.stdout.flush()
        time.sleep(0.5)

        # Fill beer level by level
        for level in range(1, _LEVELS + 1):
            sys.stdout.write(HM)
            print(render_frame(True, level, False))
            sys.stdout.flush()
            time.sleep(0.28)

        # Add foam on top
        sys.stdout.write(HM)
        print(render_frame(True, _LEVELS, True))
        sys.stdout.flush()
        time.sleep(0.4)

        # Cat blink (alternate on/off)
        for i in range(10):
            sys.stdout.write(HM)
            print(render_frame(i % 2 == 0, _LEVELS, True))
            sys.stdout.flush()
            time.sleep(0.18)

        # Final: cat on, beer full with foam
        sys.stdout.write(HM)
        print(render_frame(True, _LEVELS, True))
        sys.stdout.flush()
        time.sleep(1.6)

    finally:
        sys.stdout.write(SC)
        sys.stdout.flush()

    # Move past banner so program output appears below
    print()
