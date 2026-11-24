"""A tiny scene engine for narrated explainer videos: Pillow draws the frames, macOS `say` speaks the
narration, ffmpeg encodes. Elements appear in sync with the sentence that introduces them."""
import math, os, re, subprocess, wave
from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 1920, 1080, 30
FADE = 0.45

# ---------------- palette ----------------
BG = (11, 16, 32)
PANEL = (20, 27, 51)
PANEL2 = (28, 37, 68)
TEXT = (232, 236, 246)
MUTED = (140, 150, 181)
GREEN = (74, 222, 128)
BLUE = (96, 165, 250)
PURPLE = (167, 139, 250)
RED = (248, 113, 113)
AMBER = (251, 191, 36)
CYAN = (34, 211, 238)
GRAY = (100, 110, 140)

_fonts = {}
def font(size, kind="sans"):
    key = (size, kind)
    if key not in _fonts:
        path, idx = {"sans": ("/System/Library/Fonts/Avenir Next.ttc", 7), "medium": ("/System/Library/Fonts/Avenir Next.ttc", 5),
                     "bold": ("/System/Library/Fonts/Avenir Next.ttc", 2), "heavy": ("/System/Library/Fonts/Avenir Next.ttc", 0),
                     "mono": ("/System/Library/Fonts/Menlo.ttc", 0), "monobold": ("/System/Library/Fonts/Menlo.ttc", 1)}[kind]
        _fonts[key] = ImageFont.truetype(path, size, index=idx)
    return _fonts[key]

def mix(c, a, bg=BG):
    return tuple(int(bg[i] + (c[i] - bg[i]) * a) for i in range(3))

# ---------------- elements ----------------
class El:
    """Something on screen from `at` (seconds into the scene) until `until`."""
    def __init__(self, at=0.0, until=None):
        self.at, self.until = at, until
    def alpha(self, t):
        if t < self.at: return 0.0
        a = min(1.0, (t - self.at) / FADE)
        if self.until is not None:
            if t >= self.until + FADE: return 0.0
            if t > self.until: a = min(a, 1 - (t - self.until) / FADE)
        return a
    def animating(self, t):
        return (self.at <= t < self.at + FADE) or (self.until is not None and self.until <= t < self.until + FADE)
    def draw(self, d, t, a): pass
    def state(self, t): return None  # extra state that changes the picture (moving things)

def wrap(text, f, width):
    lines = []
    for para in text.split("\n"):
        cur = ""
        for word in para.split(" "):
            test = (cur + " " + word).strip()
            if f.getlength(test) <= width or not cur: cur = test
            else: lines.append(cur); cur = word
        lines.append(cur)
    return lines

class Text(El):
    def __init__(self, x, y, text, size=36, color=TEXT, kind="sans", anchor="la", width=None, spacing=1.25, **kw):
        super().__init__(**kw)
        self.x, self.y, self.text, self.size, self.color, self.kind, self.anchor, self.width, self.spacing = x, y, text, size, color, kind, anchor, width, spacing
    def draw(self, d, t, a):
        f = font(self.size, self.kind)
        lines = wrap(self.text, f, self.width) if self.width else self.text.split("\n")
        for i, line in enumerate(lines):
            d.text((self.x, self.y + i * self.size * self.spacing), line, font=f, fill=mix(self.color, a), anchor=self.anchor)

class Box(El):
    def __init__(self, x, y, w, h, fill=PANEL, outline=None, label=None, sub=None, size=34, sub_size=24, color=TEXT,
                 sub_color=MUTED, radius=18, width=3, kind="bold", align="center", **kw):
        super().__init__(**kw)
        self.r = (x, y, x + w, y + h)
        self.fill, self.outline, self.label, self.sub, self.size, self.sub_size = fill, outline, label, sub, size, sub_size
        self.color, self.sub_color, self.radius, self.width, self.kind, self.align = color, sub_color, radius, width, kind, align
    def draw(self, d, t, a):
        x0, y0, x1, y1 = self.r
        d.rounded_rectangle(self.r, self.radius, fill=mix(self.fill, a) if self.fill else None,
                            outline=mix(self.outline, a) if self.outline else None, width=self.width)
        lines = []
        if self.label: lines += [(l, font(self.size, self.kind), self.color) for l in wrap(self.label, font(self.size, self.kind), x1 - x0 - 40)]
        if self.sub: lines += [(l, font(self.sub_size), self.sub_color) for l in wrap(self.sub, font(self.sub_size), x1 - x0 - 40)]
        heights = [f.size * 1.3 for _, f, _ in lines]
        y = (y0 + y1) / 2 - sum(heights) / 2
        for (line, f, c), h in zip(lines, heights):
            if self.align == "center": d.text(((x0 + x1) / 2, y + h / 2), line, font=f, fill=mix(c, a), anchor="mm")
            else: d.text((x0 + 26, y + h / 2), line, font=f, fill=mix(c, a), anchor="lm")
            y += h

class Arrow(El):
    def __init__(self, x1, y1, x2, y2, color=MUTED, width=5, label=None, size=24, label_color=None, dashed=False, head=18, off=22, **kw):
        super().__init__(**kw)
        self.off = off
        self.p, self.color, self.width, self.label, self.size, self.head, self.dashed = (x1, y1, x2, y2), color, width, label, size, head, dashed
        self.label_color = label_color or color
    def draw(self, d, t, a):
        x1, y1, x2, y2 = self.p
        c = mix(self.color, a)
        ang = math.atan2(y2 - y1, x2 - x1)
        ex, ey = x2 - self.head * 0.8 * math.cos(ang), y2 - self.head * 0.8 * math.sin(ang)
        if self.head == 0: ex, ey = x2, y2
        if self.dashed:
            n = int(math.hypot(ex - x1, ey - y1) / 18)
            for i in range(0, n, 2):
                d.line([(x1 + (ex - x1) * i / n, y1 + (ey - y1) * i / n), (x1 + (ex - x1) * (i + 1) / n, y1 + (ey - y1) * (i + 1) / n)], fill=c, width=self.width)
        else:
            d.line([(x1, y1), (ex, ey)], fill=c, width=self.width)
        h = self.head
        if h: d.polygon([(x2, y2), (x2 - h * math.cos(ang - 0.45), y2 - h * math.sin(ang - 0.45)), (x2 - h * math.cos(ang + 0.45), y2 - h * math.sin(ang + 0.45))], fill=c)
        if self.label:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            off = self.off
            nx, ny = -math.sin(ang) * off, math.cos(ang) * off
            d.text((mx + nx, my + ny), self.label, font=font(self.size, "medium"), fill=mix(self.label_color, a), anchor="mm")

class Cross(El):
    def __init__(self, x, y, s=34, color=RED, width=9, **kw):
        super().__init__(**kw); self.x, self.y, self.s, self.color, self.width = x, y, s, color, width
    def draw(self, d, t, a):
        c, s = mix(self.color, a), self.s
        d.line([(self.x - s, self.y - s), (self.x + s, self.y + s)], fill=c, width=self.width)
        d.line([(self.x - s, self.y + s), (self.x + s, self.y - s)], fill=c, width=self.width)

class Check(El):
    def __init__(self, x, y, s=26, color=GREEN, width=8, **kw):
        super().__init__(**kw); self.x, self.y, self.s, self.color, self.width = x, y, s, color, width
    def draw(self, d, t, a):
        c, s = mix(self.color, a), self.s
        d.line([(self.x - s, self.y), (self.x - s * 0.3, self.y + s * 0.7), (self.x + s, self.y - s * 0.8)], fill=c, width=self.width, joint="curve")

class Frame(El):
    """A rectangle outline, optionally pulsing (to point at something)."""
    def __init__(self, x, y, w, h, color=AMBER, width=5, radius=20, pulse=False, label=None, size=26, **kw):
        super().__init__(**kw); self.r, self.color, self.width, self.radius, self.pulse, self.label, self.size = (x, y, x + w, y + h), color, width, radius, pulse, label, size
    def draw(self, d, t, a):
        if self.pulse: a *= 0.55 + 0.45 * (0.5 + 0.5 * math.sin((t - self.at) * 5))
        d.rounded_rectangle(self.r, self.radius, outline=mix(self.color, a), width=self.width)
        if self.label:
            d.text((self.r[0] + 18, self.r[1] - 8), self.label, font=font(self.size, "bold"), fill=mix(self.color, a), anchor="ld")
    def animating(self, t): return super().animating(t) or (self.pulse and self.alpha(t) > 0)
    def state(self, t): return round(t * FPS) if self.pulse and self.alpha(t) > 0 else None

class Packet(El):
    """A labelled dot travelling along a path from `at` for `dur` seconds, then resting at the end."""
    def __init__(self, points, dur=2.0, color=AMBER, label=None, size=22, r=13, **kw):
        super().__init__(**kw); self.pts, self.dur, self.color, self.label, self.size, self.r = points, dur, color, label, size, r
    def pos(self, t):
        u = max(0.0, min(1.0, (t - self.at) / self.dur))
        u = u * u * (3 - 2 * u)
        segs = [math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(self.pts, self.pts[1:])]
        total, dist = sum(segs), u * sum(segs)
        for (a, b), s in zip(zip(self.pts, self.pts[1:]), segs):
            if dist <= s or s == segs[-1]:
                f = 0 if s == 0 else min(1, dist / s)
                return a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f
            dist -= s
        return self.pts[-1]
    def alpha(self, t):
        if t < self.at: return 0.0
        if self.until is not None and t >= self.until: return 0.0
        return 1.0
    def animating(self, t): return self.at <= t <= self.at + self.dur
    def state(self, t): return round(t * FPS) if self.at <= t <= self.at + self.dur else None
    def draw(self, d, t, a):
        x, y = self.pos(t)
        d.ellipse((x - self.r, y - self.r, x + self.r, y + self.r), fill=self.color)
        if self.label:
            d.text((x, y - self.r - 8), self.label, font=font(self.size, "bold"), fill=self.color, anchor="md")

class Table(El):
    def __init__(self, x, y, widths, rows, row_h=62, size=26, header_color=MUTED, colors=None, **kw):
        super().__init__(**kw); self.x, self.y, self.widths, self.rows, self.row_h, self.size, self.header_color = x, y, widths, rows, row_h, size, header_color
        self.colors = colors or {}
    def draw(self, d, t, a):
        y = self.y
        for ri, row in enumerate(self.rows):
            if ri % 2 == 1: d.rectangle((self.x, y, self.x + sum(self.widths), y + self.row_h), fill=mix(PANEL, a))
            x = self.x
            for ci, cell in enumerate(row):
                kind = "bold" if ri == 0 or ci == 0 else "sans"
                color = self.header_color if ri == 0 else self.colors.get((ri, ci), TEXT)
                lines = wrap(cell, font(self.size, kind), self.widths[ci] - 30)
                for li, line in enumerate(lines):
                    d.text((x + 18, y + self.row_h / 2 + (li - (len(lines) - 1) / 2) * self.size * 1.15), line, font=font(self.size, kind), fill=mix(color, a), anchor="lm")
                x += self.widths[ci]
            y += self.row_h
        d.line((self.x, self.y + self.row_h, self.x + sum(self.widths), self.y + self.row_h), fill=mix(GRAY, a), width=2)

class Bars(El):
    """Horizontal bars that grow in, one after another."""
    def __init__(self, x, y, w, items, vmax, bar_h=64, gap=40, label_w=470, size=30, grow=0.8, stagger=None, **kw):
        super().__init__(**kw); self.x, self.y, self.w, self.items, self.vmax, self.bar_h, self.gap, self.label_w, self.size, self.grow = x, y, w, items, vmax, bar_h, gap, label_w, size, grow
        self.stagger = stagger or [self.at + i * 0.6 for i in range(len(items))]
    def frac(self, t, i): return max(0.0, min(1.0, (t - self.stagger[i]) / self.grow))
    def animating(self, t): return any(0 < self.frac(t, i) < 1 for i in range(len(self.items))) or super().animating(t)
    def state(self, t): return tuple(round(self.frac(t, i), 2) for i in range(len(self.items)))
    def draw(self, d, t, a):
        for i, (label, value, color, note) in enumerate(self.items):
            f = self.frac(t, i)
            if f <= 0: continue
            y = self.y + i * (self.bar_h + self.gap)
            d.text((self.x, y + self.bar_h / 2), label, font=font(self.size, "bold"), fill=mix(TEXT, f), anchor="lm")
            bx = self.x + self.label_w
            bw = max(6, (self.w - self.label_w - 220) * value / self.vmax * f)
            d.rounded_rectangle((bx, y, bx + bw, y + self.bar_h), 10, fill=mix(color, f))
            d.text((bx + bw + 20, y + self.bar_h / 2), note, font=font(self.size, "heavy"), fill=mix(color, f), anchor="lm")

class Stat(El):
    def __init__(self, x, y, big, small, color=GREEN, big_size=88, small_size=28, width=520, **kw):
        super().__init__(**kw); self.x, self.y, self.big, self.small, self.color, self.big_size, self.small_size, self.width = x, y, big, small, color, big_size, small_size, width
    def draw(self, d, t, a):
        d.text((self.x, self.y), self.big, font=font(self.big_size, "heavy"), fill=mix(self.color, a), anchor="la")
        for i, line in enumerate(wrap(self.small, font(self.small_size), self.width)):
            d.text((self.x, self.y + self.big_size * 1.15 + i * self.small_size * 1.3), line, font=font(self.small_size), fill=mix(MUTED, a), anchor="la")

class Code(El):
    def __init__(self, x, y, lines, size=28, w=None, color=GREEN, **kw):
        super().__init__(**kw); self.x, self.y, self.lines, self.size, self.w, self.color = x, y, lines, size, w, color
    def draw(self, d, t, a):
        f = font(self.size, "mono")
        w = self.w or max(f.getlength(l) for l in self.lines) + 60
        h = len(self.lines) * self.size * 1.45 + 40
        d.rounded_rectangle((self.x, self.y, self.x + w, self.y + h), 14, fill=mix((8, 11, 22), a), outline=mix(GRAY, a), width=2)
        for i, line in enumerate(self.lines):
            d.text((self.x + 30, self.y + 20 + i * self.size * 1.45), line, font=f, fill=mix(self.color, a))

# ---------------- audio ----------------
def say(text, path, voice, rate):
    aiff = path + ".aiff"
    subprocess.run(["say", "-v", voice, "-r", str(rate), "-o", aiff, text], check=True)
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", aiff, "-ar", "48000", "-ac", "1", path], check=True)
    os.remove(aiff)
    with wave.open(path) as w: return w.getnframes() / w.getframerate()

def sentences(text):
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]

def chunks(sentence, limit=96):
    """Split a long sentence into subtitle chunks of at most ~limit characters, at commas or spaces."""
    out, cur = [], ""
    for word in sentence.split(" "):
        if len(cur) + len(word) + 1 > limit and cur:
            out.append(cur); cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur: out.append(cur)
    return out
