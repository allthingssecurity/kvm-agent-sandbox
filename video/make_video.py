"""Render the explainer video.
    python make_video.py                 # full video -> build/kvm-agent-sandbox-explained.mp4 (+ .srt)
    python make_video.py --preview 3     # stills of scene 3 -> build/preview/
Needs: macOS `say`, ffmpeg, Pillow."""
import hashlib, os, subprocess, sys, wave
from PIL import Image, ImageDraw
from engine import *
from scenes import SCENES

VOICE, RATE = "Samantha", 172
LEAD, GAP, TAIL, OUTRO_FADE = 0.7, 0.3, 1.1, 0.35
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build")
os.makedirs(os.path.join(OUT, "audio"), exist_ok=True)

def sentence_audio(text):
    key = hashlib.sha1(f"{VOICE}|{RATE}|{text}".encode()).hexdigest()[:16]
    path = os.path.join(OUT, "audio", key + ".wav")
    if os.path.exists(path):
        with wave.open(path) as w: return path, w.getnframes() / w.getframerate()
    return path, say(text, path, VOICE, RATE)

def plan(scene):
    """Speak each sentence; return sentence start times, durations, wav paths and the scene length."""
    sents = sentences(scene["narration"])
    starts, durs, paths, t = [], [], [], LEAD
    for s in sents:
        p, d = sentence_audio(s)
        starts.append(t); durs.append(d); paths.append(p)
        t += d + GAP
    return sents, starts, durs, paths, t - GAP + TAIL

def subtitles(sents, starts, durs):
    subs = []
    for s, t0, d in zip(sents, starts, durs):
        parts = chunks(s)
        total = sum(len(p) for p in parts)
        t = t0
        for p in parts:
            dt = d * len(p) / total
            subs.append((t, t + dt + (GAP if p == parts[-1] else 0), p))
            t += dt
    return subs

def chrome(d, idx, title, n):
    d.text((120, 92), f"{idx + 1:02d}", font=font(30, "heavy"), fill=GREEN, anchor="ls")
    d.text((180, 92), title, font=font(40, "bold"), fill=TEXT, anchor="ls")
    d.line((120, 122, W - 120, 122), fill=PANEL2, width=2)
    for i in range(n):  # chapter dots
        x = W - 120 - (n - 1 - i) * 26
        d.ellipse((x - 6, 1052 - 6, x + 6, 1052 + 6), fill=GREEN if i == idx else (GRAY if i < idx else PANEL2))

def draw_subtitle(d, text):
    if not text: return
    f = font(34, "medium")
    lines = wrap(text, f, 1500)
    y = 990 - (len(lines) - 1) * 44
    for i, line in enumerate(lines):
        w = f.getlength(line)
        d.rounded_rectangle((W / 2 - w / 2 - 22, y + i * 44 - 30, W / 2 + w / 2 + 22, y + i * 44 + 16), 10, fill=(0, 0, 0))
        d.text((W / 2, y + i * 44 - 7), line, font=f, fill=(245, 245, 245), anchor="mm")

def frame(idx, scene, els, subs, t, D):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    chrome(d, idx, scene["title"], len(SCENES))
    for e in els:
        a = e.alpha(t)
        if a > 0.003: e.draw(d, t, a)
    draw_subtitle(d, next((s for a, b, s in subs if a <= t < b), ""))
    if t > D - OUTRO_FADE:
        img = Image.blend(img, Image.new("RGB", (W, H), BG), min(1.0, (t - (D - OUTRO_FADE)) / OUTRO_FADE))
    return img

def key(els, subs, t, D):
    vis = tuple((id(e), round(e.alpha(t), 2), e.state(t)) for e in els if e.alpha(t) > 0.003)
    sub = next((i for i, (a, b, _) in enumerate(subs) if a <= t < b), -1)
    fade = round(t * FPS) if t > D - OUTRO_FADE else None
    return vis, sub, fade

def srt_time(t):
    h, m, s, ms = int(t // 3600), int(t % 3600 // 60), int(t % 60), int(round((t % 1) * 1000)) % 1000
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"

def main():
    if "--preview" in sys.argv:
        idx = int(sys.argv[sys.argv.index("--preview") + 1]) - 1
        sc = SCENES[idx]
        sents, starts, durs, _, D = plan(sc)
        els = sc["build"](lambda i: starts[i], D)
        subs = subtitles(sents, starts, durs)
        os.makedirs(os.path.join(OUT, "preview"), exist_ok=True)
        for k, t in enumerate([starts[i] + 0.6 for i in range(len(starts))] + [D - OUTRO_FADE - 0.05]):
            frame(idx, sc, els, subs, t, D).save(os.path.join(OUT, "preview", f"s{idx + 1:02d}_{k}.png"))
        print(f"scene {idx + 1}: {D:.1f} s, {len(sents)} sentences")
        return

    # 1. audio: all sentences, with the silences between them
    plans = [plan(sc) for sc in SCENES]
    total = sum(p[4] for p in plans)
    print(f"{len(SCENES)} scenes, {total / 60:.1f} minutes")
    narration = os.path.join(OUT, "narration.wav")
    with wave.open(narration, "wb") as out:
        out.setnchannels(1); out.setsampwidth(2); out.setframerate(48000)
        for sents, starts, durs, paths, D in plans:
            written = 0.0
            for st, p in zip(starts, paths):
                out.writeframes(b"\0\0" * int((st - written) * 48000)); written = st
                with wave.open(p) as w:
                    data = w.readframes(w.getnframes()); out.writeframes(data); written += w.getnframes() / 48000
            out.writeframes(b"\0\0" * int((D - written) * 48000))

    # 2. subtitles file
    srt, n, offset = [], 1, 0.0
    for sents, starts, durs, _, D in plans:
        for a, b, s in subtitles(sents, starts, durs):
            srt.append(f"{n}\n{srt_time(offset + a)} --> {srt_time(offset + b)}\n{s}\n"); n += 1
        offset += D
    mp4 = os.path.join(OUT, "kvm-agent-sandbox-explained.mp4")
    open(mp4[:-4] + ".srt", "w").write("\n".join(srt))

    # 3. video: frames to ffmpeg (a frame is drawn only when something on screen changed)
    enc = subprocess.Popen(["nice", "-n", "10", "ffmpeg", "-loglevel", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
                            "-r", str(FPS), "-i", "-", "-i", narration, "-c:v", "libx264", "-preset", "medium", "-crf", "20",
                            "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", "-shortest", mp4], stdin=subprocess.PIPE)
    drawn = frames = 0
    for idx, (sc, (sents, starts, durs, _, D)) in enumerate(zip(SCENES, plans)):
        els = sc["build"](lambda i, st=starts: st[i], D)
        subs = subtitles(sents, starts, durs)
        last_key, last = None, None
        for f in range(int(round(D * FPS))):
            t = f / FPS
            k = key(els, subs, t, D)
            if k != last_key:
                last, last_key = frame(idx, sc, els, subs, t, D).tobytes(), k
                drawn += 1
            enc.stdin.write(last); frames += 1
        print(f"  scene {idx + 1:2d}/{len(SCENES)} {sc['title'][:48]:<48} {D:5.1f} s")
    enc.stdin.close(); enc.wait()
    print(f"{frames} frames ({drawn} drawn) -> {mp4}")

if __name__ == "__main__":
    main()
