"""Render the ghseal narrated demo: real command output + edge-tts narration.

Usage: python demo/render.py [--gif]   (needs ffmpeg, edge-tts, Pillow, cryptography, network, ghseal in /tmp/pyr)
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(ROOT, "demo.mp4")
SDKBIN = "/tmp/pyr/bin"
SANDBOX = "/tmp/ghsdemo"
W, H, FPS = 1280, 720, 24
VOICE = "en-US-AndrewNeural"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, FG = (24, 26, 33), (220, 223, 228)
ANSI = {"31": (255, 95, 95), "32": (95, 215, 120), "33": (240, 200, 80), "2": (130, 135, 145), "36": (90, 200, 230), "1": FG}
PROMPT = "dev@laptop:~/myapp $ "

APP = SANDBOX + "/myapp"
SCENES = [
    {"kind": "title", "title": "ghseal", "sub": "share .env files by sealing them\nto your teammates' GitHub SSH keys",
     "say": "This is G H seal, a small open source command line tool that stops your team passing dot env files "
            "around in Slack. It encrypts them to the SSH keys your teammates already have on GitHub."},
    {"kind": "bullets", "title": "The problem",
     "bullets": ["Teams still paste .env files into Slack and DMs",
                 "Copies drift; nobody knows who has the prod keys",
                 "Someone leaves: which secrets do we rotate?",
                 "Coding agents read whatever .env is in the workspace",
                 "Vault / Doppler / Infisical: a server and a bill"],
     "say": "Most small teams still share secrets by pasting dot env files into chat. Copies drift between laptops, "
            "nobody knows who still has the production keys after someone leaves, and A I coding agents read whatever "
            "dot env file is sitting in the workspace. Vault or Doppler fix it, but that's a server and a bill."},
    {"kind": "term", "cwd": APP,
     "cmds": ["cat .env", "ghseal init", "ghseal add ~/.ssh/id_ed25519.pub --name me", "ghseal add @hamarshehmhmd"],
     "say": "Here's an app with a real looking dot env. G H seal init creates a small config, git ignores the "
            "plaintext, and writes ignore rules for Cursor, Gemini, Windsurf, aider and Claude Code. I add myself, "
            "then a teammate by GitHub username. That's a live fetch of their public keys from GitHub, pinned by fingerprint."},
    {"kind": "term", "cwd": APP,
     "cmds": ["ghseal seal", "head -n 4 .env.sealed", "ghseal check"],
     "say": "Seal encrypts the file to every recipient. The output is a standard age file, so you commit it next to your code, "
            "and age itself can still open it if this tool ever disappears. Check reads the age header and proves "
            "exactly who can decrypt it, without decrypting anything."},
    {"kind": "term", "cwd": APP,
     "cmds": ["rm .env", "ghseal run -- python3 app.py", "ls -a"],
     "say": "Now delete the plaintext. G H seal run decrypts in memory and injects the variables into the process. "
            "The app gets its database URL and Stripe key, and there's no dot env file on disk for an agent, a backup, "
            "or a screen share to pick up."},
    {"kind": "term", "cwd": APP,
     "cmds": ["ghseal set STRIPE_SECRET_KEY=sk_live_rotated_9Qx", "ghseal names", "cat .claude/settings.json"],
     "say": "You edit secrets without ever writing them out. Set re-seals in place, and names lists what's inside, "
            "with the values hidden. And here's the Claude Code deny rule that init added."},
    {"kind": "term", "cwd": APP,
     "cmds": ["ghseal add ~/sara.pub --name sara-contractor", "ghseal remove sara-contractor", "ghseal -i ~/outsider_key open --stdout"],
     "say": "When a contractor leaves, remove re-seals the file without their key, then tells you the truth: they could "
            "read these values, and still can from git history, so rotate them. And someone who was never added simply can't open it."},
    {"kind": "term", "cwd": APP,
     "cmds": ["ghseal refresh", "ghseal check"],
     "say": "Refresh re-fetches everyone's GitHub keys and fails if they changed, which can mean a new laptop or a "
            "hijacked account. Run check in C I or pre-commit, and it fails if someone's missing, a removed key can "
            "still decrypt, or a plaintext dot env got committed."},
    {"kind": "bullets", "title": "What you get",
     "bullets": ["Encrypt to github.com/<user>.keys: no server, no accounts",
                 "Standard age files: age -d still opens them",
                 "ghseal run: secrets injected, no plaintext on disk",
                 "Offboarding rotation list + key-change detection",
                 "check for CI, AI agent ignore rules, age keys for CI"],
     "say": "So: encryption to keys your team already has, standard age files, run with no plaintext on disk, an "
            "honest rotation list when people leave, key change detection, a C I check, and age keys for your C I runners."},
    {"kind": "bullets", "title": "Try it",
     "bullets": ["curl -fsSL https://raw.githubusercontent.com/",
                 "   hamarshehmhmd/ghseal/main/install.sh | sh",
                 "ghseal init && ghseal add @you @teammate && ghseal seal",
                 "github.com/hamarshehmhmd/ghseal",
                 "GNU AGPL-3.0 (commercial licenses available)"],
     "say": "Install it with the one line installer. It's licensed under the GNU A G P L version three or later, "
            "with commercial licenses available from the author. It's on GitHub at hamarsheh m h m d slash G H seal."},
]


async def tts(text, path):
    import edge_tts
    for attempt in range(8):
        try:
            await edge_tts.Communicate(text, VOICE, rate="+4%").save(path)
            return
        except Exception:
            if os.path.exists(path):
                os.remove(path)
            if attempt == 7:
                raise
            await asyncio.sleep(5)


def duration(path):
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
        text=True,
    )
    return float(out.strip())


EXPORTS = {}


def run_cmd(cmd, cwd):
    if cmd.startswith("export ") and "=" in cmd:
        k, v = cmd[7:].split("=", 1)
        EXPORTS[k] = v
        return ""
    env = dict(os.environ, FORCE_COLOR="1", **EXPORTS)
    env.pop("NO_COLOR", None)
    env["PATH"] = SDKBIN + os.pathsep + env["PATH"]
    env["COLUMNS"] = "120"
    p = subprocess.run(
        ["bash", "-c", "shopt -s nullglob; " + cmd],
        cwd=cwd, capture_output=True, text=True, env=env,
    )
    return (p.stdout + p.stderr).rstrip("\n")


def parse_ansi(line):
    spans, color, bold = [], FG, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in ANSI:
                    color = ANSI[code]
        elif part:
            spans.append((part, color, bold))
    return spans


class Term:
    def __init__(self):
        self.font = ImageFont.truetype(MONO, 14)
        self.bold = ImageFont.truetype(MONO_B, 14)
        self.cw = self.font.getlength("M")
        self.lh = 20
        self.cols = int((W - 80) / self.cw)

    def wrap(self, spans):
        lines, cur, n = [], [], 0
        for text, c, b in spans:
            while text:
                room = self.cols - n
                if len(text) <= room:
                    cur.append((text, c, b)); n += len(text); text = ""
                else:
                    cut = text.rfind(" ", 0, room + 1)
                    cut = cut if cut > 0 else room
                    cur.append((text[:cut], c, b)); lines.append(cur); cur, n = [], 0
                    text = "    " + text[cut:].lstrip(" ")
        lines.append(cur)
        return lines

    def frame(self, lines, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([20, 14, W - 20, H - 14], 12, fill=(30, 33, 41), outline=(60, 64, 76))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([40 + i * 24, 30, 54 + i * 24, 44], fill=c)
        d.text((W // 2, 37), "~ — bash", font=ImageFont.truetype(SANS, 15), fill=(150, 155, 165), anchor="mm")
        visible = lines[-30:]
        y = 64
        for ln in visible:
            x = 40
            for text, c, b in ln:
                d.text((x, y), text, font=self.bold if b else self.font, fill=c)
                x += self.cw * len(text)
            y += self.lh
        if cursor:
            last = visible[-1] if visible else []
            x = 40 + self.cw * sum(len(t) for t, _, _ in last)
            d.rectangle([x, y - self.lh + 3, x + self.cw - 2, y - 4], fill=FG)
        return img


def card(scene):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if scene["kind"] == "title":
        d.text((W // 2, 280), scene["title"], font=ImageFont.truetype(MONO_B, 84), fill=(95, 215, 120), anchor="mm")
        d.multiline_text((W // 2, 420), scene["sub"], font=ImageFont.truetype(SANS, 34), fill=FG, anchor="mm",
                         align="center", spacing=12)
        d.text((W // 2, 620), "github.com/hamarshehmhmd/ghseal  ·  age-compatible  ·  no server  ·  GNU AGPL-3.0",
               font=ImageFont.truetype(SANS, 22), fill=(150, 155, 165), anchor="mm")
    else:
        d.text((90, 90), scene["title"], font=ImageFont.truetype(SANS_B, 52), fill=(95, 215, 120))
        f = ImageFont.truetype(SANS, 29)
        y = 200
        for b in scene["bullets"]:
            if b and not b.startswith("   "):
                d.text((90, y), "•", font=f, fill=(240, 200, 80))
            d.text((130, y), b.strip(), font=f, fill=FG)
            y += 58 if b.startswith("   ") or not b else 62
    return img


class Writer:
    def __init__(self, path, audio):
        self.p = subprocess.Popen(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", audio,
             "-af", "apad", "-c:v", "libx264", "-preset", "medium", "-crf", "23",
             "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
             "-shortest", path],
            stdin=subprocess.PIPE,
        )
        self.n = 0

    def put(self, img, count=1):
        data = img.tobytes()
        for _ in range(count):
            self.p.stdin.write(data)
        self.n += count

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        if self.p.returncode:
            sys.exit("ffmpeg failed")


def render_scene(i, scene, workdir):
    workdir = scene.get("cwd", APP)
    audio = os.path.join(BUILD, f"s{i}.mp3")
    if not os.path.exists(audio):
        asyncio.run(tts(scene["say"], audio))
    total = int((duration(audio) + 0.7) * FPS)
    path = os.path.join(BUILD, f"s{i}.mp4")
    w = Writer(path, audio)
    if scene["kind"] != "term":
        w.put(card(scene), total)
        w.close()
        return path
    t = Term()
    shown = scene.get("show", scene["cmds"])
    outputs = [run_cmd(c, workdir) for c in scene["cmds"]]
    # Truncate very long check output so it fits the terminal window
    capped = []
    for out in outputs:
        lines = out.splitlines()
        if len(lines) > 26:
            lines = lines[:24] + ["…", lines[-1]]
        capped.append("\n".join(lines))
    outputs = capped
    steps = list(zip(shown, outputs))
    typing = sum(len(s) for s, _ in steps) / 32 * FPS
    pause = max(6, int((total - typing) / max(1, len(steps))) - 4)
    lines = []
    for cmd, out in steps:
        prompt = [(PROMPT, (95, 215, 120), True)]
        for k in range(0, len(cmd) + 1, 2):
            frame = t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True)
            w.put(frame)
        lines += t.wrap(prompt + [(cmd, FG, False)])
        for ol in out.splitlines():
            lines += t.wrap(parse_ansi(ol))
        lines.append([])
        hold = min(pause, max(0, total - w.n))
        w.put(t.frame(lines), hold)
    final = t.frame(lines + t.wrap([(PROMPT, (95, 215, 120), True)]), cursor=True)
    if w.n < total:
        w.put(final, total - w.n)
    w.close()
    return path


APP_PY = """import os
db = os.environ["DATABASE_URL"].split("@")[1]
key = os.environ["STRIPE_SECRET_KEY"]
print(f"api listening on :8080  db={db}  stripe={key[:8]}…  debug={os.environ['DEBUG']}")
"""
ENV = """DATABASE_URL=postgres://app:Xk29fQ@db.internal:5432/app
STRIPE_SECRET_KEY=sk_live_51HxPq0demo
OPENAI_API_KEY=sk-proj-4fQ2demo
DEBUG=false
"""


def _key(path, comment):
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric import ed25519
    k = ed25519.Ed25519PrivateKey.generate()
    with open(path, "wb") as fh:
        fh.write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.OpenSSH, s.NoEncryption()))
    os.chmod(path, 0o600)
    with open(path + ".pub", "wb") as fh:
        fh.write(k.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH) + f" {comment}\n".encode())


def prepare():
    os.makedirs(BUILD, exist_ok=True)
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX)
    home = os.path.join(SANDBOX, "home")
    os.makedirs(os.path.join(home, ".ssh"))
    os.makedirs(APP)
    _key(os.path.join(home, ".ssh", "id_ed25519"), "dev@laptop")
    _key(os.path.join(home, "sara"), "sara@contractor")
    _key(os.path.join(home, "outsider_key"), "outsider")
    with open(os.path.join(APP, ".env"), "w") as fh:
        fh.write(ENV)
    with open(os.path.join(APP, "app.py"), "w") as fh:
        fh.write(APP_PY)
    subprocess.run(["git", "init", "-q"], cwd=APP, check=True)
    EXPORTS["HOME"] = home
    EXPORTS.pop("GHSEAL_IDENTITY", None)


def gif():
    """Short silent GIF for the README: share, seal, run without plaintext, check."""
    prepare()
    t = Term()
    run_cmd("ghseal init && ghseal add ~/.ssh/id_ed25519.pub --name me", APP)
    cmds = ["ghseal add @hamarshehmhmd", "ghseal seal", "rm .env && ghseal run -- python3 app.py", "ghseal check"]
    frames_dir = os.path.join(BUILD, "gif")
    shutil.rmtree(frames_dir, ignore_errors=True)
    os.makedirs(frames_dir)
    imgs, lines = [], []
    prompt = [(PROMPT, (95, 215, 120), True)]
    for cmd in cmds:
        out = run_cmd(cmd, APP)
        for k in range(0, len(cmd) + 1, 3):
            imgs.append((t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True), 1))
        lines += t.wrap(prompt + [(cmd, FG, False)])
        imgs.append((t.frame(lines), 4))
        for ol in out.splitlines():
            lines += t.wrap(parse_ansi(ol))
        lines.append([])
        imgs.append((t.frame(lines), 22))
    imgs.append((t.frame(lines), 40))
    n = 0
    for img, count in imgs:
        for _ in range(count):
            img.resize((960, 540)).save(os.path.join(frames_dir, f"f{n:05d}.png"))
            n += 1
    dst = os.path.join(ROOT, "docs", "demo.gif")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", "12", "-i", os.path.join(frames_dir, "f%05d.png"),
                    "-vf", "split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=none", dst], check=True)
    print(dst, os.path.getsize(dst) // 1024, "KB")


def main():
    if "--gif" in sys.argv:
        return gif()
    prepare()
    parts = [render_scene(i, s, SANDBOX) for i, s in enumerate(SCENES)]
    with open(os.path.join(BUILD, "list.txt"), "w") as fh:
        fh.writelines(f"file '{p}'\n" for p in parts)
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i",
         os.path.join(BUILD, "list.txt"), "-c:v", "libx264", "-crf", "23", "-pix_fmt", "yuv420p",
         "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", OUT],
        check=True,
    )
    with open(os.path.join(BUILD, "narration.txt"), "w") as fh:
        fh.write("\n\n".join(s["say"] for s in SCENES) + "\n")
    print(OUT, round(duration(OUT), 1), "s")


if __name__ == "__main__":
    main()
