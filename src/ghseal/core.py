"""Project config (.ghseal.json), sealing, opening and consistency checks."""
from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pyrage

from . import armor, dotenv, keys

CONFIG = ".ghseal.json"


class GhsealError(Exception):
    pass


@dataclass
class Project:
    root: Path
    data: dict = field(default_factory=dict)

    # -------------------------------------------------------------- loading
    @classmethod
    def find(cls, start: str | os.PathLike | None = None) -> "Project":
        here = Path(start or os.getcwd()).resolve()
        for d in [here, *here.parents]:
            if (d / CONFIG).is_file():
                try:
                    data = json.loads((d / CONFIG).read_text())
                except json.JSONDecodeError as e:
                    raise GhsealError(f"{d / CONFIG}: invalid JSON ({e})") from None
                return cls(d, data)
        raise GhsealError(f"no {CONFIG} found here or in a parent directory (run `ghseal init`)")

    @classmethod
    def init(cls, root: str | os.PathLike, plain: str = ".env") -> "Project":
        root = Path(root).resolve()
        if (root / CONFIG).exists():
            raise GhsealError(f"{root / CONFIG} already exists")
        p = cls(root, {"version": 1, "files": [], "recipients": []})
        p.add_file(plain)
        p.save()
        return p

    def save(self) -> None:
        (self.root / CONFIG).write_text(json.dumps(self.data, indent=2) + "\n")

    # -------------------------------------------------------------- files
    @property
    def files(self) -> list[dict]:
        return self.data.setdefault("files", [])

    def add_file(self, plain: str, sealed: str | None = None) -> dict:
        plain = Path(plain).as_posix()
        for f in self.files:
            if f["plain"] == plain:
                return f
        entry = {"plain": plain, "sealed": sealed or plain + ".sealed"}
        self.files.append(entry)
        return entry

    def file(self, plain: str | None = None) -> dict:
        if not self.files:
            raise GhsealError("no files configured (run `ghseal init` or `ghseal track FILE`)")
        if plain is None:
            return self.files[0]
        want = Path(plain).as_posix()
        for f in self.files:
            if want in (f["plain"], f["sealed"]):
                return f
        raise GhsealError(f"{plain} is not tracked by ghseal (run `ghseal track {plain}`)")

    def path(self, rel: str) -> Path:
        return self.root / rel

    # -------------------------------------------------------------- recipients
    @property
    def recipients(self) -> list[dict]:
        return self.data.setdefault("recipients", [])

    def recipient(self, name: str) -> dict | None:
        name = name.lstrip("@")
        for r in self.recipients:
            if r["name"] == name or r["source"].split(":", 1)[-1] == name:
                return r
        return None

    def add_recipient(self, spec: keys.Spec) -> dict:
        if not spec.keys:
            raise GhsealError(f"{spec.source}: no usable keys (age supports ssh-ed25519, ssh-rsa and age1 keys)")
        if self.recipient(spec.name):
            raise GhsealError(f"recipient {spec.name!r} already exists (use `ghseal refresh` to update keys)")
        r = {"name": spec.name, "source": spec.source, "keys": spec.keys,
             "added": _dt.date.today().isoformat()}
        self.recipients.append(r)
        return r

    def all_keys(self) -> list[str]:
        out: list[str] = []
        for r in self.recipients:
            for k in r["keys"]:
                if k not in out:
                    out.append(k)
        return out

    # -------------------------------------------------------------- crypto
    def encrypt(self, plaintext: bytes) -> str:
        ks = self.all_keys()
        if not ks:
            raise GhsealError("no recipients yet: add yourself first, e.g. `ghseal add @your-github-username`")
        return armor.armor(pyrage.encrypt(plaintext, [keys.to_recipient(k) for k in ks]))

    def decrypt_file(self, sealed: Path, identities=None) -> bytes:
        if not sealed.is_file():
            raise GhsealError(f"{sealed.relative_to(self.root)} does not exist (run `ghseal seal`)")
        ids = identities
        if ids is None:
            ids, _ = keys.load_identities()
        if not ids:
            raise GhsealError("no identity found: looked for ~/.ssh/id_ed25519, ~/.ssh/id_rsa, "
                              "~/.config/ghseal/keys.txt, $GHSEAL_IDENTITY and $GHSEAL_AGE_KEY")
        try:
            return pyrage.decrypt(armor.dearmor(sealed.read_bytes()), ids)
        except pyrage.DecryptError:
            raise GhsealError(f"none of your keys can open {sealed.relative_to(self.root)} "
                              "(ask a teammate to `ghseal add` you and re-seal)") from None

    def open_env(self, plain: str | None = None, identities=None) -> tuple[dict, bytes]:
        f = self.file(plain)
        data = self.decrypt_file(self.path(f["sealed"]), identities)
        return f, data

    def seal(self, plain: str | None = None, identities=None, force: bool = False,
             text: bytes | None = None) -> str:
        """Encrypt the plaintext file to every recipient. Returns 'sealed', 'unchanged'."""
        f = self.file(plain)
        src = self.path(f["plain"])
        if text is None:
            if not src.is_file():
                raise GhsealError(f"{f['plain']} does not exist")
            text = src.read_bytes()
        try:
            dotenv.parse(text.decode("utf-8"))
        except (dotenv.DotenvError, UnicodeDecodeError) as e:
            raise GhsealError(f"{f['plain']}: {e}") from None
        dst = self.path(f["sealed"])
        if dst.is_file() and not force and not recipient_problems(self, dst):
            try:
                ids = identities if identities is not None else keys.load_identities()[0]
                if ids and pyrage.decrypt(armor.dearmor(dst.read_bytes()), ids) == text:
                    return "unchanged"
            except Exception:
                pass
        dst.write_text(self.encrypt(text))
        return "sealed"


def recipient_problems(project: Project, sealed: Path) -> list[str]:
    """Compare the age header of a sealed file with the configured recipients."""
    try:
        stanzas = armor.header_stanzas(armor.dearmor(sealed.read_bytes()))
    except ValueError as e:
        return [f"{sealed.name}: unreadable age file ({e})"]
    present = {s[1] for s in stanzas if s and s[0] in keys.SUPPORTED and len(s) > 1}
    n_x25519 = sum(1 for s in stanzas if s and s[0] == "X25519")
    probs = []
    want_ssh = {}
    n_age = 0
    for r in project.recipients:
        for k in r["keys"]:
            if k.startswith("age1"):
                n_age += 1
            else:
                want_ssh.setdefault(keys.ssh_tag(k), r["name"])
    for tag, who in want_ssh.items():
        if tag not in present:
            probs.append(f"not sealed to {who} yet")
    extra = present - set(want_ssh)
    if extra:
        probs.append(f"still readable by {len(extra)} SSH key(s) that are no longer in {CONFIG} "
                     "(re-seal, then rotate those secrets)")
    if n_x25519 != n_age:
        probs.append(f"sealed to {n_x25519} age key(s) but {CONFIG} lists {n_age}")
    return probs


def env_diff(old: dict, new: dict) -> tuple[list[str], list[str], list[str]]:
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    changed = [k for k in new if k in old and old[k] != new[k]]
    return added, removed, changed


def git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    except FileNotFoundError:
        return None


def in_git(root: Path) -> bool:
    p = git(root, "rev-parse", "--is-inside-work-tree")
    return bool(p and p.returncode == 0 and p.stdout.strip() == "true")


def ensure_gitignored(root: Path, plain: str) -> bool:
    """Append plain to .gitignore unless git already ignores it. Returns True if changed."""
    if in_git(root):
        p = git(root, "check-ignore", "-q", "--no-index", plain)
        if p and p.returncode == 0:
            return False
    gi = root / ".gitignore"
    text = gi.read_text() if gi.exists() else ""
    if plain in [l.strip().lstrip("/") for l in text.splitlines()]:
        return False
    if text and not text.endswith("\n"):
        text += "\n"
    gi.write_text(text + f"# ghseal: plaintext secrets stay local\n/{plain}\n")
    return True


@dataclass
class Finding:
    level: str  # "error" | "warn" | "ok"
    msg: str


def check(project: Project, identities=None) -> list[Finding]:
    from . import guard

    out: list[Finding] = []
    if not project.recipients:
        out.append(Finding("error", f"{CONFIG} has no recipients"))
    git_ok = in_git(project.root)
    for f in project.files:
        sealed = project.path(f["sealed"])
        plain = project.path(f["plain"])
        if not sealed.is_file():
            out.append(Finding("error", f"{f['sealed']} missing (run `ghseal seal {f['plain']}`)"))
        else:
            probs = recipient_problems(project, sealed)
            for p in probs:
                out.append(Finding("error", f"{f['sealed']}: {p}"))
            if not probs:
                out.append(Finding("ok", f"{f['sealed']} is sealed to all {len(project.recipients)} recipient(s)"))
        if git_ok:
            t = git(project.root, "ls-files", "--error-unmatch", f["plain"])
            if t and t.returncode == 0:
                out.append(Finding("error", f"{f['plain']} (plaintext) is committed to git: "
                                            f"`git rm --cached {f['plain']}` and rotate its secrets"))
            else:
                ig = git(project.root, "check-ignore", "-q", "--no-index", f["plain"])
                if ig and ig.returncode != 0:
                    out.append(Finding("warn", f"{f['plain']} is not in .gitignore"))
        if plain.is_file() and sealed.is_file():
            try:
                ids = identities if identities is not None else keys.load_identities()[0]
                if ids:
                    inside = pyrage.decrypt(armor.dearmor(sealed.read_bytes()), ids)
                    a, r, c = env_diff(dotenv.parse(inside.decode()), dotenv.parse(plain.read_text()))
                    if a or r or c:
                        parts = [f"+{k}" for k in a] + [f"-{k}" for k in r] + [f"~{k}" for k in c]
                        out.append(Finding("warn", f"{f['plain']} has unsealed changes: {' '.join(parts)} "
                                                   "(run `ghseal seal`)"))
            except Exception:
                pass
    missing = guard.missing(project)
    if missing:
        out.append(Finding("warn", "AI agent ignore rules missing in: " + ", ".join(missing)
                           + " (run `ghseal guard`)"))
    return out
