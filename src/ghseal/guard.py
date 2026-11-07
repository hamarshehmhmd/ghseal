"""Write ignore/deny rules so AI coding agents don't read plaintext env files.

These are best-effort: an agent with shell access can still `cat` a file, which is
why `ghseal run` (no plaintext on disk at all) is the stronger option.
"""
from __future__ import annotations

import json
from pathlib import Path

BEGIN = "# >>> ghseal: keep plaintext secrets away from AI agents"
END = "# <<< ghseal"
IGNORE_FILES = {
    ".cursorignore": "Cursor",
    ".aiexclude": "Gemini Code Assist / Android Studio",
    ".codeiumignore": "Windsurf / Codeium",
    ".aiderignore": "aider",
}
CLAUDE = ".claude/settings.json"
EXTRA = [".env.local", ".env.*.local"]


def patterns(project) -> list[str]:
    pats = []
    for f in project.files:
        for p in (f["plain"],):
            if p not in pats:
                pats.append(p)
    for p in EXTRA:
        if p not in pats:
            pats.append(p)
    return pats


def _block(pats: list[str]) -> str:
    return "\n".join([BEGIN, *pats, END]) + "\n"


def _apply_ignore(path: Path, pats: list[str]) -> bool:
    text = path.read_text() if path.exists() else ""
    block = _block(pats)
    if BEGIN in text and END in text:
        pre, rest = text.split(BEGIN, 1)
        post = rest.split(END, 1)[1].lstrip("\n")
        new = pre + block + post
    else:
        new = text + ("\n" if text and not text.endswith("\n") else "") + block
    if new != text:
        path.write_text(new)
        return True
    return False


def _deny_rules(pats: list[str]) -> list[str]:
    return [f"Read(./{p})" for p in pats]


def _apply_claude(path: Path, pats: list[str]) -> bool:
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            raise ValueError(f"{path}: invalid JSON, not touching it") from None
    deny = data.setdefault("permissions", {}).setdefault("deny", [])
    changed = False
    for rule in _deny_rules(pats):
        if rule not in deny:
            deny.append(rule)
            changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
    return changed


def apply(project) -> list[str]:
    pats = patterns(project)
    changed = []
    for name in IGNORE_FILES:
        if _apply_ignore(project.root / name, pats):
            changed.append(name)
    if _apply_claude(project.root / CLAUDE, pats):
        changed.append(CLAUDE)
    return changed


def missing(project) -> list[str]:
    pats = patterns(project)
    out = []
    for name in IGNORE_FILES:
        p = project.root / name
        lines = p.read_text().splitlines() if p.exists() else []
        if not all(x in lines for x in pats[: len(project.files)]):
            out.append(name)
    p = project.root / CLAUDE
    try:
        deny = json.loads(p.read_text()).get("permissions", {}).get("deny", []) if p.exists() else []
    except json.JSONDecodeError:
        deny = []
    if not all(r in deny for r in _deny_rules(pats[: len(project.files)])):
        out.append(CLAUDE)
    return out
