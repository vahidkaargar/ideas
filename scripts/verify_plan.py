#!/usr/bin/env python3
"""Structural and cross-reference verifier for this repo's DNS plan documents.

Checks, across dns-server-plan.md and every phases/*.md file:
  1. Fenced code blocks are balanced (even ``` count) per file.
  2. Every embedded ```yaml, ```python and ```bash block parses. Bash blocks
     containing an angle-bracket placeholder (<PUBLIC_IP>, <vB>, <NEW-IP>,
     <the older version from madison>, ...) are skipped, since '<' reads as
     shell redirection there and is a false positive, not a real syntax
     error. A genuinely unclosed heredoc inside a block still fails `bash -n`
     normally — this skip only applies when a placeholder is present.
  3. Every markdown link resolves to a real file: 'phases/NN-*.md' links from
     the index, '../dns-server-plan.md' links back from a phase file, and
     relative './NN-*.md' nav links between phase files.

Exit status is non-zero if anything fails. Run this after any edit to
dns-server-plan.md or phases/*.md before considering the edit done.

Deliberately NOT attempted: a blacklist of "forbidden" strings (setcap,
DNSStubListener, stale table names, ...). This document explains at length,
in prose, what NOT to do and why — those exact words appear constantly in
correct, load-bearing warning sentences ("no phase grants a capability with
setcap", "there is no DNSStubListener setting"). A bare grep cannot tell a
live regression from the sentence that prevents one; an early version of
this script tried it and produced ~70 false positives on an otherwise clean
document. If you need to check for a specific regression, grep for it
deliberately and read the surrounding context — do not encode it here as a
blanket gate.
"""
import ast
import re
import subprocess
import sys
import tempfile
import os
from pathlib import Path

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "dns-server-plan.md"
PHASES = ROOT / "phases"

PLACEHOLDER = re.compile(r"<[^<>\n]+>")


def scan_fences(text):
    """Yield (lang, start_line, code) for every fenced block."""
    lines = text.split("\n")
    blocks, cur, lang, start = [], None, None, 0
    for i, line in enumerate(lines, 1):
        m = re.match(r"^```(\w*)\s*$", line)
        if m and cur is None:
            lang, cur, start = m.group(1), [], i
        elif line.strip() == "```" and cur is not None:
            blocks.append((lang, start, "\n".join(cur)))
            cur = None
        elif cur is not None:
            cur.append(line)
    return blocks


def check_file(path, errors):
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(ROOT)

    fence_lines = len(re.findall(r"^```", text, re.MULTILINE))
    if fence_lines % 2 != 0:
        errors.append(f"{rel}: odd number of ``` fence markers ({fence_lines}) — an unclosed code block")

    for lang, start, code in scan_fences(text):
        if lang == "yaml" and HAVE_YAML:
            try:
                yaml.safe_load(code)
            except Exception as e:
                errors.append(f"{rel}:{start}: yaml block fails to parse — {str(e).splitlines()[0]}")
        elif lang == "python":
            try:
                ast.parse(code)
            except SyntaxError as e:
                errors.append(f"{rel}:{start}: python block fails to parse — {e}")
        elif lang == "bash":
            if PLACEHOLDER.search(code):
                continue  # e.g. <PUBLIC_IP>, <vB>, <NEW-IP> — '<' is not redirection here
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
                f.write(code)
                tmp = f.name
            r = subprocess.run(["bash", "-n", tmp], capture_output=True, text=True)
            os.unlink(tmp)
            if r.returncode != 0:
                errors.append(f"{rel}:{start}: bash block fails `bash -n` — {r.stderr.strip().splitlines()[0]}")

    return text


def check_links(index_text, phase_texts, errors):
    for m in re.finditer(r"phases/([\w.-]+\.md)", index_text):
        target = PHASES / m.group(1)
        if not target.exists():
            errors.append(f"dns-server-plan.md: links to phases/{m.group(1)}, which does not exist")

    for name, text in phase_texts.items():
        for m in re.finditer(r"\.\./([\w.-]+\.md)", text):
            target = ROOT / m.group(1)
            if not target.exists():
                errors.append(f"phases/{name}: link to ../{m.group(1)}, which does not exist")
        for m in re.finditer(r"(?<!\.)\./([\w.-]+\.md)", text):
            target = PHASES / m.group(1)
            if not target.exists():
                errors.append(f"phases/{name}: nav link to ./{m.group(1)}, which does not exist")


def main():
    if not INDEX.exists():
        sys.exit(f"missing {INDEX}")

    errors, warnings = [], []

    index_text = check_file(INDEX, errors)

    phase_files = sorted(PHASES.glob("*.md"))
    if not phase_files:
        sys.exit(f"no phase files found under {PHASES}")

    phase_texts = {f.name: check_file(f, errors) for f in phase_files}

    check_links(index_text, phase_texts, errors)

    if not HAVE_YAML:
        warnings.append("PyYAML not installed — yaml blocks were not syntax-checked (pip install pyyaml)")

    n_files = 1 + len(phase_files)
    n_blocks = sum(len(scan_fences(t)) for t in [index_text, *phase_texts.values()])

    print(f"checked {n_files} files, {n_blocks} fenced code blocks")

    if warnings:
        print(f"\n{len(warnings)} warning(s):")
        for w in warnings:
            print(f"  ! {w}")

    if errors:
        print(f"\n{len(errors)} error(s):")
        for e in errors:
            print(f"  x {e}")
        print("\nFAIL")
        return 1

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
