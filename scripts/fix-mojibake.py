"""Preview or apply narrow cp1251->UTF-8 mojibake repairs."""

from __future__ import annotations

import argparse
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXTENSIONS = (".py", ".md", ".ps1")
SKIPPED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".python",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}
MOJIBAKE_MARKERS = (
    "Р" + "џ",
    "Р" + "ђ",
    "Р" + "Ѕ" + "Р",
    "С" + "Њ",
    "С" + "Ѓ",
    "р" + "џ",
    "в" + "њ",
    "в" + "љ",
    "В" + "«",
    "В" + "»",
    "В" + "·",
    "в" + "Ђ",
)


def iter_text_files(paths: list[Path], extensions: tuple[str, ...]):
    for root in paths:
        if root.is_file():
            candidates = [root]
        else:
            candidates = root.rglob("*")

        for path in candidates:
            if not path.is_file() or path.suffix.lower() not in extensions:
                continue
            try:
                relative_parts = path.relative_to(REPO_ROOT).parts
            except ValueError:
                relative_parts = path.parts
            if any(part in SKIPPED_DIRS for part in relative_parts[:-1]):
                continue
            yield path


def line_has_marker(line: str) -> bool:
    return any(marker in line for marker in MOJIBAKE_MARKERS)


def repair_line(line: str) -> str | None:
    try:
        return line.encode("cp1251").decode("utf-8")
    except UnicodeError:
        return None


def repair_file(path: Path, apply: bool) -> tuple[int, int]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    changed = 0
    manual = 0
    new_lines = []

    for line_number, line in enumerate(lines, start=1):
        if not line_has_marker(line):
            new_lines.append(line)
            continue

        fixed = repair_line(line)
        relative_path = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
        print(f"{relative_path}:{line_number}")
        print(f"  old: {line.rstrip()}")

        if fixed is None:
            manual += 1
            new_lines.append(line)
            print("  new: <manual repair required>")
            continue

        changed += 1
        new_lines.append(fixed)
        print(f"  new: {fixed.rstrip()}")

    if apply and changed and manual == 0:
        path.write_text("".join(new_lines), encoding="utf-8")

    return changed, manual


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preview cp1251-decoded mojibake repairs; use --apply to rewrite files."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[REPO_ROOT],
        help="Files or directories to scan. Defaults to the repository root.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Rewrite files after previewing all changed lines.",
    )
    parser.add_argument(
        "--ext",
        action="append",
        default=[],
        help="Text extension to scan, for example --ext .txt. Can be repeated.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    extensions = tuple(ext if ext.startswith(".") else f".{ext}" for ext in args.ext)
    if not extensions:
        extensions = DEFAULT_EXTENSIONS

    total_changed = 0
    total_manual = 0
    for path in iter_text_files(args.paths, extensions):
        changed, manual = repair_file(path, args.apply)
        total_changed += changed
        total_manual += manual

    if total_manual:
        print(f"Manual repairs required: {total_manual}. No unsafe partial fixes were applied.")
        return 2
    if args.apply:
        print(f"Applied repairs: {total_changed}")
    else:
        print(f"Preview repairs: {total_changed}. Re-run with --apply to write changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
