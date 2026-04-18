#!/usr/bin/env python3
"""Reject sync `subprocess.*` calls inside `async def` bodies.

Guards CLAUDE.md learned rule #5: sync subprocess blocks the event
loop.  Use `asyncio.create_subprocess_exec` instead, or wrap the
sync call with `await loop.run_in_executor(None, sync_fn, *args)`.

AST-based (not grep-based) so it correctly distinguishes an async
function that contains a nested sync helper from an async function
that itself calls subprocess.

Usage:
    python backend/scripts/lint_async_subprocess.py backend/app

Exits 0 on clean, 1 on violations.  Violations print
`path:line:col funcname -> offending.call`.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

_BLOCKING_CALLS = {"run", "Popen", "call", "check_call", "check_output"}


def _is_subprocess_blocking(node: ast.Call) -> bool:
    """Match subprocess.run / Popen / call / check_call / check_output."""
    func = node.func
    # subprocess.run(...)  or  sp.run(...)
    if isinstance(func, ast.Attribute) and func.attr in _BLOCKING_CALLS:
        v = func.value
        # Accept `subprocess.<call>` directly.  Other `sp.<call>` aliases
        # go undetected — acceptable false-negative trade-off.
        if isinstance(v, ast.Name) and v.id == "subprocess":
            return True
    return False


def _scan_async_body(
    func_node: ast.AsyncFunctionDef,
    path: Path,
    violations: list[str],
) -> None:
    # Walk only inside the AsyncFunctionDef body, and do not descend into
    # nested (sync) FunctionDef / AsyncFunctionDef — those get their own
    # scan iteration at the module level.
    for child in ast.walk(func_node):
        if child is func_node:
            continue
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Nested def — skip; the module-level walk will cover it.
            # To avoid descending into it here, replace the attribute
            # iteration with a manual traversal.  ast.walk doesn't support
            # prune, so we detect and filter via lineno range after
            # collecting.
            continue
    # Two-pass: collect nested-def line ranges to skip, then look for
    # subprocess calls outside those ranges.
    skip_ranges: list[tuple[int, int]] = []
    for child in ast.iter_child_nodes(func_node):
        for deep in ast.walk(child):
            if isinstance(deep, (ast.FunctionDef, ast.AsyncFunctionDef)):
                skip_ranges.append(
                    (deep.lineno, (deep.end_lineno or deep.lineno))
                )

    def _in_skip(line: int) -> bool:
        return any(lo <= line <= hi for lo, hi in skip_ranges)

    for child in ast.walk(func_node):
        if not isinstance(child, ast.Call):
            continue
        if not _is_subprocess_blocking(child):
            continue
        if _in_skip(child.lineno):
            continue
        attr = child.func.attr if isinstance(child.func, ast.Attribute) else "?"
        violations.append(
            f"{path}:{child.lineno}:{child.col_offset} "
            f"async def {func_node.name} calls subprocess.{attr}"
        )


def scan_file(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError:
        return []
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            _scan_async_body(node, path, violations)
    return violations


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: lint_async_subprocess.py <path> [path...]", file=sys.stderr)
        return 2
    all_violations: list[str] = []
    for root in argv[1:]:
        for py in Path(root).rglob("*.py"):
            if "__pycache__" in py.parts or ".venv" in py.parts:
                continue
            all_violations.extend(scan_file(py))
    if all_violations:
        print("Sync subprocess inside async def (CLAUDE.md learned rule #5):")
        for v in all_violations:
            print(f"  {v}")
        print(
            f"\n{len(all_violations)} violation(s).  Use "
            "asyncio.create_subprocess_exec or run_in_executor instead."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
