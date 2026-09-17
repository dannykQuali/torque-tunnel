"""Static analysis gate over every Python file in the project.

Motivated by a real regression: the credential call was threaded into six near-identical
handlers by hand, and `handle_run_on_tunneled_ssh` rebound its `config` parameter while the
other five used a `cfg` local. Passing `cfg` there was an undefined name, so *every* SSH
call failed — including ones with no credential, because Python evaluates arguments before
the callee can return early.

No amount of schema or unit testing sees that. A parser does, instantly, across the whole
tree. pyflakes is used rather than a hand-rolled AST walk because it is scope-aware: a flat
walk collecting every assignment in the module would have considered `cfg` defined, since
five *other* functions assign it — which is precisely how the bug hid.

The gate is fail-closed: everything pyflakes can report is an error except an explicit list
of cosmetic classes, so a check added by a future pyflakes release starts out enforced.
"""

import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

pyflakes_checker = pytest.importorskip(
    "pyflakes.checker",
    reason="pyflakes is required for the static-analysis gate (see requirements-dev.txt)",
)
pyflakes_messages = pytest.importorskip("pyflakes.messages")

from pyflakes.checker import Checker  # noqa: E402
from pyflakes import messages as pfm  # noqa: E402


REPO = Path(__file__).resolve().parent.parent

#: Directories that are not ours to police.
SKIP_PARTS = {".venv", "build", "dist", "__pycache__", ".tmp", ".hypothesis",
              ".git", ".pytest_cache", "egg-info"}

#: Findings that are untidy but cannot change behaviour. Everything NOT listed here fails
#: the gate, so the default for anything new is "enforced".
COSMETIC = (
    pfm.UnusedImport,
    pfm.UnusedVariable,
    pfm.UnusedAnnotation,
    pfm.UnusedIndirectAssignment,
    pfm.RedefinedWhileUnused,
)


def project_python_files() -> list[Path]:
    files = [
        p for p in sorted(REPO.rglob("*.py"))
        if not any(part in SKIP_PARTS or part.endswith(".egg-info") for part in p.parts)
    ]
    assert files, "no Python files discovered - the gate would pass vacuously"
    return files


def check_source(source: str, filename: str) -> list:
    """Every pyflakes finding for one file that is not merely cosmetic."""
    tree = ast.parse(source, filename)
    return [
        m for m in Checker(tree, filename=filename).messages
        if not isinstance(m, COSMETIC)
    ]


# ============================================================================
# The gate
# ============================================================================

def test_no_undefined_names_or_real_defects_anywhere():
    problems = []
    for path in project_python_files():
        # utf-8-sig: auth.py carries a BOM, and the parser must not see it as source.
        source = path.read_text(encoding="utf-8-sig")
        for msg in check_source(source, str(path)):
            problems.append(f"{path.relative_to(REPO)}:{msg.lineno}: {msg.message % msg.message_args}")
    assert not problems, "static analysis found real defects:\n  " + "\n  ".join(problems)


def test_every_file_parses():
    """A syntax error in a file no test imports would otherwise go unnoticed."""
    broken = []
    for path in project_python_files():
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), str(path))
        except SyntaxError as e:
            broken.append(f"{path.relative_to(REPO)}:{e.lineno}: {e.msg}")
    assert not broken, "files failed to parse:\n  " + "\n  ".join(broken)


def test_the_gate_covers_the_whole_project():
    """Guards against the skip list quietly swallowing our own source."""
    covered = {p.relative_to(REPO).as_posix() for p in project_python_files()}
    for expected in (
        "src/torque_tunnel/mcp_tool.py",
        "src/torque_tunnel/credentials.py",
        "src/torque_tunnel/torque_client.py",
        "src/torque_tunnel/auth.py",
        "src/torque_tunnel/config.py",
    ):
        assert expected in covered, f"{expected} is not being checked"


# ============================================================================
# Proof the gate detects the bug it exists for
# ============================================================================

#: The exact shape of the regression: a name assigned in one function, used in another.
#: A module-flat AST walk sees `cfg` assigned and concludes it is fine; a scope-aware
#: checker does not.
CFG_REGRESSION = '''
def handler_a(arguments, config=None):
    cfg = config or {}
    return prepare(arguments, cfg)


def handler_b(arguments, config=None):
    config = config or {}
    return prepare(arguments, cfg)


def prepare(arguments, cfg):
    return cfg
'''


def test_gate_detects_the_cfg_regression():
    found = check_source(CFG_REGRESSION, "synthetic.py")
    undefined = [m for m in found if isinstance(m, pfm.UndefinedName)]
    assert undefined, f"gate missed the regression it exists for; saw: {found}"
    assert "cfg" in (undefined[0].message % undefined[0].message_args)


def test_a_flat_ast_walk_would_have_missed_it():
    """Documents why pyflakes is used instead of the obvious hand-rolled check."""
    tree = ast.parse(CFG_REGRESSION)
    assigned = {
        n.id for n in ast.walk(tree)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
    }
    assert "cfg" in assigned, (
        "a module-flat walk sees `cfg` as defined - which is exactly how the bug survived"
    )


@pytest.mark.parametrize("snippet,expected", [
    ("def f():\n    return undefined_thing\n", pfm.UndefinedName),
    # Use-before-assignment inside a function with no outer binding.
    ("def f():\n    print(x)\n    x = 1\n", pfm.UndefinedName),
    # Same, but shadowing a module-level name — pyflakes calls this UndefinedLocal.
    ("x = 1\ndef f():\n    print(x)\n    x = 2\n", pfm.UndefinedLocal),
    ("def f(a, a):\n    pass\n", pfm.DuplicateArgument),
    ("def f():\n    raise NotImplemented\n", pfm.RaiseNotImplemented),
    ("def f(v):\n    return v is 'x'\n", pfm.IsLiteral),
])
def test_gate_is_wired_to_the_defect_classes_that_matter(snippet, expected):
    found = check_source(snippet, "synthetic.py")
    assert any(isinstance(m, expected) for m in found), \
        f"{expected.__name__} not reported; saw: {found}"


def test_gate_ignores_cosmetic_findings():
    """Otherwise it could never be green without an unrelated cleanup, and a gate that is
    always red is a gate nobody reads."""
    assert check_source("import os\n", "synthetic.py") == []
    assert check_source("def f():\n    unused = 1\n", "synthetic.py") == []


# ============================================================================
# Uniformity of the handler plumbing
# ============================================================================

MCP_TOOL = REPO / "src" / "torque_tunnel" / "mcp_tool.py"


def _run_handlers() -> list:
    tree = ast.parse(MCP_TOOL.read_text(encoding="utf-8-sig"), str(MCP_TOOL))
    return [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name.startswith("handle_run_on_tunneled_")
    ]


def test_every_run_handler_resolves_its_config_into_the_same_local():
    """The divergence itself was the bug. Keeping the name uniform means a copy-pasted
    plumbing line cannot be wrong in one handler and right in five."""
    handlers = _run_handlers()
    assert len(handlers) == 6, [h.name for h in handlers]

    for fn in handlers:
        assigns_cfg = any(
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "cfg" for t in node.targets)
            for node in ast.walk(fn)
        )
        assert assigns_cfg, f"{fn.name} does not resolve its config into `cfg`"

        # And it must not shadow the parameter instead, which is what diverged before.
        rebinds_param = any(
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "config" for t in node.targets)
            for node in ast.walk(fn)
        )
        assert not rebinds_param, (
            f"{fn.name} rebinds its `config` parameter instead of using `cfg`; keep the "
            f"local name uniform across all six handlers"
        )


def test_every_run_handler_passes_that_same_local_to_prepare_credential():
    for fn in _run_handlers():
        calls = [
            node for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_prepare_credential"
        ]
        assert len(calls) == 1, f"{fn.name} has {len(calls)} credential calls, expected 1"
        second_arg = calls[0].args[1]
        assert isinstance(second_arg, ast.Name) and second_arg.id == "cfg", (
            f"{fn.name} passes {ast.dump(second_arg)} as the config argument, not `cfg`"
        )
