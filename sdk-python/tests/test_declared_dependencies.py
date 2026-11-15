"""Every third-party module the SDK imports is a dependency it declares.

A module that is only installed because another dependency needs it can
disappear in any release of that dependency, and ``import agent_did_sdk`` then
fails for every user.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
from importlib import metadata

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src" / "agent_did_sdk"


def _normalize(distribution: str) -> str:
    return re.sub(r"[-_.]+", "-", distribution).lower()


def _declared_distributions() -> set[str]:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    names = (re.split(r"[\s<>=!~;\[]", requirement, maxsplit=1)[0] for requirement in project["dependencies"])
    return {_normalize(name) for name in names}


def _extra_distributions() -> set[str]:
    """Distributions of the optional extras users install (``dev`` is for working on the SDK)."""
    extras = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"].get(
        "optional-dependencies", {}
    )
    names = (
        re.split(r"[\s<>=!~;\[]", requirement, maxsplit=1)[0]
        for extra, requirements in extras.items()
        if extra != "dev"
        for requirement in requirements
    )
    return {_normalize(name) for name in names}


def _module_level_imports() -> dict[str, set[str]]:
    """Top-level names imported when a module is loaded: outside functions and ``if TYPE_CHECKING:`` blocks."""
    imported: dict[str, set[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        pending: list[ast.AST] = list(tree.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test):
                pending.extend(node.orelse)
                continue
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                pending.extend(ast.iter_child_nodes(node))
                continue
            for name in names:
                imported.setdefault(name.split(".")[0], set()).add(path.relative_to(PACKAGE_ROOT).as_posix())
    return imported


def _imported_modules() -> dict[str, set[str]]:
    """Top-level names of the absolute imports in the package, with the files that import them."""
    imported: dict[str, set[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                imported.setdefault(name.split(".")[0], set()).add(path.relative_to(PACKAGE_ROOT).as_posix())
    return imported


def _modules_of(distribution: str) -> set[str]:
    """Top-level modules that an installed distribution provides, read from its file list.

    ``importlib.metadata.packages_distributions`` is not used: on Python 3.10 it
    only knows the distributions that ship a ``top_level.txt``.
    """
    modules = set()
    for file in metadata.distribution(distribution).files or []:
        top = file.parts[0]
        if top == ".." or top.endswith((".dist-info", ".data")) or top == "__pycache__":
            continue
        if len(file.parts) > 1:
            modules.add(top)
        elif file.suffix in {".py", ".so", ".pyd"}:
            modules.add(top.split(".")[0])
    return modules


def test_every_imported_module_is_a_declared_dependency() -> None:
    allowed = {"agent_did_sdk"} | sys.stdlib_module_names
    for distribution in _declared_distributions() | _extra_distributions():
        allowed |= _modules_of(distribution)
    undeclared = {module: sorted(files) for module, files in _imported_modules().items() if module not in allowed}

    assert undeclared == {}, f"imported but not declared in pyproject.toml dependencies or extras: {undeclared}"


def test_modules_of_optional_extras_are_imported_lazily() -> None:
    # ``import agent_did_sdk`` must work without the extras: their modules are imported inside the functions that
    # need them (which raise ImportError naming the extra).
    base = {"agent_did_sdk"} | sys.stdlib_module_names
    for distribution in _declared_distributions():
        base |= _modules_of(distribution)
    extra_only = set().union(*(_modules_of(name) for name in _extra_distributions())) - base
    eager = {module: sorted(files) for module, files in _module_level_imports().items() if module in extra_only}

    assert extra_only, "the optional extras provide no modules: is the extra installed?"
    assert eager == {}, f"modules of optional extras imported at module level: {eager}"


def test_the_check_reads_the_declared_dependencies() -> None:
    assert {"pynacl", "rfc8785", "did-webvh"} <= _declared_distributions()
    assert "nacl" in _modules_of("pynacl")
    assert "did_webvh" in _modules_of("did-webvh")
