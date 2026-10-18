"""Python call-site scanner for discovery snapshots (TASK-02 3.4).

Parses every .py file under a root with the standard `ast` module and lists
call sites into socket, http.client, urllib3, requests, httpx, subprocess,
os.open and the builtin open, together with the import aliases that reach them.
It also emits a simple call graph (qualified function -> resolved callees).

Stdlib only. It never executes or imports the scanned code and computes no
digests. Output is one JSON object on stdout:
{"callgraph": {...}, "call_sites": {...}}.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import dataclass, field

MODULE_TARGETS = ("socket", "http.client", "urllib3", "requests", "httpx", "subprocess")
EXACT_TARGETS = ("os.open", "open")
# Lowercase factories whose result is treated as an instance of the callee.
FACTORIES = ("socket.socket", "socket.create_connection", "requests.session")

LIMITATIONS = [
    "dynamic dispatch, getattr/setattr, monkeypatching and runtime imports (importlib, __import__) are not followed",
    "receiver types are tracked only for local names bound directly to a constructor call (CapWords name or a known factory) or `with ... as name`; attributes such as self.client are not typed",
    "calls through function arguments, return values and containers are not resolved",
]


def category(dotted: str | None) -> str | None:
    if not dotted:
        return None
    if dotted in EXACT_TARGETS:
        return dotted
    for t in MODULE_TARGETS:
        if dotted == t or dotted.startswith(t + "."):
            return t
    return None


def is_constructor(dotted: str) -> bool:
    last = dotted.rpartition(".")[2]
    return dotted in FACTORIES or last[:1].isupper()


def module_name(rel: str) -> str:
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


@dataclass
class Scope:
    qualname: str
    names: dict[str, str] = field(default_factory=dict)
    # Local names that came from an import (for import_alias reporting).
    imported: set[str] = field(default_factory=set)
    class_name: str | None = None


class FileScanner(ast.NodeVisitor):
    def __init__(self, rel: str, module: str, is_package: bool) -> None:
        self.rel = rel
        self.module = module
        self.package = module if is_package else module.rpartition(".")[0]
        self.scopes = [Scope(qualname=module)]
        self.module_defs: set[str] = set()
        self.sites: list[dict] = []
        self.imports: list[dict] = []
        self.graph: dict[str, set[str]] = {module: set()}

    # --- scopes -------------------------------------------------------
    @property
    def scope(self) -> Scope:
        return self.scopes[-1]

    def lookup(self, name: str) -> tuple[str | None, bool]:
        for s in reversed(self.scopes):
            if name in s.names:
                # "" marks a local binding that shadows outer names.
                return (s.names[name] or None), name in s.imported
        if name in self.module_defs:
            return f"{self.module}.{name}", False
        if name == "open":
            return "open", False
        return None, False

    # --- imports ------------------------------------------------------
    def _bind_import(self, local: str, target: str, line: int) -> None:
        self.scope.names[local] = target
        self.scope.imported.add(local)
        if category(target) or any(t.startswith(target + ".") for t in MODULE_TARGETS + EXACT_TARGETS):
            self.imports.append({"path": self.rel, "alias": local, "target": target, "line": line})

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.asname:
                self._bind_import(a.asname, a.name, node.lineno)
            else:
                top = a.name.split(".")[0]
                self._bind_import(top, top, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = node.module or ""
        if node.level:
            pkg = self.package.split(".") if self.package else []
            if node.level > 1:
                pkg = pkg[: len(pkg) - (node.level - 1)]
            base = ".".join([p for p in pkg + ([base] if base else []) if p])
        for a in node.names:
            if a.name == "*":
                continue
            target = f"{base}.{a.name}" if base else a.name
            self._bind_import(a.asname or a.name, target, node.lineno)

    # --- definitions --------------------------------------------------
    def _enter(self, name: str, node: ast.AST, is_class: bool) -> None:
        if len(self.scopes) == 1:
            self.module_defs.add(name)
        parent = self.scope
        qual = f"{parent.qualname}.{name}"
        parent.names[name] = qual
        parent.imported.discard(name)
        self.scopes.append(Scope(qualname=qual, class_name=qual if is_class else parent.class_name))
        if not is_class:
            self.graph.setdefault(qual, set())
            args = node.args  # type: ignore[attr-defined]
            extra = [a for a in (args.vararg, args.kwarg) if a is not None]
            for a in args.posonlyargs + args.args + args.kwonlyargs + extra:
                self.scope.names[a.arg] = ""
        self.generic_visit(node)
        self.scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for d in node.decorator_list:
            self.visit(d)
        self._enter(node.name, node, is_class=False)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for b in node.bases:
            self.visit(b)
        self._enter(node.name, node, is_class=True)

    # --- bindings -----------------------------------------------------
    def _bind_value(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        resolved = self.resolve(value.func) if isinstance(value, ast.Call) else None
        if resolved and is_constructor(resolved[0]):
            self.scope.names[target.id] = resolved[0]
        else:
            self.scope.names[target.id] = ""
        self.scope.imported.discard(target.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for t in node.targets:
            self._bind_value(t, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._bind_value(node.target, node.value)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_value(item.optional_vars, item.context_expr)
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    # --- calls --------------------------------------------------------
    def resolve(self, expr: ast.AST) -> tuple[str, str | None] | None:
        """Return (dotted name, import alias used) for a call target."""
        attrs: list[str] = []
        while isinstance(expr, ast.Attribute):
            attrs.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        attrs.reverse()
        if expr.id == "self" and self.scope.class_name and attrs:
            return ".".join([self.scope.class_name, *attrs]), None
        base, via_import = self.lookup(expr.id)
        if base is None:
            return None
        alias = expr.id if via_import and expr.id != base else None
        return ".".join([base, *attrs]), alias

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        resolved = self.resolve(node.func)
        if resolved is None:
            return
        dotted, alias = resolved
        caller = self.scope.qualname
        self.graph.setdefault(caller, set()).add(dotted)
        cat = category(dotted)
        if cat:
            self.sites.append({
                "caller": caller,
                "callee": dotted,
                "category": cat,
                "path": self.rel,
                "line": node.lineno,
                "column": node.col_offset + 1,
                "import_alias": alias,
            })


def collect_defs(tree: ast.Module) -> set[str]:
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def scan(root: str) -> dict:
    sites: list[dict] = []
    imports: list[dict] = []
    graph: dict[str, set[str]] = {}
    limitations = list(LIMITATIONS)
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for f in filenames:
            if f.endswith(".py"):
                files.append(os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/"))
    for rel in sorted(files):
        with open(os.path.join(root, rel), "rb") as fh:
            src = fh.read()
        try:
            tree = ast.parse(src, filename=rel)
        except (SyntaxError, ValueError) as e:
            limitations.append(f"not parsed: {rel}: {type(e).__name__}")
            continue
        fs = FileScanner(rel, module_name(rel), rel.endswith("__init__.py"))
        fs.module_defs = collect_defs(tree)
        fs.visit(tree)
        sites.extend(fs.sites)
        imports.extend(fs.imports)
        for k, v in fs.graph.items():
            graph.setdefault(k, set()).update(v)
    sites.sort(key=lambda s: (s["path"], s["line"], s["column"], s["callee"]))
    imports.sort(key=lambda i: (i["path"], i["line"], i["alias"]))
    return {
        "callgraph": {k: sorted(v) for k, v in sorted(graph.items())},
        "call_sites": {
            "language": "python",
            "tool": "python-ast",
            "call_sites": sites,
            "imports": imports,
            "limitations": limitations,
        },
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: scan.py <root>", file=sys.stderr)
        return 2
    json.dump(scan(argv[1]), sys.stdout, ensure_ascii=False, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
