#!/usr/bin/env python3
"""CodeGraph - call graph, entry-point flow and critical points for any Python folder.

    python codegraph.py                 start the local app, pick a folder in the page
    python codegraph.py <folder>        start the app with that folder opened
    python codegraph.py <folder> --export graph.html   write one standalone HTML file

The first time a folder is opened, one LLM call (the `claude` CLI) writes the
setup: entry points, noise files to skip, project-specific critical rules and
key functions. The setup and the scan are cached under ~/.codegraph, so every
later open needs no LLM. "Rescan" re-reads the code with the stored setup.
Standard library only.
"""
import argparse
import ast
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = 3
HERE = Path(__file__).resolve().parent
CACHE = Path(os.environ.get("CODEGRAPH_HOME", str(Path.home() / ".codegraph")))
SKIP_DIRS = {"__pycache__", "node_modules", "venv", "env", "site-packages", "build", "dist",
             "wandb", "checkpoints", "outputs"}
MAX_FILE_BYTES = 1_500_000
MAX_FILES = 4000
SRC_LINES = 90

SEV_W = {"high": 5, "medium": 2, "low": 1}
CATS = {
    "process":     ("External process",   "#f97316", "Launches another program or shell command."),
    "dynamic":     ("Dynamic code",       "#ef4444", "Runs code built at run time (eval / exec)."),
    "destructive": ("Destructive",        "#dc2626", "Deletes files or kills processes."),
    "fswrite":     ("Writes files",       "#eab308", "Creates, overwrites or moves files."),
    "network":     ("Network",            "#06b6d4", "Talks to another machine or service."),
    "load":        ("Unsafe load",        "#a855f7", "Loads data that can carry code (pickle, torch.load, yaml.load)."),
    "exit":        ("Exits program",      "#f43f5e", "Stops the whole program from inside a function."),
    "concurrency": ("Concurrency",        "#8b5cf6", "Starts threads, processes, tasks or signal handlers."),
    "wait":        ("Sleeps",             "#64748b", "Blocks on a fixed sleep."),
    "swallow":     ("Swallows errors",    "#fb7185", "Catches broad exceptions; failures can pass silently."),
    "loop":        ("Unbounded loop",     "#f59e0b", "while True - ends only through break / return / exception."),
    "global":      ("Global state",       "#94a3b8", "Rebinds module-level state."),
    "complexity":  ("Complex",            "#3b82f6", "Many branches; hard to test every path."),
    "hub":         ("Hub",                "#10b981", "Called from many places; a change here ripples widely."),
    "long":        ("Long function",      "#78909c", "Very long body."),
    "recursion":   ("Recursive",          "#14b8a6", "Calls itself."),
    "custom":      ("Project rule",       "#ec4899", "Project-specific risky call found by the AI setup."),
    "key":         ("Key function",       "#facc15", "Marked by the AI setup as needing care."),
}
RULES = [
    (r"^subprocess\.(run|Popen|call|check_call|check_output|getoutput|getstatusoutput)$", "process", "high", "Launches an external process"),
    (r"^os\.(system|popen|exec[lv]\w*|spawn\w*|startfile)$", "process", "high", "Launches an external process"),
    (r"^(eval|exec|compile|__import__)$", "dynamic", "high", "Executes code built at run time"),
    (r"^importlib\.(import_module|reload)$", "dynamic", "low", "Imports a module chosen at run time"),
    (r"^shutil\.rmtree$|^os\.(remove|unlink|rmdir|removedirs)$|\.(unlink|rmtree|rmdir)$", "destructive", "high", "Deletes files or folders"),
    (r"^os\.(kill|killpg)$|\.(kill|terminate|send_signal)$", "destructive", "high", "Kills or signals a process"),
    (r"^shutil\.(copy\w*|move)$|^os\.(rename|replace|makedirs|mkdir|chmod|symlink|truncate)$", "fswrite", "low", "Changes the file system"),
    (r"\.(write_text|write_bytes|to_csv|to_parquet|to_json|to_pickle|save_pretrained|savefig|save_to_disk)$", "fswrite", "low", "Writes a file"),
    (r"^(json|pickle|yaml|torch|numpy|np|joblib|dill)\.(dump|save|savez\w*|safe_dump|savetxt)$", "fswrite", "low", "Writes a file"),
    (r"^(requests|httpx)\.\w+$|^urllib\.request\.\w+$|^socket\.\w+$|^smtplib\.\w+$|^(aiohttp|websockets|paramiko|boto3|ftplib|openai|anthropic)\.", "network", "medium", "Network call"),
    (r"^(pickle|dill|marshal)\.loads?$|^yaml\.(load|unsafe_load)$|^torch\.load$|^joblib\.load$", "load", "medium", "Loads data that can carry code"),
    (r"^sys\.exit$|^os\._exit$|^(exit|quit)$", "exit", "medium", "Exits the program"),
    (r"^threading\.(Thread|Timer)$|^multiprocessing\.(Process|Pool)$|^concurrent\.futures\.\w+Executor$|^asyncio\.(create_task|gather|run|ensure_future)$|^signal\.(signal|alarm)$|^os\.fork$", "concurrency", "medium", "Starts concurrent work"),
    (r"^time\.sleep$", "wait", "low", "Fixed sleep"),
    (r"^os\.(chdir|putenv)$", "global", "low", "Changes process-wide state"),
]
COMMON = (set(dir(str)) | set(dir(list)) | set(dir(dict)) | set(dir(set)) | set(dir(bytes)) | {
    "read", "write", "close", "open", "run", "get", "put", "send", "recv", "start", "stop", "wait", "load",
    "save", "dump", "items", "keys", "values", "append", "format", "flush", "seek", "readline", "readlines",
    "join", "to", "cpu", "cuda", "item", "mean", "sum", "size", "shape", "view", "numpy", "tolist", "eval",
    "train", "step", "backward", "forward", "generate", "encode", "decode", "match", "search", "group",
    "submit", "result", "map", "apply", "fit", "predict", "transform", "next", "reset", "update", "add",
    "info", "debug", "warning", "error", "exception", "log", "print", "exists", "mkdir", "main", "call",
})
STDLIB = set(getattr(sys, "stdlib_module_names", ()))


# ------------------------------------------------------------------ paths / cache
def norm_path(p):
    """Accept /unix, ~ and Windows (D:\\x) paths; map drive letters to /mnt/<d> on WSL."""
    p = (p or "").strip().strip('"').strip("'")
    m = re.match(r"^([A-Za-z]):[\\/]*(.*)$", p)
    if m and os.name != "nt":
        p = "/mnt/%s/%s" % (m.group(1).lower(), m.group(2).replace("\\", "/"))
    return os.path.abspath(os.path.expanduser(p)) if p else ""


def cache_file(root):
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(root.rstrip("/\\")) or "root")[:40]
    return CACHE / ("%s-%s.json" % (slug, hashlib.sha1(root.encode()).hexdigest()[:10]))


def load_cache(root):
    try:
        meta = json.loads(cache_file(root).read_text(encoding="utf-8"))
        return meta if meta.get("version") == VERSION else None
    except (OSError, ValueError):
        return None


def save_cache(meta):
    CACHE.mkdir(parents=True, exist_ok=True)
    f = cache_file(meta["root"])
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, f)


def find_py(root, exclude):
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") and not x.endswith(".egg-info"))
        rel = os.path.relpath(d, root)
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            r = f if rel == "." else (rel + "/" + f).replace(os.sep, "/")
            if any(fnmatch.fnmatch(r, g) or r.startswith(g.rstrip("/*") + "/") for g in exclude):
                continue
            try:
                if os.path.getsize(os.path.join(d, f)) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            out.append(r)
            if len(out) >= MAX_FILES:
                return out
    return out


# ------------------------------------------------------------------ AST helpers
def short(node, n=72):
    try:
        s = " ".join(ast.unparse(node).split())
    except Exception:
        s = "..."
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def dotted(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return parts[::-1]
    return None


def sub_bodies(st):
    for f in ("body", "orelse", "finalbody"):
        v = getattr(st, f, None)
        if isinstance(v, list) and v and isinstance(v[0], ast.stmt):
            yield v
    for hd in getattr(st, "handlers", []) or []:
        yield hd.body
    for c in getattr(st, "cases", []) or []:
        yield c.body


DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def complexity(fn):
    c, stack = 1, list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, DEFS):
            continue
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
        elif n.__class__.__name__ == "match_case":
            c += 1
        stack.extend(ast.iter_child_nodes(n))
    return c


def is_main_guard(st):
    if not isinstance(st, ast.If):
        return False
    s = short(st.test, 200)
    return "__name__" in s and "__main__" in s


# ------------------------------------------------------------------ analyzer
class Project:
    def __init__(self, root, setup=None):
        self.root = root
        self.setup = setup or {}
        self.nodes, self.files, self.lines = {}, {}, {}
        self.mods, self.mod_funcs, self.mod_classes, self.imports, self.stars = {}, {}, {}, {}, {}
        self.classes, self.local_defs, self.method_index = {}, {}, {}
        self.edges = {}
        self._modcache = {}
        self.rules = [(re.compile(rx), c, s, m) for rx, c, s, m in RULES]
        for r in self.setup.get("critical_rules") or []:
            try:
                self.rules.append((re.compile(r["match"]), "custom", r.get("severity", "medium"),
                                   (r.get("label") or "Project rule") + (": " + r["why"] if r.get("why") else "")))
            except (re.error, KeyError, TypeError):
                pass

    # -- pass 1: definitions ------------------------------------------------
    def load(self):
        trees = {}
        for f in find_py(self.root, self.setup.get("exclude") or []):
            try:
                text = Path(self.root, f).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self.files[f] = {"path": f, "loc": text.count("\n") + 1}
            try:
                trees[f] = ast.parse(text)
            except (SyntaxError, ValueError, RecursionError) as e:
                self.files[f]["error"] = "%s (line %s)" % (getattr(e, "msg", e), getattr(e, "lineno", "?"))
                continue
            self.lines[f] = text.split("\n")
            mod = f[:-3].replace("/", ".")
            mod = mod[:-9] if mod.endswith(".__init__") else ("" if mod == "__init__" else mod)
            self.files[f]["mod"] = mod
            self.mods[mod] = f
            self.mod_funcs[mod], self.mod_classes[mod] = {}, {}
        for f, tree in trees.items():
            mod = self.files[f]["mod"]
            self._imports(tree, mod, f)
            guard = any(is_main_guard(st) for st in tree.body)
            self.files[f]["main"] = guard
            nid = self._mk(f, mod, "<module>", os.path.basename(f), "module", None, tree, [])
            self.nodes[nid]["main"] = guard
            self._defs(tree.body, "", None, None, [], f, mod)
        for n in self.nodes.values():
            if n["k"] == "method" and not (n["n"].startswith("__") and n["n"].endswith("__")):
                self.method_index.setdefault(n["n"], []).append(n["id"])

    def _imports(self, tree, mod, f):
        imp, stars = {}, []
        pkg = mod.split(".") if f.endswith("__init__.py") else mod.split(".")[:-1]
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        imp[a.asname] = ("mod", a.name)
                    else:
                        top = a.name.split(".")[0]
                        imp[top] = ("mod", top)
            elif isinstance(n, ast.ImportFrom):
                base = (n.module or "").split(".") if n.module else []
                if n.level:
                    base = pkg[:max(0, len(pkg) - (n.level - 1))] + base
                b = ".".join(x for x in base if x)
                for a in n.names:
                    if a.name == "*":
                        stars.append(b)
                    else:
                        imp[a.asname or a.name] = ("name", b, a.name)
        self.imports[mod], self.stars[mod] = imp, stars

    def _mk(self, f, mod, qual, name, kind, cls, a, scopes):
        nid = "%s::%s" % (f, qual)
        if nid in self.nodes:
            nid += "@%d" % a.lineno
        is_mod = kind == "module"
        try:
            sig = "" if is_mod else " ".join(ast.unparse(a.args).split())
        except Exception:
            sig = "..."
        self.nodes[nid] = {
            "id": nid, "n": name, "q": qual, "file": f, "k": kind, "c": cls,
            "l": 1 if is_mod else a.lineno, "e": len(self.lines[f]) if is_mod else (a.end_lineno or a.lineno),
            "s": sig if len(sig) <= 160 else sig[:159] + "\u2026",
            "d": (ast.get_docstring(a) or "")[:1600],
            "a": isinstance(a, ast.AsyncFunctionDef),
            "dec": [] if is_mod else [short(d, 48) for d in a.decorator_list],
            "_ast": a, "_ctx": {"mod": mod, "file": f, "cls": cls, "scopes": scopes + [nid]},
        }
        self.local_defs[nid] = {}
        return nid

    def _defs(self, body, prefix, direct_cls, ctx_cls, scopes, f, mod):
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nid = self._mk(f, mod, prefix + st.name, st.name, "method" if direct_cls else "function", ctx_cls, st, scopes)
                if direct_cls:
                    self.classes[(mod, direct_cls)]["methods"].setdefault(st.name, nid)
                elif scopes:
                    self.local_defs[scopes[-1]][st.name] = nid
                else:
                    self.mod_funcs[mod][st.name] = nid
                self._defs(st.body, prefix + st.name + ".", None, ctx_cls, scopes + [nid], f, mod)
            elif isinstance(st, ast.ClassDef):
                cq = prefix + st.name
                self.classes[(mod, cq)] = {"methods": {}, "bases": [b for b in map(dotted, st.bases) if b]}
                if not scopes and not prefix:
                    self.mod_classes[mod][st.name] = cq
                self._defs(st.body, cq + ".", cq, cq, scopes, f, mod)
            else:
                for sub in sub_bodies(st):
                    self._defs(sub, prefix, direct_cls, ctx_cls, scopes, f, mod)

    # -- name resolution ----------------------------------------------------
    def find_module(self, name, f):
        d = os.path.dirname(f).replace("/", ".")
        key = (name, d)
        if key not in self._modcache:
            r = None
            if d and (d + "." + name) in self.mods:
                r = d + "." + name
            elif name in self.mods:
                r = name
            elif name.split(".")[0] not in STDLIB:
                c = [m for m in self.mods if m.endswith("." + name)]
                r = c[0] if len(c) == 1 else None
            self._modcache[key] = r
        return self._modcache[key]

    def find_class(self, chain, mod, f):
        if len(chain) == 1 and chain[0] in self.mod_classes.get(mod, {}):
            return mod, chain[0]
        imp = self.imports.get(mod, {}).get(chain[0])
        if not imp:
            return None
        full = [x for x in imp[1].split(".") if x] + ([imp[2]] if imp[0] == "name" else []) + chain[1:]
        m = self.find_module(".".join(full[:-1]), f) if len(full) > 1 else None
        return (m, full[-1]) if m is not None and full[-1] in self.mod_classes[m] else None

    def find_method(self, mod, cq, name, depth=0):
        c = self.classes.get((mod, cq))
        if not c or depth > 5:
            return None
        if name in c["methods"]:
            return c["methods"][name]
        for b in c["bases"]:
            bc = self.find_class(b, mod, self.mods[mod])
            if bc:
                r = self.find_method(bc[0], bc[1], name, depth + 1)
                if r:
                    return r
        return None

    def resolve_abs(self, full, f, depth=0):
        for i in range(len(full), 0, -1):
            m = self.find_module(".".join(full[:i]), f)
            if m is None:
                continue
            rest = full[i:]
            if len(rest) == 1:
                if rest[0] in self.mod_funcs[m]:
                    return self.mod_funcs[m][rest[0]], None, False
                if rest[0] in self.mod_classes[m]:
                    return self.find_method(m, rest[0], "__init__"), "", False
                imp = self.imports[m].get(rest[0])
                if imp and depth < 3:
                    f2 = [x for x in imp[1].split(".") if x] + ([imp[2]] if imp[0] == "name" else [])
                    r = self.resolve_abs(f2, self.mods[m], depth + 1)
                    if r is not None:
                        return r
            elif len(rest) == 2 and rest[0] in self.mod_classes[m]:
                return self.find_method(m, rest[0], rest[1]), "", False
            return None, "", False
        return None

    def resolve(self, chain, ctx):
        """-> (node id | None, external dotted name | '' , name came from an import)."""
        head, mod = chain[0], ctx["mod"]
        if head in ("self", "cls") and ctx["cls"]:
            if len(chain) == 2:
                m = self.find_method(mod, ctx["cls"], chain[1])
                if m:
                    return m, None, False
            return None, ".".join(chain), False
        if len(chain) == 1:
            for sc in reversed(ctx["scopes"]):
                if head in self.local_defs.get(sc, ()):
                    return self.local_defs[sc][head], None, False
            if head in self.mod_funcs[mod]:
                return self.mod_funcs[mod][head], None, False
            if head in self.mod_classes[mod]:
                return self.find_method(mod, head, "__init__"), "", False
        imp = self.imports[mod].get(head)
        if imp:
            full = [x for x in imp[1].split(".") if x] + ([imp[2]] if imp[0] == "name" else []) + chain[1:]
            r = self.resolve_abs(full, ctx["file"])
            return r if r is not None else (None, ".".join(full), True)
        if len(chain) == 2 and head in self.mod_classes[mod]:
            m = self.find_method(mod, head, chain[1])
            if m:
                return m, None, False
        if len(chain) == 1:
            for s in self.stars[mod]:
                m = self.find_module(s, ctx["file"])
                if m is not None and head in self.mod_funcs[m]:
                    return self.mod_funcs[m][head], None, False
        return None, ".".join(chain), False

    # -- pass 2: bodies -----------------------------------------------------
    def analyze(self):
        for nid, n in self.nodes.items():
            w = Walker(self, n)
            n["fl"] = w.steps(n["_ast"].body)
            n["cr"] = w.crit
            n["cx"] = complexity(n["_ast"])
            n["loc"] = n["e"] - n["l"] + 1

    def edge(self, a, b, kind, line):
        e = self.edges.get((a, b))
        if e is None:
            self.edges[(a, b)] = [kind, 1, line]
        else:
            e[1] += 1
            e[0] = min(e[0], kind)

    # -- finish -------------------------------------------------------------
    def build(self):
        self.load()
        self.analyze()
        th = dict({"complexity": 12, "fan_in": 6, "long": 120}, **{k: v for k, v in (self.setup.get("thresholds") or {}).items() if isinstance(v, (int, float))})
        outdeg, callers = {}, {}
        for (a, b), e in self.edges.items():
            outdeg[a] = outdeg.get(a, 0) + 1
            if e[0] == 0:
                callers.setdefault(b, set()).add(a)
        keep = [nid for nid, n in self.nodes.items()
                if n["k"] != "module" or outdeg.get(nid) or n["cr"] or n.get("main")]
        idx = {nid: i for i, nid in enumerate(keep)}
        keyfn = {}
        for k in self.setup.get("key_functions") or []:
            m = self.match_id(k.get("id"), idx)
            if m:
                keyfn[m] = k
        fidx = {f: i for i, f in enumerate(self.files)}
        out = []
        for nid in keep:
            n = self.nodes[nid]
            cr = n["cr"]
            if n["k"] != "module":
                if n["cx"] >= th["complexity"]:
                    cr.append({"c": "complexity", "s": "high" if n["cx"] >= 2 * th["complexity"] else "medium", "l": n["l"],
                               "m": "Cyclomatic complexity %d" % n["cx"]})
                if n["loc"] >= th["long"]:
                    cr.append({"c": "long", "s": "low", "l": n["l"], "m": "%d lines long" % n["loc"]})
            nc = len(callers.get(nid, ()))
            if nc >= th["fan_in"]:
                cr.append({"c": "hub", "s": "medium", "l": n["l"], "m": "Called from %d functions" % nc})
            if nid in keyfn:
                cr.append({"c": "key", "s": keyfn[nid].get("severity", "medium"), "l": n["l"], "m": keyfn[nid].get("why", "Key function")})
            seen, uniq, best = set(), [], {}
            for c in sorted(cr, key=lambda c: c["l"]):
                if (c["c"], c["l"]) in seen:
                    continue
                seen.add((c["c"], c["l"]))
                ln = self.lines[n["file"]]
                c["t"] = ln[c["l"] - 1].strip()[:140] if 0 < c["l"] <= len(ln) else ""
                uniq.append(c)
                best[c["c"]] = max(best.get(c["c"], 0), SEV_W.get(c["s"], 1))
            src = None
            if n["k"] != "module":
                seg = self.lines[n["file"]][n["l"] - 1:n["e"]]
                src = "\n".join(x[:200] for x in seg[:SRC_LINES])
            out.append({"id": nid, "n": n["n"], "q": n["q"], "f": fidx[n["file"]], "k": n["k"], "c": n["c"], "l": n["l"],
                        "e": n["e"], "s": n["s"], "d": n["d"], "a": n["a"], "dec": n["dec"], "cx": n["cx"], "loc": n["loc"],
                        "main": bool(n.get("main")), "fl": self._reindex(n["fl"], idx), "cr": uniq,
                        "rs": sum(best.values()), "src": src})
        edges = [[idx[a], idx[b], e[0], e[1], e[2]] for (a, b), e in self.edges.items() if a in idx and b in idx]
        roles = self.setup.get("file_roles") or {}
        files = []
        for f, info in self.files.items():
            mine = [o for o in out if o["f"] == fidx[f]]
            files.append({"path": f, "loc": info["loc"], "error": info.get("error"), "role": roles.get(f, ""),
                          "main": bool(info.get("main")), "n": sum(1 for o in mine if o["k"] != "module"),
                          "rs": sum(o["rs"] for o in mine)})
        entries = []
        for e in self.setup.get("entry_points") or []:
            m = self.match_id(e.get("id"), idx)
            if m and all(x["i"] != idx[m] for x in entries):
                entries.append({"i": idx[m], "label": e.get("label") or "", "why": e.get("why") or ""})
        if not entries:
            entries = heuristic_entries(out, edges)
        sev = {"high": 0, "medium": 0, "low": 0}
        for o in out:
            for c in o["cr"]:
                sev[c["s"]] = sev.get(c["s"], 0) + 1
        return {
            "version": VERSION, "root": self.root, "name": os.path.basename(self.root.rstrip("/\\")) or self.root,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M"), "setup": self.setup or None,
            "cats": {k: {"label": v[0], "color": v[1], "desc": v[2]} for k, v in CATS.items()},
            "files": files, "nodes": out, "edges": edges, "entries": entries,
            "stats": {"files": len(files), "functions": sum(1 for o in out if o["k"] != "module"), "edges": len(edges),
                      "loc": sum(f["loc"] for f in files), "crit": sev,
                      "errors": sum(1 for f in files if f["error"])},
        }

    def match_id(self, s, idx):
        if not isinstance(s, str):
            return None
        if s in idx:
            return s
        f, _, q = s.partition("::")
        if q in ("<module>", "__main__", "module", "") and (f + "::<module>") in idx:
            return f + "::<module>"
        q = q or f
        c = [i for i in idx if self.nodes[i]["q"] == q or i.endswith("::" + q) or self.nodes[i]["q"].endswith("." + q)]
        if f and len(c) > 1:
            c = [i for i in c if self.nodes[i]["file"].endswith(f)] or c
        return c[0] if len(c) == 1 else None

    def _reindex(self, steps, idx):
        out = []
        for s in steps:
            if s["t"] == "c":
                if s["to"] not in idx:
                    continue
                s = dict(s, to=idx[s["to"]])
            elif "steps" in s:
                s = dict(s, steps=self._reindex(s["steps"], idx))
            elif "br" in s:
                s = dict(s, br=[dict(b, steps=self._reindex(b["steps"], idx)) for b in s["br"]])
            out.append(s)
        return out


class Walker:
    """One pass over a function body: ordered flow steps, call edges, critical points."""

    def __init__(self, P, node):
        self.P, self.node, self.ctx, self.nid = P, node, node["_ctx"], node["id"]
        self.crit, self.called = [], set()

    def flag(self, cat, sev, line, msg):
        self.crit.append({"c": cat, "s": sev, "l": line, "m": msg})

    def steps(self, stmts):
        out = []
        for st in stmts:
            if isinstance(st, DEFS):
                continue
            ln = st.lineno
            if isinstance(st, ast.If):
                out += self.calls(st.test)
                main = self.node["k"] == "module" and is_main_guard(st)
                br, cur = [{"label": "run as script" if main else "if " + short(st.test), "l": ln, "steps": self.steps(st.body)}], st
                while len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
                    cur = cur.orelse[0]
                    br.append({"label": "elif " + short(cur.test), "l": cur.lineno, "steps": self.calls(cur.test) + self.steps(cur.body)})
                if cur.orelse:
                    br.append({"label": "else", "l": cur.orelse[0].lineno, "steps": self.steps(cur.orelse)})
                out.append({"t": "if", "l": ln, "br": br})
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                out += self.calls(st.iter)
                out.append({"t": "loop", "l": ln, "label": "for %s in %s" % (short(st.target, 30), short(st.iter, 44)),
                            "steps": self.steps(st.body)})
                out += self.steps(st.orelse)
            elif isinstance(st, ast.While):
                forever = isinstance(st.test, ast.Constant) and bool(st.test.value)
                if forever:
                    self.flag("loop", "medium", ln, "Unbounded loop: ends only through break, return or an exception")
                out.append({"t": "loop", "l": ln, "label": "while " + short(st.test, 60),
                            "steps": self.calls(st.test) + self.steps(st.body)})
                out += self.steps(st.orelse)
            elif isinstance(st, ast.Try) or st.__class__.__name__ == "TryStar":
                br = [{"label": "try", "l": ln, "steps": self.steps(st.body) + self.steps(st.orelse)}]
                for hd in st.handlers:
                    name = short(hd.type, 40) if hd.type is not None else ""
                    broad = hd.type is None or name in ("Exception", "BaseException")
                    silent = all(isinstance(b, (ast.Pass, ast.Continue)) or
                                 (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant)) for b in hd.body)
                    if broad and silent:
                        self.flag("swallow", "high", hd.lineno, "Catches %s and does nothing: failures pass silently" % (name or "everything"))
                    elif hd.type is None:
                        self.flag("swallow", "low", hd.lineno, "Bare except also catches KeyboardInterrupt and SystemExit")
                    elif silent:
                        self.flag("swallow", "low", hd.lineno, "Ignores %s without a trace" % name)
                    br.append({"label": "except " + name if name else "except", "l": hd.lineno, "x": 1,
                               "sw": 1 if silent else 0, "steps": self.steps(hd.body)})
                out.append({"t": "try", "l": ln, "br": br})
                if st.finalbody:
                    fin = self.steps(st.finalbody)
                    if fin:
                        out.append({"t": "block", "l": st.finalbody[0].lineno, "label": "finally", "steps": fin})
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for it in st.items:
                    out += self.calls(it.context_expr)
                out += self.steps(st.body)
            elif st.__class__.__name__ == "Match":
                out += self.calls(st.subject)
                out.append({"t": "if", "l": ln, "br": [{"label": "case " + short(c.pattern, 50), "l": c.pattern.lineno,
                                                        "steps": self.steps(c.body)} for c in st.cases]})
            elif isinstance(st, ast.Return):
                if st.value is not None:
                    out += self.calls(st.value)
                out.append({"t": "ret", "l": ln, "label": "return" + (" " + short(st.value, 50) if st.value is not None else "")})
            elif isinstance(st, ast.Raise):
                if st.exc is not None:
                    out += self.calls(st.exc)
                out.append({"t": "raise", "l": ln, "label": "raise" + (" " + short(st.exc, 50) if st.exc is not None else "")})
            elif isinstance(st, (ast.Break, ast.Continue)):
                out.append({"t": "jump", "l": ln, "label": "break" if isinstance(st, ast.Break) else "continue"})
            elif isinstance(st, ast.Global):
                self.flag("global", "low", ln, "Rebinds module-level " + ", ".join(st.names))
            else:
                out += self.calls(st)
        return out

    def calls(self, node):
        out = []

        def rec(n):
            if isinstance(n, DEFS):
                return
            if isinstance(n, ast.Call):
                self.called.add(id(n.func))
            for ch in ast.iter_child_nodes(n):
                rec(ch)
            if isinstance(n, ast.Call):
                s = self.on_call(n)
                if s:
                    out.append(s)
            elif id(n) not in self.called and isinstance(getattr(n, "ctx", None), ast.Load):
                if isinstance(n, ast.Name):
                    self.on_ref([n.id], n)
                elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in ("self", "cls"):
                    self.on_ref([n.value.id, n.attr], n)

        rec(node)
        return out

    def on_ref(self, chain, n):
        if len(chain) == 1 and chain[0] in self.P.mod_classes[self.ctx["mod"]]:
            return
        nid = self.P.resolve(chain, self.ctx)[0]
        if nid and nid != self.nid and self.P.nodes[nid]["n"] != "__init__":
            self.P.edge(self.nid, nid, 1, n.lineno)

    def on_call(self, n):
        chain = dotted(n.func)
        nid, ext, known = self.P.resolve(chain, self.ctx) if chain else (None, None, False)
        attr = n.func.attr if isinstance(n.func, ast.Attribute) else None
        inferred = False
        if nid is None and attr and chain and not known and ext != "" and attr not in COMMON:  # only on plain names, not on call results
            cand = self.P.method_index.get(attr)
            if cand and len(cand) == 1:
                nid, inferred = cand[0], True
        if nid:
            if nid == self.nid:
                self.flag("recursion", "low", n.lineno, "Calls itself")
                return None
            self.P.edge(self.nid, nid, 2 if inferred else 0, n.lineno)
            s = {"t": "c", "to": nid, "l": n.lineno}
            if inferred:
                s["i"] = 1
            return s
        if ext is None and attr:
            ext = "?." + attr
        if not ext:
            return None
        hit = None
        for rx, cat, sev, msg in self.P.rules:
            if rx.search(ext):
                hit = (cat, sev, "%s  \u2192  %s()" % (msg, ext))
                break
        if hit is None and (ext == "open" or ext.endswith(".open")):
            mode = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg == "mode"), None)
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+"):
                hit = ("fswrite", "low", "Opens a file for writing (mode %r)" % mode.value)
        if hit:
            self.flag(hit[0], hit[1], n.lineno, hit[2])
            return {"t": "x", "n": ext, "l": n.lineno, "c": hit[0]}
        return {"t": "x", "n": ext, "l": n.lineno} if known else None


def heuristic_entries(nodes, edges):
    out_adj, indeg = {}, {}
    for a, b, k, _, _ in edges:
        if k != 2:
            out_adj.setdefault(a, []).append(b)
            indeg[b] = indeg.get(b, 0) + 1

    def reach(i):
        seen, st = {i}, [i]
        while st:
            for b in out_adj.get(st.pop(), ()):
                if b not in seen:
                    seen.add(b)
                    st.append(b)
        return len(seen)

    c = [(reach(i), i, "Script entry (__main__ guard)") for i, n in enumerate(nodes) if n["k"] == "module" and n["main"]]
    c += [(reach(i), i, "main() with no caller") for i, n in enumerate(nodes)
          if n["k"] != "module" and n["n"] in ("main", "cli", "run") and not indeg.get(i)]
    if not c:
        c = [(reach(i), i, "Nothing calls it") for i, n in enumerate(nodes) if not indeg.get(i) and out_adj.get(i)]
    c.sort(key=lambda x: (-x[0], x[1]))
    return [{"i": i, "label": "", "why": why} for r, i, why in c[:12]]


def scan(root, setup=None):
    return Project(root, setup).build()


# ------------------------------------------------------------------ one-time LLM setup
PROMPT = """You are configuring a static code-map tool for a Python codebase. Below is a machine summary
(files, functions with first docstring line, call counts). Decide the setup ONCE; it is cached and reused.

Reply with ONE JSON object and nothing else (no prose, no code fence, do not use tools):
{
 "summary": "what this code does, plain words, at most 45 words",
 "entry_points": [{"id": "<file>::<qualname>  or  <file>::<module> for a script body", "label": "short human name", "why": "what starts here"}],
 "exclude": ["glob of files that are noise: backups, vendored, generated, dead experiments"],
 "critical_rules": [{"match": "python regex on a dotted call name, e.g. ^docker\\\\.", "label": "short", "severity": "high|medium|low", "why": "risk"}],
 "key_functions": [{"id": "<file>::<qualname>", "severity": "high|medium|low", "why": "one sentence: why a maintainer must be careful here"}],
 "file_roles": {"<file>": "one-line role"}
}
Rules: ids must be copied exactly from the summary. entry_points: at most 12, most important first (the real
starting points a person runs). critical_rules: at most 10, only project-specific risky calls not covered by the
generic rules (subprocess, file delete, network, eval, pickle, sys.exit, threads are already covered).
key_functions: at most 25. file_roles: at most 60 files. exclude: be conservative.

"""


def summarize(meta, limit=60000):
    L = ["PROJECT %s  (%d files, %d functions, %d call edges)" % (meta["name"], meta["stats"]["files"], meta["stats"]["functions"], meta["stats"]["edges"])]
    for nm in ("README.md", "README.rst", "README.txt", "README"):
        p = Path(meta["root"], nm)
        if p.is_file():
            L += ["", "README (start):"] + p.read_text(encoding="utf-8", errors="replace").split("\n")[:40]
            break
    indeg, outdeg = {}, {}
    for a, b, _, _, _ in meta["edges"]:
        indeg[b] = indeg.get(b, 0) + 1
        outdeg[a] = outdeg.get(a, 0) + 1
    by_file = {}
    for i, n in enumerate(meta["nodes"]):
        by_file.setdefault(n["f"], []).append((i, n))
    L += ["", "FILES (id = <file>::<qualname>; in/out = callers/callees; cx = complexity):"]
    for fi, f in sorted(enumerate(meta["files"]), key=lambda x: -x[1]["loc"]):
        L.append("\n## %s  (%d lines%s%s)" % (f["path"], f["loc"], ", has __main__ guard" if f["main"] else "", ", SYNTAX ERROR" if f["error"] else ""))
        rows = sorted(by_file.get(fi, []), key=lambda x: -(outdeg.get(x[0], 0) + indeg.get(x[0], 0)))
        for i, n in rows[:30]:
            doc = n["d"].split("\n")[0][:90]
            cr = ",".join(sorted({c["c"] for c in n["cr"]}))
            L.append("  %s  in=%d out=%d cx=%d%s%s" % (n["id"], indeg.get(i, 0), outdeg.get(i, 0), n["cx"], "  [" + cr + "]" if cr else "", "  - " + doc if doc else ""))
        if len(rows) > 30:
            L.append("  ... %d more functions" % (len(rows) - 30))
        if sum(len(x) + 1 for x in L) > limit:
            L.append("\n(summary truncated)")
            break
    return "\n".join(L)[:limit + 2000]


def ask_llm(prompt, timeout=420):
    exe = shutil.which("claude")
    model = os.environ.get("CODEGRAPH_MODEL", "")
    if exe:
        cmd = [exe, "-p"] + (["--model", model] if model else [])
    elif os.name == "nt" and shutil.which("wsl"):  # Windows Python: use the claude CLI installed inside WSL
        if not re.fullmatch(r"[\w.\-\[\]]*", model):
            raise RuntimeError("bad CODEGRAPH_MODEL")
        cmd = ["wsl.exe", "-e", "bash", "-lc", "cd /tmp && claude -p" + (" --model " + model if model else "")]
    else:
        raise RuntimeError("the `claude` CLI is not on PATH")
    tmp = tempfile.mkdtemp(prefix="codegraph_")  # neutral folder: no project memory or settings
    try:
        r = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, cwd=tmp if exe else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "claude failed").strip()[:300])
    a, b = r.stdout.find("{"), r.stdout.rfind("}")
    if a < 0 or b <= a:
        raise RuntimeError("no JSON in the reply")
    return json.loads(r.stdout[a:b + 1])


def clean_setup(raw, source):
    def lst(k, n):
        v = raw.get(k)
        return [x for x in v if isinstance(x, dict)][:n] if isinstance(v, list) else []
    rules = []
    for r in lst("critical_rules", 10):
        try:
            re.compile(r.get("match", "("))
            if r.get("severity") not in SEV_W:
                r["severity"] = "medium"
            rules.append(r)
        except (re.error, TypeError):
            pass
    keys = lst("key_functions", 25)
    for k in keys:
        if k.get("severity") not in SEV_W:
            k["severity"] = "medium"
    roles = raw.get("file_roles") if isinstance(raw.get("file_roles"), dict) else {}
    return {"source": source, "at": time.strftime("%Y-%m-%d %H:%M"), "summary": str(raw.get("summary") or "")[:600],
            "entry_points": lst("entry_points", 12), "critical_rules": rules, "key_functions": keys,
            "exclude": [x for x in (raw.get("exclude") or []) if isinstance(x, str)][:40],
            "file_roles": {str(k): str(v)[:160] for k, v in list(roles.items())[:80]}}


def run_setup(root, use_llm=True):
    """Scan, ask the LLM once for the setup (or fall back to rules), rescan with it, cache."""
    base = scan(root)
    setup, err = None, None
    if use_llm and base["nodes"]:
        try:
            setup = clean_setup(ask_llm(PROMPT + summarize(base)), "claude")
        except Exception as e:  # noqa: BLE001 - any failure falls back to the rule-based setup
            err = str(e)[:300]
    if setup is None:
        setup = clean_setup({"summary": ""}, "rules")
        if err:
            setup["error"] = err
    meta = scan(root, setup)
    if not meta["nodes"] and base["nodes"]:  # the exclude list removed everything: ignore it
        setup["exclude"] = []
        meta = scan(root, setup)
    save_cache(meta)
    return meta


def open_project(root, refresh=False, redo=False, use_llm=True):
    meta = load_cache(root)
    if meta is None or redo or not meta.get("setup"):
        return run_setup(root, use_llm)
    if refresh:
        meta = scan(root, meta["setup"])
        save_cache(meta)
    return meta


# ------------------------------------------------------------------ server
def page(meta=None):
    html = (HERE / "template.html").read_text(encoding="utf-8")
    data = "null" if meta is None else json.dumps(meta, separators=(",", ":")).replace("</", "<\\/")
    return html.replace("/*__META__*/null", data, 1)


def browse(path):
    p = norm_path(path) or str(Path.home())
    if not os.path.isdir(p):
        p = str(Path.home())
    dirs, npy = [], 0
    try:
        for e in sorted(os.scandir(p), key=lambda e: e.name.lower()):
            if e.name.startswith(".") or e.name in SKIP_DIRS:
                continue
            if e.is_dir(follow_symlinks=True):
                dirs.append(e.name)
            elif e.name.endswith(".py"):
                npy += 1
    except OSError:
        pass
    roots = [str(Path.home()), os.getcwd()]
    if os.name == "nt":
        roots += [d + ":\\" for d in "CDEFGH" if os.path.isdir(d + ":\\")]
    elif os.path.isdir("/mnt"):
        roots += ["/mnt/" + d for d in sorted(os.listdir("/mnt")) if len(d) == 1]
    return {"path": p, "parent": os.path.dirname(p.rstrip("/")) or "/", "dirs": dirs[:400], "py": npy, "roots": roots}


def recent():
    out = []
    for f in sorted(CACHE.glob("*.json"), key=lambda f: -f.stat().st_mtime)[:12]:
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
            if m.get("version") == VERSION:
                out.append({"root": m["root"], "name": m["name"], "scanned_at": m["scanned_at"], "stats": m["stats"],
                            "setup": (m.get("setup") or {}).get("source")})
        except (OSError, ValueError, KeyError):
            pass
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _local(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        origin = self.headers.get("Origin")
        return host in ("localhost", "127.0.0.1") and (not origin or re.match(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$", origin))

    def do_GET(self):
        if not self._local():
            return self._send(403, {"error": "local only"})
        if self.path.split("?")[0] in ("/", "/index.html"):
            return self._send(200, page(), "text/html")
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._local() or "json" not in (self.headers.get("Content-Type") or ""):
            return self._send(403, {"error": "local only"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            name = self.path.strip("/").split("/")[-1]
            if name == "browse":
                return self._send(200, browse(body.get("path")))
            if name == "recent":
                return self._send(200, {"items": recent(), "start": getattr(self.server, "start", "")})
            root = norm_path(body.get("path"))
            if not root or not os.path.isdir(root):
                return self._send(400, {"error": "Not a folder: %s" % (body.get("path") or "(empty)")})
            if name == "scan":      # fast, never calls the LLM
                meta = load_cache(root)
                if meta and meta.get("setup") and body.get("refresh"):
                    meta = scan(root, meta["setup"])
                    save_cache(meta)
                elif meta is None:
                    meta = scan(root)
                return self._send(200, {"root": root, "needs_setup": not meta.get("setup"), "stats": meta["stats"]})
            if name == "setup":     # the one LLM call
                meta = run_setup(root, use_llm=body.get("llm", True))
                return self._send(200, {"root": root, "source": meta["setup"]["source"], "error": meta["setup"].get("error")})
            if name == "meta":
                meta = load_cache(root)
                return self._send(200, meta) if meta else self._send(404, {"error": "not scanned yet"})
            self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001 - report to the page instead of dropping the connection
            self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


def open_browser(url):
    try:
        if "microsoft" in platform.release().lower() and shutil.which("cmd.exe"):
            subprocess.Popen(["cmd.exe", "/c", "start", "", url.replace("&", "^&")], cwd="/mnt/c",
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(url)
    except Exception:  # noqa: BLE001 - the URL is printed anyway
        pass


def main():
    ap = argparse.ArgumentParser(description="CodeGraph: call graph, flow and critical points for a Python folder.")
    ap.add_argument("folder", nargs="?", help="folder to open (optional; you can pick one in the page)")
    ap.add_argument("--export", metavar="FILE", help="write one standalone HTML file and exit")
    ap.add_argument("--refresh", action="store_true", help="rescan the code (keeps the stored setup, no LLM)")
    ap.add_argument("--redo-setup", action="store_true", help="ask the LLM for a new setup")
    ap.add_argument("--no-llm", action="store_true", help="never call the LLM; use the rule-based setup")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    root = norm_path(a.folder) if a.folder else ""
    if root and not os.path.isdir(root):
        sys.exit("Not a folder: %s" % root)
    if a.export:
        if not root:
            sys.exit("--export needs a folder")
        meta = open_project(root, a.refresh, a.redo_setup, not a.no_llm)
        Path(a.export).write_text(page(meta), encoding="utf-8")
        print("Wrote %s  (%d functions, %d edges, setup: %s)" % (a.export, meta["stats"]["functions"], meta["stats"]["edges"], meta["setup"]["source"]))
        return
    if root and (a.refresh or a.redo_setup or a.no_llm):
        open_project(root, a.refresh, a.redo_setup, not a.no_llm)
    srv = None
    for port in range(a.port, a.port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if srv is None:
        sys.exit("No free port near %d" % a.port)
    srv.start = root
    url = "http://localhost:%d/" % srv.server_address[1]
    print("CodeGraph running at %s   (Ctrl+C to stop)" % url)
    if not a.no_browser:
        threading.Timer(0.4, open_browser, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
