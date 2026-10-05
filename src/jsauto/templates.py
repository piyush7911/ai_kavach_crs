"""
Where a template prints a value, and in what HTML context.

An application can escape correctly in the handler and still be vulnerable once the value lands in the page:
HTML-encoding is not enough at the START of a URL attribute (`href="{{x}}"` accepts `javascript:...`), in an event
handler (`onclick="{{x}}"`), inside `<script>`, or anywhere the template prints the value raw. This module finds
those places, for the common template syntaxes, without knowing which engine an application uses.

It is a deliberately small tokenizer, not an HTML parser. What it recognises:

    {{ x }}   {{{ x }}}   {{ x | safe }}        mustache, handlebars, swig, nunjucks, twig, liquid
    <%= x %>  <%- x %>                          ejs
    #{x}      !{x}                              pug

and, from the text before each print site, one of these contexts:

    html        text between tags
    attr        a quoted or unquoted attribute value that is not a URL, handler or style
    url-start   the very start of a URL attribute value (the scheme is attacker-controlled)
    url         later in a URL attribute value (only encoding matters)
    event       an on* handler attribute (JavaScript)
    script      inside <script>
    css         inside <style> or a style attribute

DANGEROUS contexts are `raw` output anywhere, plus `url-start`, `event` and `script`: a value that reaches one of
them from the request is a cross-site-scripting candidate whatever encoding the handler applied.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

KNOWLEDGE_PATH = Path(__file__).resolve().parents[2] / "config" / "js_knowledge.json"
SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "coverage", ".git", "test", "tests", "__tests__",
             "spec", "cypress", "assets", "public", "static"}
MAX_BYTES = 400_000

# One alternation so print sites are found in document order. Group names say which syntax matched.
_SITE = re.compile(
    r"(?P<hbs3>\{\{\{\s*(?P<e1>[^}]+?)\s*\}\}\})"
    r"|(?P<mus>\{\{(?![#/!>^&])\s*(?P<e2>[^}]+?)\s*\}\})"
    r"|(?P<ejsraw><%-\s*(?P<e3>.+?)\s*%>)"
    r"|(?P<ejs><%=\s*(?P<e4>.+?)\s*%>)"
    r"|(?P<pugraw>!\{\s*(?P<e5>[^}]+?)\s*\})"
    r"|(?P<pug>#\{\s*(?P<e6>[^}]+?)\s*\})", re.S)
_RAW_FILTER = re.compile(r"\|\s*(safe|raw|noescape|unescape)\b")
_ROOT = re.compile(r"[A-Za-z_$][\w$]*")


@dataclass
class Site:
    file: str            # relative to the project root
    line: int
    var: str             # the root variable printed (`user` for `user.name | safe`)
    expr: str
    raw: bool            # printed without escaping
    context: str         # html | attr | url-start | url | event | script | css

    @property
    def dangerous(self) -> bool:
        return self.raw or self.context in ("url-start", "event", "script")

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "var": self.var, "raw": self.raw, "context": self.context}


def load_knowledge(path: Path = KNOWLEDGE_PATH) -> dict:
    return json.loads(Path(path).read_text())


def html_context(text: str, pos: int, url_attrs: set) -> str:
    """The HTML context of the character position `pos` in `text`."""
    lt, gt = text.rfind("<", 0, pos), text.rfind(">", 0, pos)
    if lt > gt:                                              # inside a tag
        tag = text[lt:pos]
        quoted = None
        for m in re.finditer(r"([A-Za-z_:][\w:.\-]*)\s*=\s*(\"|')", tag):
            quoted = m
        attr, at_start = None, False
        if quoted is not None and quoted.group(2) not in tag[quoted.end():]:       # inside the quotes
            attr = quoted.group(1).lower()
            at_start = tag[quoted.end():].strip() == ""
        else:
            m = re.search(r"([A-Za-z_:][\w:.\-]*)\s*=\s*$", tag)                  # unquoted value, at its start
            if m:
                attr, at_start = m.group(1).lower(), True
        if attr is None:
            return "attr"
        if attr.startswith("on"):
            return "event"
        if attr in url_attrs:
            return "url-start" if at_start else "url"
        if attr == "style":
            return "css"
        return "attr"
    before = text[:pos].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return "script"
    if before.rfind("<style") > before.rfind("</style"):
        return "css"
    return "html"


def scan_text(text: str, rel: str, url_attrs: set) -> list[Site]:
    sites = []
    for m in _SITE.finditer(text):
        expr = next(m.group(g) for g in ("e1", "e2", "e3", "e4", "e5", "e6") if m.group(g) is not None)
        root = _ROOT.match(expr.lstrip("!-+ ("))
        if not root:
            continue
        outer = next(g for g in ("hbs3", "mus", "ejsraw", "ejs", "pugraw", "pug") if m.group(g) is not None)
        raw = outer in ("hbs3", "ejsraw", "pugraw") or bool(_RAW_FILTER.search(expr))
        sites.append(Site(file=rel, line=text.count("\n", 0, m.start()) + 1, var=root.group(0), expr=expr.strip(),
                          raw=raw, context=html_context(text, m.start(), url_attrs)))
    return sites


class TemplateIndex:
    """Every print site in the project's templates, findable by the view name a handler renders."""

    def __init__(self, root: Path, knowledge: dict = None):
        self.root = Path(root).resolve()
        k = knowledge or load_knowledge()
        self.exts = {e.lower() for e in k["template_extensions"]}
        self.url_attrs = set(k["url_attributes"])
        self.by_file: dict[str, list[Site]] = {}
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in self.exts or path.stat().st_size > MAX_BYTES:
                continue
            rel = path.relative_to(self.root)
            if any(part in SKIP_DIRS for part in rel.parts[:-1]):
                continue
            text = path.read_text(errors="replace")
            sites = scan_text(text, rel.as_posix(), self.url_attrs)
            if sites:
                self.by_file[rel.as_posix()] = sites

    def sites_for(self, view: str) -> list[Site]:
        """Sites of the template a handler renders by name (`profile`, `admin/users`): matched on the path
        without its extension, so it works for any views directory layout."""
        view = view.strip("/").replace("\\", "/")
        out = []
        for rel, sites in self.by_file.items():
            stem = rel.rsplit(".", 1)[0]
            if stem == view or stem.endswith("/" + view):
                out += sites
        return out
