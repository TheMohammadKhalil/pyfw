from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
CODE = ROOT / "code"
OUT = ROOT / "html"
GITHUB = "https://github.com/TheMohammadKhalil/pyfw/blob/main"

DOC_PAGES: list[tuple[str, str]] = [
    ("01-topology.md", "Topology"),
    ("02-libraries.md", "Libraries & tools"),
    ("03-setup.md", "Setup"),
    ("04-gateway-and-router.md", "Bridge & router"),
    ("05-code-walkthrough.md", "How it works"),
]
CODE_FILES: list[str] = [
    "frame_parse.py", "fcs_check.py", "token_bucket.py", "rule_engine.py",
    "mini_bridge.py", "router_nft.py", "router_setup.sh",
]


def page_for_code(name: str) -> str:
    return "code-" + name.replace(".", "-") + ".html"


def rewrite_link(href: str, base: str) -> str:
    if re.match(r"^[a-z]+:", href) or href.startswith("#"):
        return href
    path, _, anchor = href.partition("#")
    frag = f"#{anchor}" if anchor else ""

    parts = {"root": [], "docs": ["docs"], "code": ["code"]}[base]
    stack = list(parts)
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack:
                stack.pop()
            else:
                stack.append("..")
        else:
            stack.append(seg)
    norm = "/".join(stack)
    if norm.startswith("docs/") and norm.endswith(".md"):
        return Path(norm).stem + ".html" + frag
    if norm in ("code", "code/README.md"):
        return "code.html" + frag
    if norm.startswith("code/") and norm.count("/") == 1 and Path(norm).name in CODE_FILES:
        return page_for_code(Path(norm).name) + frag
    if norm in ("README.md", "", "html", "html/index.html"):
        return "index.html" + frag
    if norm.startswith("html/"):
        return norm[5:] + frag
    if norm.startswith("../"):
        return f"{GITHUB}/{norm[3:]}{frag}"
    return f"../{norm}{frag}"


_INLINE = re.compile(r"`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)|\*\*(.+?)\*\*|\*(\S[^*]*?)\*")


def inline(text: str, base: str) -> str:
    out: list[str] = []
    pos = 0
    for m in _INLINE.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        if m.group(1) is not None:
            out.append(f"<code>{html.escape(m.group(1))}</code>")
        elif m.group(2) is not None:
            out.append(f'<a href="{html.escape(rewrite_link(m.group(3), base))}">{inline(m.group(2), base)}</a>')
        elif m.group(4) is not None:
            out.append(f"<strong>{inline(m.group(4), base)}</strong>")
        else:
            out.append(f"<em>{inline(m.group(5), base)}</em>")
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return "".join(out)


def slug(text: str) -> str:
    s = html.unescape(re.sub(r"<[^>]+>", "", text)).lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "section"


@dataclass
class Doc:
    title: str = ""
    body: list[str] = field(default_factory=list)
    toc: list[tuple[str, str]] = field(default_factory=list)


_LIST_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")


def _table(rows: list[str], base: str) -> str:
    def cells(row: str) -> list[str]:
        row = row.strip()
        if row.startswith("|"):
            row = row[1:]
        if row.endswith("|") and not row.endswith("\\|"):
            row = row[:-1]
        return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", row)]

    head = cells(rows[0])
    body = [cells(r) for r in rows[2:]]
    h = "".join(f"<th>{inline(c, base)}</th>" for c in head)
    b = "".join("<tr>" + "".join(f"<td>{inline(c, base)}</td>" for c in r) + "</tr>" for r in body)
    return f'<div class="tbl"><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'


def _code_block(lang: str, code: str) -> str:
    cls = "term" if lang in ("", "text") and any(ch in code for ch in "─│┌└►◄") else "cmd"
    if lang in ("bash", "powershell", "python", "yaml", "json", "sh"):
        label = {"bash": "bash", "sh": "bash", "powershell": "PowerShell", "python": "Python",
                 "yaml": "YAML", "json": "JSON"}[lang]
        return f'<div class="code"><span class="lang">{label}</span><pre class="{cls}">{html.escape(code)}</pre></div>'
    return f'<pre class="{cls} diagram">{html.escape(code)}</pre>' if cls == "term" else f'<pre class="{cls}">{html.escape(code)}</pre>'


def blocks(lines: list[str], base: str, doc: Doc | None = None) -> list[str]:
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        s = line.strip()
        if not s:
            i += 1
            continue
        if s.startswith("```"):
            lang = s[3:].strip().lower()
            indent = len(line) - len(line.lstrip())
            j = i + 1
            code: list[str] = []
            while j < n and not lines[j].strip().startswith("```"):
                code.append(lines[j][indent:] if lines[j][:indent].strip() == "" else lines[j])
                j += 1
            out.append(_code_block(lang, "\n".join(code)))
            i = j + 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", s)
        if m:
            level = len(m.group(1))
            text = inline(m.group(2), base)
            if level == 1 and doc is not None and not doc.title:
                doc.title = m.group(2)
                i += 1
                continue
            hid = slug(text)
            if level == 2 and doc is not None:
                doc.toc.append((hid, re.sub(r"<[^>]+>", "", text)))
            out.append(f'<h{level} id="{hid}">{text}</h{level}>')
            i += 1
            continue
        if s == "---":
            out.append("<hr>")
            i += 1
            continue
        if s.startswith("|"):
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(_table(rows, base))
            continue
        if s.startswith(">"):
            quote = []
            while i < n and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].lstrip())
                i += 1
            out.append('<div class="callout">' + "".join(blocks(quote, base)) + "</div>")
            continue
        lm = _LIST_RE.match(line)
        if lm:
            ordered = lm.group(2)[0].isdigit()
            base_indent = len(lm.group(1))
            items: list[list[str]] = []
            while i < n:
                cur = lines[i]
                cm = _LIST_RE.match(cur)
                if cm and len(cm.group(1)) == base_indent and (cm.group(2)[0].isdigit()) == ordered:
                    items.append([cm.group(3)])
                    i += 1
                    continue
                if not cur.strip():
                    nxt = lines[i + 1] if i + 1 < n else ""
                    if nxt.strip() and len(nxt) - len(nxt.lstrip()) > base_indent:
                        items[-1].append("")
                        i += 1
                        continue
                    break
                if len(cur) - len(cur.lstrip()) > base_indent:
                    items[-1].append(cur)
                    i += 1
                    continue
                break
            tag = "ol" if ordered else "ul"
            li = []
            for item in items:
                rest = item[1:]
                ind = min((len(x) - len(x.lstrip()) for x in rest if x.strip()), default=0)
                sub = [item[0]] + [x[ind:] if x.strip() else "" for x in rest]
                inner = blocks(sub, base)
                if len(inner) == 1 and inner[0].startswith("<p>"):
                    inner = [inner[0][3:-4]]
                li.append("<li>" + "".join(inner) + "</li>")
            out.append(f"<{tag}>" + "".join(li) + f"</{tag}>")
            continue
        para = []
        while i < n and lines[i].strip() and not re.match(r"^\s*(```|#{1,4}\s|\||>|---$)", lines[i]) and not _LIST_RE.match(lines[i]):
            para.append(lines[i].strip())
            i += 1
        out.append("<p>" + inline(" ".join(para), base) + "</p>")
    return out


def markdown(text: str, base: str) -> Doc:
    doc = Doc()
    doc.body = blocks(text.splitlines(), base, doc)
    return doc


CSS = """
:root{--ink:#111827;--ink-2:#374151;--muted:#6b7280;--line:#e5e7eb;--soft:#f9fafb;--paper:#fff;--bg:#eef1f5;
--a:#2563eb;--a-soft:#eff6ff;--b:#ea580c;--b-soft:#fff7ed;--fw:#7c3aed;--fw-soft:#f5f3ff;--rt:#0f766e;--rt-soft:#f0fdfa;
--term:#0b1220;--term-ink:#dbe4f0;--code-bg:#f3f4f6;
--mono:ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;--sans:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif}
@media (prefers-color-scheme:dark){:root{--ink:#e5e7eb;--ink-2:#cbd5e1;--muted:#94a3b8;--line:#334155;--soft:#111827;--paper:#0f172a;--bg:#020617;
--a-soft:#172554;--b-soft:#431407;--fw-soft:#2e1065;--rt-soft:#042f2e;--code-bg:#1e293b}}
*{box-sizing:border-box}html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 var(--sans)}
.shell{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}
nav.side{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;padding:24px 18px;border-right:1px solid var(--line);background:var(--paper)}
nav.side .brand{font:700 13px/1.2 var(--sans);letter-spacing:.12em;text-transform:uppercase;color:var(--fw);margin-bottom:4px}
nav.side .sub{color:var(--muted);font-size:12.5px;margin-bottom:16px}
nav.side b{display:block;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:16px 0 4px}
nav.side a{display:block;color:var(--ink-2);text-decoration:none;padding:4px 8px;border-radius:7px;font-size:14px}
nav.side a:hover{background:var(--soft)}nav.side a.on{background:var(--fw-soft);color:var(--fw);font-weight:600}
nav.side a.file{font-family:var(--mono);font-size:12.5px}
main{background:var(--paper);min-width:0}
.cover{background:linear-gradient(135deg,#0f172a 0%,#1e293b 60%,#312e81 100%);color:#fff;padding:40px 48px 32px}
.cover .kicker{font:600 12px/1 var(--sans);letter-spacing:.14em;text-transform:uppercase;color:#a5b4fc}
.cover h1{font-size:32px;line-height:1.15;margin:10px 0 8px;letter-spacing:-.02em}
.cover p{margin:0;color:#cbd5e1;max-width:720px;font-size:16px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}
.chip{font:600 12px/1 var(--sans);padding:7px 10px;border-radius:999px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);color:#e2e8f0}
.content{padding:8px 48px 56px}
.pagetoc{border:1px solid var(--line);background:var(--soft);border-radius:12px;padding:12px 16px;margin:24px 0 8px;font-size:14px}
.pagetoc b{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.pagetoc a{color:var(--ink-2);text-decoration:none;margin-right:14px;white-space:nowrap;display:inline-block}
h2{font-size:23px;margin:40px 0 8px;padding-top:18px;border-top:2px solid var(--ink);letter-spacing:-.01em}
h3{font-size:18px;margin:28px 0 6px}h4{font-size:15.5px;margin:20px 0 4px}
p{margin:8px 0}a{color:var(--a)}hr{border:0;border-top:1px dashed var(--line);margin:28px 0}
code{font-family:var(--mono);font-size:.86em;background:var(--code-bg);border:1px solid var(--line);border-radius:5px;padding:1px 5px;overflow-wrap:anywhere}
pre{margin:8px 0;padding:12px 14px;border-radius:10px;font:12.5px/1.55 var(--mono);overflow-x:auto}
pre code{background:none;border:0;padding:0}
pre.cmd{background:var(--soft);border:1px solid var(--line);color:var(--ink)}
pre.term{background:var(--term);color:var(--term-ink)}
.code{position:relative}.code .lang{position:absolute;right:10px;top:6px;font:700 10px/1 var(--sans);letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.tbl{overflow-x:auto;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--soft);font-size:12.5px;letter-spacing:.03em}
ul,ol{padding-left:22px}li{margin:4px 0}
.callout{border-radius:12px;padding:10px 16px;margin:14px 0;border:1px solid #fcd34d;background:#fffbeb;color:#78350f}
@media (prefers-color-scheme:dark){.callout{background:#422006;border-color:#a16207;color:#fde68a}}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;margin:16px 0}
.card{display:block;border:1px solid var(--line);border-radius:12px;padding:14px 16px;text-decoration:none;color:var(--ink);background:var(--paper);border-top:4px solid var(--c,var(--fw))}
.card:hover{background:var(--soft)}.card .t{font-weight:700}.card .d{color:var(--muted);font-size:13.5px;margin-top:4px}
.card .n{font:700 12px/1 var(--mono);color:var(--c,var(--fw))}
figure{margin:18px 0}figure svg{width:100%;height:auto;display:block}figcaption{color:var(--muted);font-size:13px;margin-top:6px}
.pager{display:flex;justify-content:space-between;gap:12px;margin-top:40px;padding-top:16px;border-top:1px solid var(--line)}
.pager a{text-decoration:none;font-weight:600}
.src-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
pre.src{background:var(--term);color:var(--term-ink);counter-reset:ln}
pre.src span{display:block}pre.src span::before{counter-increment:ln;content:counter(ln);display:inline-block;width:3.2em;margin-right:12px;text-align:right;color:#475569}
footer{color:var(--muted);font-size:12.5px;margin-top:32px}
@media (max-width:820px){.shell{grid-template-columns:1fr}nav.side{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);padding:12px 16px}
nav.side .sub{display:none}nav.side b{margin:8px 0 2px}nav.side a{display:inline-block;padding:2px 8px;font-size:13px}nav.side a.file{font-size:12px}
.content{padding:8px 16px 40px}.cover{padding:28px 16px 24px}.cover h1{font-size:26px}}
@media print{nav.side{display:none}.shell{display:block}body{background:#fff}}
"""


def nav(active: str) -> str:
    def a(href: str, text: str, cls: str = "") -> str:
        on = " on" if href == active else ""
        return f'<a class="{cls}{on}" href="{href}">{html.escape(text)}</a>'

    parts = ['<nav class="side">', '<div class="brand">pyfw</div>',
             '<div class="sub">Python network firewall</div>',
             a("index.html", "Overview"), "<b>Documents</b>"]
    for i, (md, title) in enumerate(DOC_PAGES, 1):
        parts.append(a(Path(md).stem + ".html", f"{i} · {title}"))
    parts.append("<b>Code</b>")
    parts.append(a("code.html", "All modules"))
    for f in CODE_FILES:
        parts.append(a(page_for_code(f), f, "file"))
    parts.append("</nav>")
    return "".join(parts)


def frame(active: str, title: str, cover: str, body: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)} · pyfw</title><style>{CSS}</style></head>"
        f'<body><div class="shell">{nav(active)}<main>{cover}<div class="content">{body}'
        "<footer>pyfw · Python network firewall</footer>"
        "</div></main></div></body></html>\n"
    )


def cover(kicker: str, title: str, lead: str = "", chips: tuple[str, ...] = ()) -> str:
    c = "".join(f'<span class="chip">{html.escape(x)}</span>' for x in chips)
    lead_html = f"<p>{lead}</p>" if lead else ""
    chips_html = f'<div class="chips">{c}</div>' if c else ""
    return f'<header class="cover"><div class="kicker">{html.escape(kicker)}</div><h1>{html.escape(title)}</h1>{lead_html}{chips_html}</header>'


def pager(prev: tuple[str, str] | None, nxt: tuple[str, str] | None) -> str:
    left = f'<a href="{prev[0]}">← {html.escape(prev[1])}</a>' if prev else "<span></span>"
    right = f'<a href="{nxt[0]}">{html.escape(nxt[1])} →</a>' if nxt else "<span></span>"
    return f'<div class="pager">{left}{right}</div>'


def build_index() -> str:
    readme = markdown((ROOT / "README.md").read_text(encoding="utf-8"), "root")
    return frame("index.html", "Overview",
                 cover("pyfw", "Python network firewall", "A small network lab project.",
                       ("Python 3.11+", "Bridge and router modes", "Standard library")),
                 "".join(readme.body))


def build_doc(idx: int) -> str:
    md, short = DOC_PAGES[idx]
    doc = markdown((DOCS / md).read_text(encoding="utf-8"), "docs")
    num, _, title = doc.title.partition(" · ")
    toc = ""
    if doc.toc:
        toc = '<div class="pagetoc"><b>On this page</b><br>' + "".join(
            f'<a href="#{i}">{html.escape(t)}</a>' for i, t in doc.toc) + "</div>"
    prev = ("index.html", "Overview") if idx == 0 else (Path(DOC_PAGES[idx - 1][0]).stem + ".html", DOC_PAGES[idx - 1][1])
    nxt = (Path(DOC_PAGES[idx + 1][0]).stem + ".html", DOC_PAGES[idx + 1][1]) if idx + 1 < len(DOC_PAGES) else ("code.html", "Code")
    return frame(Path(md).stem + ".html", short,
                 cover(f"pyfw · document {num.strip()}", title or doc.title),
                 toc + "".join(doc.body) + pager(prev, nxt))


def build_code_index() -> str:
    doc = markdown((CODE / "README.md").read_text(encoding="utf-8"), "code")
    cards = []
    for f in CODE_FILES:
        first = describe_file(CODE / f)[0]
        cards.append(f'<a class="card" href="{page_for_code(f)}"><div class="t"><code>{f}</code></div>'
                     f'<div class="d">{html.escape(first)}</div></a>')
    body = '<h2 id="files">Files</h2><div class="cards">' + "".join(cards) + "</div>" + "".join(doc.body)
    return frame("code.html", "Code",
                 cover("pyfw · code", "Code",
                       "Firewall modules and examples using the Python standard library. "
                       "Each page includes a description and the source code."),
                 body + pager((Path(DOC_PAGES[-1][0]).stem + ".html", DOC_PAGES[-1][1]), (page_for_code(CODE_FILES[0]), CODE_FILES[0])))


def describe_file(path: Path) -> tuple[str, str]:
    for line in (CODE / "README.md").read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) == 2 and cells[0] == f"[{path.name}]({path.name})":
            return cells[1], ""
    return path.name, ""


def build_code_page(k: int) -> str:
    name = CODE_FILES[k]
    path = CODE / name
    first, _ = describe_file(path)
    src = path.read_text(encoding="utf-8")
    lines = "".join(f"<span>{html.escape(ln) or ' '}</span>" for ln in src.splitlines())
    lang = {".py": "Python", ".sh": "bash"}[path.suffix]
    run = (f"sudo bash code/{name} up" if path.suffix == ".sh" else
           "sudo python3 code/mini_bridge.py --p25 enp45s0 --p1 enp46s0" if name == "mini_bridge.py" else
           f"python code/{name}")
    setup = ('<p>Follow the <a href="03-setup.html">setup instructions</a> before changing the lab network.</p>'
             if name in ("mini_bridge.py", "router_setup.sh") else "")
    body = (f"<h2 id=\"what-it-shows\">What it shows</h2><p><strong>{html.escape(first)}</strong></p>"
            f'<h2 id="run-it">Run it</h2>{setup}<pre class="cmd">{html.escape(run)}</pre>'
            f'<h2 id="source"><span class="src-head">Source <small><a href="{GITHUB}/code/{name}">{name} on GitHub</a> · '
            f"{len(src.splitlines())} lines · {lang}</small></span></h2>"
            f'<pre class="src">{lines}</pre>')
    prev = ("code.html", "Code") if k == 0 else (page_for_code(CODE_FILES[k - 1]), CODE_FILES[k - 1])
    nxt = (page_for_code(CODE_FILES[k + 1]), CODE_FILES[k + 1]) if k + 1 < len(CODE_FILES) else None
    return frame(page_for_code(name), name, cover("pyfw · code example", name, html.escape(first)), body + pager(prev, nxt))


def build_all() -> dict[str, str]:
    pages = {"index.html": build_index(), "code.html": build_code_index()}
    for i, (md, _) in enumerate(DOC_PAGES):
        pages[Path(md).stem + ".html"] = build_doc(i)
    for k, name in enumerate(CODE_FILES):
        pages[page_for_code(name)] = build_code_page(k)
    return pages


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build html from the docs and code examples.")
    ap.add_argument("--check", action="store_true", help="only check that html is up to date")
    a = ap.parse_args(argv)
    pages = build_all()
    stale = [n for n, text in pages.items()
             if not (OUT / n).exists() or (OUT / n).read_text(encoding="utf-8") != text]
    if a.check:
        if stale:
            print("out of date: " + ", ".join(stale) + "  (run python tools/build_html.py)", file=sys.stderr)
            return 1
        print(f"{len(pages)} pages up to date")
        return 0
    OUT.mkdir(exist_ok=True)
    for n, text in pages.items():
        (OUT / n).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(pages)} pages to {OUT} ({len(stale)} changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
