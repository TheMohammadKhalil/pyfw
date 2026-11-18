from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import build_html as b

GH = b.GITHUB


def test_links_map_to_pages_or_github() -> None:
    assert b.rewrite_link("docs/03-setup.md", "root") == "03-setup.html"
    assert b.rewrite_link("04-gateway-and-router.md#x", "docs") == "04-gateway-and-router.html#x"
    assert b.rewrite_link("../code/README.md", "docs") == "code.html"
    assert b.rewrite_link("../code/", "docs") == "code.html"
    assert b.rewrite_link("code/rule_engine.py", "root") == "code-rule_engine-py.html"
    assert b.rewrite_link("../../shared", "docs") == f"{GH}/shared"
    assert b.rewrite_link("../README.md", "root") == f"{GH}/README.md"
    assert b.rewrite_link("https://x.org/a", "docs") == "https://x.org/a"
    assert b.rewrite_link("#top", "docs") == "#top"


def test_inline_code_links_bold_escape() -> None:
    out = b.inline("**Bold** and `a<b` and [`shared/`](../shared) & *it*", "root")
    assert out == (f'<strong>Bold</strong> and <code>a&lt;b</code> and <a href="{GH}/shared"><code>shared/</code></a>'
                   " &amp; <em>it</em>")
    assert b.inline("`**not bold**`", "root") == "<code>**not bold**</code>"


def test_blocks_table_list_code_quote() -> None:
    md = """# 9 · Title

## Part one

| A | B |
|---|---|
| `x\\|y` | 2 |

1. first
2. second with code:

   ```bash
   echo hi
   ```

   after the code

> a note

- plain item
"""
    doc = b.markdown(md, "docs")
    body = "".join(doc.body)
    assert doc.title == "9 · Title" and doc.toc == [("part-one", "Part one")]
    assert "<td><code>x|y</code></td><td>2</td>" in body
    assert '<ol><li>first</li><li><p>second with code:</p><div class="code"><span class="lang">bash</span><pre class="cmd">echo hi</pre></div><p>after the code</p></li></ol>' in body
    assert '<div class="callout"><p>a note</p></div>' in body
    assert "<ul><li>plain item</li></ul>" in body


def test_describe_file_reads_module_documentation() -> None:
    for name in b.CODE_FILES:
        first, rest = b.describe_file(b.CODE / name)
        assert first and first != name
        assert rest == ""


def test_every_page_builds_and_internal_links_resolve() -> None:
    pages = b.build_all()
    assert set(pages) == {"index.html", "code.html", *(Path(md).stem + ".html" for md, _ in b.DOC_PAGES),
                          *(b.page_for_code(f) for f in b.CODE_FILES)}
    for name, text in pages.items():
        assert text.startswith("<!doctype html>") and "</html>" in text, name
        assert "```" not in text and "](" not in text, name
        ids = set(re.findall(r'id="([^"]+)"', text))
        for href in re.findall(r'href="([^"]+)"', text):
            if href.startswith("http"):
                continue
            page, _, frag = href.partition("#")
            if page:
                if page.startswith("../"):
                    assert (b.OUT / page).resolve().exists(), f"{name}: broken link {href}"
                else:
                    assert page in pages, f"{name}: broken link {href}"
            if frag and not page:
                assert frag in ids, f"{name}: missing anchor #{frag}"


def test_html_folder_is_up_to_date() -> None:
    assert b.main(["--check"]) == 0, "run: python tools/build_html.py"
