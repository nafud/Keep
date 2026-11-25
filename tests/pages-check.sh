#!/bin/bash
# pages-check.sh [-h] : builds the pages of Keep with MkDocs and looks at what was built.
#
#   tests/pages-check.sh                      mkdocs is the one on PATH
#   MKDOCS=/path/to/mkdocs tests/pages-check.sh
#
# The pages are built from mkdocs.yml, docs/ and overrides/ into a temporary directory, with
# --strict, so that a link between the pages without its target ends the build. Then the built
# pages are read:
#
#   pages      the home page, the four sections and the page for an address that is not there
#   frame      every page has the four sections on its frame in the order of mkdocs.yml, and
#              its own marked
#   own        a page loads nothing from another host: every script, stylesheet, font and
#              picture is a file of the site itself
#   theme      what the stylesheet and the scripts hook in Material is still in the built pages,
#              and what they removed is not: sidebars, the search and Kiln's palette
#   version    the pages name the version of the C program, KEEP_VERSION, and no other
#   references every reference of the About page is cited and every citation has its reference
#
# It reads the repository and writes into a temporary directory, which it removes. It needs
# mkdocs with the packages of requirements.txt and python3. Exit status 0 with RESULT: PASS,
# 1 with RESULT: FAIL or where the pages cannot be built, 2 for a wrong option.
set -u
cd "$(dirname "$0")/.." || exit 1

usage() { sed -n '2,/^set -u$/p' "$0" | sed '$d; s/^# \{0,1\}//'; }
while getopts h opt; do
    case $opt in
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || { usage >&2; exit 2; }

MKDOCS=${MKDOCS:-mkdocs}
command -v "$MKDOCS" > /dev/null || { echo "pages-check.sh: no mkdocs: pip install --require-hashes -r requirements.txt" >&2; exit 1; }
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
FAILED=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }
check() {
    local name=$1; shift
    if "$@" > "$T/out.txt" 2>&1; then pass "$name"; else fail "$name"; sed 's/^/      /' "$T/out.txt"; fi
}

echo "==== the pages of Keep"
"$MKDOCS" --version
# The notice of the theme about its successor is no part of the build.
if ! NO_MKDOCS_2_WARNING=1 "$MKDOCS" build --strict --site-dir "$T/site" > "$T/build.txt" 2>&1; then
    fail "mkdocs build --strict"
    sed 's/^/      /' "$T/build.txt"
    echo; echo "RESULT: FAIL"; exit 1
fi
pass "mkdocs build --strict"

built() {
    python3 -I - "$T/site" "$1" << 'EOF'
import glob, os, re, sys
site, what = sys.argv[1], sys.argv[2]
SECTIONS = ["installation", "usage", "systems", "about"]
HOME = "https://nafud.github.io/Keep/"      # site_url: the page for a missing address names its files by it
bad = []
def page(name):
    path = os.path.join(site, name, "index.html") if name else os.path.join(site, "index.html")
    return open(path, encoding="utf-8").read() if os.path.isfile(path) else None
pages = {name: page(name) for name in [""] + SECTIONS}
missing = open(os.path.join(site, "404.html"), encoding="utf-8").read() if os.path.isfile(os.path.join(site, "404.html")) else None

if what == "pages":
    for name, text in pages.items():
        if text is None:
            bad.append("no page " + (name or "index"))
    if missing is None:
        bad.append("no 404.html")
    for name in SECTIONS:
        if pages[name] and not re.search(r"<h1[^>]*>", pages[name]):
            bad.append(name + ": no first heading")
    if pages[""] and 'class="keep-ascii"' not in pages[""]:
        bad.append("the home page has no word to draw")

elif what == "frame":
    for name, text in pages.items():
        if text is None:
            continue
        nav = re.search(r'<ul class="keep-header__nav">(.*?)</ul>', text, re.S)
        links = re.findall(r'<a class="(keep-header__link[^"]*)" href="([^"]*)">([^<]*)</a>', nav.group(1)) if nav else []
        if [l[2] for l in links] != SECTIONS:
            bad.append("%s: the sections on its frame are %s" % (name or "index", [l[2] for l in links]))
        active = [l[2] for l in links if "keep-header__link--active" in l[0]]
        if active != ([name] if name else []):
            bad.append("%s: the marked section is %s" % (name or "index", active))
        if not re.search(r'class="[^"]*\bmd-logo\b[^"]*"[^>]*>\[keep\]</a>', text):
            bad.append("%s: no [keep] on the frame" % (name or "index"))
        if 'class="keep-header__src"' not in text:
            bad.append("%s: no link to the source on the frame" % (name or "index"))

elif what == "own":
    files = glob.glob(os.path.join(site, "**", "*.html"), recursive=True)
    for path in files:
        text = open(path, encoding="utf-8").read()
        for tag, attrs in re.findall(r"<(script|link|img|source|iframe|video|audio|object|embed)\b([^>]*)>", text):
            for ref in re.findall(r'\b(?:src|href)="([^"]*)"', attrs):
                if tag == "link" and re.search(r'\brel="(?:canonical|alternate|prev|next)"', attrs):
                    continue                    # an address of the page itself, nothing is loaded
                if ref.startswith(HOME):
                    ref = ref[len(HOME):]
                if re.match(r"[a-z][a-z0-9+.-]*:|//", ref):
                    bad.append("%s: <%s> loads %s" % (os.path.relpath(path, site), tag, ref))
    for path in glob.glob(os.path.join(site, "**", "*.css"), recursive=True):
        text = open(path, encoding="utf-8").read()
        for ref in re.findall(r"url\(\s*[\"']?([^\"')]+)", text) + re.findall(r"@import\s+[\"']([^\"']+)", text):
            if re.match(r"(?:https?:)?//", ref):
                bad.append("%s: loads %s" % (os.path.relpath(path, site), ref))
    if not files:
        bad.append("no page was built")

elif what == "theme":
    home, usage = pages[""] or "", pages["usage"] or ""
    for hook in ['data-md-component="dialog"', "md-logo", "__palette", 'data-md-component="palette"', "md-main__inner",
                 "md-content__inner", "md-typeset", "md-header", "md-container", "md-footer", "data-md-color-scheme",
                 "data-md-color-primary", "data-md-color-accent", "keep-js", "keep-header__nav"]:
        if hook not in home:
            bad.append("the home page has no %s: the theme has changed below extra.css, the page scripts or overrides/" % hook)
    if len(re.findall(r'name="__palette"', home)) != 5:
        bad.append("the home page does not offer five themes")
    if "md-sidebar" in usage:
        bad.append("a page has sidebars again: overrides/main.html no longer empties them")
    if missing is not None and "keep-404" not in missing:
        bad.append("404.html is not the page of overrides/404.html")
    for name, text in list(pages.items()) + [("404", missing)]:
        for gone in ["md-search", "keep-jump", "quick-jump", "widgets.js"]:
            if text and gone in text:
                bad.append("%s: %s is in the page" % (name or "index", gone))
    if os.path.exists(os.path.join(site, "search")):
        bad.append("a search index was built")

elif what == "version":
    source = open("src/triage.h", encoding="utf-8").read()
    m = re.search(r'#define KEEP_VERSION "([^ "]+)', source)
    if not m:
        bad.append("no KEEP_VERSION in src/triage.h")
    else:
        version = m.group(1)
        if ("keep %s (" % version) not in re.sub(r"<[^>]+>", "", pages["installation"] or ""):
            bad.append("the installation page does not show keep %s" % version)
        for name, text in pages.items():
            for other in set(re.findall(r"\b\d+\.\d+-pre\d+\b", text or "")) - {version}:
                bad.append("%s names the version %s" % (name or "index", other))

elif what == "references":
    text = pages["about"] or ""
    have = [int(n) for n in re.findall(r'<span id="ref-(\d+)">', text)]
    cited = {int(n) for n in re.findall(r'href="[^"#]*#ref-(\d+)"', text)}
    if not have or have != list(range(1, len(have) + 1)):
        bad.append("the references are not numbered from 1 on: %s" % have)
    if cited != set(have):
        bad.append("cited and not listed, or listed and not cited: %s" % sorted(cited ^ set(have)))
    for n, shown in re.findall(r'href="[^"#]*#ref-(\d+)">\[(\d+)\]', text):
        if n != shown:
            bad.append("the citation [%s] leads to reference %s" % (shown, n))

sys.exit("\n".join(bad) or 0)
EOF
}

check "the home page, the four sections and 404.html are built" built pages
check "every page has the four sections on its frame, and its own marked" built frame
check "a page loads nothing from another host" built own
check "what the stylesheet and the scripts hook in the theme is there, and no sidebar, search or palette" built theme
check "the pages name the version of the C program and no other" built version
check "every reference is cited and every citation leads to its reference" built references

echo
if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
echo "RESULT: FAIL"; exit 1
