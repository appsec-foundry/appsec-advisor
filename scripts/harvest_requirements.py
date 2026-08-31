#!/usr/bin/env python3
"""
harvest-requirements.py — Crawls configured source URLs for requirements and
blueprints, then writes a catalog YAML and optional functional-spec exports.

Usage:
    python harvest-requirements.py [OPTIONS]

Options:
    --config PATH       Path to harvest-config.json (default: next to this script)
    --output PATH       Override the catalog YAML output path
    --format FORMAT     Output yaml, openspec, specdd, or all (repeatable)
    --openspec-output PATH
                        Override the single-file OpenSpec output path
    --specdd-output PATH
                        Override the single-file SpecDD output path
    --token TOKEN       Bearer token (overrides HARVEST_AUTH_TOKEN env var)
    --dry-run           Fetch and parse but do not write the output file
    --verbose, -v       Print each parsed item
    --req-only          Only process sources of type 'requirement'
    --blueprint-only    Only process sources of type 'blueprint'

Configuration:
    The config file is a JSON document with a top-level `sources` array. Each
    source declares {id, type, title, crawl_url, mode, [max_pages],
    [section_max_chars], [reference_url], [outputs]}. Existing sources default
    to outputs=["catalog"]. Add "openspec" and/or "specdd" only to sources
    that describe observable functional behavior.

    For a full template, see harvest-config.example.json (copy it to
    harvest-config.json and edit). Key sections:
        - request   — HTTP session (timeout, auth env, proxy, TLS verify, headers)
        - defaults  — max_pages, requirements_mode, blueprints_mode, section_max_chars
        - sources[] — one entry per URL to crawl
        - description / url / output — optional metadata + output path

How discovery works (per source):
    1. Fetch crawl_url (e.g. https://appsec.int.example.com/scg)
    2. Include the fetched crawl_url page itself in the pages to index
    3. Collect and fetch direct same-origin <a href> links that are children of
       the base path (linked pages are capped at max_pages; crawling is not recursive)
    4. For requirement sources: keep pages that contain any [PREFIX-…] token
       or an AsciiDoc-style <span class="badge">PREFIX-…</span> and extract items
    5. For blueprint sources: index <h2>/<h3> sections with their content

    Backwards compatibility: legacy top-level `crawl` + `*_overrides` keys are
    still accepted and converted into a synthetic `sources` list internally.

Authentication:
    Set HARVEST_AUTH_TOKEN in the environment or pass --token.
    Sent as "Authorization: Bearer <token>".
"""

import argparse
import copy
import html as html_lib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import requirements_state as rstate  # noqa: E402
except ImportError:
    # Copying this script alone into another repository or CI job is a common
    # way to run the harvester. It needs its sibling module for the catalog
    # schema validation that guards the written output.
    print(
        "Missing sibling module requirements_state.py — copy it next to "
        f"{Path(__file__).name} ({Path(__file__).resolve().parent}).",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import requests
    import urllib3
    import yaml
    from bs4 import BeautifulSoup
except ImportError:
    print(
        "Missing dependencies. Run:  pip install requests beautifulsoup4 pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Any requirement/guideline ID uses the shape <PREFIX>-<PART>[-<PART>]...
# where PREFIX is 2+ uppercase-letter-or-digit chars starting with a letter
# (e.g. SEC, SCG, OWASP, REQ, ISO27K). No specific prefixes are hardcoded.
_ID_BODY = r"[A-Z][A-Z0-9]*-[A-Z0-9]+(?:-[A-Z0-9]+)*"

REQ_ID_PATTERN = re.compile(r"\[\s*(" + _ID_BODY + r")\s*\]", re.IGNORECASE)
ANCHOR_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d+$")
PRIORITY_PATTERN = re.compile(r"\b(MUST|SHOULD|MAY)\b")
ANCHOR_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "div", "span", "dt", "section", "article"}

# PREFIX-CATEGORY-NUMBER → capture PREFIX-CATEGORY (used for grouping)
CATEGORY_FROM_NUMERIC_ID = re.compile(r"^([A-Z][A-Z0-9]*-[A-Z0-9]+)-\d+$")
# Generic uppercase ID prefix (PREFIX-…), used for badge recognition and ID sanity-checks.
ID_PREFIX_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*-")

# Priority label span classes: must-label, should-label, may-label
PRIORITY_LABEL_PATTERN = re.compile(r"(must|should|may)-label", re.IGNORECASE)
# Any ID reference in free text — generic prefix, same shape as REQ_ID_PATTERN without brackets.
# Case-insensitive like REQ_ID_PATTERN: source pages often render a link's
# visible text in title case (e.g. "SEC-Api-Exposure") even though the canonical ID is all caps.
REF_ID_PATTERN = re.compile(r"\b(" + _ID_BODY + r")\b", re.IGNORECASE)

# An element (table cell, <dt>) whose entire text is just the ID — no brackets
# needed since the surrounding structure (its own cell/tag) is the delimiter.
ID_ONLY_PATTERN = re.compile(r"^\s*(" + _ID_BODY + r")\s*$", re.IGNORECASE)
# An ID at the very start of an element's text, followed by a clear separator
# (colon, or a dash/em-dash surrounded by whitespace) before the requirement
# text. Requires an explicit separator (not just a following word) to avoid
# matching ordinary hyphenated terms such as "UTF-8 encoding" or "ISO-27001
# certification".
ID_LEADING_PATTERN = re.compile(r"^\s*(" + _ID_BODY + r")(?:\s*:\s*|\s+[-‐‑‒–—―]\s+)", re.IGNORECASE)


def extract_id_and_text(raw: str, allow_unbracketed: bool = True) -> Optional[tuple[str, str]]:
    """
    Find a leading requirement ID in `raw` free text, in order of preference:
      1. [PREFIX-ID] anywhere (bracket convention)
      2. the entire (stripped) text is just PREFIX-ID (e.g. a table cell or <dt>)
      3. PREFIX-ID at the very start, followed by ':' or a whitespace-bounded
         dash/em-dash (e.g. "REQ-001: text", "REQ-002 - text")
    Returns (id, remaining_text) or None if no convention matches. Set
    `allow_unbracketed=False` to only accept the bracket convention — used for
    contexts (code samples, hyperlink text) where an unbracketed "ID: text" or
    "ID - text" shape is likely to be something else (an example HTTP header, a
    link caption referencing another page) rather than a requirement definition.
    """
    m = REQ_ID_PATTERN.search(raw)
    if m:
        return m.group(1).upper(), (raw[: m.start()] + raw[m.end() :]).strip()
    if not allow_unbracketed:
        return None
    stripped = raw.strip()
    m = ID_ONLY_PATTERN.match(stripped)
    if m:
        return m.group(1).upper(), ""
    m = ID_LEADING_PATTERN.match(stripped)
    if m:
        return m.group(1).upper(), stripped[m.end() :].strip()
    return None


CATALOG_OUTPUT = "catalog"
OPENSPEC_OUTPUT = "openspec"
SPECDD_OUTPUT = "specdd"
VALID_SOURCE_OUTPUTS = {CATALOG_OUTPUT, OPENSPEC_OUTPUT, SPECDD_OUTPUT}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def build_session(
    token: Optional[str],
    extra_headers: dict,
    timeout: int,
    use_proxy: bool = True,
    verify_ssl: bool = True,
) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "appsec-advisor/harvest-requirements (internal)",
            "Accept": "text/html,application/xhtml+xml",
        }
    )
    if extra_headers:
        session.headers.update(extra_headers)
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    session.timeout = timeout
    # trust_env=False makes requests ignore HTTPS_PROXY/HTTP_PROXY env vars,
    # which is needed when the proxy can't resolve internal hostnames.
    session.trust_env = use_proxy
    # verify can be False or a path to a CA bundle for self-signed/internal certs.
    session.verify = verify_ssl
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def fetch(session: requests.Session, url: str, label: str) -> tuple[Optional[str], str]:
    """Returns (html, final_url). final_url is the URL after any redirects."""
    try:
        resp = session.get(url)
        resp.raise_for_status()
        # Force UTF-8: servers often omit charset in Content-Type, causing requests
        # to default to ISO-8859-1, which garbles multi-byte characters (em-dashes etc.)
        if resp.encoding and resp.encoding.upper() in ("ISO-8859-1", "LATIN-1"):
            resp.encoding = "utf-8"
        return resp.text, resp.url
    except requests.exceptions.Timeout:
        print(f"  [WARN] {label}: request timed out — {url}", file=sys.stderr)
    except requests.exceptions.HTTPError as e:
        print(f"  [WARN] {label}: HTTP {e.response.status_code} — {url}", file=sys.stderr)
    except requests.exceptions.ConnectionError:
        print(f"  [WARN] {label}: connection failed — {url}", file=sys.stderr)
    return None, url


# ---------------------------------------------------------------------------
# Crawler: link discovery
# ---------------------------------------------------------------------------


def same_origin_links(html: str, base_url: str) -> list[str]:
    """
    Return all unique href links in html that are children of base_url
    (same scheme+host, path starts with base_url path).
    Excludes the base_url itself, anchor-only links, and non-HTTP links.
    """
    soup = BeautifulSoup(html, "html.parser")
    base = urlparse(base_url)
    # If the final URL points to a file (e.g. /scg/index.html after redirect from /scg),
    # use its parent directory for the "child path" check so sibling pages like
    # /scg/page.html are not erroneously excluded.
    last_segment = base.path.rstrip("/").rsplit("/", 1)[-1]
    if "." in last_segment:
        base_dir = base.path.rstrip("/").rsplit("/", 1)[0] + "/"
    else:
        base_dir = base.path.rstrip("/") + "/"
    seen: set[str] = set()
    result: list[str] = []

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        # Strip fragment
        absolute = parsed._replace(fragment="").geturl()
        if absolute in seen or absolute == base_url:
            continue
        # Must be same scheme and host, and path must be under base path
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc != base.netloc:
            continue
        if not parsed.path.startswith(base_dir):
            continue
        seen.add(absolute)
        result.append(absolute)

    return result


def crawl_index(
    session: requests.Session,
    base_url: str,
    label: str,
    max_pages: int,
) -> tuple[list[tuple[str, str]], Optional[tuple[str, str]]]:
    """
    Fetch base_url, discover sub-page links, fetch each one.
    Returns (sub_pages, index_page) where:
      - sub_pages: list of (url, html) for successfully fetched sub-pages
      - index_page: (final_url, html) of the index page itself, or None on failure

    Uses the final URL after HTTP redirects as the base for resolving relative hrefs,
    which prevents relative links from resolving to the wrong path when the index URL
    redirects (e.g. /scg → /scg/ causing urljoin to drop the path segment).
    """
    print(f"  Crawling index: {base_url}")
    index_html, final_url = fetch(session, base_url, label)
    if index_html is None:
        return [], None

    # Use final URL (after redirects) so relative hrefs like "page-name" resolve to
    # /scg/page-name rather than /page-name when the server redirects /scg → /scg/
    links = same_origin_links(index_html, final_url)
    print(f"  Found {len(links)} sub-page link(s) under {final_url}")
    if len(links) > max_pages:
        print(f"  [WARN] Capping at {max_pages} pages (found {len(links)})", file=sys.stderr)
        links = links[:max_pages]

    pages: list[tuple[str, str]] = []
    for url in links:
        html, page_final_url = fetch(session, url, url)
        if html is not None:
            pages.append((page_final_url, html))

    return pages, (final_url, index_html)


# ---------------------------------------------------------------------------
# Requirement page parser
# ---------------------------------------------------------------------------


def detect_priority(text: str) -> str:
    m = PRIORITY_PATTERN.search(text)
    return m.group(1) if m else "MUST"


def clean_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    text = REQ_ID_PATTERN.sub("", text, count=1).strip(" .—:-")
    return text


def as_req_id(text: str) -> str:
    """Normalize text the way a rendered ID reads, for ID comparisons only.

    Antora badges use a non-breaking hyphen and some sources write the first
    separator as an underscore, so the visible ID differs from the canonical one
    character by character.
    """
    return text.upper().replace("\u2011", "-").replace("_", "-")


def deduplicate_text(text: str) -> str:
    """
    Remove consecutive duplicate sentences/phrases that Antora/AsciiDoc HTML
    often produces (e.g. rendering list items twice for different viewports).
    Splits on sentence boundaries, drops any sentence that is identical to the
    immediately preceding one, then rejoins.
    """
    # Split on ". " or newline boundaries, preserving the separator
    parts = re.split(r"(?<=\.)\s+|\n", text)
    seen: list[str] = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if seen and p == seen[-1]:
            continue
        seen.append(p)
    return " ".join(seen)


UNBRACKETED_EXCLUDED_TAGS = ("pre", "code", "a")


def extract_id_from_element(tag) -> Optional[tuple[str, str]]:
    """Extract a requirement definition while respecting semantic markup.

    Bracketed IDs remain explicit in every context. Unbracketed ID-shaped text
    inside code samples or links is a reference/example, including when an
    outer element supplies the separator and description.
    """
    raw = element_text(tag)
    bracketed = REQ_ID_PATTERN.search(raw) is not None
    allow_unbracketed = tag.name not in UNBRACKETED_EXCLUDED_TAGS and tag.find_parent(UNBRACKETED_EXCLUDED_TAGS) is None
    extracted = extract_id_and_text(raw, allow_unbracketed=allow_unbracketed)
    if not extracted or bracketed:
        return extracted

    req_id, _ = extracted
    for nested in tag.find_all(UNBRACKETED_EXCLUDED_TAGS):
        nested_extracted = extract_id_and_text(nested.get_text())
        if nested_extracted and nested_extracted[0] == req_id:
            return None
    return extracted


def page_has_requirements(html: str) -> bool:
    """Return whether the page contains at least one extractable requirement."""
    return bool(parse_requirements_from_page(html, ""))


def parse_page_intro(html: str) -> str:
    """
    Extract the introductory paragraph(s) that appear before the first
    requirement item on the page. Used in 'full' indexing mode for requirements.
    Returns an empty string when nothing useful is found.
    """
    soup = BeautifulSoup(html, "html.parser")
    main = (
        soup.find("main")
        or soup.find("article")
        or soup.find("div", {"role": "main"})
        or soup.find("div", {"id": re.compile(r"content|main", re.I)})
        or soup.body
    )
    if not main:
        return ""

    intro_parts: list[str] = []
    for el in main.find_all(["p", "div", "blockquote"], recursive=True):
        # Stop at the first element that contains an extractable requirement.
        # This shares the parser's bracketed/unbracketed and markup semantics.
        if extract_id_from_element(el):
            break
        # Skip elements that contain child block elements (likely containers)
        if el.find(["p", "ul", "ol", "table", "section"]):
            continue
        text = element_text(el)
        if len(text) > 40:  # ignore navigation snippets and short labels
            intro_parts.append(text)
        if len(intro_parts) >= 3:  # at most 3 intro paragraphs
            break

    return " ".join(intro_parts)


# Direct children of an Antora <div class="sectionbody"> that carry requirement
# text. Anything else there (anchors, scripts, navigation) is not content.
SECTIONBODY_CONTENT_TAGS = ("div", "p", "details", "table", "dl", "ul", "ol", "pre", "blockquote")


def parse_requirements_from_page(html: str, page_url: str) -> list[dict]:
    """
    Try multiple strategies to extract structured requirements from a page.
    Returns list of dicts: {id, url, text, priority}.
    """
    soup = BeautifulSoup(html, "html.parser")
    found: dict[str, dict] = {}

    # Strategy 0: Antora/AsciiDoc format
    #   <h2 id="..."><span class="must-label">MUST</span> Title</h2>
    #   <div class="sectionbody">
    #     <p><span class="badge">PREFIX-ID</span></p>  ← requirement ID (any prefix)
    #     <p>Short requirement text</p>
    #     <details>...</details>   ← excluded (details content)
    #   </div>
    for sectionbody in soup.find_all("div", class_="sectionbody"):
        badge = sectionbody.find("span", class_="badge")
        if not badge:
            continue
        # Normalize underscore variant: PREFIX_NAME → PREFIX-NAME
        # Also normalize Unicode non-breaking hyphen U+2011 → ASCII hyphen
        req_id = badge.get_text(strip=True).upper().replace("\u2011", "-").replace("_", "-", 1)
        if not ID_PREFIX_PATTERN.match(req_id):
            continue
        if req_id in found:
            continue

        h2 = sectionbody.find_previous_sibling("h2")
        anchor = h2.get("id", "").lower() if h2 else ""
        if h2:
            label_span = h2.find("span", class_=PRIORITY_LABEL_PATTERN)
            # Strip trailing colon that Antora adds: "SHOULD:" → "SHOULD"
            priority = (
                label_span.get_text(strip=True).rstrip(":").upper() if label_span else detect_priority(h2.get_text())
            )
            h2_title = PRIORITY_PATTERN.sub("", h2.get_text(strip=True), count=1).strip(" :")
        else:
            # Badge-only preamble under h1 (no preceding h2) — pages where the
            # entire page describes one atomic requirement.
            priority = "MUST"
            prev_h1 = sectionbody.find_previous("h1")
            h2_title = PRIORITY_PATTERN.sub("", prev_h1.get_text(strip=True), count=1).strip(" :") if prev_h1 else ""
        if priority not in ("MUST", "SHOULD", "MAY"):
            priority = "MUST"

        # Collect every content block of the section body. Antora puts prose in
        # <div>/<p>, tabular limits in a direct <table>, and rationale, examples
        # or verification steps in a collapsible <details> — all of it belongs to
        # the requirement.
        text_parts: list[str] = []
        for child in sectionbody.children:
            if getattr(child, "name", None) not in SECTIONBODY_CONTENT_TAGS:
                continue
            if child.find("div", class_="sectionbody") is not None:
                continue  # nested sub-section — parsed as its own requirement
            text = block_text(child)
            if text and as_req_id(text) != as_req_id(req_id):
                if not text.endswith((".", ";", ":", "!", "?")):
                    text += ";"  # keep an unpunctuated block apart from the next one
                text_parts.append(text)

        req_text = deduplicate_text(" ".join(text_parts).strip())
        # Badge-only preamble (atomic-requirement pages): grab text from the following
        # Summary sect1 before falling back to a heading, which only names the
        # requirement instead of stating it.
        if not req_text or as_req_id(req_text) == as_req_id(req_id):
            preamble = sectionbody.parent
            for sibling in preamble.find_next_siblings("div", class_="sect1"):
                sibling_h2 = sibling.find("h2")
                if sibling_h2 and sibling_h2.get_text(strip=True).lower() in ("summary", "details"):
                    sibling_body = sibling.find("div", class_="sectionbody")
                    if sibling_body:
                        req_text = element_text(sibling_body)
                    break
        if not req_text:
            req_text = h2_title
        # Last resort: if req_text is still empty or equals the ID, use the page <h1> title
        if not req_text or as_req_id(req_text) == as_req_id(req_id):
            page_h1 = soup.find("h1")
            if page_h1:
                req_text = PRIORITY_PATTERN.sub("", page_h1.get_text(strip=True), count=1).strip(" :")
        url_anchor = f"{page_url.rstrip('/')}#{anchor}" if anchor else page_url

        found[req_id] = {
            "id": req_id,
            "url": url_anchor,
            "text": clean_text(req_text),
            "priority": priority,
        }

    # Strategy 1: elements with id matching sec-xx-n
    for tag in soup.find_all(ANCHOR_TAGS):
        tag_id = (tag.get("id") or "").strip()
        if not ANCHOR_ID_PATTERN.match(tag_id):
            continue
        req_id = tag_id.upper()
        text = clean_text(element_text(tag))
        if not text:
            sib = tag.find_next_sibling(["p", "dd", "div", "span"])
            text = clean_text(element_text(sib)) if sib else ""
        if text and req_id not in found:
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{tag_id.lower()}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Strategy 2: definition list <dt>PREFIX-XX-N</dt><dd>text</dd>
    # (with or without brackets, and with or without a "PREFIX-XX-N: text" separator)
    for dt in soup.find_all("dt"):
        extracted = extract_id_and_text(element_text(dt))
        if not extracted:
            continue
        req_id, dt_remainder = extracted
        if req_id in found:
            continue
        dd = dt.find_next_sibling("dd")
        text = clean_text(element_text(dd)) if dd else clean_text(dt_remainder)
        if text:
            anchor = req_id.lower()
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{anchor}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Strategy 3: any element whose text names PREFIX-XX-N (bracketed, or a bare
    # ID at the start of the element followed by a separator, e.g. "REQ-001: text")
    for tag in soup.find_all(True):
        extracted = extract_id_from_element(tag)
        if not extracted:
            continue
        req_id, remainder = extracted
        if req_id in found:
            continue
        # Skip containers whose children already matched — but only when that
        # child match is itself a usable requirement (non-empty text). A child
        # that is just the bare ID (e.g. an <strong>ID</strong> wrapper with the
        # separator and text as the parent's sibling text) cannot stand alone,
        # so let this container win instead.
        if tag.find(True):
            child_extracted = extract_id_and_text(" ".join(c.get_text() for c in tag.find_all(True, recursive=False)))
            if child_extracted and clean_text(child_extracted[1]):
                continue
        text = clean_text(remainder)
        if text:
            anchor = req_id.lower()
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{anchor}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Strategy 4: table rows — ID cell (bracketed or bare) + text cell
    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if len(cells) < 2:
            continue
        extracted = extract_id_and_text(element_text(cells[0]))
        if not extracted:
            continue
        req_id, _ = extracted
        if req_id in found:
            continue
        text = clean_text(element_text(cells[1]))
        if text:
            anchor = req_id.lower()
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{anchor}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Sort: numeric IDs first (by number), then descriptive IDs alphabetically
    def _req_sort_key(r: dict):
        m = re.search(r"-(\d+)$", r["id"])
        return (0, int(m.group(1)), "") if m else (1, 0, r["id"])

    result = sorted(found.values(), key=_req_sort_key)
    return result


def group_by_category(
    all_reqs: list[dict],
    page_url: str,
    page_title: str,
    mode: str = "structured",
    page_intro: str = "",
) -> list[dict]:
    """
    Group a flat list of requirements into categories for the YAML schema.

    Grouping rules (prefix-agnostic):
      * If the page yields exactly one requirement, that requirement's ID becomes
        its own category (atomic-requirement pages such as standalone lifecycle
        controls).
      * Otherwise, IDs of the form ``PREFIX-CATEGORY-NUMBER`` are grouped under
        ``PREFIX-CATEGORY``. IDs without a trailing number fall back to a
        category derived from the URL slug.

    mode="structured" — id, url, text, priority per requirement (default)
    mode="full"       — structured + category-level context field with page intro
    """
    from collections import defaultdict

    # URL-slug-derived fallback category for multi-requirement pages whose IDs
    # don't carry a trailing numeric suffix.
    url_slug = urlparse(page_url).path.rstrip("/").split("/")[-1]
    url_cat = url_slug.upper().replace("-", "_") or "UNCATEGORIZED"

    groups: dict[str, list] = defaultdict(list)

    if len(all_reqs) == 1:
        # Atomic-requirement page — use the ID itself as category label.
        sole = all_reqs[0]
        groups[sole["id"]].append(sole)
    else:
        for r in all_reqs:
            m = CATEGORY_FROM_NUMERIC_ID.match(r["id"])
            cat = m.group(1) if m else url_cat
            groups[cat].append(r)

    categories = []
    for cat_id, reqs in groups.items():
        entry: dict = {
            "id": cat_id,
            "url": page_url,
            "title": page_title,
        }
        if mode == "full" and page_intro:
            entry["context"] = wrap_long(page_intro)
        entry["requirements"] = [
            {
                "id": r["id"],
                "url": r["url"],
                "text": wrap_long(r["text"]),
                "priority": r["priority"],
            }
            for r in reqs
        ]
        categories.append(entry)
    return categories


def page_title(html: str, fallback: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(strip=True)
    if soup.title:
        return soup.title.get_text(strip=True)
    return fallback


# ---------------------------------------------------------------------------
# Blueprint page parser
# ---------------------------------------------------------------------------


def section_anchor(title: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", title.lower())
    return re.sub(r"\s+", "-", slug.strip())


# Tags whose text is collected as blueprint section content: prose blocks, table
# rows (taken whole so a row's cells stay together) and definition lists. A tag of
# one of these types nested inside another (e.g. <p> inside <li>, <code> inside
# <pre>) is visited twice by find_all() — skip the nested one so its text
# isn't captured twice.
BLUEPRINT_CONTENT_TAGS = ("p", "li", "pre", "code", "blockquote", "tr", "dt", "dd")


def element_text(el) -> str:
    """Extract an element's text with a space inserted at tag boundaries.

    Plain ``get_text(strip=True)`` strips each text fragment individually
    before joining with an empty separator, so words on either side of an
    inline tag (e.g. ``<strong>``) end up glued together. Use an explicit
    separator and collapse the result to single spaces.
    """
    text = re.sub(r"\s+", " ", el.get_text(" ", strip=True)).strip()
    # The inserted separator can leave a stray space where an inline tag
    # boundary sits directly next to punctuation (e.g. "text : more" or "( x )").
    text = re.sub(r"\s+([.,:;)])", r"\1", text)
    text = re.sub(r"([(])\s+", r"\1", text)
    return text


# Elements that end one item of an enumeration. Their boundary carries meaning:
# without it a table or list collapses into a run-on string ("15 min idle 8 h
# absolute API token 60 min") in which no value can be attributed to its subject.
ITEM_TAGS = ("li", "tr", "dd")


def block_text(el) -> str:
    """Extract a content block's text, keeping list, table and collapsible boundaries."""
    if not el.find(ITEM_TAGS) and not el.find("summary"):
        return element_text(el)
    marked = copy.copy(el)  # bs4 copies deeply; the parsed document stays untouched
    for item in marked.find_all(ITEM_TAGS):
        item.append(";")
    for label in marked.find_all("summary"):
        label.append(":")  # a collapsible's summary titles the block it opens
    text = element_text(marked)
    text = re.sub(r"(?:\s*;)+", ";", text)
    text = re.sub(r";(?=\S)", "; ", text)
    return text.strip(" ;")


def parse_blueprint_page(html: str, bp_url: str, mode: str = "full", max_section_chars: int = 500) -> dict:
    """
    Index a blueprint page.

    mode="full"    — title, summary, topics + all sections with content (default)
    mode="summary" — title, summary, topics only; sections are omitted
    """
    soup = BeautifulSoup(html, "html.parser")

    h1 = soup.find("h1")
    title = element_text(h1) if h1 else (soup.title.get_text(strip=True) if soup.title else bp_url)

    meta = soup.find("meta", {"name": re.compile(r"description", re.I)})
    meta_summary = meta.get("content", "").strip() if meta else ""

    main = (
        soup.find("main")
        or soup.find("article")
        or soup.find("div", {"role": "main"})
        or soup.find("div", {"id": re.compile(r"content|main", re.I)})
        or soup.body
    )

    sections: list[dict] = []
    summary = ""
    current_title: Optional[str] = None
    current_anchor: Optional[str] = None
    current_parts: list[str] = []
    heading_anchors: list[str] = []  # collected even in summary mode for topics
    # Paragraphs before the first heading (used when there are no sections)
    preamble_parts: list[str] = []

    if main:
        for el in main.find_all(["h1", "h2", "h3", *BLUEPRINT_CONTENT_TAGS], recursive=True):
            if el.name == "h1":
                continue
            if el.name in ("h2", "h3"):
                heading_title = element_text(el)
                # Prefer explicit id attribute; fall back to slug derived from title
                heading_id = el.get("id") or section_anchor(heading_title)
                heading_anchors.append(heading_id)
                if mode == "full":
                    if current_title:
                        raw = " ".join(current_parts).strip()
                        sections.append(
                            {
                                "title": current_title,
                                "anchor": current_anchor,
                                "content": deduplicate_text(raw)[:max_section_chars],
                            }
                        )
                    current_title = heading_title
                    current_anchor = heading_id
                    current_parts = []
                continue
            if el.name in BLUEPRINT_CONTENT_TAGS and el.find_parent(BLUEPRINT_CONTENT_TAGS) is not None:
                continue  # nested match (e.g. <p> inside <li>) — parent already captures this text
            text = element_text(el)
            if not text:
                continue
            if el.name in ITEM_TAGS and not text.endswith((".", ";", ":", "!", "?")):
                text += ";"  # keep one row or list item apart from the next
            if not current_title:
                # Before first heading: collect preamble, first meaningful sentence → summary
                if len(text) > 30 and not summary:
                    summary = text
                elif len(text) > 30:
                    preamble_parts.append(text)
                continue
            if mode == "full":
                current_parts.append(text)

        if mode == "full" and current_title:
            raw = " ".join(current_parts).strip()
            sections.append(
                {
                    "title": current_title,
                    "anchor": current_anchor,
                    "content": deduplicate_text(raw)[:max_section_chars],
                }
            )

    # For flat pages with no section headings (e.g. CORS), collect preamble as one section
    if mode == "full" and not sections and preamble_parts:
        all_preamble = (summary + " " + " ".join(preamble_parts)).strip()
        sections.append(
            {
                "title": "Overview",
                "anchor": "overview",
                "content": deduplicate_text(all_preamble)[:max_section_chars],
            }
        )

    if not summary:
        summary = meta_summary or f"Blueprint: {title}"

    # Topics are the anchor IDs of all headings
    topics = [a for a in heading_anchors if a]

    result: dict = {
        "title": title,
        "summary": summary,
        "topics": topics,
    }
    if mode == "full":
        result["sections"] = sections
    return result


# ---------------------------------------------------------------------------
# YAML helpers
# ---------------------------------------------------------------------------


class LiteralStr(str):
    pass


def literal_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_representer)


def wrap_long(text: str, threshold: int = 120) -> str:
    return LiteralStr(text) if len(text) > threshold else text


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> dict:
    with open(config_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Harvest: requirements
# ---------------------------------------------------------------------------


def resolve_indexing_mode(cfg: dict, source_type: str, entry_override: Optional[str], default: str) -> str:
    """
    Resolve the effective indexing mode for a source.
    Priority: per-entry override > global config defaults > hardcoded default.
    """
    if entry_override:
        return entry_override
    defaults = cfg.get("defaults", {})
    if source_type == "requirement":
        return defaults.get("requirements_mode", default)
    elif source_type == "blueprint":
        return defaults.get("blueprints_mode", default)
    return default


def harvest_requirements_source(
    session: requests.Session,
    cfg: dict,
    source: dict,
    verbose: bool,
) -> list[dict]:
    """
    Harvest requirements from a single source entry.
    Returns list of category dicts for the YAML output.
    """
    crawl_url: str = source.get("crawl_url", "")
    source_id: str = source.get("id", "unknown")
    max_pages: int = source.get("max_pages", cfg.get("defaults", {}).get("max_pages", 100))
    mode: str = resolve_indexing_mode(cfg, "requirement", source.get("mode"), "structured")

    if not crawl_url:
        print(f"  [WARN] Source '{source_id}': no crawl_url — skipping", file=sys.stderr)
        return []

    all_categories: dict[str, dict] = {}  # category_id → category dict

    pages_with_html, index_page = crawl_index(session, crawl_url, source_id, max_pages)

    # Also include the index page itself — Antora sites often put all content on a
    # single page (no sub-pages), or the index page may also contain requirements.
    if index_page:
        idx_url, idx_html = index_page
        pages_with_html = [(idx_url, idx_html)] + pages_with_html

    pages_to_parse = [(url, html, url, mode) for url, html in pages_with_html]

    print(f"  Indexing: mode={mode}")

    # First-seen-wins across the whole source: a requirement ID that already surfaced
    # under one category (e.g. its own atomic page) is dropped from any later category
    # (e.g. a downstream aggregator page that re-lists the same ID with different text/URL),
    # instead of silently duplicating the ID across categories in the final catalog.
    seen_req_urls: dict[str, str] = {}
    for url, html, title_hint, effective_mode in pages_to_parse:
        reqs = parse_requirements_from_page(html, url)
        if not reqs:
            print(f"  [SKIP] No requirement-ID tokens found: {url}")
            continue

        ptitle = page_title(html, title_hint)
        intro = parse_page_intro(html) if effective_mode == "full" else ""
        cats = group_by_category(reqs, url, ptitle, mode=effective_mode, page_intro=intro)

        for cat in cats:
            cat_id = cat["id"]
            cat["source_id"] = source_id

            kept_reqs = []
            for r in cat["requirements"]:
                rid = r["id"]
                if rid in seen_req_urls:
                    print(
                        f"  [WARN] {cat_id}: dropping duplicate requirement ID {rid} "
                        f"(already harvested from {seen_req_urls[rid]}; this occurrence: {r['url']})",
                        file=sys.stderr,
                    )
                    continue
                seen_req_urls[rid] = r["url"]
                kept_reqs.append(r)
            cat["requirements"] = kept_reqs
            if not cat["requirements"]:
                continue

            if cat_id not in all_categories:
                all_categories[cat_id] = cat
                context_note = " + context" if effective_mode == "full" and cat.get("context") else ""
                print(f"  [{cat_id}] {ptitle} — {len(cat['requirements'])} requirements{context_note}")
            else:
                all_categories[cat_id]["requirements"].extend(cat["requirements"])
                print(f"  [{cat_id}] merged {len(cat['requirements'])} more requirements from {url}")

        if verbose:
            for r in reqs:
                print(f"      {r['id']} [{r['priority']}]: {r['text'][:80]}…")

    total_reqs = sum(len(cat["requirements"]) for cat in all_categories.values())
    print(f"  → {total_reqs} requirements in {len(all_categories)} categories")

    # Sort requirements within each category (numeric first, then alphabetic)
    def _cat_req_sort_key(r: dict):
        m = re.search(r"-(\d+)$", r["id"])
        return (0, int(m.group(1)), "") if m else (1, 0, r["id"])

    for cat in all_categories.values():
        cat["requirements"].sort(key=_cat_req_sort_key)

    return sorted(all_categories.values(), key=lambda c: c["id"])


# ---------------------------------------------------------------------------
# Harvest: blueprints
# ---------------------------------------------------------------------------


def harvest_blueprints_source(
    session: requests.Session,
    cfg: dict,
    source: dict,
    verbose: bool,
) -> list[dict]:
    """
    Harvest blueprints from a single source entry.
    Returns list of blueprint dicts for the YAML output.
    """
    crawl_url: str = source.get("crawl_url", "")
    source_id: str = source.get("id", "unknown")
    max_pages: int = source.get("max_pages", cfg.get("defaults", {}).get("max_pages", 100))
    max_section_chars: int = source.get("section_max_chars", cfg.get("defaults", {}).get("section_max_chars", 5000))
    mode: str = resolve_indexing_mode(cfg, "blueprint", source.get("mode"), "full")

    if not crawl_url:
        print(f"  [WARN] Source '{source_id}': no crawl_url — skipping", file=sys.stderr)
        return []

    blueprints: list[dict] = []

    pages_with_html, index_page = crawl_index(session, crawl_url, source_id, max_pages)
    if index_page:
        idx_url, idx_html = index_page
        # crawl_index retains final redirect URLs. Deduplicate page identity by
        # that URL while preserving distinct pages that happen to share content.
        seen_urls = {idx_url.rstrip("/")}
        deduped_pages: list[tuple[str, str]] = []
        for url, html in pages_with_html:
            page_key = url.rstrip("/")
            if page_key in seen_urls:
                continue
            seen_urls.add(page_key)
            deduped_pages.append((url, html))
        pages_with_html = [(idx_url, idx_html)] + deduped_pages

    print(f"  Indexing: mode={mode}" + (f", section_max_chars={max_section_chars}" if mode == "full" else ""))

    for url, html in pages_with_html:
        parsed = parse_blueprint_page(html, url, mode=mode, max_section_chars=max_section_chars)

        # Derive ID from URL slug
        bp_id = "BP-" + urlparse(url).path.rstrip("/").split("/")[-1].upper().replace("-", "_")

        section_count = len(parsed.get("sections", []))
        if mode == "full":
            print(f"  [{bp_id}] {parsed['title']} — {section_count} sections, topics: {parsed['topics'][:5]}")
        else:
            print(f"  [{bp_id}] {parsed['title']} — summary only, topics: {parsed['topics'][:5]}")

        if verbose and mode == "full":
            for s in parsed.get("sections", []):
                print(f"      [{s['title']}]: {s['content'][:60]}…")

        entry: dict = {
            "id": bp_id,
            "source_id": source_id,
            "url": url,
            "title": parsed["title"],
            "summary": wrap_long(parsed["summary"]),
            "topics": parsed["topics"],
        }
        if mode == "full" and parsed.get("sections"):
            entry["sections"] = [
                {
                    "title": s["title"],
                    "url": f"{url.rstrip('/')}#{s['anchor']}",
                    "content": wrap_long(s["content"]),
                }
                for s in parsed["sections"]
            ]
        blueprints.append(entry)

    print(f"  → {len(blueprints)} blueprint(s) indexed")
    return blueprints


# ---------------------------------------------------------------------------
# Cross-reference resolution
# ---------------------------------------------------------------------------


def resolve_references(text: str, req_url_map: dict) -> list[dict]:
    """
    Scan text for any uppercase ID references (PREFIX-X-Y-…) and return a list
    of {id, url} entries for those present in req_url_map. IDs not in the map
    are silently skipped (they belong to other catalogs).
    """
    seen: set[str] = set()
    resolved: list[dict] = []
    for m in REF_ID_PATTERN.finditer(text):
        rid = m.group(1).upper()
        if rid in seen:
            continue
        seen.add(rid)
        if rid in req_url_map:
            resolved.append({"id": rid, "url": req_url_map[rid]})
    return resolved


def add_references_to_blueprints(blueprints: list[dict], req_url_map: dict) -> int:
    """
    Post-process blueprint sections: add 'references' list to any section
    whose content mentions a resolvable requirement ID.
    Returns total number of resolved links added.
    """
    total = 0
    for bp in blueprints:
        for section in bp.get("sections", []):
            refs = resolve_references(section.get("content", ""), req_url_map)
            if refs:
                section["references"] = refs
                total += len(refs)
    return total


# ---------------------------------------------------------------------------
# Functional specification exports
# ---------------------------------------------------------------------------


def source_outputs(source: dict) -> set[str]:
    """Return output targets for a source, preserving catalog-only defaults."""
    configured = source.get("outputs")
    if configured is None:
        return {CATALOG_OUTPUT}
    if not isinstance(configured, list) or not configured:
        raise ValueError("outputs must be a non-empty array")
    if any(not isinstance(value, str) for value in configured):
        raise ValueError("outputs entries must be strings")
    outputs = set(configured)
    unknown = sorted(outputs - VALID_SOURCE_OUTPUTS)
    if unknown:
        raise ValueError(f"unknown outputs value(s): {', '.join(unknown)}")
    return outputs


def requested_outputs(args: argparse.Namespace) -> set[str]:
    """Translate repeatable CLI format names to internal output targets."""
    formats = getattr(args, "output_formats", None) or ["yaml"]
    if "all" in formats:
        return set(VALID_SOURCE_OUTPUTS)
    mapping = {"yaml": CATALOG_OUTPUT, "openspec": OPENSPEC_OUTPUT, "specdd": SPECDD_OUTPUT}
    return {mapping[value] for value in formats}


def _flatten_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _markdown_inline(value: object) -> str:
    """Flatten harvested text so it cannot create Markdown structure or HTML."""
    return html_lib.escape(_flatten_text(value), quote=False)


def _safe_http_url(value: object) -> Optional[str]:
    """Return a safe HTTP(S) URL for an autolink, or None when malformed."""
    raw = str(value or "").strip()
    if not raw or any(char.isspace() or ord(char) < 32 for char in raw):
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return html_lib.escape(raw, quote=False)


def _mandatory_requirements(categories: list[dict]) -> tuple[list[tuple[dict, dict]], list[str]]:
    """Select hard functional requirements and reject ambiguous identity."""
    selected: list[tuple[dict, dict]] = []
    skipped: list[str] = []
    seen_ids: set[str] = set()
    duplicate_ids: set[str] = set()

    for category in categories:
        for requirement in category.get("requirements", []) or []:
            req_id = str(requirement.get("id") or "").strip()
            if not req_id or not str(requirement.get("text") or "").strip():
                raise ValueError("functional requirements must contain non-empty id and text fields")
            if re.fullmatch(_ID_BODY, req_id, flags=re.IGNORECASE) is None:
                raise ValueError(f"invalid functional requirement ID: {req_id!r}")
            if req_id in seen_ids:
                duplicate_ids.add(req_id)
                continue
            seen_ids.add(req_id)
            if str(requirement.get("priority") or "MUST").upper() != "MUST":
                skipped.append(req_id)
                continue
            selected.append((category, requirement))

    if duplicate_ids:
        raise ValueError(f"duplicate functional requirement IDs: {', '.join(sorted(duplicate_ids))}")
    if not selected:
        raise ValueError("no MUST requirements were selected for functional specification output")
    return selected, skipped


def _openspec_statement(requirement: dict) -> str:
    """Render a requirement body accepted by OpenSpec's SHALL/MUST gate."""
    text = _markdown_inline(requirement.get("text"))
    modal = re.search(r"\b(shall|must)\b", text, flags=re.IGNORECASE)
    if modal:
        text = text[: modal.start()] + modal.group(1).upper() + text[modal.end() :]
        return text.rstrip(".") + "."
    return f"The system MUST satisfy this harvested behavior: {text.rstrip('.')}."


def render_openspec(
    categories: list[dict],
    *,
    title: str = "Application Specification",
    purpose: Optional[str] = None,
) -> tuple[str, list[str]]:
    """Render selected functional requirements as one OpenSpec Markdown file."""
    selected, skipped = _mandatory_requirements(categories)
    rendered_title = _markdown_inline(title) or "Application Specification"
    rendered_purpose = _markdown_inline(
        purpose
        or "This specification defines observable application behavior harvested from the functional requirement sources selected in the harvester configuration."
    )
    lines = [f"# {rendered_title}", "", "## Purpose", "", rendered_purpose, "", "## Requirements", ""]

    for category, requirement in selected:
        req_id = str(requirement["id"]).strip()
        category_title = _markdown_inline(category.get("title") or category.get("id") or "Uncategorized")
        statement = _openspec_statement(requirement)
        lines.extend(
            [
                f"### Requirement: {req_id}",
                "",
                statement,
                "",
                f"**Category:** {category_title}",
            ]
        )
        source_url = _safe_http_url(requirement.get("url"))
        if source_url:
            lines.extend(["", f"**Source:** <{source_url}>"])
        lines.extend(
            [
                "",
                f"#### Scenario: {req_id} behavior is satisfied",
                "",
                f"- **WHEN** the behavior governed by `{req_id}` is exercised",
                f"- **THEN** {statement}",
                "",
            ]
        )

    content = "\n".join(lines).rstrip() + "\n"
    requirement_count = len(re.findall(r"(?m)^### Requirement: ", content))
    scenario_count = len(re.findall(r"(?m)^#### Scenario: ", content))
    if requirement_count != scenario_count:
        raise ValueError("every OpenSpec requirement must contain one scenario")
    return content, skipped


def _specdd_text(value: object) -> str:
    """Keep imported prose literal in SpecDD instead of creating authority links."""
    text = _flatten_text(value).replace("`", "'").replace("@", r"\@")

    def quote_explicit_path(match: re.Match) -> str:
        return f"`{match.group(0)}`"

    return re.sub(r"(?<!\S)(?:\.\.?/|/)[^\s,;]+", quote_explicit_path, text)


def render_specdd(
    categories: list[dict],
    *,
    name: str = "Application Behavior",
    purpose: Optional[str] = None,
) -> tuple[str, list[str]]:
    """Render selected functional requirements as one root-level SpecDD file."""
    selected, skipped = _mandatory_requirements(categories)
    spec_name = _specdd_text(name) or "Application Behavior"
    spec_purpose = _specdd_text(
        purpose
        or "Describe the observable functional behavior harvested from the requirement sources selected in the harvester configuration."
    )
    positive: list[tuple[dict, dict, str]] = []
    negative: list[tuple[dict, dict, str]] = []
    for category, requirement in selected:
        statement = _specdd_text(requirement.get("text"))
        has_negative_modal = bool(re.search(r"\b(?:MUST|SHALL)\s+NOT\b", statement, re.IGNORECASE))
        has_positive_modal = bool(re.search(r"\b(?:MUST|SHALL)\b(?!\s+NOT)", statement, re.IGNORECASE))
        target = negative if has_negative_modal and not has_positive_modal else positive
        target.append((category, requirement, statement))

    lines = [f"Spec: {spec_name}", "", "Purpose:", f"  {spec_purpose}"]
    for label, entries in (("Must", positive), ("Must not", negative)):
        if not entries:
            continue
        lines.extend(["", f"{label}:"])
        current_category: Optional[str] = None
        for category, requirement, statement in entries:
            category_title = _specdd_text(category.get("title") or category.get("id") or "Uncategorized")
            if category_title != current_category:
                lines.append(f"  # Category: {category_title}")
                current_category = category_title
            lines.append(f"  {requirement['id']}: {statement}")

    for _category, requirement in selected:
        req_id = str(requirement["id"]).strip()
        statement = _specdd_text(requirement.get("text"))
        lines.extend(
            [
                "",
                f"Scenario: {req_id} behavior is satisfied",
                f"  When the behavior governed by {req_id} is exercised",
                f"  Then {statement}",
            ]
        )

    content = "\n".join(lines).rstrip() + "\n"
    if not content.startswith("Spec: ") or "\t" in content:
        raise ValueError("SpecDD output violates the required file header or indentation")
    if len(re.findall(r"(?m)^Scenario: ", content)) != len(selected):
        raise ValueError("every SpecDD requirement must contain one generated scenario")
    return content, skipped


def resolve_functional_output_path(
    kind: str,
    args: argparse.Namespace,
    cfg: dict,
    config_path: Path,
    catalog_output_path: Path,
) -> Path:
    """Resolve an export path only from operator-controlled CLI or configuration."""
    explicit = getattr(args, f"{kind}_output", None)
    if explicit:
        return Path(explicit)
    kind_cfg = cfg.get(kind, {})
    configured = kind_cfg.get("output") if isinstance(kind_cfg, dict) else None
    if configured:
        return (config_path.parent / configured).resolve()
    suffix = ".openspec.md" if kind == OPENSPEC_OUTPUT else ".sdd"
    return catalog_output_path.with_name(f"{catalog_output_path.stem}{suffix}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if args.config else Path(__file__).parent / "harvest-config.json"
    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    cfg = load_config(config_path)
    output_path: Path = (
        Path(args.output) if args.output else ((config_path.parent / cfg.get("output", "requirements.yaml")).resolve())
    )
    requested = requested_outputs(args)
    export_paths = {
        kind: resolve_functional_output_path(kind, args, cfg, config_path, output_path)
        for kind in (OPENSPEC_OUTPUT, SPECDD_OUTPUT)
        if kind in requested
    }
    paths = ([output_path] if CATALOG_OUTPUT in requested else []) + list(export_paths.values())
    resolved_paths = [path.resolve() for path in paths]
    if len(resolved_paths) != len(set(resolved_paths)):
        print("Requested outputs must use different paths.", file=sys.stderr)
        return 1

    req_cfg: dict = cfg.get("request", {})
    timeout: int = req_cfg.get("timeout_seconds", 15)
    token: Optional[str] = args.token or os.environ.get(req_cfg.get("auth_header_env", "HARVEST_AUTH_TOKEN"))

    use_proxy: bool = req_cfg.get("use_proxy", True)
    verify_ssl = req_cfg.get("verify_ssl", True)
    session = build_session(token, req_cfg.get("extra_headers", {}), timeout, use_proxy, verify_ssl)

    sources: list[dict] = cfg.get("sources", [])
    if not sources:
        # Backwards compatibility: fall back to legacy crawl config
        crawl_cfg = cfg.get("crawl", {})
        if crawl_cfg.get("requirements_base_url"):
            sources.append(
                {
                    "id": "legacy-requirements",
                    "type": "requirement",
                    "title": "Requirements",
                    "crawl_url": crawl_cfg["requirements_base_url"],
                    "max_pages": crawl_cfg.get("max_pages", 100),
                }
            )
        if crawl_cfg.get("blueprints_base_url"):
            sources.append(
                {
                    "id": "legacy-blueprints",
                    "type": "blueprint",
                    "title": "Blueprints",
                    "crawl_url": crawl_cfg["blueprints_base_url"],
                    "max_pages": crawl_cfg.get("max_pages", 100),
                }
            )
        # Legacy overrides
        for entry in cfg.get("requirements_overrides", []):
            sources.append(
                {
                    "id": entry.get("id", "override-req"),
                    "type": "requirement",
                    "title": entry.get("title", "Override"),
                    "crawl_url": entry["url"],
                    "mode": entry.get("indexing_mode"),
                }
            )
        for entry in cfg.get("blueprints_overrides", []):
            sources.append(
                {
                    "id": entry.get("id", "override-bp"),
                    "type": "blueprint",
                    "title": entry.get("title", "Override"),
                    "crawl_url": entry["url"],
                    "mode": entry.get("indexing_mode"),
                }
            )

    # Filter sources by --req-only / --blueprint-only
    if args.req_only:
        sources = [s for s in sources if s.get("type") == "requirement"]
    if args.blueprint_only:
        sources = [s for s in sources if s.get("type") == "blueprint"]

    if not sources:
        print("No sources configured — nothing to do.", file=sys.stderr)
        return 1

    selected_sources: list[dict] = []
    for source in sources:
        source_id = source.get("id", "unknown")
        try:
            outputs = source_outputs(source)
        except ValueError as exc:
            print(f"Source '{source_id}': {exc}", file=sys.stderr)
            return 1
        if source.get("type", "requirement") == "blueprint" and outputs & {OPENSPEC_OUTPUT, SPECDD_OUTPUT}:
            print(f"Source '{source_id}': blueprints can target only the catalog output.", file=sys.stderr)
            return 1
        if outputs & requested:
            selected_sources.append(source)
    sources = selected_sources

    if not sources:
        print(
            "No sources target the selected format. Add the format to a functional requirement source's outputs array.",
            file=sys.stderr,
        )
        return 1

    req_categories: list[dict] = []
    functional_categories: dict[str, list[dict]] = {OPENSPEC_OUTPUT: [], SPECDD_OUTPUT: []}
    blueprints: list[dict] = []
    sources_meta: list[dict] = []
    failed = 0
    processed_sources = 0

    for source in sources:
        source_id = source.get("id", "unknown")
        source_type = source.get("type", "requirement")
        crawl_url = source.get("crawl_url", "")
        outputs = source_outputs(source)

        if not crawl_url:
            print(f"\n[SKIP] Source '{source_id}': no crawl_url configured")
            continue

        processed_sources += 1
        indexed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        items_count = 0

        if source_type == "requirement":
            print(f"\n— Requirements: {source.get('title', source_id)} —")
            cats = harvest_requirements_source(session, cfg, source, args.verbose)
            if cats:
                if CATALOG_OUTPUT in outputs and CATALOG_OUTPUT in requested:
                    req_categories.extend(cats)
                for kind in (OPENSPEC_OUTPUT, SPECDD_OUTPUT):
                    if kind in outputs and kind in requested:
                        functional_categories[kind].extend(cats)
                items_count = sum(len(c.get("requirements", [])) for c in cats)
            else:
                failed += 1

        elif source_type == "blueprint":
            print(f"\n— Blueprints: {source.get('title', source_id)} —")
            bps = harvest_blueprints_source(session, cfg, source, args.verbose)
            if bps:
                blueprints.extend(bps)
                items_count = len(bps)

        else:
            print(f"\n[WARN] Source '{source_id}': unknown type '{source_type}' — skipping", file=sys.stderr)
            continue

        meta: dict = {
            "id": source_id,
            "type": source_type,
            "title": source.get("title", source_id),
            "crawl_url": crawl_url,
            "indexed_at": indexed_at,
            "items_count": items_count,
            "mode": source.get(
                "mode",
                resolve_indexing_mode(cfg, source_type, None, "structured" if source_type == "requirement" else "full"),
            ),
        }
        if source.get("reference_url"):
            meta["reference_url"] = source["reference_url"]
        if CATALOG_OUTPUT in outputs and CATALOG_OUTPUT in requested:
            sources_meta.append(meta)

    # Resolve cross-references: scan blueprint section content for requirement IDs
    # and attach {id, url} links to any section that references a known requirement.
    if req_categories and blueprints:
        print("\n— Cross-references —")
        req_url_map = {r["id"]: r["url"] for cat in req_categories for r in cat.get("requirements", [])}
        total_links = add_references_to_blueprints(blueprints, req_url_map)
        print(f"  → {total_links} requirement link(s) resolved across blueprint sections")

    doc: dict = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "harvested",
    }
    if cfg.get("description"):
        doc["description"] = cfg["description"]
    if cfg.get("url"):
        doc["url"] = cfg["url"]
    doc.update(
        {
            "sources_meta": sources_meta,
            "categories": req_categories,
            "blueprints": blueprints,
        }
    )

    total_reqs = sum(len(c.get("requirements", [])) for c in req_categories)
    export_contents: dict[str, str] = {}
    export_counts: dict[str, int] = {}
    for kind in (OPENSPEC_OUTPUT, SPECDD_OUTPUT):
        if kind not in requested:
            continue
        kind_cfg = cfg.get(kind, {})
        if not isinstance(kind_cfg, dict):
            print(f"The top-level '{kind}' configuration must be an object.", file=sys.stderr)
            return 1
        try:
            if kind == OPENSPEC_OUTPUT:
                content, skipped = render_openspec(
                    functional_categories[kind],
                    title=kind_cfg.get("title", "Application Specification"),
                    purpose=kind_cfg.get("purpose"),
                )
                count = len(re.findall(r"(?m)^### Requirement: ", content))
            else:
                content, skipped = render_specdd(
                    functional_categories[kind],
                    name=kind_cfg.get("name", "Application Behavior"),
                    purpose=kind_cfg.get("purpose"),
                )
                count = len(re.findall(r"(?m)^Scenario: ", content))
        except ValueError as exc:
            print(f"{kind} output error: {exc}", file=sys.stderr)
            return 2
        if skipped:
            print(
                f"  [WARN] {kind} skipped non-mandatory requirements: {', '.join(skipped)}",
                file=sys.stderr,
            )
        export_contents[kind] = content
        export_counts[kind] = count

    if args.dry_run:
        print("\nDry run — output not written.")
        print(f"  Sources:      {processed_sources}")
        print(f"  Categories:   {len(req_categories)}")
        print(f"  Requirements: {total_reqs}")
        print(f"  Blueprints:   {len(blueprints)}")
        for kind in (OPENSPEC_OUTPUT, SPECDD_OUTPUT):
            if kind in export_counts:
                print(f"  {kind}: {export_counts[kind]} requirements")
        return 0

    if CATALOG_OUTPUT in requested:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(doc, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=120)

        print(f"\nWritten: {output_path}")
        print(f"  Sources:      {len(sources_meta)}")
        print(f"  Categories:   {len(req_categories)}")
        print(f"  Requirements: {total_reqs}")
        print(f"  Blueprints:   {len(blueprints)}")

        # Validate the harvested output against the canonical catalog schema so a
        # malformed crawl is caught here rather than silently under-parsed by the
        # skills that consume it.
        cat_errors, cat_warnings = rstate.validate_catalog(output_path.read_bytes())
        for warning in cat_warnings:
            print(f"  ⚠ schema warning: {warning}")
        if cat_errors:
            for error in cat_errors[:6]:
                print(f"  ✗ schema error: {error}", file=sys.stderr)
            print(
                "✗ Harvested catalog failed schema validation (see schemas/requirements-catalog.schema.yaml).",
                file=sys.stderr,
            )
            return 2

    for kind in (OPENSPEC_OUTPUT, SPECDD_OUTPUT):
        if kind not in export_contents:
            continue
        export_path = export_paths[kind]
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(export_contents[kind], encoding="utf-8")
        print(f"\nWritten: {export_path}")
        print(f"  Requirements: {export_counts[kind]}")

    return 0 if failed == 0 else 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Harvest a catalog YAML and optional single-file OpenSpec and SpecDD exports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", metavar="PATH")
    parser.add_argument("--output", metavar="PATH")
    parser.add_argument(
        "--format",
        dest="output_formats",
        action="append",
        choices=("yaml", "openspec", "specdd", "all"),
        help="repeat to combine formats; 'all' writes every format",
    )
    parser.add_argument("--openspec-output", metavar="PATH")
    parser.add_argument("--specdd-output", metavar="PATH")
    parser.add_argument("--token", metavar="TOKEN")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--req-only", action="store_true")
    parser.add_argument("--blueprint-only", action="store_true")
    sys.exit(run(parser.parse_args()))


if __name__ == "__main__":
    main()
