#!/usr/bin/env python3
"""
harvest-requirements.py — Crawls configured source URLs for security requirements
and blueprints, then writes a structured YAML consumed by the appsec plugin.

Usage:
    python harvest-requirements.py [OPTIONS]

Options:
    --config PATH       Path to harvest-config.json (default: next to this script)
    --output PATH       Override the output path from the config
    --token TOKEN       Bearer token (overrides HARVEST_AUTH_TOKEN env var)
    --dry-run           Fetch and parse but do not write the output file
    --verbose, -v       Print each parsed item
    --req-only          Only process sources of type 'requirement'
    --blueprint-only    Only process sources of type 'blueprint'

Configuration:
    The config file is a JSON document with a top-level `sources` array. Each
    source declares {id, type, title, crawl_url, mode, [max_pages],
    [section_max_chars], [reference_url]}.

    For a full template, see harvest-config.example.json (copy it to
    harvest-config.json and edit). Key sections:
        - request   — HTTP session (timeout, auth env, proxy, TLS verify, headers)
        - defaults  — max_pages, requirements_mode, blueprints_mode, section_max_chars
        - sources[] — one entry per URL to crawl
        - description / url / output — optional metadata + output path

How discovery works (per source):
    1. Fetch crawl_url (e.g. https://security.example.com/scg)
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
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    import urllib3
    from bs4 import BeautifulSoup
    import yaml
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

# Antora/AsciiDoc format: <span class="badge">PREFIX-ID</span> with any uppercase prefix.
# Some pages use Unicode non-breaking hyphen U+2011 (‑) instead of ASCII hyphen after the prefix.
BADGE_ID_PATTERN = re.compile(r'class="badge"[^>]*>\s*[A-Z][A-Z0-9]*[-\u2011]', re.IGNORECASE)
# Priority label span classes: must-label, should-label, may-label
PRIORITY_LABEL_PATTERN = re.compile(r"(must|should|may)-label", re.IGNORECASE)
# Any ID reference in free text — generic prefix, same shape as REQ_ID_PATTERN without brackets.
REF_ID_PATTERN = re.compile(r"\b(" + _ID_BODY + r")\b")


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
    session.headers.update({
        "User-Agent": "appsec-advisor/harvest-requirements (internal)",
        "Accept": "text/html,application/xhtml+xml",
    })
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
        html, _ = fetch(session, url, url)
        if html is not None:
            pages.append((url, html))

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


def page_has_requirements(html: str) -> bool:
    return bool(REQ_ID_PATTERN.search(html)) or bool(BADGE_ID_PATTERN.search(html))


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
        # Stop at the first element that contains a requirement ID
        if REQ_ID_PATTERN.search(el.get_text()):
            break
        # Skip elements that contain child block elements (likely containers)
        if el.find(["p", "ul", "ol", "table", "section"]):
            continue
        text = re.sub(r"\s+", " ", el.get_text()).strip()
        if len(text) > 40:  # ignore navigation snippets and short labels
            intro_parts.append(text)
        if len(intro_parts) >= 3:  # at most 3 intro paragraphs
            break

    return " ".join(intro_parts)


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
            priority = label_span.get_text(strip=True).rstrip(":").upper() if label_span else detect_priority(h2.get_text())
            h2_title = PRIORITY_PATTERN.sub("", h2.get_text(strip=True), count=1).strip(" :")
        else:
            # Badge-only preamble under h1 (no preceding h2) — pages where the
            # entire page describes one atomic requirement.
            priority = "MUST"
            prev_h1 = sectionbody.find_previous("h1")
            h2_title = PRIORITY_PATTERN.sub("", prev_h1.get_text(strip=True), count=1).strip(" :") if prev_h1 else ""
        if priority not in ("MUST", "SHOULD", "MAY"):
            priority = "MUST"

        # Collect text paragraphs before <details>
        text_parts: list[str] = []
        for child in sectionbody.children:
            if getattr(child, "name", None) == "details":
                break
            if getattr(child, "name", None) in ("div", "p"):
                text = re.sub(r"\s+", " ", child.get_text()).strip()
                if text and text.upper().replace("_", "-", 1) != req_id:
                    text_parts.append(text)

        req_text = " ".join(text_parts).strip() or h2_title
        # Badge-only preamble (atomic-requirement pages): grab text from the following
        # Summary sect1. Also trigger when req_text is just the requirement ID itself
        # (h2_title was the badge).
        req_text_normalized = req_text.upper().replace("\u2011", "-").replace("_", "-") if req_text else ""
        if not req_text or req_text_normalized == req_id or req_text_normalized == req_id.replace("-", "\u2011"):
            preamble = sectionbody.parent
            for sibling in preamble.find_next_siblings("div", class_="sect1"):
                sibling_h2 = sibling.find("h2")
                if sibling_h2 and sibling_h2.get_text(strip=True).lower() in ("summary", "details"):
                    sibling_body = sibling.find("div", class_="sectionbody")
                    if sibling_body:
                        req_text = re.sub(r"\s+", " ", sibling_body.get_text()).strip()
                    break
        # Last resort: if req_text is still empty or equals the ID, use the page <h1> title
        if not req_text or req_text.upper().replace("\u2011", "-").replace("_", "-") == req_id:
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
        text = clean_text(tag.get_text())
        if not text:
            sib = tag.find_next_sibling(["p", "dd", "div", "span"])
            text = clean_text(sib.get_text()) if sib else ""
        if text and req_id not in found:
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{tag_id.lower()}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Strategy 2: definition list <dt>[PREFIX-XX-N]</dt><dd>text</dd>
    for dt in soup.find_all("dt"):
        m = REQ_ID_PATTERN.search(dt.get_text())
        if not m:
            continue
        req_id = m.group(1).upper()
        if req_id in found:
            continue
        dd = dt.find_next_sibling("dd")
        text = clean_text(dd.get_text()) if dd else clean_text(dt.get_text())
        if text:
            anchor = req_id.lower()
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{anchor}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Strategy 3: any element whose text contains [PREFIX-XX-N]
    for tag in soup.find_all(True):
        raw = tag.get_text()
        m = REQ_ID_PATTERN.search(raw)
        if not m:
            continue
        req_id = m.group(1).upper()
        if req_id in found:
            continue
        # Skip containers whose children already matched
        if tag.find(True) and REQ_ID_PATTERN.search(
            " ".join(c.get_text() for c in tag.find_all(True, recursive=False))
        ):
            continue
        text = clean_text(raw)
        if text:
            anchor = req_id.lower()
            found[req_id] = {
                "id": req_id,
                "url": f"{page_url.rstrip('/')}#{anchor}",
                "text": text,
                "priority": detect_priority(text),
            }

    # Strategy 4: table rows
    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if len(cells) < 2:
            continue
        m = REQ_ID_PATTERN.search(cells[0].get_text())
        if not m:
            continue
        req_id = m.group(1).upper()
        if req_id in found:
            continue
        text = clean_text(cells[1].get_text())
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


def parse_blueprint_page(html: str, bp_url: str, mode: str = "full", max_section_chars: int = 500) -> dict:
    """
    Index a blueprint page.

    mode="full"    — title, summary, topics + all sections with content (default)
    mode="summary" — title, summary, topics only; sections are omitted
    """
    soup = BeautifulSoup(html, "html.parser")

    h1 = soup.find("h1")
    title = h1.get_text(strip=True) if h1 else (
        soup.title.get_text(strip=True) if soup.title else bp_url
    )

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
        for el in main.find_all(
            ["h1", "h2", "h3", "p", "li", "pre", "code", "blockquote"], recursive=True
        ):
            if el.name == "h1":
                continue
            if el.name in ("h2", "h3"):
                heading_title = el.get_text(strip=True)
                # Prefer explicit id attribute; fall back to slug derived from title
                heading_id = el.get("id") or section_anchor(heading_title)
                heading_anchors.append(heading_id)
                if mode == "full":
                    if current_title and current_parts:
                        raw = " ".join(current_parts).strip()
                        sections.append({
                            "title": current_title,
                            "anchor": current_anchor,
                            "content": deduplicate_text(raw)[:max_section_chars],
                        })
                    current_title = heading_title
                    current_anchor = heading_id
                    current_parts = []
                continue
            text = el.get_text(strip=True)
            if not text:
                continue
            if not current_title:
                # Before first heading: collect preamble, first meaningful sentence → summary
                if len(text) > 30 and not summary:
                    summary = text
                elif len(text) > 30:
                    preamble_parts.append(text)
                continue
            if mode == "full":
                current_parts.append(text)

        if mode == "full" and current_title and current_parts:
            raw = " ".join(current_parts).strip()
            sections.append({
                "title": current_title,
                "anchor": current_anchor,
                "content": deduplicate_text(raw)[:max_section_chars],
            })

    # For flat pages with no section headings (e.g. CORS), collect preamble as one section
    if mode == "full" and not sections and preamble_parts:
        all_preamble = (summary + " " + " ".join(preamble_parts)).strip()
        sections.append({
            "title": "Overview",
            "anchor": "overview",
            "content": deduplicate_text(all_preamble)[:max_section_chars],
        })

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
        if page_has_requirements(idx_html):
            pages_with_html = [(idx_url, idx_html)] + pages_with_html

    pages_to_parse = [(url, html, url, mode) for url, html in pages_with_html]

    print(f"  Indexing: mode={mode}")

    total_reqs = 0
    for url, html, title_hint, effective_mode in pages_to_parse:
        if not page_has_requirements(html):
            print(f"  [SKIP] No requirement-ID tokens found: {url}")
            continue

        reqs = parse_requirements_from_page(html, url)
        if not reqs:
            print(f"  [WARN] Page matched but no requirements extracted: {url}", file=sys.stderr)
            continue

        ptitle = page_title(html, title_hint)
        intro = parse_page_intro(html) if effective_mode == "full" else ""
        cats = group_by_category(reqs, url, ptitle, mode=effective_mode, page_intro=intro)
        total_reqs += len(reqs)

        for cat in cats:
            cat_id = cat["id"]
            cat["source_id"] = source_id
            if cat_id not in all_categories:
                all_categories[cat_id] = cat
                context_note = " + context" if effective_mode == "full" and cat.get("context") else ""
                print(f"  [{cat_id}] {ptitle} — {len(cat['requirements'])} requirements{context_note}")
            else:
                # Merge: add requirements not already present
                existing_ids = {r["id"] for r in all_categories[cat_id]["requirements"]}
                new_reqs = [r for r in cat["requirements"] if r["id"] not in existing_ids]
                all_categories[cat_id]["requirements"].extend(new_reqs)
                if new_reqs:
                    print(f"  [{cat_id}] merged {len(new_reqs)} more requirements from {url}")

        if verbose:
            for r in reqs:
                print(f"      {r['id']} [{r['priority']}]: {r['text'][:80]}…")

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
        pages_with_html = [(idx_url, idx_html)] + [
            (url, html)
            for url, html in pages_with_html
            if url.rstrip("/") != idx_url.rstrip("/")
        ]

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
# Main
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config) if args.config else Path(__file__).parent / "harvest-config.json"
    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    cfg = load_config(config_path)
    output_path = Path(args.output) if args.output else (
        (config_path.parent / cfg.get("output", "requirements.yaml")).resolve()
    )

    req_cfg: dict = cfg.get("request", {})
    timeout: int = req_cfg.get("timeout_seconds", 15)
    token: Optional[str] = (
        args.token
        or os.environ.get(req_cfg.get("auth_header_env", "HARVEST_AUTH_TOKEN"))
    )

    use_proxy: bool = req_cfg.get("use_proxy", True)
    verify_ssl = req_cfg.get("verify_ssl", True)
    session = build_session(token, req_cfg.get("extra_headers", {}), timeout, use_proxy, verify_ssl)

    sources: list[dict] = cfg.get("sources", [])
    if not sources:
        # Backwards compatibility: fall back to legacy crawl config
        crawl_cfg = cfg.get("crawl", {})
        if crawl_cfg.get("requirements_base_url"):
            sources.append({
                "id": "legacy-requirements",
                "type": "requirement",
                "title": "Requirements",
                "crawl_url": crawl_cfg["requirements_base_url"],
                "max_pages": crawl_cfg.get("max_pages", 100),
            })
        if crawl_cfg.get("blueprints_base_url"):
            sources.append({
                "id": "legacy-blueprints",
                "type": "blueprint",
                "title": "Blueprints",
                "crawl_url": crawl_cfg["blueprints_base_url"],
                "max_pages": crawl_cfg.get("max_pages", 100),
            })
        # Legacy overrides
        for entry in cfg.get("requirements_overrides", []):
            sources.append({
                "id": entry.get("id", "override-req"),
                "type": "requirement",
                "title": entry.get("title", "Override"),
                "crawl_url": entry["url"],
                "mode": entry.get("indexing_mode"),
            })
        for entry in cfg.get("blueprints_overrides", []):
            sources.append({
                "id": entry.get("id", "override-bp"),
                "type": "blueprint",
                "title": entry.get("title", "Override"),
                "crawl_url": entry["url"],
                "mode": entry.get("indexing_mode"),
            })

    # Filter sources by --req-only / --blueprint-only
    if args.req_only:
        sources = [s for s in sources if s.get("type") == "requirement"]
    if args.blueprint_only:
        sources = [s for s in sources if s.get("type") == "blueprint"]

    if not sources:
        print("No sources configured — nothing to do.", file=sys.stderr)
        return 1

    req_categories: list[dict] = []
    blueprints: list[dict] = []
    sources_meta: list[dict] = []
    failed = 0

    for source in sources:
        source_id = source.get("id", "unknown")
        source_type = source.get("type", "requirement")
        crawl_url = source.get("crawl_url", "")

        if not crawl_url:
            print(f"\n[SKIP] Source '{source_id}': no crawl_url configured")
            continue

        indexed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        items_count = 0

        if source_type == "requirement":
            print(f"\n— Requirements: {source.get('title', source_id)} —")
            cats = harvest_requirements_source(session, cfg, source, args.verbose)
            if cats:
                req_categories.extend(cats)
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
            "mode": source.get("mode", resolve_indexing_mode(
                cfg, source_type, None, "structured" if source_type == "requirement" else "full"
            )),
        }
        if source.get("reference_url"):
            meta["reference_url"] = source["reference_url"]
        sources_meta.append(meta)

    # Resolve cross-references: scan blueprint section content for requirement IDs
    # and attach {id, url} links to any section that references a known requirement.
    if req_categories and blueprints:
        print(f"\n— Cross-references —")
        req_url_map = {
            r["id"]: r["url"]
            for cat in req_categories
            for r in cat.get("requirements", [])
        }
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
    doc.update({
        "sources_meta": sources_meta,
        "categories": req_categories,
        "blueprints": blueprints,
    })

    total_reqs = sum(len(c.get("requirements", [])) for c in req_categories)

    if args.dry_run:
        print(f"\nDry run — output not written.")
        print(f"  Sources:      {len(sources_meta)}")
        print(f"  Categories:   {len(req_categories)}")
        print(f"  Requirements: {total_reqs}")
        print(f"  Blueprints:   {len(blueprints)}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=120)

    print(f"\nWritten: {output_path}")
    print(f"  Sources:      {len(sources_meta)}")
    print(f"  Categories:   {len(req_categories)}")
    print(f"  Requirements: {total_reqs}")
    print(f"  Blueprints:   {len(blueprints)}")
    return 0 if failed == 0 else 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Crawl and harvest security requirements and blueprints into a plugin YAML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", metavar="PATH")
    parser.add_argument("--output", metavar="PATH")
    parser.add_argument("--token", metavar="TOKEN")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--req-only", action="store_true")
    parser.add_argument("--blueprint-only", action="store_true")
    sys.exit(run(parser.parse_args()))


if __name__ == "__main__":
    main()
