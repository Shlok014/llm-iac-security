"""Presentation layer for `app.py` — CSS, and the few components Streamlit does not have.

Split out of `app.py` so the page itself stays readable as a sequence of calls. Nothing here
knows what a finding is: every function takes already-decided values and turns them into markup.
The design brief, the token table and the reasoning behind the gate rail are in
`docs/UI_DESIGN.md`.

Two things in here are load-bearing rather than decorative:

* **Amber plus a dashed border means "not verified", everywhere.** Drift that could not be
  measured, a candidate rejected before it was ever scanned, a severity the scanner declined to
  give. A reader learns the convention once and reads the rest of the page correctly.
* **The gate rail draws a rejected candidate to the left of the rescan station.** The loop's
  guarantee is that a rejected candidate is never scanned and so can never post a number; the
  rail has no position where a deleted resource could have produced a count.

Colours come from `light-dark()` over a `color-scheme: light dark` root, which tracks the same
`prefers-color-scheme` signal Streamlit's own theme follows, so the two never disagree.
"""

from __future__ import annotations

import html

import streamlit as st

# Stations in the order `iac_agent.loop` applies them. The order is the argument: `drift` sits
# before `rescan` precisely so that a candidate which deleted a resource cannot reach a scanner.
STATIONS: tuple[tuple[str, str], ...] = (
    ("input", "the file as given"),
    ("model", "rewrite proposed"),
    ("parse", "must still be valid IaC"),
    ("drift", "must not have deleted a resource"),
    ("rescan", "only now can it score"),
    ("returned", "best candidate kept"),
)

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

:root {
  color-scheme: light dark;
  --ix-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --ix-sans: "IBM Plex Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --ix-ink:        light-dark(#15171F, #E8EAF0);
  --ix-muted:      light-dark(#5C6270, #98A0B0);
  /* `faint` was #8A90A0 / #6B7383, which measures 2.98:1 on paper and 3.65:1 on the dark
     surface — below the 4.5:1 minimum for text this size. That would be defensible for
     decoration, but faint is what the tab strip, the rail's station names and the line under
     the verdict number are set in, and those carry the scanner, the filename and the page's
     own navigation. The replacements clear 4.5:1 in both schemes and stay a step quieter than
     `muted` (5.70 / 7.18), so the hierarchy the design depends on survives. */
  --ix-faint:      light-dark(#6B7181, #8A92A2);
  --ix-rule:       light-dark(#D8DBE2, #2A2E3A);
  /* Hairlines can be faint; the rail's marks cannot. Its unreached stations were drawn in
     `rule` at 1.29:1, so the dotted pips and the track between them were all but invisible —
     and "not reached" looking like nothing at all is the one thing §4 says the rail must not
     do. These are graphics rather than text, so the bar is 3:1: 3.14/3.36 light, 3.68/3.39
     dark, measured against page and card backgrounds respectively. */
  --ix-rule-strong: light-dark(#868C9C, #666E7E);
  --ix-surface:    light-dark(#FFFFFF, #171A22);
  --ix-signal:     light-dark(#B45309, #E9A23B);
  --ix-signal-bg:  light-dark(#FDF3E3, #2B1E0B);
  --ix-blocked:    light-dark(#B42318, #F27B72);
  --ix-blocked-bg: light-dark(#FDECEA, #2E1512);
  --ix-verified:   light-dark(#15803D, #5FBE7D);
  --ix-verified-bg:light-dark(#EAF6EE, #12251A);
}

/* ---------------------------------------------------------------- chrome */

/* Local tool: there is nothing to deploy, and the button is the loudest pixel in the header. */
[data-testid="stAppDeployButton"] { display: none; }
/* The toolbar floats over the page, so the masthead has to start below it. */
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMainBlockContainer"] { max-width: 1160px; padding-top: 3.9rem; padding-bottom: 6rem; }
[data-testid="stSidebarUserContent"] { padding-top: 1.15rem; }
[data-testid="stSidebarUserContent"] [data-testid="stVerticalBlock"] { gap: .85rem; }
/* Streamlit's default sidebar is 244px, and the fixture names are longer than that: the picker
   read `docker_insecure.Dock…`, so the control that chooses what gets scanned could not show
   what had been chosen. Wide enough for the longest name in `samples/`, and no wider. */
[data-testid="stSidebar"] { width: 296px !important; min-width: 296px !important; }

/* Tab strips are navigation, not headings: small, tracked, quiet until selected. */
.stTabs [data-baseweb="tab-list"] { gap: 1.75rem; border-bottom: 1px solid var(--ix-rule); }
.stTabs [data-baseweb="tab"] {
  font-family: var(--ix-mono); font-size: 11.5px; font-weight: 500;
  letter-spacing: .1em; text-transform: uppercase;
  color: var(--ix-faint); padding: 0 0 .55rem; height: auto;
}
.stTabs [data-baseweb="tab"]:hover { color: var(--ix-muted); }
.stTabs [aria-selected="true"] { color: var(--ix-ink); }
.stTabs [data-baseweb="tab-highlight"] { background: var(--ix-ink); height: 2px; }
.stTabs [data-baseweb="tab-border"] { display: none; }

[data-testid="stCaptionContainer"] p { font-size: 12.75px; line-height: 1.55; color: var(--ix-muted); }
[data-testid="stMetricValue"] { font-family: var(--ix-mono); font-variant-numeric: tabular-nums; }
[data-testid="stMetricLabel"] p {
  font-family: var(--ix-mono); font-size: 10.5px; font-weight: 500;
  letter-spacing: .085em; text-transform: uppercase; color: var(--ix-muted);
}
[data-testid="stExpander"] summary p { font-family: var(--ix-mono); font-size: 12.5px; }
.stButton button { font-weight: 500; }

/* The primary button is filled with `ink`, which is near-black in light and near-white in
   dark. Streamlit picks a light label for both, so in dark it came out light-on-light. The
   label has to invert with the fill. */
[data-testid="stBaseButton-primary"],
.stButton button[kind="primary"] { color: light-dark(#F6F7F9, #15171F); }

/* A popover in the control rail is disclosure, not a third action: it must not look like the
   two buttons above it. */
[data-testid="stSidebar"] [data-testid="stPopover"] button {
  border: none; background: transparent; padding: .1rem 0; min-height: 0;
  font-family: var(--ix-mono); font-size: 11.5px; font-weight: 400;
  color: var(--ix-muted); justify-content: flex-start;
}
[data-testid="stSidebar"] [data-testid="stPopover"] button:hover { color: var(--ix-ink); }

/* ------------------------------------------------------------- masthead */

.ix-mast {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: .55rem 1.1rem;
  border-bottom: 1px solid var(--ix-rule); padding-bottom: .8rem; margin-bottom: 1.5rem;
}
.ix-mast-id {
  font-family: var(--ix-mono); font-size: 15px; font-weight: 600;
  letter-spacing: .14em; text-transform: uppercase; color: var(--ix-ink);
  display: inline-flex; align-items: center; gap: .55rem;
}
.ix-mast-id::before {
  content: ""; width: 9px; height: 9px; background: var(--ix-ink);
  /* The mark is the gate seen end-on: a square with one corner cut. */
  clip-path: polygon(0 0, 100% 0, 100% 62%, 62% 100%, 0 100%);
}
.ix-mast-thesis {
  font-family: var(--ix-mono); font-size: 12px; letter-spacing: .05em; color: var(--ix-faint);
}
.ix-mast-thesis b { color: var(--ix-ink); font-weight: 600; }
.ix-mast-meta {
  margin-left: auto; font-family: var(--ix-mono); font-size: 11px;
  letter-spacing: .03em; color: var(--ix-faint);
}

/* ------------------------------------------------------- section labels */

.ix-eyebrow {
  display: flex; align-items: center; gap: .8rem;
  font-family: var(--ix-mono); font-size: 10.5px; font-weight: 500;
  letter-spacing: .13em; text-transform: uppercase; color: var(--ix-faint);
  margin: 1.9rem 0 .85rem;
}
.ix-eyebrow::after { content: ""; flex: 1; height: 1px; background: var(--ix-rule); }

/* ------------------------------------------------------------- verdict */

.ix-verdict { display: flex; align-items: flex-start; gap: 1.15rem; margin: .35rem 0 .2rem; }
.ix-verdict > div:last-child { padding-top: .35rem; }
.ix-verdict-num {
  font-family: var(--ix-mono); font-size: 58px; font-weight: 500; line-height: .95;
  font-variant-numeric: tabular-nums; letter-spacing: -.02em; color: var(--ix-ink);
}
.ix-verdict[data-tone="blocked"] .ix-verdict-num { color: var(--ix-blocked); }
.ix-verdict[data-tone="verified"] .ix-verdict-num { color: var(--ix-verified); }
.ix-verdict[data-tone="signal"] .ix-verdict-num { color: var(--ix-signal); }
.ix-verdict-label {
  font-family: var(--ix-mono); font-size: 11px; font-weight: 500;
  letter-spacing: .13em; text-transform: uppercase; color: var(--ix-muted);
}
.ix-verdict-qual {
  font-family: var(--ix-mono); font-size: 12px; color: var(--ix-faint);
  margin-top: .35rem; line-height: 1.7; max-width: 96ch; word-break: break-word;
}
.ix-verdict-qual b { color: var(--ix-muted); font-weight: 500; }

/* An empty screen is an invitation to act, so it is not a verdict with no number in it. */
.ix-empty {
  border-left: 2px dashed var(--ix-signal); padding: .1rem 0 .1rem 1.05rem;
  margin: .5rem 0 .3rem; max-width: 66ch;
}
.ix-empty-title {
  font-family: var(--ix-mono); font-size: 11px; font-weight: 500;
  letter-spacing: .13em; text-transform: uppercase; color: var(--ix-signal);
}
.ix-empty p {
  font-family: var(--ix-sans); font-size: 14.5px; line-height: 1.6;
  color: var(--ix-muted); margin: .4rem 0 0;
}
.ix-empty b { color: var(--ix-ink); font-weight: 600; }

/* Deltas read as movement, so they are set apart from the number they qualify. */
.ix-delta {
  font-family: var(--ix-mono); font-size: 13px; font-weight: 500;
  padding: .12rem .45rem; border-radius: .25rem; white-space: nowrap;
}
.ix-delta[data-tone="verified"] { color: var(--ix-verified); background: var(--ix-verified-bg); }
.ix-delta[data-tone="blocked"] { color: var(--ix-blocked); background: var(--ix-blocked-bg); }
.ix-delta[data-tone="muted"] { color: var(--ix-muted); background: light-dark(#F0F2F5, #1B1F29); }

/* ---------------------------------------------------------- the gate rail */

.ix-rail {
  border: 1px solid var(--ix-rule); border-radius: .3rem;
  background: var(--ix-surface); padding: 1.1rem 1.25rem .9rem;
}
.ix-rail-grid {
  display: grid;
  grid-template-columns: 58px repeat(6, minmax(26px, 1fr)) minmax(250px, 2.7fr);
  align-items: center; row-gap: .1rem; column-gap: 0;
}
.ix-rail-grid > .ix-head {
  font-family: var(--ix-mono); font-size: 10px; font-weight: 500;
  letter-spacing: .09em; text-transform: uppercase; color: var(--ix-faint);
  text-align: center; padding-bottom: .55rem;
}
.ix-rail-grid > .ix-head.ix-left { text-align: left; }
.ix-rail-grid > .ix-iter {
  font-family: var(--ix-mono); font-size: 11px; color: var(--ix-muted);
  white-space: nowrap; padding-right: .5rem;
}
.ix-rail-grid > .ix-why {
  font-family: var(--ix-mono); font-size: 11.5px; line-height: 1.45;
  padding-left: .85rem; color: var(--ix-muted);
}
.ix-why b { font-weight: 500; color: var(--ix-tone, var(--ix-ink)); }
.ix-why i { font-style: normal; color: var(--ix-faint); }

.ix-pip { position: relative; display: block; height: 30px; }
.ix-pip::before {
  content: ""; position: absolute; left: 0; right: 0; top: 50%;
  transform: translateY(-50%); height: 0; border-top: 1.5px solid var(--ix-rule-strong);
}
.ix-pip.pass::before { border-top-color: var(--ix-ink); }
.ix-pip.never::before { border-top-style: dotted; }
/* The stopping cell takes the line only as far as its own centre: the candidate got here and
   no further, and the empty right half is the part of the pipeline it never entered. */
.ix-pip.stop::before { right: 50%; border-top-color: var(--ix-tone); }
.ix-pip.stop.unverified::before { border-top-style: dashed; }
/* The line ends at the dot it ends at — nothing trails off the end of the rail. */
.ix-pip.done::before { right: 50%; }
/* Nothing precedes `input`, so the line starts at its dot rather than at the cell edge. */
.ix-pip.first::before { left: 50%; }

.ix-pip::after {
  content: ""; position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%);
  width: 8px; height: 8px; border-radius: 50%; background: var(--ix-rule-strong);
}
.ix-pip.pass::after { background: var(--ix-ink); }
.ix-pip.never::after { background: none; border: 1.5px dotted var(--ix-rule-strong); }
.ix-pip.stop::after {
  width: 13px; height: 13px; background: var(--ix-surface);
  border: 2px solid var(--ix-tone);
}
.ix-pip.stop.unverified::after { border-style: dashed; }
.ix-pip.done::after {
  width: 13px; height: 13px; background: var(--ix-verified-bg);
  border: 2px solid var(--ix-verified);
}

.ix-rail-note {
  font-family: var(--ix-sans); font-size: 12.5px; line-height: 1.55; color: var(--ix-muted);
  border-top: 1px solid var(--ix-rule); margin-top: .85rem; padding-top: .7rem;
}
.ix-rail-list { display: none; margin: 0; padding: 0; list-style: none; }
.ix-rail-list li {
  font-family: var(--ix-mono); font-size: 12px; line-height: 1.5; color: var(--ix-muted);
  padding: .3rem 0; border-bottom: 1px dotted var(--ix-rule);
}

/* Below this the rail would be a squeezed diagram rather than a diagram, so it becomes the
   list it always also was. */
@media (max-width: 820px) {
  .ix-rail-grid { display: none; }
  .ix-rail-list { display: block; }
  .ix-verdict-num { font-size: 44px; }
  .ix-mast-meta { margin-left: 0; }
}

/* ------------------------------------------------- source excerpt */

/* A finding cites a line number. Streamlit's `st.code` numbers from 1 with no way to offset,
   so showing lines 118-122 of a file would label them 1-5 — wrong in the one respect that
   matters here. Hence a small block of our own: real line numbers, and the cited line marked. */
.ix-src {
  border: 1px solid var(--ix-rule); border-radius: .3rem; background: var(--ix-surface);
  overflow-x: auto; margin: .1rem 0 .2rem;
}
.ix-src table { border-collapse: collapse; width: 100%; }
.ix-src td {
  font-family: var(--ix-mono); font-size: 12.5px; line-height: 1.65;
  padding: 0; white-space: pre; vertical-align: top;
}
.ix-src .ix-ln {
  width: 1%; text-align: right; padding: 0 .85rem 0 .8rem;
  color: var(--ix-faint); user-select: none;
  border-right: 1px solid var(--ix-rule);
}
.ix-src .ix-code { padding: 0 1rem 0 .85rem; color: var(--ix-muted); width: 99%; }
/* Deliberately *not* amber. Amber-plus-dashed means "not verified" everywhere on this page,
   and the cited line is a fact the scanner reported — the most established thing on screen.
   Emphasis here is weight and a neutral tint, so the convention keeps its one meaning. */
.ix-src tr.ix-hit .ix-code {
  color: var(--ix-ink); background: light-dark(#EEF0F4, #1B1F29); font-weight: 500;
}
.ix-src tr.ix-hit .ix-ln {
  color: var(--ix-ink); background: light-dark(#EEF0F4, #1B1F29); font-weight: 500;
  box-shadow: inset 2px 0 0 var(--ix-ink);
}

/* ------------------------------------------------------------- chips */

.ix-chips { display: flex; flex-wrap: wrap; gap: .4rem; margin: .1rem 0 .2rem; }
.ix-chip {
  font-family: var(--ix-mono); font-size: 11px; font-weight: 500; letter-spacing: .03em;
  padding: .18rem .5rem; border-radius: .25rem;
  border: 1px solid var(--ix-tone); color: var(--ix-tone); background: transparent;
}
.ix-chip[data-fill="1"] { background: var(--ix-tone-bg); }
.ix-chip.unverified { border-style: dashed; }
.ix-chip .ix-n { font-variant-numeric: tabular-nums; opacity: .75; margin-left: .3rem; }

/* Focus stays visible: the palette is low-contrast by design and the default ring is not. */
.ix-rail a:focus-visible, .stTabs [data-baseweb="tab"]:focus-visible {
  outline: 2px solid var(--ix-signal); outline-offset: 2px;
}

@media (prefers-reduced-motion: reduce) {
  * { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
"""

# Severity as a single warm-to-cool ramp, so the column reads as an ordering rather than as five
# unrelated hues. `unknown` is deliberately not the palest: Checkov's community build reports it
# for most checks, and it means the scanner declined to say, not that the finding is minor.
# The light-mode `medium` and `info` foregrounds were 4.45:1 and 4.24:1 on their own chip
# backgrounds — under the 4.5:1 minimum for 11px text. Darkened just enough to clear it
# (5.35 and 5.65) without leaving the ramp or disturbing the ordering.
SEVERITY_TONE: dict[str, tuple[str, str]] = {
    "critical": ("light-dark(#9F1239, #F2789B)", "light-dark(#FDECF1, #2C0F1A)"),
    "high": ("light-dark(#B45309, #E9A23B)", "light-dark(#FDF3E3, #2B1E0B)"),
    "medium": ("light-dark(#8A5A0B, #D9B04A)", "light-dark(#FBF3DF, #26200C)"),
    "low": ("light-dark(#475569, #94A3B8)", "light-dark(#EEF0F4, #1B1F29)"),
    "info": ("light-dark(#556074, #8B93A3)", "light-dark(#F0F2F5, #1B1F29)"),
    "unknown": ("light-dark(#B45309, #E9A23B)", "light-dark(#FDF3E3, #2B1E0B)"),
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def inject() -> None:
    """Install the stylesheet. Call once, before anything else renders."""
    st.markdown(_CSS, unsafe_allow_html=True)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def masthead(thesis_tail: str, meta: str) -> None:
    st.markdown(
        f'<div class="ix-mast">'
        f'<div class="ix-mast-id">iac-security</div>'
        f'<div class="ix-mast-thesis">{thesis_tail}</div>'
        f'<div class="ix-mast-meta">{_esc(meta)}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )


def eyebrow(label: str) -> None:
    st.markdown(f'<div class="ix-eyebrow">{_esc(label)}</div>', unsafe_allow_html=True)


def verdict(number: str, label: str, qualifier: str, tone: str = "ink") -> None:
    """The one number the page exists to return, and the single line that qualifies it.

    `qualifier` is inserted as markup so the caller can emphasise parts of it; it is the caller's
    job to escape anything from disk. Everything else here is escaped.
    """
    st.markdown(
        f'<div class="ix-verdict" data-tone="{_esc(tone)}">'
        f'<div class="ix-verdict-num">{_esc(number)}</div>'
        f"<div>"
        f'<div class="ix-verdict-label">{_esc(label)}</div>'
        f'<div class="ix-verdict-qual">{qualifier}</div>'
        f"</div></div>",
        unsafe_allow_html=True,
    )


def empty(title: str, body: str) -> None:
    """The no-result state. `body` is markup, so the caller escapes anything from disk."""
    st.markdown(
        f'<div class="ix-empty"><div class="ix-empty-title">{_esc(title)}</div>'
        f"<p>{body}</p></div>",
        unsafe_allow_html=True,
    )


def chips(items: list[tuple[str, str, bool]]) -> None:
    """A row of small labelled counts. Each item is (text, severity-or-tone, unverified)."""
    if not items:
        return
    out = ['<div class="ix-chips">']
    for text, key, unverified in items:
        fg, bg = SEVERITY_TONE.get(key, SEVERITY_TONE["info"])
        cls = "ix-chip unverified" if unverified else "ix-chip"
        out.append(
            f'<span class="{cls}" data-fill="1" '
            f'style="--ix-tone:{fg};--ix-tone-bg:{bg}">{_esc(text)}</span>'
        )
    out.append("</div>")
    st.markdown("".join(out), unsafe_allow_html=True)


def source_excerpt(code: str, focus: int | None, context: int = 4) -> None:
    """Show the lines around `focus`, numbered as they are numbered in the file.

    `focus` is 1-based and comes from a scanner. It is clamped rather than trusted: a scanner
    that reports a line past the end of the file should shift the window, not raise.
    """
    lines = code.splitlines()
    if not lines:
        return
    if focus is None:
        start, end = 1, min(len(lines), 1 + context * 2)
    else:
        focus = max(1, min(int(focus), len(lines)))
        start = max(1, focus - context)
        end = min(len(lines), focus + context)

    body = []
    for number in range(start, end + 1):
        hit = ' class="ix-hit"' if number == focus else ""
        body.append(
            f"<tr{hit}><td class=\"ix-ln\">{number}</td>"
            f'<td class="ix-code">{_esc(lines[number - 1]) or "&nbsp;"}</td></tr>'
        )
    st.markdown(
        f'<div class="ix-src"><table><tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def gate_rail(rows: list[dict], note: str) -> None:
    """Draw every candidate against the gates it had to survive.

    Each row needs: `iteration` (label), `reached` (1-based index into STATIONS of the station it
    stopped at), `tone` (a CSS colour), `unverified` (dashed treatment), `outcome` (markup for the
    right-hand column) and `finished` (True when this is the candidate that was returned).
    """
    head = ['<div class="ix-rail-grid">', '<div class="ix-head ix-left"></div>']
    for name, hint in STATIONS:
        head.append(f'<div class="ix-head" title="{_esc(hint)}">{_esc(name)}</div>')
    head.append('<div class="ix-head ix-left">outcome</div>')

    body: list[str] = []
    items: list[str] = []
    for row in rows:
        reached = int(row["reached"])
        tone = row["tone"]
        unverified = " unverified" if row.get("unverified") else ""
        body.append(f'<div class="ix-iter">{_esc(row["iteration"])}</div>')
        for index in range(1, len(STATIONS) + 1):
            if index < reached:
                cls = "ix-pip pass"
            elif index == reached:
                cls = "ix-pip pass done" if row.get("finished") else f"ix-pip stop{unverified}"
            else:
                cls = "ix-pip never"
            if index == 1:
                cls += " first"
            body.append(f'<div class="{cls}" style="--ix-tone:{tone}"></div>')
        # The outcome column shows a truncated rejection reason; the full one is carried as a
        # tooltip rather than dropped, so "rejected — drift unverifiable · could not parse the
        # original as…" has somewhere to finish.
        full = f' title="{_esc(row["full"])}"' if row.get("full") else ""
        body.append(
            f'<div class="ix-why" style="--ix-tone:{tone}"{full}>{row["outcome"]}</div>'
        )
        items.append(
            f'<li><b>{_esc(row["iteration"])}</b> — reached <b>{_esc(STATIONS[reached - 1][0])}</b>'
            f" · {row['outcome']}</li>"
        )

    st.markdown(
        '<div class="ix-rail">'
        + "".join(head)
        + "".join(body)
        + "</div>"
        + '<ul class="ix-rail-list">'
        + "".join(items)
        + "</ul>"
        + f'<div class="ix-rail-note">{note}</div>'
        + "</div>",
        unsafe_allow_html=True,
    )
