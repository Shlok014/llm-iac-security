# UI design — the Streamlit view

The question this document answers: **why does `app.py` look the way it does, and what is it
allowed to say?**

The UI is not the product. `iac_agent` is, and the CLI is its supported interface. But this page
is the first thing a reader sees, and a page that reads as a generic scanner dashboard undercuts
the one claim the project actually makes — that it is careful about what it does and does not
know. The design brief is therefore narrow: **make the provenance of a number as legible as the
number.**

Tag vocabulary follows the rest of `docs/`: *implemented* means it is in `app.py` today.

---

## 1. What was wrong with the previous page

The redesign was prompted by one word — *cluttered* — so the diagnosis comes first. Each item
below was measured against the rendered page, not inferred from the source.

| # | Problem | Evidence |
|---|---|---|
| 1 | **The reader travels ~450 px of prose before reaching a control.** | An `h1` with an emoji, a three-line subtitle, and a bordered drift primer all render above the tab strip. Nothing above the fold is interactive or is a result. |
| 2 | **The drift argument is stated twice, verbatim in substance.** | `_render_drift_primer(compact=True)` on the landing page and `compact=False` in the *Drift gate* tab. A reader who reads both learns nothing the second time. |
| 3 | **Every element carries a caption, so no caption is read.** | The sidebar had explanatory prose under the fixture picker, the scanner picker, and both buttons — the API-key status alone ran to six lines. The main column had a caption under the metric, the severity bar, the findings table, and the trail. Roughly half the page's text was gray. |
| 4 | **The same fact was rendered three ways in a row.** | `#### checkov on ec2_open.tf`, then a `Failed checks / 8` metric, then a caption reading "Scanned as `ec2_open.tf` (terraform) … 7 checks passed". Scanner and filename appeared twice; the count had no visual priority over its own restatement. |
| 5 | **Decoration had no hierarchy because everything was decorated.** | 🔒 in the title, ▶ 🚫 📊 ❓ on the tabs, an emoji per severity, an emoji per verdict, ✅/🔒 leading captions. When every line has an icon, none of them mark anything. |
| 6 | **Tabs inside tabs.** | The fix result opened a five-tab strip (*Diff / Findings / Per-iteration detail / What the model claimed / Download*) nested inside the four-tab page strip, so two independent tab states had to be held in the reader's head. |
| 7 | **Five equal-weight metrics, none of them the answer.** | `before`, `after`, `resolved`, `introduced`, `tokens` rendered as five identical `st.metric` cards. Token count — the least load-bearing figure on the page — got exactly as much space as the finding delta. |
| 8 | **No visual identity at all.** | Stock Streamlit: `#FF4B4B` accent, Source Sans Pro, default radii. A security tool whose entire argument is *don't trust the pretty number* looked like every other Streamlit demo. |

**What was right, and is preserved.** The page never states a measured number of its own — the
evaluation figures are read from `eval/results/RESULTS.md` at runtime and the fixture list is read
from `samples/`. It renders a scanner failure and a clean scan differently and loudly. It reports
rejected candidates rather than hiding them. Every one of those properties survives the redesign;
several are now *more* prominent, not less. See §6.

---

## 2. Brief

- **Subject.** A remediation loop that refuses to let a falling number stand in for a fix.
- **Audience.** Platform and security engineers, and reviewers assessing the engineering. Both
  arrive sceptical, which is the correct posture and the page should reward it.
- **The page's single job.** Return a verdict, and make it obvious what that verdict was
  *derived from* — including which candidates were thrown out before they could score.
- **Non-goal.** Being a dashboard. There is no fleet, no trend line, no time series. One file,
  one run, one answer.

## 3. Tokens

### Colour

Six named values. The palette is derived from the subject's own artifacts — a unified diff and a
`terraform plan` — not from a dashboard convention.

| Token | Light | Dark | Used for |
|---|---|---|---|
| `ink` | `#15171F` | `#E8EAF0` | All primary text. Also the primary button fill — see the risk below. |
| `paper` | `#F4F5F7` | `#0F1117` | Page ground. Cool, not cream. |
| `surface` | `#FFFFFF` | `#171A22` | Cards, tables, the rail. |
| `rule` | `#D8DBE2` | `#2A2E3A` | Hairlines, borders, gate stations. |
| `signal` | `#B45309` | `#E9A23B` | **Reserved for absence of knowledge.** Nothing else may use it. |
| `blocked` | `#B42318` | `#F27B72` | A gate rejection, and the top of the severity ramp. |
| `verified` | `#15803D` | `#5FBE7D` | A scanner that actually ran and reported zero failures. |

**The rule that makes it a system: `signal` means "we do not know", everywhere, without
exception.** Drift that could not be measured, a candidate that was rejected before it was ever
scanned, a Checkov severity of `unknown`, a scanner that produced parse errors — all render in
amber, and all render with a **dashed** border rather than a solid one. Dashed is the visual
grammar for *unverified*. A reader who learns it once on the severity chip reads the drift banner
correctly without being told.

**The risk taken, and its justification.** The primary action button is `ink`, not a bright
accent, so it is *not* the loudest thing on the page — the amber "not checked" state is. This
inverts the usual hierarchy, where the call to action is the brightest pixel. It is justified by
the brief: on this page the most important information is what the run failed to establish, and a
design that shouted "Scan, fix and verify" louder than "drift was not checked" would be arguing
against the project's own thesis. The cost is that first-time users take marginally longer to find
the run button; that is mitigated by putting it alone at the bottom of the control rail with
nothing competing for the position.

Severity is a single warm-to-cool ramp rather than a five-hue rainbow, so it reads as an ordering:
`critical #9F1239` → `high #B45309` → `medium #A16207` → `low #475569` → `info #94A3B8`, with
`unknown` taking the dashed amber treatment above. Checkov's community build reports `unknown` for
most checks, so under the old rainbow the most common severity was also the palest — which
contradicted the caption sitting directly beneath it.

### Type

Two families, with the roles deliberately inverted from the usual arrangement.

- **IBM Plex Mono** — *display and structure.* The wordmark, every verdict numeral, every label
  and eyebrow, rule IDs, resource names, gate station names, counts.
- **IBM Plex Sans** — *prose.* Explanations, captions, button labels, the reference tabs.

Making the monospace the display face rather than the code-block face is the type decision. It is
true to a subject whose every artifact — the input, the diff, the output, the rule IDs, the
scanner output — is already monospaced; the page stops switching register every time it shows a
piece of the thing it is talking about. Plex specifically because it was drawn for an
infrastructure vendor's engineering documentation and its mono has enough character at display
sizes to carry a headline, which most UI monos do not.

| Role | Face | Size / weight / tracking |
|---|---|---|
| Verdict numeral | Plex Mono | 60 px / 500 / `tabular-nums` |
| Wordmark | Plex Mono | 15 px / 600 / +0.14 em, uppercase |
| Eyebrow, section label | Plex Mono | 11 px / 500 / +0.09 em, uppercase |
| Data label, rule ID, chip | Plex Mono | 12 px / 500 |
| Body | Plex Sans | 15 px / 400 / 1.55 line-height |
| Caption | Plex Sans | 13 px / 400 |

Fonts load from Google Fonts by `@import`. **Offline is a supported state**: the stack falls back
to `ui-monospace, SFMono-Regular, Menlo` and `system-ui`, and the layout is specified in `rem` and
`ch` so nothing reflows badly. The page must not require network access to render, because the
scanner path is deliberately usable with no network and no API key.

### Layout

```
┌───────────────────────────────────────────────────────────────────────┐
│ ▪ IAC-SECURITY · detect fix verify              iac_agent 0.x · gpt-… │  masthead, hairline under
├─────────────┬─────────────────────────────────────────────────────────┤
│             │  ANALYSE    DRIFT GATE    MEASURED RESULTS    METHOD    │  tab strip, mono, small caps
│  SOURCE     │ ─────────────────────────────────────────────────────── │
│  ○ sample   │                                                         │
│  ○ upload   │   8   FAILED CHECKS                                     │  verdict — one number, one line
│  [ec2_o… ▾] │       checkov · ec2_open.tf · terraform · 7 passed      │
│             │                                                         │
│  SCANNER    │   ┌───────────────────────────────────────────────────┐ │
│  [checkov▾] │   │ input ──▪ parse ──▪ drift ──▪ rescan ──▪ returned │ │  ◀ SIGNATURE: the gate rail
│  ITERATIONS │   │            ╎         ╎                            │ │
│  ●────      │   │            ╎         └ iter 2 · deleted a resource│ │
│             │   │            └ iter 1 · did not parse               │ │
│  ┌────────┐ │   └───────────────────────────────────────────────────┘ │
│  │  Scan  │ │                                                         │
│  ├────────┤ │   EVIDENCE                                              │
│  │ Fix  ▸ │ │   [ findings ][ diff ][ iterations ][ model ][ file ]   │  one tab level, not two
│  └────────┘ │                                                         │
└─────────────┴─────────────────────────────────────────────────────────┘
```

Three bands, in the order a sceptic reads them: **what is the answer / how was it reached / show
me**. The reference material (the drift essay, the measured results, the method) keeps its own
top-level tabs and is deleted from the landing page, which resolves problem #2 — it is stated
once, in the place named after it.

## 4. Signature: the gate rail

The one element the page is meant to be remembered by, and the only place complexity is spent.

`iac_agent.loop` puts every candidate through `parse → drift → rescan` in that order, and a
candidate that fails a gate is **never scanned**, so it can never post a number. The old UI
asserted this in a caption under a row of metric cards. The rail *shows* it: stations run left to
right, and each iteration is drawn as a token sitting at the station that stopped it. A rejected
candidate is physically to the left of `rescan`. There is no position on the rail where a deleted
resource could have produced a count, because the geometry does not contain one.

This earns its complexity on three grounds:

1. **The content genuinely is a sequence.** Gates are ordered and the order is load-bearing —
   drift is checked before the rescan precisely so a deletion cannot score. Sequential structure
   is honest here in a way that decorative `01 / 02 / 03` numbering never is.
2. **It replaces rather than adds.** It absorbs the metric-card trail, the textual trail line, and
   part of the drift primer's job.
3. **It is the argument.** If a reader takes one image away from the page, this is the one that
   carries the project's claim.

Rendering rules:

- Stations that a run never reached are drawn in `rule`, not hidden. *Not reached* and *passed*
  must not look alike.
- A Dockerfile has no addressable resources, so the drift station is drawn **dashed amber and
  labelled `n/a`** — it is neither passed nor failed, and the ramp for "unknown" already means
  exactly that.
- If the original file does not parse, drift cannot be measured at all; the station is dashed
  amber with the loop's own `drift_gate_note` beside it. The rail never renders an unmeasured gate
  as a passed one.
- The rail is a list on narrow viewports, not a squeezed diagram, and it is emitted as semantic
  markup with text labels so it survives with CSS off.

## 5. Decluttering rules the page now follows

Rules, so a future edit does not reintroduce the problem:

1. **One caption per block, maximum.** If a second sentence is needed, it goes in a `help=`
   tooltip or a `st.popover`, not into the flow.
2. **A fact appears once.** Scanner, filename and IaC type appear in the verdict's qualifier line
   and nowhere else on that screen.
3. **Iconography is semantic or absent.** Emoji are gone from the title, the tab strip and the
   captions. The remaining marks are the severity chip, the gate token and the diff `+`/`−`, each
   of which encodes a value rather than labelling a topic.
4. **The control rail holds controls.** Explanation in the sidebar lives behind `help=`. The
   API-key status is one line with a popover, not a paragraph.
5. **No nested tabs.** One tab level on the page and one strip inside a result — the result strip
   only ever appears when the page strip is on *Analyse*.
6. **Weight tracks importance.** The verdict number is the largest thing in the band; token cost
   is a caption. They are not the same size, because they are not the same news.
7. **One word, one meaning.** The package uses `accepted` for two different things —
   `IterationRecord.accepted` means *cleared every gate and was scanned*, while
   `LoopResult.accepted_any` means *a candidate beat the baseline and is being returned*. The
   page previously borrowed both, so a run could show two candidates labelled "accepted" above a
   banner reading "no candidate was accepted". The view now says **cleared the gates** for the
   first and **beat the baseline** for the second, and never uses "accepted" unqualified.

## 6. What the page is not allowed to do

Unchanged from the previous implementation and restated because it is the point of the project.
These are constraints on the view, enforced by `tests/test_app_contract.py` where they are
mechanically checkable.

- **No measured number is written in `app.py`.** Evaluation figures come from
  `eval/results/RESULTS.md` at page load; the fixture list comes from `samples/` at page load. If
  `RESULTS.md` is absent the page says so and shows nothing, rather than printing a remembered
  figure.
- **An absent analysis is never rendered as a passing one.** A scanner that fails to run produces
  a failure state with no finding count attached. A clean scan produces an explicit "the scanner
  ran and reported zero failures", with the count of checks that passed.
- **"Not checked" is never displayed as "no drift".** Amber and dashed, always.
- **Rejections are shown, not filtered.** Every rejected candidate appears on the rail with its
  reason.
- **No policy lives in the view.** What counts as a finding, when a candidate is rejected and when
  the loop stops are decided in `iac_agent`. `app.py` chooses labels and colours.

## 7. Cost, and what breaks

- **A theme file now exists.** `.streamlit/config.toml` is checked in, so the app no longer picks
  up a developer's personal Streamlit theme. That is deliberate — the page's colour semantics are
  load-bearing and a user theme could turn "unverified" green — but it does mean a reader who
  prefers the stock look cannot get it without editing the file. Light and dark are both defined;
  the OS preference still chooses between them.
- **Google Fonts is a soft dependency.** Offline, the page renders in the fallback stack and looks
  plainer. Nothing breaks, and no functionality is gated on it.
- **The rail is hand-written markup.** It is the one place the view leaves Streamlit's component
  vocabulary, and it is therefore the one place a Streamlit upgrade could visibly break. It is
  isolated in `ui_theme.py` for that reason, and it degrades to a readable list rather than to
  nothing.
- **`ui_theme.py` is not part of the installed package.** `pyproject.toml` installs `iac_agent`
  only. Like `app.py`, the theme module is repository-level: the UI is a view over the package and
  is not importable from it.
