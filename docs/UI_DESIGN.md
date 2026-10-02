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

Eight named values, seven of them from the original palette. It is derived from the subject's own
artifacts — a unified diff and a `terraform plan` — not from a dashboard convention.

| Token | Light | Dark | Used for |
|---|---|---|---|
| `ink` | `#15171F` | `#E8EAF0` | All primary text. Also the primary button fill — see the risk below. |
| `paper` | `#F6F7F9` | `#0F1117` | Page ground, set in `.streamlit/config.toml`. Cool, not cream. |
| `surface` | `#FFFFFF` | `#171A22` | Cards, tables, the rail. |
| `rule` | `#D8DBE2` | `#2A2E3A` | Hairlines and borders. |
| `rule-strong` | `#868C9C` | `#666E7E` | The rail's own marks — see §8. |
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
`critical #9F1239` → `high #B45309` → `medium #8A5A0B` → `low #475569` → `info #556074`, with
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
| Verdict numeral | Plex Mono | 58 px / 500 / `tabular-nums` |
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
│ [ec2_open▾] │                                                         │
│  38 lines   │   8   FAILED CHECKS                                     │  verdict — one number, one line
│ › upload    │       checkov · ec2_open.tf · 7 passed                  │
│             │                                                         │
│  SCANNER    │   ┌───────────────────────────────────────────────────┐ │
│  [checkov▾] │   │ input ──▪ parse ──▪ drift ──▪ rescan ──▪ returned │ │  ◀ SIGNATURE: the gate rail
│  MAX FIX    │   │            ╎         ╎                            │ │
│  ●────      │   │            ╎         └ iter 2 · deleted a resource│ │
│             │   │            └ iter 1 · did not parse               │ │
│  ┌────────┐ │   └───────────────────────────────────────────────────┘ │
│  │Scan—fre│ │                                                         │
│  ├────────┤ │   EVIDENCE                                              │
│  │Fix—paid│ │   [ diff ][ findings ][ what the model claimed ]        │  one tab level, not two
│  └────────┘ │                                                         │
└─────────────┴─────────────────────────────────────────────────────────┘
```

The source picker has no mode switch: the uploader lives under the fixture list and wins when it
holds a file. Cost is in the run labels rather than in a tooltip. Both are §8.

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

- Stations that a run never reached are drawn in `rule-strong`, not hidden. *Not reached* and
  *passed* must not look alike — which is also why the token is `rule-strong` rather than
  `rule`: at `rule`'s contrast they looked like nothing at all. See §8.
- A Dockerfile has no addressable resources. The current runtime checks a bounded structural
  signature instead: base image family, application copy presence, and startup command presence.
  The station can pass or reject, but a pass does not prove semantic equivalence or a build.
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

---

## 8. Second pass: what was still hard

§1 fixed a page that was *cluttered*. This pass answers a different complaint — *make it
easier* — and the distinction matters, because almost none of what follows is about how the page
looks. Each item was found by driving the running app rather than by reading the source, and each
is a step someone had to take that they should not have had to.

### The reader could not read it

`--ix-faint` measured **2.98:1** on light paper and **3.65:1** on the dark card — under the 4.5:1
minimum for text at any of the sizes it is used at. That would be defensible for decoration, but
`faint` is what the **tab strip**, the **rail's station names** and the **line under the verdict
number** are set in, so the page's navigation and the sentence naming the scanner and the file
were both below the threshold. Now `#6B7181` / `#8A92A2` — 4.55 and 5.56, still a clear step
quieter than `muted` at 5.70 / 6.62.

The rail had the same problem in a worse place. Its unreached stations were drawn in `rule` at
**1.29:1**, which made the dotted pips and the track between them almost invisible — and §4 says
in as many words that *not reached* and *passed* must not look alike. Graphics need 3:1, not
4.5:1, so `rule-strong` is a separate token: hairlines stay hairlines. Two severity chips
(`medium` 4.45, `info` 4.24) were darkened for the same reason.

### The table was hard to use as a table

| Was | Now |
|---|---|
| Sorted by severity then rule ID. Checkov reports `unknown` for everything, so in practice it sorted alphabetically by rule ID and scattered one resource's problems across the whole list. | Sorted by severity, then **resource**, then line. Everything wrong with one bucket sits together. |
| A `severity` column reading `unknown` in every row — the widest column on screen spending its width on one repeated word. Trivy on a Dockerfile reports no resource at all, giving a column of blanks. | A column whose every value is identical is dropped. The chips above the table already state the breakdown. |
| Dockerfile findings named `/var/folders/q0/…/tmp8f2/Dockerfile.ADD`: sixty characters of scratch path in front of the one word that identifies the instruction. | Paths **inside this run's own scratch directory** are shortened to their last component. Anything else is left exactly as the scanner reported it. |
| A fixed ten-row height, so five findings got a scrollbar they did not need and thirty got a scroll region that ate the page's scroll whenever the pointer was over it. | Sized to its contents, to a ceiling. |
| A finding cited line 120; the file was in a collapsed expander at the bottom of the page. | Select a row and the cited line appears **beneath the table**, numbered as it is numbered in the file. |

The excerpt is deliberately **not** highlighted in amber. Amber-plus-dashed means "not verified"
everywhere on this page, and a line a scanner reported is the most established thing on screen;
emphasis there is weight and a neutral tint, so the convention keeps its one meaning.

### "What changed?" was answered with two tables and a request to diff them by eye

The *findings* evidence view put before and after in two half-width columns, each truncating,
while the numbers that are the actual answer sat in a different line entirely. It is now one
full-width table with a `status` column — `introduced`, then `still failing`, then `resolved`,
worst news first.

The classification is **not** computed here. `LoopResult.resolved` and `.introduced` are the
loop's own key sets, and `loop.finding_key` — exported for this — is the loop's own
normalisation, so the table cannot disagree with the counts printed above it. That normalisation
is load-bearing rather than tidy: the baseline is scanned where the input was written and the
candidate in the loop's output directory, so Checkov names the same Dockerfile instruction two
different ways, and a naive join would report every finding resolved and every survivor newly
introduced.

### The controls asked for knowledge the page had not given

- **Cost was in a tooltip.** Streamlit buttons give no sign they have one, so the single most
  important thing to know before clicking — that this one spends money — was behind a hover
  nobody had a reason to try. It is in the labels now: *Scan only — free* and *Scan, fix and
  verify — paid*. Emphasis follows availability too: with no key the paid button is disabled, and
  styling a dead control as the primary action made the loudest thing on the page the one where
  nothing happens.
- **The empty state described a button instead of containing one.** It read "press Scan only"
  while the control was in the other column, past three groups the visitor had not learned yet.
  The same action is now in the empty state, and it clears itself when used.
- **A `Bundled sample` / `Upload` radio silently destroyed uploads.** Switching back to the
  samples unmounted the uploader, which in Streamlit discards the file — so glancing at a fixture
  cost you your own Terraform, with nothing on screen explaining why. The radio is gone; the
  uploader sits under the picker and wins when it holds a file. Collapsing its expander does not
  unmount it, which is the whole difference.
- **A missing scanner was discovered by waiting for it to fail.** `pip install` provides Checkov
  and not Trivy, which is a Go binary. `scanners.scanner_path` answers the question before the
  run. The failure path is unchanged and still renders loudly if it happens.
- **The default fixture was `docker_insecure.Dockerfile`** — alphabetically first, and historically
  shown with the drift gate as *not applicable*. The current runtime has a bounded Dockerfile
  structural gate. The page still opens on the first Terraform fixture because resource-address
  drift is the project's measured evaluation case; selection remains data-driven.
- **The reason a control was dead was printed underneath it.** Read in order you met the greyed
  button first and the explanation second. Both moved above. The "fixing is unavailable"
  explanation came out of a popover entirely: a popover styled with no border does not read as a
  control, and being stuck is exactly when the reason must not be one click away.

### Things that were saying themselves twice

The verdict qualifier ended `stopped: Hit the iteration cap` and the caption directly beneath it
began `MAX_ITERS — The loop used every attempt…`. The caption is the line that can also explain
it, so it says it alone. `scanned as X (terraform)` now appears only when the scanned name
differs from the one you chose — an upload or a Dockerfile, which is the case it was written for
— rather than restating the filename from the line above. A completed run's `Done` box removes
itself instead of sitting between the tab strip and the answer for the rest of the session.

### The slow path said nothing while it was slow

A remediation run is tens of seconds of model calls. The status box listed three numbered steps
written *before* any of them had run — asserting work was finished, then sitting still. It now
reports as it goes, from `run_loop`'s `on_step` callback: the baseline count, then that the
model has read the file, then one line per candidate as it settles.

The wording matches the rail on purpose. Someone who watched *cleared the gates* appear during
the run finds the same phrase under the same station afterwards, so the live view and the
post-hoc view are the same vocabulary rather than two accounts of one run.

Two properties of the callback are load-bearing and are tested. A candidate is reported **once**,
and only after every gate has had its say — reporting mid-decision would let the box announce a
finding count for a candidate the drift gate was about to reject, which is the confusion the
gates exist to prevent. And a callback that raises cannot abort the run: by the third iteration
real money has been spent, and a status handler is a courtesy, not the contract.

### Two things that were not about the view at all

- `_do_scan` is memoised. The same file through the same scanner takes about five seconds and
  returns the same thing every time. `_do_fix` is **deliberately not** memoised: it spends money
  and it is not reproducible, so caching it would quietly turn a second paid run into a replay of
  the first, which is the substitution this project objects to everywhere else.
- The input preview renders the **result's** file, not the sidebar's current selection. Those
  diverge the moment someone changes fixture without re-running, and the old version put the new
  file's source directly under the old file's findings — line numbers indexing a listing they did
  not come from.

### Rules added to §5

8. **A column whose every value is the same is not a column.** Say it once, above the table.
9. **Cost goes in the label.** Never only in `help=`; a Streamlit control gives no sign it has a
   tooltip.
10. **Emphasis follows availability.** A disabled control is never the primary action.
11. **The source shown belongs to the result shown**, never to the current selection.
