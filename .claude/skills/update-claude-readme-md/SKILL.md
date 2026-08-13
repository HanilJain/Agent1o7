---
name: update-claude-readme-md
description: Sync a stage's (or the project's) CLAUDE.md/README.md against real git history — add rows for new files, remove rows for deleted ones, refresh CLI flags/input/output/debugging sections. Use when the user asks to update docs after a feature/file addition or removal, or invokes /update-claude-readme-md.
origin: project
---

# update-claude-readme-md

Keeps `CLAUDE.md`/`README.md` honest against what the code actually does,
by diffing git history since each doc was last touched — never by
guessing or doing a full rewrite. Only touches the stage(s) named in
`args`. This is a **manual, on-demand** sync: it never runs on its own,
only when this skill is explicitly invoked.

## Parsing `args`

Split on whitespace/commas, lowercase, strip non-alphanumerics. Map each
token to a target using this table; unrecognized tokens → ask the user to
clarify rather than guessing:

| Token forms | Target | Doc files | Source scope |
|---|---|---|---|
| `stage1`, `stage 1`, `1` | Stage 1 | `fw_audit/stage1_ingestion/{CLAUDE,README}.md` | `fw_audit/stage1_ingestion/` |
| `stage2`, `stage 2`, `2` | Stage 2 | `fw_audit/stage2_extraction/{CLAUDE,README}.md` | `fw_audit/stage2_extraction/` |
| `stage3`, `stage 3`, `3` | Stage 3 | `fw_audit/stage3_analysis/{CLAUDE,README}.md` | `fw_audit/stage3_analysis/` |
| `stage4`..`stage6` | Stage N | `fw_audit/stageN_*/{CLAUDE,README}.md` | `fw_audit/stageN_*/` |
| `main`, `root`, `project` | Project | `CLAUDE.md`, `README.md` (repo root) | `fw_audit/executors/`, `fw_audit/config/`, `fw_audit/common/`, plus **the set of stage packages that exist** (for the routing table) |
| `all` | Every target above | — | — |

No args → ask which stage(s)/`main` via AskUserQuestion rather than
defaulting to `all` (a full-repo sync is expensive and rarely what's meant).

## Per-target procedure

Run this once per resolved target, independently — do not batch edits
across targets into one pass, so a mistake in one target's diff can't
bleed into another's.

### 1. Find the diff window

```bash
git log -1 --format=%H -- <doc_file>   # for each of the target's doc files
```

Use the **older** of the two (CLAUDE.md/README.md, or root CLAUDE.md/README.md
for `main`) as `<since>`. If a doc file has no history yet (skill just
created it, never committed), use the repo's first commit
(`git log --reverse --format=%H | head -1`) as `<since>` — but say so in
your summary, since that means "everything" counts as new.

```bash
git log --name-status <since>..HEAD -- <source_scope>
git log <since>..HEAD --pretty=format:"%h %s" -- <source_scope>
```

If this is empty, report "<target> docs are already current — no commits
touched <source_scope> since <since>" and stop for that target. Do not
edit files with nothing to say.

### 2. Classify each changed path

- **A** (added), non-test, non-`__init__.py` → new file needing a row in
  the doc's file table. Read the file's module docstring / first
  comment block to write its one-line purpose — never invent one.
- **D** (deleted) → remove its row from the file table and any command
  examples that reference it.
- **R** (renamed) → update the path in place, keep the existing purpose
  text unless the diff shows behavior changed too.
- **M** on `runner.py` → re-read `_parse_args()` in full; reconcile the
  doc's "Invoke"/flag list against the actual `argparse` arguments (added,
  removed, renamed, changed defaults).
- **M** on `fw_audit/config/settings.py` → check whether any new/changed
  `Field` is stage-relevant (its `validation_alias` prefix or a docstring
  reference names the stage); if so, reconcile the doc's env-var mentions.
- **A/M** under `tests/` matching the stage (`test_stageN_*.py` or a name
  referenced in the doc's Testing/Debugging section) → update the pytest
  command list.
- **A/D** on `common/schemas.py` or `common/findings.py` types the stage's
  files reference → check the "Output"/"Input" sections still describe the
  right fields.
- Everything else (formatting-only diffs, comment tweaks, non-behavioral
  refactors) → skip; don't churn the doc over it.

For `main`: additionally check whether the set of `fw_audit/stage*/`
packages changed (new stage folder appeared, or a placeholder stage grew
real files) — if so, update the routing table and status line. Check
`fw_audit/executors/`, `fw_audit/config/`, `fw_audit/common/` for new
modules affecting the "Cross-cutting architecture" section.

### 3. Edit

Use Edit (not Write — these files carry a lot of hand-tuned wording; a
full rewrite loses that). Make the smallest change that makes the doc
correct again: add/remove/update table rows and sections identified in
step 2, keep the surrounding prose/tone/structure untouched.

### 4. Enforce the 500-word budget (stage docs only)

`main`'s `CLAUDE.md`/`README.md` have no word cap. Every stage's
`CLAUDE.md`/`README.md` do:

```bash
wc -w <doc_file>
```

If over 500, tighten wording (drop filler words, merge short bullets,
shorten table cells) — never delete a fact to make the count without
saying so. Re-run `wc -w` until under 500.

### 5. Report

For each target, list: commits covered (`<since>..HEAD`, count), files
added/removed/modified in the docs, and the final word counts for stage
docs. If something was ambiguous (e.g. a new file's purpose wasn't
obvious from its docstring, or a change looked architectural enough to
need the user's framing rather than a mechanical row edit), say so
explicitly instead of guessing — flag it, don't silently skip it.

## Non-goals

- Never invents CLI flags, file purposes, or output paths — always reads
  the real source first.
- Never touches a stage's docs beyond what's in `args`.
- Never commits — leaves changes staged/unstaged for the user to review.
- Never runs automatically on file save, commit, or session start — this
  skill only acts when explicitly invoked.
