# SETUP.md — fw-audit local setup (Linux)

This is the full, from-zero setup guide for running fw-audit on a Linux
machine: system prerequisites, Python environment, configuration, and all
three Docker images the pipeline needs — with every fix this project has
already hit baked directly into the instructions below, not left as a
troubleshooting afterthought. Follow it in order; each section says what it
verifies before you move on.

Windows/macOS setup isn't covered here yet — this file is Linux-first by
design (see the request that created it). The commands below assume a
Debian/Ubuntu-family host (`apt-get`); substitute your distro's package
manager for the two or three OS-package installs and everything else is
identical.

---

## 0. What you're setting up

fw-audit is a six-stage pipeline (ingestion → decompile/normalize/clean →
chunk/queue → agentic LLM analysis → RAG sink-to-source tracing →
sandboxed Joern verification → reporting). Stages 1, 2, and 5 each run
inside their own purpose-built Docker image; Stages 3 and 4 run in-process
against an LLM. You need:

- Python 3.11+
- Docker (daemon running, current user able to run `docker build`/`docker run`)
- ~10GB free disk (Ghidra image ~2GB, Joern image ~2.5GB, firmware/db data on top)
- An Anthropic API key (or a local Ollama install) — Stage 1's Identifier
  Agent and Stage 3's vulnerability analyst are **mandatory LLM agents,
  no heuristic fallback**
- git, curl, unzip on the host (used by the setup steps below, not just
  inside the containers)

---

## 1. System packages

```bash
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3-pip git curl unzip
```

Install Docker Engine if it isn't already present — follow
[Docker's official install guide](https://docs.docker.com/engine/install/)
for your distro rather than the distro's own `docker.io` package, which is
often stale. After installing, add yourself to the `docker` group so you
don't need `sudo` for every `docker` command, then re-login (or `newgrp
docker`) for it to take effect:

```bash
sudo usermod -aG docker "$USER"
```

Verify Docker works:

```bash
docker info >/dev/null && echo "Docker OK"
```

---

## 2. Clone and Python environment

```bash
git clone <this-repo-url> fw-audit
cd fw-audit

python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

Install the package. `all` pulls every LLM provider's LangChain
integration; add `stage2`/`stage4` for the tree-sitter cleaning pass and
the local RAG pipeline respectively (both needed for a full pipeline run —
only skip them if you're testing a single stage in isolation). `dev` adds
pytest/ruff/mypy:

```bash
pip install -e ".[all,stage2,stage4,dev]"
```

If you only need one LLM provider, replace `all` with just that extra
(`anthropic`, `ollama`, `openai`, or `google`) — see `pyproject.toml`'s
`[project.optional-dependencies]` for the full list and what each pulls in.

**Verify**: `python -c "import fw_audit"` should succeed with no output,
and `fw-ingest --help` / `fw-extract --help` / `fw-analyze --help` /
`fw-trace --help` / `fw-verify --help` should all print usage text.

---

## 3. Configuration (`.env`)

```bash
cp .env.example .env
```

Open `.env` and fill in at minimum:

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

Every other variable has a working default (see `.env.example`'s own
comments for what each one does — it's written as documentation, not just
a template). If you want to run fully offline instead of against Anthropic,
see `.env.example`'s "Local LLM (Ollama)" section — install
[Ollama](https://ollama.com), `ollama pull qwen2.5-coder:1.5b` (or a larger
model), and set `FWA_USE_LOCAL_MODEL=true` or `FWA_LLM_MODEL=ollama:<model>`.
Expect materially lower finding quality from a small local model — that
path verifies plumbing, not analysis quality.

**Verify**: `python -c "from fw_audit.config.settings import get_settings; get_settings()"`
should succeed with no output.

---

## 4. Build the three Docker images

Each stage that touches Docker has its own purpose-built image, kept
deliberately separate (see root `CLAUDE.md`'s "Three Docker images,
deliberately separate" section for the full rationale) — don't try to
merge them.

### 4.1 Stage 1 — extraction sandbox (`fw-audit-sandbox:latest`)

```bash
docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .
```

No pre-fetch needed — everything it downloads is small. **Known
limitation, not a setup mistake**: the `tp-link-decrypt` sub-build is
best-effort against TP-Link's currently-served firmware samples; if it
fails, the image still builds successfully with a stub binary installed in
its place (only `is_tplink`-routed extraction is affected — binwalk,
sasquatch, squashfs-tools all work regardless). You'll see a clearly
labeled "build failed — installing stub" line in the build log if this
happens; it's expected, not something to debug.

### 4.2 Stage 2 — Ghidra decompilation (`fw-audit-ghidra:latest`)

```bash
docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .
```

The Ghidra release archive (~500MB) is downloaded and SHA256-verified
*inside* this build. The hash is already pinned and verified in the
committed Dockerfile — you don't need to compute anything yourself for the
default pinned version. This build takes longer than Stage 1's (JDK base
image + Ghidra unzip) but shouldn't need any special network handling.

### 4.3 Stage 5 — Joern verification sandbox (`fw-audit-joern:latest`)

This is the one with a real, previously-hit gotcha: `joern-cli.zip` is
**~1.8GB**, and a `docker build`-time download of a file that large over
one long-lived connection failed repeatedly in this project's own dev
environment (`curl: (18) HTTP/2 stream ... not closed cleanly`, twice, at
38% and 83% through the transfer — the network simply didn't sustain one
stream that long). The fix that's already built into this repo: the
archive is **pre-fetched to the host first**, verified against a pinned
SHA256, then `COPY`'d into the build — `docker build` itself never has to
sustain that download.

**Step 1 — pre-fetch the archive** (once; re-fetch only if you bump
`JOERN_VERSION` in the Dockerfile):

```bash
curl --http1.1 --speed-limit 20000 --speed-time 20 -C - -fSL \
    -o docker/.joern-cli.zip \
    "https://github.com/joernio/joern/releases/download/v4.0.420/joern-cli.zip"
```

If your network is reliable, this finishes in one shot. If it stalls or
drops (you'll see the transfer rate flatline), **just re-run the exact
same command** — `-C -` resumes from wherever it left off rather than
restarting; `--speed-limit 20000 --speed-time 20` aborts automatically if
throughput drops below ~20KB/s for 20 seconds straight, so a hung
connection doesn't sit there forever. Run it in a loop if you'd rather not
babysit it:

```bash
for i in $(seq 1 40); do
  curl --http1.1 --speed-limit 20000 --speed-time 20 -C - -fSL \
      -o docker/.joern-cli.zip \
      "https://github.com/joernio/joern/releases/download/v4.0.420/joern-cli.zip" \
      --connect-timeout 15 && break
  sleep 2
done
```

`docker/.joern-cli.zip` is git-ignored (it's a build input, not source —
never commit it).

**Step 2 — verify the download landed intact** (optional but recommended —
this is the exact hash pinned in `docker/Dockerfile.joern`'s
`JOERN_CLI_SHA256`, so a mismatch here means a bad/partial download, not a
build-time surprise):

```bash
echo "d30760165d964e141d5cd6a1841912a5c7bbf92910b6ba022f2b74e73ba0ce81  docker/.joern-cli.zip" | sha256sum -c -
```

**Step 3 — build**:

```bash
docker build -f docker/Dockerfile.joern -t fw-audit-joern:latest .
```

This runs a build-time smoke test (`joern-parse` a trivial C file into a
CPG, then run a real query against it) — a successful build means Joern
genuinely works end-to-end, not just that the files got copied in.

**If you change `JOERN_VERSION`**: the pinned `JOERN_CLI_SHA256` in
`docker/Dockerfile.joern` won't match a different release's zip. Download
the new version's `joern-cli.zip` the same way, `sha256sum` it yourself,
and update `JOERN_CLI_SHA256` in the Dockerfile — never paste a hash from
somewhere else. The build fails safely (`sha256sum -c` errors out) rather
than silently installing the wrong release if you forget this.

### Verify all three images exist

```bash
docker images | grep fw-audit
```

You should see `fw-audit-sandbox`, `fw-audit-ghidra`, and `fw-audit-joern`,
all tagged `latest`.

---

## 5. Run the test suite

```bash
pytest -m "not integration" -q
```

This should be fully green with no Docker daemon calls and no real LLM
calls (every stage's tests mock both boundaries — see root `CLAUDE.md`'s
"Testing notes"). If it isn't green, stop here and fix that before moving
on to a real firmware run — it means something in steps 1–3 is off, not
that you need Docker/an API key yet.

Optional, matches CI-equivalent checks:

```bash
ruff check .
mypy fw_audit
```

`pytest -m integration` needs real firmware plus the Docker images built
in step 4 — skip it for now unless you have a firmware sample ready.

---

## 6. First real pipeline run

Once steps 1–5 are all green, run the stages in order against a real
firmware image (`.bin`/`.pkgtb`/etc. — whatever your target router ships).
Each command's `--help` and its stage's own `CLAUDE.md`
(`fw_audit/stage<N>_*/CLAUDE.md`) has the full flag reference; this is just
the minimal happy path:

```bash
# Stage 1: ingest + shortlist binaries worth analyzing
fw-ingest path/to/firmware.bin
# -> writes data/db/<stem>/stage1_summary.json

# Stage 2: decompile the shortlist with Ghidra, normalize two ways
fw-extract data/db/<stem>/stage1_summary.json
# -> writes data/db/<stem>/stage2/

# Stage 3: chunk + queue + LLM vulnerability analysis
fw-analyze data/db/<stem>/stage1_summary.json
# -> writes data/db/<stem>/stage3/findings/*.json

# Stage 4: RAG sink-to-source tracing (build corpus once, then run)
fw-trace build-corpus --db-subfolder data/db/<stem> \
    --rootfs data/db/<stem>/binwalk_1/_input.pkgtb.extracted/squashfs-root \
    --stage2-binaries data/db/<stem>/stage2/binaries
fw-trace run --db-subfolder data/db/<stem>
# -> writes data/db/<stem>/stage4/

# Stage 5: sandboxed Joern verification of Stage 3's findings
fw-verify run --db-subfolder data/db/<stem>
# -> writes data/db/<stem>/stage5/
```

Each stage has a `debug` subcommand for inspecting/testing one component in
isolation without running the whole thing (e.g. `fw-verify debug
build-cpg`, `fw-trace debug taint`) — see that stage's `CLAUDE.md` for the
full list. Reach for these first when something's not working, rather than
re-running the whole pipeline to see one component's output.

---

## Troubleshooting quick reference

| Symptom | Cause | Fix |
|---|---|---|
| `error: Execution backend unavailable ... fw-audit-ghidra image` | `fw-audit-ghidra:latest` not built | Step 4.2 |
| `ok: False` / `stderr: sh: 1: joern-parse: not found` | `fw-audit-joern:latest` not built, or an old checkout predating this repo's image-routing fix | Step 4.3; confirm you're on a checkout with the fix (this exact failure mode is what it fixes) |
| `docker: Error response from daemon: pull access denied for fw-audit-joern` | Image not built locally — Docker tried to pull it from a registry instead | Step 4.3 |
| `curl: (18) HTTP/2 stream ... not closed cleanly` during `docker build -f docker/Dockerfile.joern` | Your network can't sustain the in-container 1.8GB download | Use the pre-fetch-to-host approach in step 4.3 (already the default in this repo's Dockerfile) |
| `sha256sum -c` fails on `docker/.joern-cli.zip` | Partial/corrupted download | Re-run the curl command in step 4.3 (`-C -` resumes) |
| Stage 5 `Stage5InputError: No normalized Joern C resolved for bin_id=...` | The `bin_id` your `--gid`/`--bin-id` derives from doesn't match anything in `stage2_summary.json` — commonly a symlinked binary (e.g. a busybox-style applet) shortlisted under a different name than Stage 2 actually decompiled it under | Check `stage2/stage2_summary.json`'s `binaries[].bin_id` list against what you're passing; a Stage 3 finding file's `chunk_id` must match one of those exactly |
| `pytest -m "not integration"` not green | A step in 1–3 is off (venv, extras, or `.env`/settings import) | Re-check step 2's install command and step 3's settings import before touching Docker at all |
| `VerifierModelUnavailableError` / any `AgentRole` credential error | No usable LLM credential for that role | Set `ANTHROPIC_API_KEY` in `.env`, or point the relevant `FWA_*_MODEL` override at a running local Ollama (step 3) |

For anything not covered here, check the specific stage's own `CLAUDE.md`
(`fw_audit/stage<N>_*/CLAUDE.md`) — each one has its own "Debugging"
section with stage-specific known errors and exact debug commands.
