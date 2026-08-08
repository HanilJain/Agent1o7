# syntax=docker/dockerfile:1
#
# fw-audit extraction sandbox. This is a PLAIN, deterministic container —
# targeted by fw_audit.executors.docker_executor.DockerExecutor for Stage 1's
# Extraction Script (a fixed command sequence: unzip -> binwalk -> optional
# tp-link-decrypt -> binwalk -> unsquashfs). It is NOT an LLM-controlled
# sandbox; see fw_audit/executors/sandbox_executor.py for that (unimplemented,
# reserved for later stages).
#
# Runtime is started with --network=none (see docker_executor.py); the two
# builder stages below need network access at BUILD time only.

# ---------------------------------------------------------------------------
# Stage A: tpl-builder — compiles tp-link-decrypt (robbins/tp-link-decrypt,
# the maintained successor to the now-deprecated watchfulip/tp-link-decrypt).
#
# extract_keys.sh downloads two TP-Link firmware images (~100MB total) over
# plain HTTP from download.tplinkcloud.com solely to harvest RSA keys into
# include/RSA_0.h / RSA_1.h at build time; only the compiled binary is copied
# into the runtime stage — no firmware ships in the final image.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS tpl-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev binwalk git wget xxd binutils ca-certificates \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*
# One of the two firmware samples extract_keys.sh downloads is UBI-imaged;
# binwalk's default toolchain doesn't include a UBI extractor, so its scan
# detects the "UBI erase count header" signature but extracts nothing past
# it — leaving the script unable to find nvrammanager and its embedded key.
RUN pip install --break-system-packages --no-cache-dir ubi_reader
WORKDIR /build
RUN git clone --depth 1 https://github.com/robbins/tp-link-decrypt.git
WORKDIR /build/tp-link-decrypt
# Two upstream-script quirks, both worked around rather than patched deeper:
#  1. It interactively prompts ("run binwalk in quiet mode? [yes/no]") after
#     extracting the DES key; there's no stdin in a Docker build, so `read`
#     would hit EOF and fail. Pipe an answer in.
#  2. Its own `binwalk -M -e -C 1 <fw>` calls omit `--run-as=root`. binwalk
#     refuses third-party-utility extraction when running AS root without
#     that flag (we are, by default, in this build) — `ModuleException:
#     ... use '--run-as=root'`. sed the flag into both call sites.
RUN sed -i 's/binwalk -M -e/binwalk -M -e --run-as=root/' extract_keys.sh
# KNOWN LIMITATION: extract_keys.sh's RSA-key harvest reaches into two
# specific TP-Link/Tapo firmware images (hardcoded URLs) and greps for a
# specific binary (nvrammanager / slpupgrade) at a specific extraction
# depth to pull DES/RSA key material out of it. As of this build, TP-Link's
# currently-served firmware at those URLs no longer contains one of those
# binaries at the expected path — a firmware-content mismatch upstream, not
# a defect in this Dockerfile — so key extraction fails.
#
# Rather than let that sink the entire image (sasquatch, binwalk,
# squashfs-tools, unzip below are all independently functional and don't
# need this), build tp-link-decrypt on a best-effort basis: on failure,
# install a stub that clearly explains itself instead of a working binary.
# `is_tplink` runs will hard-fail with an honest message until this is
# revisited against current firmware samples.
RUN chmod +x extract_keys.sh; \
    if echo "yes" | ./extract_keys.sh && make; then \
        echo "tp-link-decrypt: built successfully"; \
    else \
        echo "tp-link-decrypt: build failed (see log above) — installing stub"; \
        mkdir -p bin; \
        printf '#!/bin/sh\necho "tp-link-decrypt: not available in this image (upstream RSA key extraction currently fails against TP-Link'"'"'s served firmware samples; see docker/Dockerfile)" >&2\nexit 1\n' > bin/tp-link-decrypt; \
        chmod +x bin/tp-link-decrypt; \
    fi

# ---------------------------------------------------------------------------
# Stage B: sasquatch-builder — a patched unsquashfs (devttys0/sasquatch) for
# vendor-modified SquashFS images that stock unsquashfs 4.5.1 cannot unpack
# (TP-Link/Broadcom-style non-standard compression).
#
# Deliberately NOT `make install`: that target's default install path could
# collide with the stock squashfs-tools `unsquashfs` on PATH. The patched
# Makefile already names its own output binary `sasquatch` (not
# `unsquashfs`) and defaults `all:` to build it, so we just copy that binary
# out directly — both tools end up coexisting under distinct names, and
# extraction/binwalk.py can try the stock tool first, sasquatch as fallback.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS sasquatch-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential zlib1g-dev liblzma-dev liblzo2-dev libssl-dev \
        git wget ca-certificates patch \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN git clone --depth 1 https://github.com/devttys0/sasquatch.git
WORKDIR /build/sasquatch
RUN wget -q https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz \
    && tar xzf squashfs4.3.tar.gz
# patch0.txt's paths are relative to inside the extracted squashfs4.3/
# directory (it diffs squashfs-tools/ vs squashfs-tools-patched/), not to
# /build/sasquatch where the tarball lands — apply it from there.
RUN cd squashfs4.3 && patch -p0 < ../patches/patch0.txt
WORKDIR /build/sasquatch/squashfs4.3/squashfs-tools
# The patched Makefile already enables gzip/xz/lzo/lzma/xattr support (with
# LZMA_DIR pointed at the bundled ./LZMA/lzma465 sources) by default.
#
# CFLAGS is injected via `sed`, NOT `make CFLAGS=...` on the command line.
# `lzma_wrapper.o` (needed for LZMA_SUPPORT) recursively invokes sub-makes
# for two bundled 7-zip-SDK C++ libraries (lzmalt, lzmadaptive); GNU Make
# auto-propagates command-line-origin variables into those sub-makes, where
# they silently WIN over the sub-makefiles' own `CFLAGS = ...` lines. One of
# them (LZMA_Lib/makefile) embeds its `-c` (compile-only) flag *inside* that
# CFLAGS value — losing it turns "compile ZLib.cpp" into "compile-AND-LINK
# ZLib.cpp as a standalone executable", which fails with `undefined
# reference to main` and a wall of missing-symbol errors that look like a
# real code bug but aren't. A plain in-file `+=` assignment stays local to
# this Makefile and never propagates to sub-makes, avoiding the whole class
# of failure.
#   -fcommon:      GCC >=10 defaults to -fno-common, which breaks this old
#                  codebase with multiple-definition link errors.
#   -D_GNU_SOURCE: this 2016-era code uses GNU extensions (FNM_EXTMATCH from
#                  <fnmatch.h>, asprintf from <stdio.h>) that modern glibc
#                  only exposes when _GNU_SOURCE is explicitly defined.
#   -Wno-error:    the Makefile's own CFLAGS already sets -Wall -Werror; a
#                  -Wmisleading-indentation hit in 2016-era code (predating
#                  that GCC diagnostic) would otherwise hard-fail the build
#                  over a style warning, not a real bug. Appended (not
#                  inserted at the top) so it lands *after* -Werror in the
#                  final flag order and actually cancels it.
RUN echo 'CFLAGS += -fcommon -D_GNU_SOURCE -Wno-error' >> Makefile
# XATTR_SUPPORT=  Disables SquashFS extended-attribute support. squashfs-
#                 tools 4.3's xattr.h has `static inline` fallback stubs
#                 (read_xattrs_from_disk, get_xattr) that collide with
#                 read_xattrs.c's real definitions when XATTR_SUPPORT=1 — a
#                 known upstream 4.3 build bug, unrelated to the sasquatch
#                 patch or the CFLAGS issue above. Not needed for read-only
#                 firmware extraction, and XATTR_SUPPORT isn't referenced by
#                 any sub-make, so overriding it on the command line is safe.
RUN make XATTR_SUPPORT=
RUN cp sasquatch /build/sasquatch-bin

# ---------------------------------------------------------------------------
# Stage C: runtime — the image DockerExecutor actually runs.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        binwalk squashfs-tools file unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tpl-builder /build/tp-link-decrypt/bin/tp-link-decrypt /usr/local/bin/tp-link-decrypt
COPY --from=sasquatch-builder /build/sasquatch-bin /usr/local/bin/sasquatch
RUN chmod +x /usr/local/bin/tp-link-decrypt /usr/local/bin/sasquatch
WORKDIR /work
