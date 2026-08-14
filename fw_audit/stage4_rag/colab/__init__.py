"""Stage 4, Components 1+2 — the Google Colab-deployed corpus build.

See `chunk_and_embed.py`'s module docstring for the full picture: that
file is deliberately self-contained (stdlib + `chromadb` + a sentence-
embedding library only, zero `fw_audit.*` imports) so it is both this
repo's source of truth and directly paste-able into a Colab cell.
"""

from __future__ import annotations
