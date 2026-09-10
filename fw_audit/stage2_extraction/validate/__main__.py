"""`python -m fw_audit.stage2_extraction.validate <file>` entry point — see
`__init__.py`'s module docstring for the full CLI contract. This file
exists only because `python -m <package>` requires `__main__.py`; the
actual argument parsing and logic live in `__init__.py::_main` so
`validate_text`/`validate_file` stay importable without pulling in
`argparse`/`sys` at import time for a normal library caller.
"""

from __future__ import annotations

import sys

from fw_audit.stage2_extraction.validate import _main

if __name__ == "__main__":
    sys.exit(_main())
