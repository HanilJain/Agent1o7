#!/usr/bin/env python3
"""
Count how many files of each extension exist within a folder (recursively).
No hardcoded extension list — any new extension found is just added to the dict.

Usage:
    python count_extensions.py /path/to/folder
"""

import os
import sys
from collections import defaultdict


def count_extensions(root_dir):
    counts = defaultdict(int)

    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            _, ext = os.path.splitext(fname)
            if ext == "":
                ext = "<no_extension>"
            counts[ext] += 1

    return counts


def main():
    if len(sys.argv) != 2:
        print("Usage: python count_extensions.py <folder_path>")
        sys.exit(1)

    root_dir = sys.argv[1]

    if not os.path.isdir(root_dir):
        print(f"Error: '{root_dir}' is not a valid directory")
        sys.exit(1)

    counts = count_extensions(root_dir)

    # Sort by count, descending
    for ext, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ext} {count}")


if __name__ == "__main__":
    main()