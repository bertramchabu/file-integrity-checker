# File Integrity Checker

A small Python command-line tool that creates a SHA-256 baseline manifest for a
folder and detects files that have been modified, added, or removed.

## Features

- Hash-based detection catches content changes even when file size and
  modification time are unchanged.
- Recursively scans nested subdirectories with `pathlib.Path.rglob`.
- Records file size and UTC modification time alongside each hash.
- Captures per-file permission and I/O errors in the manifest or verification
  report instead of crashing the scan.

## Stack

Python 3, `hashlib`, `pathlib`, and JSON. No third-party packages are required.

## Setup and usage

Run the script with Python 3:

```text
python integrity_checker.py baseline <folder> [--manifest manifest.json]
python integrity_checker.py verify <folder> [--manifest manifest.json]
```

Create a baseline, then verify the folder against that baseline:

```text
python integrity_checker.py baseline testdata
python integrity_checker.py verify testdata
```

The default manifest path is `manifest.json`. Verification exits with status 1
if it finds modified, added, or missing files, or if a file cannot be checked.
Keep the manifest outside the folder being scanned so it does not become part
of its own baseline.

## Manifest schema

The JSON manifest contains:

- `created`: when the baseline was generated, in UTC.
- `root`: the folder used to create the baseline.
- `files`: a mapping from each relative file path to its `sha256`, `size`, and
  UTC `mtime`. Files that could not be read have an `error` field instead.

## Single-byte tamper simulation

```text
$ mkdir testdata && echo "original content" > testdata/report.txt
$ python integrity_checker.py baseline testdata
Baseline written: manifest.json (1 files)

$ printf 'X' | dd of=testdata/report.txt bs=1 seek=0 conv=notrunc   # single-byte tamper
$ python integrity_checker.py verify testdata
=== Integrity Report ===
MODIFIED (1):
  - report.txt
ADDED (0):
MISSING (0):
```

The single-byte edit leaves the file size unchanged. The hash comparison
detects the content change independently of size and modification time.