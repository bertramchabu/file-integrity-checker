"""
File Integrity Checker — CodeNova Cybersecurity Internship, Task 3.
SHA-256 baseline manifests and tamper detection.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path, chunk: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while block := file.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict:
    entries = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative_path = path.relative_to(root).as_posix()
            try:
                file_hash = sha256_file(path)
                stat = path.stat()
                entries[relative_path] = {
                    "sha256": file_hash,
                    "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(
                        stat.st_mtime, timezone.utc
                    ).isoformat(),
                }
            except (PermissionError, OSError) as error:
                entries[relative_path] = {"error": str(error)}

    return {
        "created": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "files": entries,
    }


def verify(root: Path, manifest: dict) -> dict:
    old_files = manifest.get("files")
    if not isinstance(old_files, dict):
        raise ValueError("manifest must contain a 'files' object")

    new_files = build_manifest(root)["files"]
    report = {"modified": [], "added": [], "missing": [], "errors": []}

    for path, old_meta in old_files.items():
        if path not in new_files:
            report["missing"].append(path)
            continue

        new_meta = new_files[path]
        if "error" in new_meta:
            report["errors"].append({"path": path, "error": new_meta["error"]})
        elif not isinstance(old_meta, dict) or "sha256" not in old_meta:
            report["errors"].append(
                {"path": path, "error": "baseline has no SHA-256 hash"}
            )
        elif new_meta.get("sha256") != old_meta["sha256"]:
            report["modified"].append(path)

    for path, meta in new_files.items():
        if path not in old_files:
            report["added"].append(path)
            if "error" in meta:
                report["errors"].append({"path": path, "error": meta["error"]})

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create and verify SHA-256 file integrity manifests."
    )
    parser.add_argument("mode", choices=["baseline", "verify"])
    parser.add_argument("folder", help="folder to scan")
    parser.add_argument("--manifest", default="manifest.json")
    args = parser.parse_args()

    root = Path(args.folder)
    if not root.is_dir():
        parser.error(f"folder is not an accessible directory: {root}")

    manifest_path = Path(args.manifest)
    if args.mode == "baseline":
        manifest = build_manifest(root)
        try:
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
        except OSError as error:
            parser.error(f"could not write manifest {manifest_path}: {error}")
        print(f"Baseline written: {manifest_path} ({len(manifest['files'])} files)")
        return

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"could not read manifest {manifest_path}: {error}")

    try:
        report = verify(root, manifest)
    except (AttributeError, ValueError) as error:
        parser.error(f"invalid manifest {manifest_path}: {error}")

    print("=== Integrity Report ===")
    for category in ("modified", "added", "missing"):
        print(f"{category.upper()} ({len(report[category])}):")
        for path in report[category]:
            print(f"  - {path}")
    if report["errors"]:
        print(f"ERRORS ({len(report['errors'])}):")
        for item in report["errors"]:
            print(f"  - {item['path']}: {item['error']}")

    sys.exit(1 if any(report.values()) else 0)


if __name__ == "__main__":
    main()
