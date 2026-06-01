#!/usr/bin/env python3
import json
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: generate-release-sbom.py <output>", file=sys.stderr)
        return 2

    output = Path(sys.argv[1])
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            text=True,
        )
    )
    workspace_members = set(metadata.get("workspace_members", []))
    components = []
    for package in sorted(metadata.get("packages", []), key=lambda item: item["id"]):
        package_type = "library"
        if package["id"] in workspace_members and package["name"] == "veritas-cli":
            package_type = "application"
        components.append(
            {
                "type": package_type,
                "bom-ref": package["id"],
                "name": package["name"],
                "version": package["version"],
                "purl": f"pkg:cargo/{package['name']}@{package['version']}",
                "licenses": [
                    {"license": {"id": license_id.strip()}}
                    for license_id in package.get("license", "").replace("/", " OR ").split(" OR ")
                    if license_id.strip()
                ],
            }
        )

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [
                {
                    "vendor": "veritas",
                    "name": "scripts/generate-release-sbom.py",
                    "version": "1",
                }
            ],
            "component": {
                "type": "application",
                "name": "veritas",
                "version": workspace_version(metadata),
            },
        },
        "components": components,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    return 0


def workspace_version(metadata: dict) -> str:
    members = set(metadata.get("workspace_members", []))
    for package in metadata.get("packages", []):
        if package["id"] in members and package["name"] == "veritas-cli":
            return package["version"]
    return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
