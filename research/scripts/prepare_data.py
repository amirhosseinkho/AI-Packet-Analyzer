"""Check, unpack, and fingerprint the datasets.

Both datasets are distributed behind a registration form or a SharePoint
folder, so they cannot be fetched by script. Download them by hand, put the
archives or CSVs in the folders below, and run this script:

  CIC-IDS2017  https://www.unb.ca/cic/datasets/ids-2017.html
               file: GeneratedLabelledFlows.zip (the "TrafficLabelling" CSVs,
               which contain timestamps; MachineLearningCVE does not)
               -> research/data/cic-ids2017/

  UNSW-NB15    https://research.unsw.edu.au/projects/unsw-nb15-dataset
               files: UNSW-NB15_1.csv ... UNSW-NB15_4.csv (from "CSV Files")
               -> research/data/unsw-nb15/

The script writes research/data/manifest.json with the SHA-256 of every CSV,
so a results folder can be traced back to the exact data it used.

    python scripts/prepare_data.py
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
EXPECTED = {
    "cic-ids2017": [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ],
    "unsw-nb15": [f"UNSW-NB15_{i}.csv" for i in range(1, 5)],
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    manifest, missing = {}, []
    for name, files in EXPECTED.items():
        folder = DATA / name
        folder.mkdir(parents=True, exist_ok=True)
        for archive in folder.glob("*.zip"):
            with zipfile.ZipFile(archive) as zf:
                for member in zf.namelist():
                    if member.endswith(".csv") and not (folder / Path(member).name).exists():
                        print(f"unpacking {member}")
                        (folder / Path(member).name).write_bytes(zf.read(member))
        found = {p.name: p for p in folder.rglob("*.csv")}
        for fname in files:
            if fname in found:
                manifest[f"{name}/{fname}"] = sha256(found[fname])
                print(f"ok       {name}/{fname}")
            else:
                missing.append(f"{name}/{fname}")
                print(f"MISSING  {name}/{fname}")
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if missing:
        print(f"\n{len(missing)} file(s) missing; see the instructions at the top of this script.")
        return 1
    print("\nAll files present. Fingerprints written to data/manifest.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
