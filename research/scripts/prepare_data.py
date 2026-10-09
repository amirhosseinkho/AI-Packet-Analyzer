"""Download and verify the datasets used in research/.

    python scripts/prepare_data.py            # both datasets (about 490 MB)
    python scripts/prepare_data.py --only cic

Sources (public Hugging Face mirrors, no account needed):

  CIC-IDS2017  huggingface.co/datasets/bvsam/cic-ids-2017, folder traffic_labels/
               The official TrafficLabelling (GeneratedLabelledFlows) CSVs, converted
               to Parquet with timestamps normalised to UTC. 8 files, about 306 MB.
               Official source (registration form):
               https://www.unb.ca/cic/datasets/ids-2017.html

  UNSW-NB15    huggingface.co/datasets/rdpahalavan/UNSW-NB15, Network-Flows/UNSW_Flow.parquet
               The UNSW-NB15 flow table with the original 49 features, re-derived
               by the mirror's authors and linked to the packets. 2,059,415 flows
               (the four official CSVs have 2,540,047, many of them duplicates).
               183 MB. Official source:
               https://research.unsw.edu.au/projects/unsw-nb15-dataset

The official CSVs also work: put them in data/cic-ids2017/ or data/unsw-nb15/
and the loaders will use them instead.

After downloading, the script checks the label counts against the published
figures and writes the SHA-256 of every file to data/manifest.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import pandas as pd

DATA = Path(__file__).resolve().parents[1] / "data"
HF = "https://huggingface.co/datasets"

CIC_FILES = [
    "Monday-WorkingHours", "Tuesday-WorkingHours", "Wednesday-workingHours",
    "Thursday-WorkingHours-Morning-WebAttacks", "Thursday-WorkingHours-Afternoon-Infilteration",
    "Friday-WorkingHours-Morning", "Friday-WorkingHours-Afternoon-PortScan",
    "Friday-WorkingHours-Afternoon-DDos",
]
DOWNLOADS = {
    "cic": [(f"{HF}/bvsam/cic-ids-2017/resolve/main/traffic_labels/{f}.pcap_ISCX.csv.parquet",
             DATA / "cic-ids2017" / f"{f}.pcap_ISCX.csv.parquet") for f in CIC_FILES],
    "unsw": [(f"{HF}/rdpahalavan/UNSW-NB15/resolve/main/Network-Flows/UNSW_Flow.parquet",
              DATA / "unsw-nb15" / "UNSW_Flow.parquet")],
}

# Published CIC-IDS2017 label counts (Sharafaldin et al., 2018; identical in both CSV releases).
CIC_EXPECTED = {
    "BENIGN": 2273097, "DoS Hulk": 231073, "PortScan": 158930, "DDoS": 128027,
    "DoS GoldenEye": 10293, "FTP-Patator": 7938, "SSH-Patator": 5897, "DoS slowloris": 5796,
    "DoS Slowhttptest": 5499, "Bot": 1966, "Infiltration": 36, "Heartbleed": 11,
}
UNSW_EXPECTED_ROWS = 2_059_415


def download(url: str, target: Path) -> None:
    if target.exists() and target.stat().st_size > 0:
        print(f"exists   {target.relative_to(DATA)}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    print(f"download {target.relative_to(DATA)}")
    for attempt in range(3):
        try:
            urllib.request.urlretrieve(url, tmp)
            tmp.replace(target)
            return
        except OSError as exc:
            print(f"  attempt {attempt + 1} failed: {exc}")
    raise SystemExit(f"Could not download {url}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_cic() -> bool:
    labels = pd.concat(pd.read_parquet(p, columns=["Label"]) for _, p in DOWNLOADS["cic"])["Label"].dropna()
    counts = labels.value_counts()
    ok = all(counts.get(k, 0) == v for k, v in CIC_EXPECTED.items())
    print(f"CIC-IDS2017: {len(labels):,} labelled flows; label counts match the published figures: {ok}")
    return ok


def verify_unsw() -> bool:
    n = len(pd.read_parquet(DOWNLOADS["unsw"][0][1], columns=["binary_label"]))
    print(f"UNSW-NB15: {n:,} flows (expected {UNSW_EXPECTED_ROWS:,})")
    return n == UNSW_EXPECTED_ROWS


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", choices=list(DOWNLOADS))
    args = ap.parse_args()
    names = [args.only] if args.only else list(DOWNLOADS)

    manifest_path = DATA / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    for name in names:
        for url, target in DOWNLOADS[name]:
            download(url, target)
            manifest[str(target.relative_to(DATA)).replace("\\", "/")] = {"url": url, "sha256": sha256(target)}
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ok = all({"cic": verify_cic, "unsw": verify_unsw}[n]() for n in names)
    print("Fingerprints written to data/manifest.json." if ok else "Verification FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
