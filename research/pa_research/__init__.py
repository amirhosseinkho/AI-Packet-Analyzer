"""Reproducible evaluation of the AI-Packet-Analyzer detectors and LLM explanations.

The application code under ``backend/app`` is imported, not copied, so every
experiment measures the detectors and prompts that the application ships.
"""

from pathlib import Path
import sys

RESEARCH_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = RESEARCH_DIR.parent
BACKEND_DIR = REPO_DIR / "backend"
DATA_DIR = RESEARCH_DIR / "data"
RESULTS_DIR = RESEARCH_DIR / "results"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# The 13 features produced by FlowStatistics.to_feature_vector(), in order.
APP_FEATURES = [
    "packet_count", "byte_count", "avg_packet_size",
    "duration_seconds", "packets_per_second", "bytes_per_second",
    "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
    "tcp_ack_count", "tcp_psh_count", "src_port", "dst_port",
]
TCP_FLAG_FEATURES = APP_FEATURES[6:11]
# Features that exist in both CIC-IDS2017 and UNSW-NB15 (UNSW has no per-flow flag counts).
COMMON_FEATURES = [f for f in APP_FEATURES if f not in TCP_FLAG_FEATURES]
