from __future__ import annotations

import os
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
WEBAPP_ROOT = APP_DIR.parent
PROJECT_ROOT = WEBAPP_ROOT.parent


def _find_mmd_root() -> Path:
    override = os.getenv("MMD_ROOT")
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.exists():
            return candidate

    direct = PROJECT_ROOT / "mmd2025"
    if direct.exists():
        return direct

    matches = sorted(PROJECT_ROOT.glob("*/mmd2025"))
    if matches:
        return matches[0]

    raise RuntimeError(
        "Cannot locate mmd2025. Set the MMD_ROOT environment variable to the "
        "directory containing original/, feature_output/, and mmdynamics-main/."
    )


MMD_ROOT = _find_mmd_root()
CHECKPOINT_PATH = Path(
    os.getenv(
        "MMD_CHECKPOINT",
        MMD_ROOT / "mmdynamics-main" / "model" / "CIC" / "checkpoint.pt",
    )
).expanduser()
MODEL_SOURCE_PATH = MMD_ROOT / "mmdynamics-main" / "model7.py"
RAW_DATASET_PATH = MMD_ROOT / "feature_output" / "csv" / "dataset2.csv"
SELECTED_DATASET_PATH = (
    MMD_ROOT
    / "feature_output"
    / "csv"
    / "Forest"
    / "dataset2_Standardization_3_3.csv"
)
API_EMBEDDING_PATH = MMD_ROOT / "original" / "method_cluster_mapping_tr200_2000.pkl"
SENSITIVE_API_PATH = MMD_ROOT / "original" / "sensitive_name.txt"

DATA_DIR = WEBAPP_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
FEATURE_SCHEMA_PATH = DATA_DIR / "feature_schema.json"
HISTORY_DB_PATH = DATA_DIR / "history.db"
STATIC_DIR = APP_DIR / "static"
os.environ.setdefault("MPLCONFIGDIR", str(DATA_DIR / ".matplotlib"))

MAX_UPLOAD_BYTES = int(os.getenv("MMD_MAX_UPLOAD_BYTES", 500 * 1024 * 1024))
MAX_ARCHIVE_ENTRIES = int(os.getenv("MMD_MAX_ARCHIVE_ENTRIES", 50000))
MAX_UNCOMPRESSED_BYTES = int(
    os.getenv("MMD_MAX_UNCOMPRESSED_BYTES", 2 * 1024 * 1024 * 1024)
)
MAX_HISTORY_ROWS = 100

DYNAMIC_ANALYSIS_ENABLED = os.getenv("MMD_DYNAMIC_ENABLED", "").lower() in {
    "1",
    "true",
    "yes",
}
DYNAMIC_AVD_NAME = os.getenv("MMD_DYNAMIC_AVD", "").strip()
ADB_PATH = os.getenv("MMD_ADB_PATH", "adb")
EMULATOR_PATH = os.getenv("MMD_EMULATOR_PATH", "emulator")

