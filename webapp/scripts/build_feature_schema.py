from __future__ import annotations

import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parent


def find_project_file(relative_path: str) -> Path:
    direct = PROJECT_ROOT / relative_path
    if direct.exists():
        return direct
    matches = sorted(PROJECT_ROOT.glob(f"*/{relative_path}"))
    if matches:
        return matches[0]
    raise FileNotFoundError(f"Cannot find {relative_path} below {PROJECT_ROOT}")


@dataclass
class RunningStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def std(self) -> float:
        if self.count < 2:
            return 1.0
        value = math.sqrt(self.m2 / self.count)
        return value if value > 1e-12 else 1.0


def main() -> None:
    raw_path = find_project_file("mmd2025/feature_output/csv/dataset2.csv")
    merged_path = find_project_file(
        "mmd2025/feature_output/csv/Forest/merge_4_features.csv"
    )
    selected_path = find_project_file(
        "mmd2025/feature_output/csv/Forest/dataset2_Standardization_3_3.csv"
    )
    training_path = find_project_file(
        "mmd2025/feature_output/csv/Forest/"
        "dataset2_Standardization_3_3_malware15000x.csv"
    )
    output_path = APP_ROOT / "data" / "feature_schema.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with selected_path.open("r", encoding="utf-8", newline="") as handle:
        selected_header = next(csv.reader(handle))
    if not selected_header or selected_header[0] != "label":
        raise RuntimeError("The selected dataset must start with a label column")
    selected_features = selected_header[1:]

    with raw_path.open("r", encoding="utf-8", newline="") as handle:
        raw_header = next(csv.reader(handle))
    with merged_path.open("r", encoding="utf-8", newline="") as handle:
        merged_header = next(csv.reader(handle))

    raw_index = {name: index for index, name in enumerate(raw_header)}
    merged_index = {name: index for index, name in enumerate(merged_header)}
    stats = [RunningStats() for _ in selected_features]
    grouped_sources: dict[Path, list[tuple[int, int]]] = {raw_path: [], merged_path: []}
    approximated: list[str] = []

    for feature_number, feature in enumerate(selected_features):
        if feature in raw_index:
            grouped_sources[raw_path].append((feature_number, raw_index[feature]))
            continue

        # Two API clusters in the selected training columns are stored without
        # the "3-" prefix in merge_4_features.csv.
        unprefixed = feature[2:] if feature.startswith("3-") else feature
        if feature.startswith("3-") and unprefixed in merged_index:
            grouped_sources[merged_path].append(
                (feature_number, merged_index[unprefixed])
            )
            continue

        # Keep the feature in the model input. A zero/one default is recorded
        # explicitly so the approximation is auditable.
        approximated.append(feature)

    for source_path, source_columns in grouped_sources.items():
        if not source_columns:
            continue
        with source_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            next(reader)
            for row_number, row in enumerate(reader, start=2):
                if not row:
                    continue
                try:
                    for feature_number, column_index in source_columns:
                        stats[feature_number].add(float(row[column_index]))
                except (ValueError, IndexError) as exc:
                    raise RuntimeError(
                        f"Invalid value in {source_path.name} row {row_number}"
                    ) from exc

    categories = Counter(feature.split("-", 1)[0] for feature in selected_features)
    with raw_path.open("rb") as handle:
        sample_count = sum(1 for _ in handle) - 1
    with training_path.open("rb") as handle:
        training_sample_count = sum(1 for _ in handle) - 1

    schema = {
        "version": 1,
        "source_dataset": str(raw_path),
        "fallback_dataset": str(merged_path),
        "selected_dataset": str(selected_path),
        "training_dataset": str(training_path),
        "sample_count": sample_count,
        "training_sample_count": training_sample_count,
        "feature_count": len(selected_features),
        "modalities": {
            "behavioral": categories.get("1", 0) + categories.get("2", 0),
            "api": categories.get("3", 0),
            "opcode": categories.get("4", 0),
        },
        "features": selected_features,
        "mean": [round(stat.mean, 10) for stat in stats],
        "scale": [round(stat.std, 10) for stat in stats],
        "approximated_features": approximated,
    }
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    print(
        f"Built {output_path} from {schema['sample_count']} samples "
        f"with {schema['feature_count']} selected features."
    )


if __name__ == "__main__":
    main()

