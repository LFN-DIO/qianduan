from __future__ import annotations

import sys
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from app.services.pipeline import analyze_apk, load_feature_schema, sha256_file
from app.services.predictor import predictor
from app.services.risk_assessment import build_risk_assessment


def main() -> None:
    schema = load_feature_schema()
    assert schema["feature_count"] == 260
    assert schema["modalities"] == {"behavioral": 34, "api": 121, "opcode": 105}
    predictor.warm_up()
    smoke_prediction = predictor.predict(
        [0.0] * schema["feature_count"],
        schema["mean"],
        schema["scale"],
    )
    assert 0.0 <= smoke_prediction["malicious_probability"] <= 1.0
    assert len(smoke_prediction.get("modality_attention") or []) == 3
    assert abs(sum(smoke_prediction["modality_attention"]) - 1.0) < 1e-4
    risk_check = build_risk_assessment(
        {
            "permissions": [{"short_name": "READ_SMS"}, {"short_name": "INTERNET"}],
            "components": {},
            "sensitive_apis": [],
        },
        {"code": "malware", "malicious_probability": 0.9},
        {},
    )
    assert len(risk_check["dimensions"]) == 5
    assert risk_check["scenarios"]
    assert risk_check["recommendations"]
    print(
        "Core self-test passed: "
        f"{schema['feature_count']} features, "
        f"{schema.get('training_sample_count', schema['sample_count'])} training rows, "
        f"model on {smoke_prediction['device']}."
    )

    if len(sys.argv) > 1:
        apk_path = Path(sys.argv[1]).resolve()
        if not apk_path.exists():
            raise FileNotFoundError(apk_path)
        result = analyze_apk(
            analysis_id="selftest",
            apk_path=apk_path,
            original_filename=apk_path.name,
            size_bytes=apk_path.stat().st_size,
            sha256=sha256_file(apk_path),
        )
        print(
            f"APK self-test passed: {result['verdict']['label']}, "
            f"risk={result['verdict']['score']}, "
            f"package={result['apk']['package_name']}"
        )


if __name__ == "__main__":
    main()

