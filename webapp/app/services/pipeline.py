from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from app.config import FEATURE_SCHEMA_PATH
from app.services.capabilities import dynamic_capability_snapshot
from app.services.extractor import extract_apk
from app.services.predictor import predictor
from app.services.risk_assessment import build_risk_assessment


_schema_cache: dict | None = None


def load_feature_schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        if not FEATURE_SCHEMA_PATH.exists():
            raise RuntimeError(
                "Feature schema is missing. Run "
                "`.venv\\Scripts\\python.exe webapp\\scripts\\build_feature_schema.py`."
            )
        _schema_cache = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _schema_cache


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _risk_presentation(malicious_probability: float) -> dict:
    if malicious_probability >= 0.85:
        return {
            "code": "malware",
            "label": "发现恶意特征",
            "risk_level": "高风险",
            "tone": "danger",
        }
    if malicious_probability >= 0.5:
        return {
            "code": "malware",
            "label": "疑似恶意软件",
            "risk_level": "中高风险",
            "tone": "warning",
        }
    if malicious_probability >= 0.3:
        return {
            "code": "benign",
            "label": "建议人工复核",
            "risk_level": "观察",
            "tone": "caution",
        }
    return {
        "code": "benign",
        "label": "未发现明显威胁",
        "risk_level": "低风险",
        "tone": "safe",
    }


def analyze_apk(
    analysis_id: str,
    apk_path: Path,
    original_filename: str,
    size_bytes: int,
    sha256: str,
    progress=None,
) -> dict:
    started = time.perf_counter()
    schema = load_feature_schema()

    def on_progress(value: int, message: str):
        if progress:
            progress(value, message)

    on_progress(5, "文件校验通过，准备静态分析")
    extraction = extract_apk(
        apk_path=apk_path,
        selected_features=schema["features"],
        progress=on_progress,
    )
    on_progress(84, "正在运行多模态融合模型")
    prediction = predictor.predict(
        extraction.vector,
        means=schema["mean"],
        scales=schema["scale"],
    )
    on_progress(96, "正在生成可解释分析报告")

    probability = prediction["malicious_probability"]
    verdict = _risk_presentation(probability)
    high_permissions = [
        item for item in extraction.permissions if item["risk"] == "高"
    ]
    medium_permissions = [
        item for item in extraction.permissions if item["risk"] == "中"
    ]

    evidence_summary: list[str] = []
    if high_permissions:
        evidence_summary.append(
            f"命中 {len(high_permissions)} 项高关注权限，例如 "
            + "、".join(item["short_name"] for item in high_permissions[:4])
        )
    if extraction.sensitive_apis:
        evidence_summary.append(
            f"扫描到 {sum(item['count'] for item in extraction.sensitive_apis)} 次敏感 API 调用"
        )
    if extraction.metadata["component_summary"]["receivers"]:
        evidence_summary.append(
            f"声明 {extraction.metadata['component_summary']['receivers']} 个广播接收器"
        )
    if not evidence_summary:
        evidence_summary.append("未发现显著的高关注权限或敏感调用组合")

    evidence_payload = {
        "summary": evidence_summary,
        "permissions": extraction.permissions,
        "permissions_high_count": len(high_permissions),
        "permissions_medium_count": len(medium_permissions),
        "components": extraction.components,
        "component_samples": extraction.component_samples,
        "sensitive_apis": extraction.sensitive_apis,
        "opcode_counts": extraction.opcode_counts,
        "modality_totals": extraction.modality_totals,
        "model_inputs": {
            "behavioral": sum(1 for value in extraction.vector[0:34] if value > 0),
            "api": sum(1 for value in extraction.vector[34:155] if value > 0),
            "opcode": sum(1 for value in extraction.vector[155:260] if value > 0),
        },
    }
    verdict_payload = {
        **verdict,
        "benign_probability": prediction["benign_probability"],
        "malicious_probability": probability,
        "confidence": max(
            prediction["benign_probability"],
            prediction["malicious_probability"],
        ),
        "score": round(probability * 100),
    }
    risk_assessment = build_risk_assessment(
        evidence_payload,
        verdict_payload,
        extraction.metadata,
    )
    dynamic_capability = dynamic_capability_snapshot()
    dynamic_stage_status = (
        "recommended"
        if verdict["code"] == "malware"
        else ("available" if dynamic_capability["status"] == "configured" else "optional")
    )

    processing_ms = round((time.perf_counter() - started) * 1000)
    result = {
        "id": analysis_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file": {
            "name": original_filename,
            "size_bytes": size_bytes,
            "sha256": sha256,
        },
        "apk": extraction.metadata,
        "verdict": verdict_payload,
        "evidence": evidence_payload,
        "risk_assessment": risk_assessment,
        "pipeline": {
            "analysis_mode": "static_multimodal",
            "stages": [
                {
                    "id": "static",
                    "label": "静态多模态分析",
                    "status": "completed",
                    "description": "Manifest、敏感 API 与 Opcode 已完成提取和推理。",
                },
                {
                    "id": "dynamic",
                    "label": "动态沙箱分析",
                    "status": dynamic_stage_status,
                    "description": (
                        "当前部署没有执行未知 APK。"
                        if dynamic_capability["status"] != "configured"
                        else "沙箱工具已配置，仍需在隔离环境中人工启动。"
                    ),
                },
                {
                    "id": "family",
                    "label": "恶意家族识别",
                    "status": "unavailable",
                    "description": "家族模型需要经过校验的动态行为特征。",
                },
            ],
            "dynamic_capability": dynamic_capability,
            "scope_note": (
                "本次报告完全来自静态分析。静态结果适合初筛，"
                "但无法观察到只有运行时才出现的联网、动态加载或规避行为。"
            ),
        },
        "model": {
            "name": "MMDynamic 多模态动态融合模型",
            "architecture": [34, 121, 105],
            "feature_count": schema["feature_count"],
            "device": prediction["device"],
            "modality_attention": prediction.get("modality_attention"),
            "explanation": (
                "模型综合行为特征、敏感 API 与 Opcode 三种模态，通过注意力交互和"
                "动态权重形成最终风险判断。"
            ),
        },
        "processing_ms": processing_ms,
        "warnings": extraction.warnings
        + (
            ["feature_schema_approximation"]
            if schema.get("approximated_features")
            else []
        ),
    }
    on_progress(100, "分析完成")
    return result

