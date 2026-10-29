from __future__ import annotations

import pickle
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.config import API_EMBEDDING_PATH, SENSITIVE_API_PATH


ProgressCallback = Callable[[int, str], None]


@dataclass
class ExtractionResult:
    vector: list[float]
    metadata: dict
    permissions: list[dict]
    components: dict[str, int]
    component_samples: dict[str, list[str]]
    sensitive_apis: list[dict]
    opcode_counts: dict[str, int]
    modality_totals: dict[str, int]
    warnings: list[str]


PERMISSION_RULES: dict[str, tuple[str, str]] = {
    "SEND_SMS": ("高", "可发送短信，可能产生费用或进行传播"),
    "RECEIVE_SMS": ("高", "可读取/拦截短信，可能绕过双因素认证"),
    "READ_SMS": ("高", "可读取短信内容，存在隐私泄露风险"),
    "CALL_PHONE": ("高", "可直接拨打电话"),
    "READ_CONTACTS": ("高", "可读取联系人信息"),
    "WRITE_CONTACTS": ("高", "可修改联系人信息"),
    "READ_CALL_LOG": ("高", "可读取通话记录"),
    "WRITE_CALL_LOG": ("高", "可修改通话记录"),
    "READ_PHONE_STATE": ("高", "可获取设备与电话状态信息"),
    "RECORD_AUDIO": ("高", "可录制麦克风音频"),
    "CAMERA": ("高", "可调用摄像头"),
    "ACCESS_FINE_LOCATION": ("高", "可获取精确地理位置"),
    "ACCESS_COARSE_LOCATION": ("中", "可获取粗略地理位置"),
    "SYSTEM_ALERT_WINDOW": ("高", "可在其他应用上方显示悬浮窗口"),
    "REQUEST_INSTALL_PACKAGES": ("高", "可请求安装其他应用"),
    "BIND_ACCESSIBILITY_SERVICE": ("高", "可访问界面内容并模拟用户操作"),
    "PACKAGE_USAGE_STATS": ("高", "可读取应用使用情况"),
    "READ_EXTERNAL_STORAGE": ("中", "可读取外部存储文件"),
    "WRITE_EXTERNAL_STORAGE": ("中", "可写入或修改外部存储文件"),
    "RECEIVE_BOOT_COMPLETED": ("中", "可在设备开机后自动启动"),
    "FOREGROUND_SERVICE": ("中", "可持续运行前台服务"),
    "INTERNET": ("低", "可访问网络，属于常见基础权限"),
    "ACCESS_NETWORK_STATE": ("低", "可读取网络连接状态"),
    "WAKE_LOCK": ("低", "可阻止设备进入休眠"),
    "VIBRATE": ("低", "可控制设备振动"),
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _android_name(element) -> str | None:
    for key, value in element.attrib.items():
        if key == "name" or key.endswith("}name"):
            return value
    return None


def _permission_label(permission: str) -> str:
    return permission.rsplit(".", 1)[-1]


def _permission_evidence(permissions: list[str]) -> list[dict]:
    items: list[dict] = []
    for permission in sorted(set(permissions)):
        short_name = _permission_label(permission)
        risk, reason = PERMISSION_RULES.get(short_name, ("低", "普通权限"))
        items.append(
            {
                "name": permission,
                "short_name": short_name,
                "risk": risk,
                "reason": reason,
            }
        )
    risk_order = {"高": 0, "中": 1, "低": 2}
    return sorted(items, key=lambda item: (risk_order[item["risk"]], item["name"]))


def _load_androguard():
    try:
        from loguru import logger

        logger.remove()
        logger.add(lambda _: None, level="WARNING")
    except ImportError:
        pass

    try:
        from androguard.core.apk import APK
    except ImportError:
        from androguard.core.bytecodes.apk import APK

    try:
        from androguard.core.dex import DEX
    except ImportError:
        from androguard.core.bytecodes.dvm import DalvikVMFormat

        DEX = DalvikVMFormat
    return APK, DEX


def _load_api_mapping() -> tuple[dict[str, int], set[str]]:
    with API_EMBEDDING_PATH.open("rb") as handle:
        raw_mapping = pickle.load(handle)
    with SENSITIVE_API_PATH.open("r", encoding="utf-8") as handle:
        sensitive = {line.strip() for line in handle if line.strip()}

    mapping = {
        api_name: int(cluster)
        for api_name, cluster in raw_mapping.items()
        if api_name in sensitive
    }
    return mapping, sensitive


def _extract_manifest_components(manifest) -> tuple[dict[str, Counter], dict[str, list[str]]]:
    counts = {
        "activity": Counter(),
        "service": Counter(),
        "receiver": Counter(),
        "provider": Counter(),
        "intent": Counter(),
    }
    samples = {name: [] for name in counts}
    if manifest is None:
        return counts, samples

    for element in manifest.iter():
        tag = _local_name(element.tag)
        if tag in {"activity", "service", "receiver", "provider"}:
            name = _android_name(element)
            if name:
                counts[tag][name] += 1
                if len(samples[tag]) < 30:
                    samples[tag].append(name)
        elif tag == "action":
            name = _android_name(element)
            if name:
                counts["intent"][name] += 1
                if len(samples["intent"]) < 30:
                    samples["intent"].append(name)
    return counts, samples


def _normalise_api_name(output: str) -> str | None:
    if "L" not in output:
        return None
    match = re.search(r"L([^;]+);", output)
    if not match:
        return None
    class_name = match.group(1).replace("/", ".")
    method_part = output[match.end() :]
    method_match = re.match(r"->([^(]+)", method_part)
    if method_match:
        return f"{class_name}.{method_match.group(1)}"
    return class_name


def extract_apk(
    apk_path: Path,
    selected_features: list[str],
    progress: ProgressCallback | None = None,
) -> ExtractionResult:
    def report(value: int, message: str) -> None:
        if progress:
            progress(max(0, min(100, value)), message)

    APK, DEX = _load_androguard()
    api_mapping, sensitive_names = _load_api_mapping()
    warnings: list[str] = []

    report(8, "正在校验 APK 结构")
    apk = APK(str(apk_path))
    permissions = list(dict.fromkeys(apk.get_permissions() or []))

    report(18, "正在解析 AndroidManifest")
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception as exc:
        manifest = None
        warnings.append(f"Manifest XML 解析不完整：{exc}")
    component_counts, component_samples = _extract_manifest_components(manifest)

    metadata = {
        "package_name": apk.get_package() or "未知",
        "app_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "main_activity": None,
    }
    for field, getter in (
        ("app_name", "get_app_name"),
        ("version_name", "get_version_name"),
        ("version_code", "get_version_code"),
        ("min_sdk", "get_min_sdk_version"),
        ("target_sdk", "get_target_sdk_version"),
        ("main_activity", "get_main_activity"),
    ):
        try:
            metadata[field] = getattr(apk, getter)()
        except Exception:
            metadata[field] = None

    if manifest is not None:
        for element in manifest.iter():
            if _local_name(element.tag) != "manifest":
                continue
            for key, value in element.attrib.items():
                attribute = key.rsplit("}", 1)[-1].lower()
                if attribute == "versionname" and not metadata["version_name"]:
                    metadata["version_name"] = value
                elif attribute == "versioncode" and not metadata["version_code"]:
                    metadata["version_code"] = value
                elif attribute == "package" and metadata["package_name"] == "未知":
                    metadata["package_name"] = value
            break

    raw_features: Counter[str] = Counter()
    for permission in permissions:
        raw_features[f"1-{permission}"] += 1
    for component_type in ("activity", "service", "receiver", "provider", "intent"):
        for name, count in component_counts[component_type].items():
            raw_features[f"2-{name}"] += count

    report(30, "正在扫描 DEX 调用与 Opcode")
    opcode_counts: Counter[str] = Counter()
    sensitive_api_counts: Counter[str] = Counter()
    dex_count = 0
    instruction_count = 0

    with zipfile.ZipFile(apk_path) as archive:
        dex_names = sorted(
            name
            for name in archive.namelist()
            if name.startswith("classes") and name.endswith(".dex")
        )
        for dex_position, dex_name in enumerate(dex_names, start=1):
            dex_count += 1
            dex = DEX(archive.read(dex_name))
            for cls in dex.get_classes():
                for method in cls.get_methods():
                    for instruction in method.get_instructions():
                        instruction_count += 1
                        opcode = instruction.get_name()
                        if not opcode:
                            continue
                        opcode = str(opcode)
                        opcode_counts[opcode] += 1

                        output = instruction.get_output()
                        if not output or not (
                            "Lcom" in output or "Landroid" in output
                        ):
                            continue
                        api_name = _normalise_api_name(str(output))
                        if not api_name or api_name not in sensitive_names:
                            continue
                        sensitive_api_counts[api_name] += 1
                        cluster = api_mapping.get(api_name)
                        if cluster is not None:
                            raw_features[f"3-{cluster}"] += 1

            progress_value = 30 + int((dex_position / max(1, len(dex_names))) * 45)
            report(progress_value, f"正在分析 DEX {dex_position}/{len(dex_names)}")

    for opcode, count in opcode_counts.items():
        raw_features[f"4-{opcode}"] += count

    if not dex_names:
        warnings.append("APK 中未找到标准 classes*.dex 文件。")

    vector = [float(raw_features.get(feature, 0)) for feature in selected_features]
    component_summary = {
        "activities": sum(component_counts["activity"].values()),
        "services": sum(component_counts["service"].values()),
        "receivers": sum(component_counts["receiver"].values()),
        "providers": sum(component_counts["provider"].values()),
        "intents": sum(component_counts["intent"].values()),
    }
    modality_totals = {
        "behavioral": sum(vector[:34]),
        "api": int(sum(vector[34:155])),
        "opcode": int(sum(vector[155:])),
    }
    sensitive_apis = [
        {"name": name, "count": count}
        for name, count in sensitive_api_counts.most_common(30)
    ]

    metadata.update(
        {
            "permissions_count": len(permissions),
            "component_summary": component_summary,
            "dex_count": dex_count,
            "instruction_count": instruction_count,
        }
    )
    report(80, "静态特征提取完成")
    return ExtractionResult(
        vector=vector,
        metadata=metadata,
        permissions=_permission_evidence(permissions),
        components=component_summary,
        component_samples=component_samples,
        sensitive_apis=sensitive_apis,
        opcode_counts=dict(opcode_counts.most_common(40)),
        modality_totals=modality_totals,
        warnings=warnings,
    )

