from __future__ import annotations

import importlib.util
import shutil

from app.config import (
    ADB_PATH,
    DYNAMIC_ANALYSIS_ENABLED,
    DYNAMIC_AVD_NAME,
    EMULATOR_PATH,
)


def _tool_status(configured_path: str) -> dict:
    resolved = shutil.which(configured_path)
    return {
        "configured": configured_path,
        "available": resolved is not None,
        "resolved_path": resolved,
    }


def dynamic_capability_snapshot() -> dict:
    adb = _tool_status(ADB_PATH)
    emulator = _tool_status(EMULATOR_PATH)
    frida_python = importlib.util.find_spec("frida") is not None
    missing: list[str] = []
    if not adb["available"]:
        missing.append("adb")
    if not emulator["available"]:
        missing.append("Android emulator")
    if not frida_python:
        missing.append("Frida Python package")
    if not DYNAMIC_AVD_NAME:
        missing.append("MMD_DYNAMIC_AVD")

    if not DYNAMIC_ANALYSIS_ENABLED:
        status = "disabled"
        reason = (
            "动态分析未启用。当前部署仅运行经过校验的静态多模态分析。"
        )
    elif missing:
        status = "unavailable"
        reason = "已允许动态分析，但缺少 adb、Android 模拟器、Frida 或 AVD 配置。"
    else:
        status = "configured"
        reason = (
            "沙箱工具已配置，但仍须在独立的 Android 安全主机中由分析人员明确启动。"
        )

    return {
        "status": status,
        "enabled": DYNAMIC_ANALYSIS_ENABLED,
        "missing": missing,
        "tooling": {
            "adb": adb,
            "emulator": emulator,
            "frida_python": frida_python,
        },
        "avd_name": DYNAMIC_AVD_NAME or None,
        "execution_allowed": False,
        "reason": reason,
        "safety_requirements": [
            "专用且隔离的虚拟机或分析主机",
            "禁止挂载宿主机文件目录",
            "限制或关闭样本外联网络",
            "每个样本执行后恢复模拟器快照",
            "设置强制的执行超时和终止机制",
            "确认已获得样本分析授权",
        ],
    }

