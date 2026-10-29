from __future__ import annotations

from typing import Iterable


PERMISSION_LABELS = {
    "ACCESS_FINE_LOCATION": "精确定位",
    "ACCESS_COARSE_LOCATION": "大致位置",
    "CAMERA": "摄像头",
    "RECORD_AUDIO": "录音",
    "READ_PHONE_STATE": "读取电话状态",
    "CALL_PHONE": "拨打电话",
    "SEND_SMS": "发送短信",
    "RECEIVE_SMS": "接收短信",
    "READ_SMS": "读取短信",
    "READ_CONTACTS": "读取联系人",
    "WRITE_CONTACTS": "修改联系人",
    "READ_CALL_LOG": "读取通话记录",
    "WRITE_CALL_LOG": "修改通话记录",
    "REQUEST_INSTALL_PACKAGES": "安装其他应用",
    "SYSTEM_ALERT_WINDOW": "显示悬浮窗",
    "BIND_ACCESSIBILITY_SERVICE": "辅助功能控制",
    "PACKAGE_USAGE_STATS": "读取应用使用记录",
    "READ_EXTERNAL_STORAGE": "读取外部文件",
    "WRITE_EXTERNAL_STORAGE": "修改外部文件",
    "RECEIVE_BOOT_COMPLETED": "开机自启动",
    "FOREGROUND_SERVICE": "前台常驻",
    "WAKE_LOCK": "保持后台唤醒",
    "INTERNET": "访问网络",
    "GET_ACCOUNTS": "读取账户信息",
    "MANAGE_ACCOUNTS": "管理账户",
}


def _permission_set(evidence: dict) -> set[str]:
    return {
        item.get("short_name", "")
        for item in evidence.get("permissions", [])
        if item.get("short_name")
    }


def _api_index(evidence: dict) -> list[tuple[str, int]]:
    return [
        (str(item.get("name", "")).lower(), int(item.get("count", 0)))
        for item in evidence.get("sensitive_apis", [])
    ]


def _api_matches(
    api_index: list[tuple[str, int]], needles: Iterable[str]
) -> tuple[int, list[str]]:
    lowered = tuple(needle.lower() for needle in needles)
    matched = [
        (name, count)
        for name, count in api_index
        if any(needle in name for needle in lowered)
    ]
    return sum(count for _, count in matched), [name for name, _ in matched]


def _permission_signals(
    permissions: set[str], names: Iterable[str]
) -> list[str]:
    return [
        PERMISSION_LABELS.get(name, name.replace("_", " ").lower())
        for name in names
        if name in permissions
    ]


def _level(score: int) -> tuple[str, str]:
    if score >= 75:
        return "高", "danger"
    if score >= 50:
        return "较高", "danger"
    if score >= 25:
        return "中", "warning"
    if score > 0:
        return "低", "caution"
    return "未发现", "safe"


def _dimension(
    key: str,
    label: str,
    description: str,
    score: int,
    signals: list[str],
) -> dict:
    score = max(0, min(100, score))
    level, tone = _level(score)
    return {
        "key": key,
        "label": label,
        "description": description,
        "score": score,
        "level": level,
        "tone": tone,
        "signals": signals or ["未发现明显相关信号"],
    }


def build_risk_assessment(
    evidence: dict,
    verdict: dict,
    metadata: dict | None = None,
) -> dict:
    permissions = _permission_set(evidence)
    components = evidence.get("components", {})
    api = _api_index(evidence)
    metadata = metadata or {}

    sms_hits, _ = _api_matches(
        api, ("smsmanager", "sendtextmessage", "content://sms", "read_sms")
    )
    contact_hits, _ = _api_matches(
        api, ("contactscontract", "contactsservice")
    )
    location_hits, _ = _api_matches(
        api, ("locationmanager", "getlastknownlocation", "requestlocationupdates")
    )
    camera_hits, _ = _api_matches(
        api, ("android.hardware.camera", "camera.open", "cameramanager")
    )
    audio_hits, _ = _api_matches(
        api, ("mediarecorder", "audiorecord", "microphone")
    )
    network_hits, _ = _api_matches(
        api, ("urlconnection", "okhttp", "httpclient", "socket", "webview.loadurl")
    )
    dynamic_hits, _ = _api_matches(
        api, ("dexclassloader", "pathclassloader", "classloader.loadclass")
    )
    command_hits, _ = _api_matches(
        api, ("runtime.exec", "processbuilder")
    )
    install_hits, _ = _api_matches(
        api, ("packageinstaller", "installpackage")
    )

    sms_permissions = {"READ_SMS", "RECEIVE_SMS", "SEND_SMS"}
    contact_permissions = {"READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG"}
    location_permissions = {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"}
    media_permissions = {"CAMERA", "RECORD_AUDIO"}
    control_permissions = {
        "REQUEST_INSTALL_PACKAGES",
        "SYSTEM_ALERT_WINDOW",
        "BIND_ACCESSIBILITY_SERVICE",
        "PACKAGE_USAGE_STATS",
    }
    storage_permissions = {
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
    }
    persistence_permissions = {
        "RECEIVE_BOOT_COMPLETED",
        "FOREGROUND_SERVICE",
        "WAKE_LOCK",
    }

    privacy_score = 0
    privacy_signals: list[str] = []
    privacy_score += 28 if permissions & sms_permissions else 0
    privacy_signals += _permission_signals(permissions, sms_permissions)
    privacy_score += 22 if permissions & contact_permissions else 0
    privacy_signals += _permission_signals(permissions, contact_permissions)
    privacy_score += 22 if permissions & location_permissions else 0
    privacy_signals += _permission_signals(permissions, location_permissions)
    privacy_score += 22 if permissions & media_permissions else 0
    privacy_signals += _permission_signals(permissions, media_permissions)
    privacy_score += 12 if "READ_PHONE_STATE" in permissions else 0
    privacy_signals += _permission_signals(permissions, {"READ_PHONE_STATE"})
    privacy_score += 10 if permissions & storage_permissions else 0
    privacy_signals += _permission_signals(permissions, storage_permissions)
    if sms_hits or contact_hits or location_hits or camera_hits or audio_hits:
        privacy_score += 10
        privacy_signals.append("发现与上述数据相关的敏感 API 调用")

    finance_score = 0
    finance_signals: list[str] = []
    if "SEND_SMS" in permissions:
        finance_score += 42
    if {"READ_SMS", "RECEIVE_SMS"} & permissions:
        finance_score += 34
    if "CALL_PHONE" in permissions:
        finance_score += 18
    if {"GET_ACCOUNTS", "MANAGE_ACCOUNTS"} & permissions:
        finance_score += 18
    finance_signals += _permission_signals(
        permissions,
        {
            "SEND_SMS",
            "READ_SMS",
            "RECEIVE_SMS",
            "CALL_PHONE",
            "GET_ACCOUNTS",
            "MANAGE_ACCOUNTS",
        },
    )

    control_score = 0
    control_signals: list[str] = []
    weights = {
        "REQUEST_INSTALL_PACKAGES": 42,
        "BIND_ACCESSIBILITY_SERVICE": 42,
        "SYSTEM_ALERT_WINDOW": 26,
        "PACKAGE_USAGE_STATS": 12,
    }
    for permission, weight in weights.items():
        if permission in permissions:
            control_score += weight
    control_signals += _permission_signals(permissions, weights)
    if install_hits or command_hits or dynamic_hits:
        control_score += 18
        control_signals.append("发现安装、命令执行或动态加载相关 API")

    persistence_score = 0
    persistence_signals: list[str] = []
    persistence_score += 30 if "RECEIVE_BOOT_COMPLETED" in permissions else 0
    persistence_score += 20 if "FOREGROUND_SERVICE" in permissions else 0
    persistence_score += 12 if "WAKE_LOCK" in permissions else 0
    persistence_signals += _permission_signals(permissions, persistence_permissions)
    receiver_count = int(components.get("receivers", 0))
    service_count = int(components.get("services", 0))
    if receiver_count >= 5:
        persistence_score += 18
        persistence_signals.append(f"声明了 {receiver_count} 个广播接收器")
    if service_count >= 8:
        persistence_score += 10
        persistence_signals.append(f"声明了 {service_count} 个后台服务")

    exfil_score = 0
    exfil_signals: list[str] = []
    if "INTERNET" in permissions:
        exfil_score += 18
        exfil_signals.append("具备网络访问能力")
    if storage_permissions & permissions:
        exfil_score += 18
        exfil_signals += _permission_signals(permissions, storage_permissions)
    if permissions & (
        sms_permissions
        | contact_permissions
        | location_permissions
        | media_permissions
    ):
        exfil_score += 24
        exfil_signals.append("同时具备敏感数据访问能力")
    if network_hits:
        exfil_score += min(25, 10 + network_hits // 20)
        exfil_signals.append("发现网络通信相关敏感 API")

    dimensions = [
        _dimension(
            "privacy",
            "隐私与数据访问",
            "应用能够接触哪些个人信息和敏感数据。",
            privacy_score,
            privacy_signals,
        ),
        _dimension(
            "account_finance",
            "账号与资金风险",
            "短信、电话和账户权限可能影响登录验证或产生费用。",
            finance_score,
            finance_signals,
        ),
        _dimension(
            "device_control",
            "设备控制能力",
            "安装应用、辅助功能和悬浮窗等能力可能影响用户操作。",
            control_score,
            control_signals,
        ),
        _dimension(
            "persistence",
            "后台驻留能力",
            "开机启动、后台服务与广播接收器可能让应用持续运行。",
            persistence_score,
            persistence_signals,
        ),
        _dimension(
            "data_exfiltration",
            "数据外传可能性",
            "网络能力与敏感数据访问组合可能带来数据上传风险。",
            exfil_score,
            exfil_signals,
        ),
    ]

    scenarios: list[dict] = []

    def add_scenario(
        title: str,
        description: str,
        weight: int,
        signals: list[str],
        tone: str = "warning",
    ) -> None:
        if weight > 0:
            scenarios.append(
                {
                    "title": title,
                    "description": description,
                    "weight": weight,
                    "level": "高风险暴露" if weight >= 70 else "需关注",
                    "tone": "danger" if weight >= 70 else tone,
                    "signals": signals,
                }
            )

    if permissions & sms_permissions or sms_hits:
        add_scenario(
            "可能读取、拦截或发送短信",
            "如果代码实际使用这些能力，应用可能获取短信验证码、产生短信费用，或利用短信进行进一步传播。",
            90,
            _permission_signals(permissions, sms_permissions)
            + ([f"相关 API 调用 {sms_hits} 次"] if sms_hits else []),
            "danger",
        )
    if permissions & contact_permissions or contact_hits:
        add_scenario(
            "可能收集联系人或通话信息",
            "应用可能读取联系人、通话记录等信息，用于用户画像、关系链分析或上传到远程服务器。",
            64,
            _permission_signals(permissions, contact_permissions)
            + ([f"相关 API 调用 {contact_hits} 次"] if contact_hits else []),
        )
    if permissions & location_permissions or location_hits:
        add_scenario(
            "可能追踪设备位置",
            "与网络权限同时存在时，位置信息可能被持续记录、关联到设备标识并上传。",
            68,
            _permission_signals(permissions, location_permissions)
            + ([f"相关 API 调用 {location_hits} 次"] if location_hits else []),
        )
    if permissions & media_permissions or camera_hits or audio_hits:
        add_scenario(
            "可能调用摄像头或麦克风",
            "若用户授予权限且代码存在相应调用，应用可能采集照片、视频或环境录音。",
            76,
            _permission_signals(permissions, media_permissions)
            + (
                [f"相关 API 调用 {camera_hits + audio_hits} 次"]
                if camera_hits or audio_hits
                else []
            ),
            "danger",
        )
    if (
        "SYSTEM_ALERT_WINDOW" in permissions
        and "BIND_ACCESSIBILITY_SERVICE" in permissions
    ):
        add_scenario(
            "可能覆盖界面并诱导用户操作",
            "悬浮窗与辅助功能组合可能被用于遮挡真实界面、读取页面内容、代替用户点击或诱导授权。",
            95,
            _permission_signals(
                permissions,
                {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"},
            ),
            "danger",
        )
    if "REQUEST_INSTALL_PACKAGES" in permissions or install_hits:
        add_scenario(
            "可能安装或推广其他应用",
            "应用可能请求安装额外 APK，造成广告软件扩散、恶意组件替换或绕过应用商店审核。",
            82,
            _permission_signals(permissions, {"REQUEST_INSTALL_PACKAGES"})
            + ([f"相关 API 调用 {install_hits} 次"] if install_hits else []),
            "danger",
        )
    if persistence_score >= 25:
        add_scenario(
            "可能在后台持续运行",
            "开机自启动、广播接收器或前台服务可能让应用在用户未主动打开时继续工作，并定期执行任务。",
            min(78, 40 + persistence_score // 3),
            persistence_signals,
        )
    if exfil_score >= 50:
        add_scenario(
            "可能将本地数据发送到远程服务",
            "网络权限与短信、位置、联系人、文件访问能力组合后，敏感数据存在被上传或外传的可能。",
            min(75, exfil_score),
            exfil_signals,
        )
    if dynamic_hits or command_hits:
        add_scenario(
            "可能动态加载代码或执行命令",
            "应用可能从外部加载额外代码，或在设备上执行命令，使实际行为超出 APK 静态代码可见范围。",
            73,
            (
                [f"动态加载相关 API 调用 {dynamic_hits} 次"]
                if dynamic_hits
                else []
            )
            + (
                [f"命令执行相关 API 调用 {command_hits} 次"]
                if command_hits
                else []
            ),
        )

    scenarios.sort(key=lambda item: item["weight"], reverse=True)
    scenarios = scenarios[:5]
    if not scenarios:
        if verdict.get("code") == "malware":
            scenarios.append(
                {
                    "title": "未命中明确的预设滥用路径",
                    "description": (
                        "当前证据中没有触发短信、位置、设备控制等固定组合规则，但模型仍发现代码结构"
                        "与恶意样本相似，因此需要进一步动态验证。"
                    ),
                    "weight": 50,
                    "level": "需进一步验证",
                    "tone": "warning",
                    "signals": ["模型风险较高，但公开规则未发现明确滥用组合"],
                }
            )
        else:
            scenarios.append(
                {
                    "title": "未发现明确的预设滥用路径",
                    "description": (
                        "权限、API 和代码结构中没有发现明显的敏感能力组合。"
                        "这降低了风险，但无法排除正常权限被滥用或隐藏代码的情况。"
                    ),
                    "weight": 0,
                    "level": "未发现",
                    "tone": "safe",
                    "signals": ["权限与 API 组合未命中重点风险规则"],
                }
            )

    malicious_probability = float(verdict.get("malicious_probability", 0))
    recommendations: list[dict] = []

    if malicious_probability >= 0.5:
        recommendations.append(
            {
                "priority": "立即",
                "title": "先不要安装或运行",
                "description": "把文件留在隔离目录中，不要点击安装，也不要授予任何权限。",
            }
        )
        recommendations.append(
            {
                "priority": "优先",
                "title": "核实来源、开发者与签名",
                "description": "确认下载渠道是否为官方网站或可信应用商店，并请专业人员核对签名。",
            }
        )
    else:
        recommendations.append(
            {
                "priority": "首先",
                "title": "确认下载来源可信",
                "description": "只从官方网站或可信应用商店安装；来源不明的 APK 不应因为“低风险”而直接使用。",
            }
        )

    if permissions & sms_permissions or finance_score >= 50:
        recommendations.append(
            {
                "priority": "防止损失",
                "title": "保护短信验证码与支付账号",
                "description": (
                    "如果已经安装，暂停短信读取或发送权限，检查近期验证码、支付和登录记录；"
                    "发现异常时联系运营商和银行。"
                ),
            }
        )
    if permissions & control_permissions:
        recommendations.append(
            {
                "priority": "权限",
                "title": "不要开启辅助功能、悬浮窗或未知来源安装",
                "description": "这些能力会显著扩大应用对界面的控制和安装其他软件的能力。",
            }
        )
    if persistence_score >= 25:
        recommendations.append(
            {
                "priority": "设备检查",
                "title": "检查自启动、后台运行和设备管理状态",
                "description": "如果应用已经安装，检查并关闭不必要的自启动、后台服务和设备管理权限。",
            }
        )
    if malicious_probability >= 0.5 or any(
        item["score"] >= 75 for item in dimensions
    ):
        recommendations.append(
            {
                "priority": "进一步研判",
                "title": "提交沙箱或专业人员复核",
                "description": "静态分析不会运行样本。需要动态分析确认是否联网、读取数据、下载代码或执行其他行为。",
            }
        )
    if permissions & (
        storage_permissions | location_permissions | media_permissions
    ):
        recommendations.append(
            {
                "priority": "日常使用",
                "title": "只授予与应用功能直接相关的权限",
                "description": "例如手电筒应用通常不需要短信、联系人或通话记录权限。",
            }
        )
    if len(recommendations) < 3:
        recommendations.append(
            {
                "priority": "通用建议",
                "title": "保持系统和安全软件更新",
                "description": "即使本次未发现明显风险，也应避免安装来源不明或签名异常的应用。",
            }
        )

    return {
        "dimensions": dimensions,
        "scenarios": scenarios,
        "recommendations": recommendations[:5],
        "scope_note": (
            "风险画像描述的是应用“具备多大能力以及可能发生什么”，不等同于这些行为已经发生。"
            "最终判断应结合应用用途、签名、来源和动态行为。"
        ),
    }

