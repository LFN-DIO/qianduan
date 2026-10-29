# MMD Sentinel Web

多模态 Android 恶意软件静态分析系统的 Web 界面。界面负责 APK 上传、异步分析进度、可解释结果、历史记录和模型说明；后端复用项目现有的 `MMDynamic` 模型。

## 报告能力

- 通俗总结：面向非专业用户解释结论、依据和下一步行动。
- 风险画像：展示隐私、账号资金、设备控制、后台驻留和数据外传五个维度。
- 场景推演：根据权限和 API 组合说明应用“可能发生什么”，避免把可能性写成既成事实。
- 可点击详情：风险、权限、敏感 API 和模型证据都可展开阅读。
- 模型解释：展示 260 维输入构成、真实跨模态注意力权重和判读方法。
- 报告输出：支持复制摘要、导出 JSON、浏览器打印或另存为 PDF。
- MobSF 风格报告：最近扫描、应用概览、安全问题、Manifest、代码/API 和模型解释分栏展示。

## 两阶段分析状态

当前部署默认只运行静态多模态分析。动态沙箱、动态行为特征和恶意家族识别
会在报告中明确标记为未启用，不会用静态数据伪造动态结论。

可以通过环境变量描述独立的动态分析环境：

```powershell
$env:MMD_DYNAMIC_ENABLED = "true"
$env:MMD_DYNAMIC_AVD = "malware_sandbox"
$env:MMD_ADB_PATH = "C:\Android\platform-tools\adb.exe"
$env:MMD_EMULATOR_PATH = "C:\Android\emulator\emulator.exe"
```

`/api/capabilities` 会返回工具是否齐全、缺少项和安全前提。即使工具齐全，
当前代码仍不会自动执行未知 APK；动态执行必须放在专用隔离主机中，
并通过独立的后端服务与样本授权流程接入。

## 快速启动

```powershell
cd webapp
.\run.ps1
```

浏览器打开 `http://127.0.0.1:8000`。

也可以直接双击 `run.bat`。首次启动需要安装 PyTorch、Androguard 等依赖，
下载体积较大；后续启动会直接复用 `.venv`。

首次运行会检查虚拟环境和依赖。如果依赖未安装，可手动执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\build_feature_schema.py
```

核心环境自检：

```powershell
.\.venv\Scripts\python.exe scripts\selftest.py
```

使用真实 APK 进行完整自检：

```powershell
.\.venv\Scripts\python.exe scripts\selftest.py "C:\path\to\sample.apk"
```

## 安全边界

- 只接受 `.apk` 文件，限制文件大小，并检查 ZIP/APK 文件头。
- 拒绝文件数量或解压体积异常的压缩包，并校验 AndroidManifest.xml。
- APK 仅用于解析，绝不会被执行。
- 上传文件分析结束后立即删除，历史记录仅保存分析摘要和结果。
- 检测结论用于辅助安全研判，不替代人工审核或完整沙箱分析。

