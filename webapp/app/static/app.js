const state = {
  file: null,
  currentResult: null,
  history: [],
  historyFilter: "all",
  historyQuery: "",
  modelInfo: null,
  activeJob: null,
  pollGeneration: 0,
  confirmAction: null,
  modalityDetails: [],
  detailText: "",
  detailTrigger: null,
};

const MAX_APK_BYTES = 500 * 1024 * 1024;
const MAX_APK_MB = 500;

const elements = {
  sidebar: document.querySelector("#sidebar"),
  mobileScrim: document.querySelector("#mobileScrim"),
  menuButton: document.querySelector("#menuButton"),
  pageTitle: document.querySelector("#pageTitle"),
  systemDot: document.querySelector("#systemDot"),
  systemLabel: document.querySelector("#systemLabel"),
  systemDetail: document.querySelector("#systemDetail"),
  navHistoryCount: document.querySelector("#navHistoryCount"),
  newAnalysisButton: document.querySelector("#newAnalysisButton"),
  analysisHero: document.querySelector("#analysisHero"),
  analysisUploadCard: document.querySelector("#analysisUploadCard"),
  recentScansPanel: document.querySelector("#recentScansPanel"),
  recentScansBody: document.querySelector("#recentScansBody"),
  recentScansEmpty: document.querySelector("#recentScansEmpty"),
  dropZone: document.querySelector("#dropZone"),
  fileInput: document.querySelector("#fileInput"),
  selectedFile: document.querySelector("#selectedFile"),
  selectedFileName: document.querySelector("#selectedFileName"),
  selectedFileMeta: document.querySelector("#selectedFileMeta"),
  removeFileButton: document.querySelector("#removeFileButton"),
  consentCheck: document.querySelector("#consentCheck"),
  analyzeButton: document.querySelector("#analyzeButton"),
  progressPanel: document.querySelector("#progressPanel"),
  progressFile: document.querySelector("#progressFile"),
  progressPercent: document.querySelector("#progressPercent"),
  progressMessage: document.querySelector("#progressMessage"),
  progressBar: document.querySelector("#progressBar"),
  progressTrack: document.querySelector(".progress-track"),
  progressStages: [...document.querySelectorAll("[data-progress-stage]")],
  analysisError: document.querySelector("#analysisError"),
  analysisErrorMessage: document.querySelector("#analysisErrorMessage"),
  retryButton: document.querySelector("#retryButton"),
  resultSection: document.querySelector("#resultSection"),
  dynamicPipelineStage: document.querySelector("#dynamicPipelineStage"),
  familyPipelineStage: document.querySelector("#familyPipelineStage"),
  analysisScopeNote: document.querySelector("#analysisScopeNote"),
  verdictCard: document.querySelector("#verdictCard"),
  verdictBadge: document.querySelector("#verdictBadge"),
  reportId: document.querySelector("#reportId"),
  scoreRing: document.querySelector("#scoreRing"),
  riskScore: document.querySelector("#riskScore"),
  verdictTitle: document.querySelector("#verdictTitle"),
  verdictSubtitle: document.querySelector("#verdictSubtitle"),
  confidenceValue: document.querySelector("#confidenceValue"),
  benignPart: document.querySelector("#benignPart"),
  malwarePart: document.querySelector("#malwarePart"),
  benignProbability: document.querySelector("#benignProbability"),
  malwareProbability: document.querySelector("#malwareProbability"),
  findingList: document.querySelector("#findingList"),
  publicSummaryLead: document.querySelector("#publicSummaryLead"),
  publicSummaryFinding: document.querySelector("#publicSummaryFinding"),
  publicSummaryMeaning: document.querySelector("#publicSummaryMeaning"),
  publicSummaryAction: document.querySelector("#publicSummaryAction"),
  riskIntelligence: document.querySelector("#riskIntelligence"),
  riskDimensionList: document.querySelector("#riskDimensionList"),
  riskScenarioList: document.querySelector("#riskScenarioList"),
  riskActionList: document.querySelector("#riskActionList"),
  riskScopeNote: document.querySelector("#riskScopeNote"),
  metricGrid: document.querySelector("#metricGrid"),
  copySummaryButton: document.querySelector("#copySummaryButton"),
  reportOverviewButton: document.querySelector("#reportOverviewButton"),
  printReportButton: document.querySelector("#printReportButton"),
  exportButton: document.querySelector("#exportButton"),
  historyTotal: document.querySelector("#historyTotal"),
  historyMalware: document.querySelector("#historyMalware"),
  historyBenign: document.querySelector("#historyBenign"),
  historySearch: document.querySelector("#historySearch"),
  historyFilter: document.querySelector("#historyFilter"),
  historyBody: document.querySelector("#historyBody"),
  historyEmpty: document.querySelector("#historyEmpty"),
  historyEmptyTitle: document.querySelector("#historyEmptyTitle"),
  historyEmptyText: document.querySelector("#historyEmptyText"),
  toastStack: document.querySelector("#toastStack"),
  confirmModal: document.querySelector("#confirmModal"),
  confirmTitle: document.querySelector("#confirmTitle"),
  confirmMessage: document.querySelector("#confirmMessage"),
  confirmCancel: document.querySelector("#confirmCancel"),
  confirmAccept: document.querySelector("#confirmAccept"),
  detailModal: document.querySelector("#detailModal"),
  detailKicker: document.querySelector("#detailKicker"),
  detailTitle: document.querySelector("#detailTitle"),
  detailContent: document.querySelector("#detailContent"),
  detailClose: document.querySelector("#detailClose"),
  detailCopyButton: document.querySelector("#detailCopyButton"),
  detailDoneButton: document.querySelector("#detailDoneButton"),
  modelBehavioralFeatures: document.querySelector("#modelBehavioralFeatures"),
  modelApiFeatures: document.querySelector("#modelApiFeatures"),
  modelOpcodeFeatures: document.querySelector("#modelOpcodeFeatures"),
  modelTrainingSamples: document.querySelector("#modelTrainingSamples"),
  modelFeatureCount: document.querySelector("#modelFeatureCount"),
};

const viewTitles = {
  analysis: "分析中心",
  history: "历史记录",
  model: "模型说明",
};

const riskTone = {
  高: "high",
  中: "medium",
  低: "low",
};

const permissionFriendlyNames = {
  ACCESS_FINE_LOCATION: "精确定位",
  ACCESS_COARSE_LOCATION: "大致位置",
  CAMERA: "摄像头",
  RECORD_AUDIO: "录音",
  READ_PHONE_STATE: "读取电话状态",
  CALL_PHONE: "直接拨打电话",
  SEND_SMS: "发送短信",
  RECEIVE_SMS: "接收短信",
  READ_SMS: "读取短信",
  READ_CONTACTS: "读取联系人",
  WRITE_CONTACTS: "修改联系人",
  READ_CALL_LOG: "读取通话记录",
  WRITE_CALL_LOG: "修改通话记录",
  REQUEST_INSTALL_PACKAGES: "安装其他应用",
  SYSTEM_ALERT_WINDOW: "在其他应用上显示浮窗",
  BIND_ACCESSIBILITY_SERVICE: "读取并控制界面操作",
  PACKAGE_USAGE_STATS: "读取应用使用记录",
  READ_EXTERNAL_STORAGE: "读取文件",
  WRITE_EXTERNAL_STORAGE: "修改文件",
  RECEIVE_BOOT_COMPLETED: "开机后自动启动",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value.toFixed(index === 0 || value >= 10 ? 0 : 1)} ${units[index]}`;
}

function formatPercent(value, digits = 1) {
  return `${(Number(value || 0) * 100).toFixed(digits)}%`;
}

function formatDate(value, includeTime = true) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    ...(includeTime
      ? { hour: "2-digit", minute: "2-digit", hour12: false }
      : {}),
  }).format(date);
}

function showToast(message, tone = "info", duration = 3200) {
  const toast = document.createElement("div");
  toast.className = `toast is-${tone}`;
  toast.innerHTML = `
    <span class="toast-dot"></span>
    <span>${escapeHtml(message)}</span>
  `;
  elements.toastStack.append(toast);
  window.setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(6px)";
    window.setTimeout(() => toast.remove(), 180);
  }, duration);
}

function setSystemState(tone, label, detail) {
  elements.systemDot.className = `status-dot ${tone}`;
  elements.systemLabel.textContent = label;
  elements.systemDetail.textContent = detail;
}

async function parseResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const detail =
      typeof body === "object" && body?.detail
        ? body.detail
        : `请求失败（HTTP ${response.status}）`;
    throw new Error(detail);
  }
  return body;
}

async function checkHealth() {
  try {
    const health = await parseResponse(await fetch("/api/health"));
    const depsReady =
      health.dependencies?.torch && health.dependencies?.androguard &&
      health.checkpoint && health.feature_schema;
    if (depsReady) {
      const dynamicStatus = health.dynamic_analysis?.status;
      const dynamicLabel =
        dynamicStatus === "configured"
          ? "动态沙箱待人工复核"
          : "动态沙箱未启用";
      setSystemState(
        "is-ready",
        "分析引擎就绪",
        `静态模型已加载 · ${dynamicLabel}`
      );
    } else {
      setSystemState(
        "",
        "分析引擎待配置",
        "请检查依赖、模型文件与特征映射"
      );
      const missing = [];
      if (!health.dependencies?.torch) missing.push("PyTorch");
      if (!health.dependencies?.androguard) missing.push("Androguard");
      if (!health.checkpoint) missing.push("模型文件");
      if (!health.feature_schema) missing.push("特征映射");
      showToast(`分析环境缺少：${missing.join("、")}`, "error", 6000);
    }
  } catch (error) {
    setSystemState("is-error", "服务连接失败", "请确认后端已经启动");
  }
}

function setView(viewName) {
  const target = viewName in viewTitles ? viewName : "analysis";
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    const active = panel.dataset.viewPanel === target;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
  document.querySelectorAll(".nav-item[data-nav]").forEach((button) => {
    const active = button.dataset.nav === target;
    button.classList.toggle("is-active", active);
    if (active) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });
  elements.pageTitle.textContent = viewTitles[target];
  document.title = `${viewTitles[target]} · MMD Sentinel`;
  const nextUrl = new URL(window.location.href);
  nextUrl.searchParams.set("view", target);
  if (target !== "analysis") nextUrl.searchParams.delete("analysis");
  window.history.replaceState({}, "", nextUrl);
  closeMobileSidebar();
  window.scrollTo({ top: 0, behavior: "auto" });
  if (target === "history") loadHistory(50);
  if (target === "model") loadModelInfo();
}

function openMobileSidebar() {
  elements.sidebar.classList.add("is-open");
  elements.mobileScrim.hidden = false;
  document.body.style.overflow = "hidden";
}

function closeMobileSidebar() {
  elements.sidebar.classList.remove("is-open");
  elements.mobileScrim.hidden = true;
  document.body.style.overflow = "";
}

function resetAnalysisWorkspace({ keepFile = false } = {}) {
  state.pollGeneration += 1;
  state.activeJob = null;
  state.currentResult = null;
  elements.resultSection.hidden = true;
  elements.progressPanel.hidden = true;
  elements.analysisError.hidden = true;
  elements.analysisHero.hidden = false;
  elements.analysisUploadCard.hidden = false;
  elements.recentScansPanel.hidden = false;
  if (!keepFile) {
    state.file = null;
    elements.fileInput.value = "";
    elements.consentCheck.checked = false;
    elements.selectedFile.hidden = true;
    elements.dropZone.hidden = false;
    updateAnalyzeButton();
  }
  const nextUrl = new URL(window.location.href);
  nextUrl.searchParams.set("view", "analysis");
  nextUrl.searchParams.delete("analysis");
  window.history.replaceState({}, "", nextUrl);
  setView("analysis");
}

function selectFile(file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".apk")) {
    showToast("请选择扩展名为 .apk 的文件", "error");
    return;
  }
  if (file.size > MAX_APK_BYTES) {
    showToast(`文件超过 ${MAX_APK_MB} MB 限制`, "error");
    return;
  }
  state.file = file;
  elements.selectedFileName.textContent = file.name;
  elements.selectedFileMeta.textContent = `${formatBytes(file.size)} · APK 安装包`;
  elements.selectedFile.hidden = false;
  elements.dropZone.hidden = true;
  elements.analysisError.hidden = true;
  updateAnalyzeButton();
}

function updateAnalyzeButton() {
  elements.analyzeButton.disabled = !(state.file && elements.consentCheck.checked);
}

async function beginAnalysis() {
  if (!state.file || !elements.consentCheck.checked) return;
  const selectedFile = state.file;
  const formData = new FormData();
  formData.append("file", selectedFile, selectedFile.name);

  elements.analysisHero.hidden = true;
  elements.analysisUploadCard.hidden = true;
  elements.recentScansPanel.hidden = true;
  elements.resultSection.hidden = true;
  elements.analysisError.hidden = true;
  elements.progressPanel.hidden = false;
  elements.progressFile.textContent = selectedFile.name;
  updateProgress(1, "正在上传并校验文件");

  const generation = ++state.pollGeneration;
  try {
    const response = await parseResponse(
      await fetch("/api/analyze", {
        method: "POST",
        body: formData,
      })
    );
    state.activeJob = response.job_id;
    showToast("文件已进入分析队列", "success");
    pollJob(response.job_id, generation);
  } catch (error) {
    showAnalysisError(error.message);
  }
}

function updateProgress(progress, message) {
  const value = Math.max(0, Math.min(100, Math.round(progress || 0)));
  elements.progressPercent.textContent = `${value}%`;
  elements.progressMessage.textContent = message;
  elements.progressBar.style.width = `${value}%`;
  elements.progressTrack.setAttribute("aria-valuenow", String(value));
  elements.progressStages.forEach((stage) => {
    stage.classList.toggle("is-done", value >= Number(stage.dataset.progressStage));
  });
}

async function pollJob(jobId, generation) {
  if (generation !== state.pollGeneration) return;
  try {
    const job = await parseResponse(await fetch(`/api/jobs/${jobId}`));
    if (generation !== state.pollGeneration) return;
    if (job.status === "completed" && job.result) {
      state.activeJob = null;
      updateProgress(100, "分析完成，正在打开报告");
      window.setTimeout(() => {
        if (generation !== state.pollGeneration) return;
        elements.progressPanel.hidden = true;
        state.currentResult = job.result;
        renderResult(job.result);
        loadHistory(5);
      }, 260);
      return;
    }
    if (job.status === "failed") {
      showAnalysisError(job.error || "模型或特征提取过程发生错误");
      return;
    }
    updateProgress(job.progress, job.message || "正在分析");
    window.setTimeout(() => pollJob(jobId, generation), 650);
  } catch (error) {
    showAnalysisError(error.message);
  }
}

function showAnalysisError(message) {
  state.activeJob = null;
  elements.progressPanel.hidden = true;
  elements.resultSection.hidden = true;
  elements.analysisHero.hidden = true;
  elements.analysisUploadCard.hidden = true;
  elements.analysisErrorMessage.textContent = message;
  elements.analysisError.hidden = false;
}

function renderResult(result) {
  const { verdict, file, apk, evidence } = result;
  elements.verdictCard.classList.remove("is-danger", "is-warning", "is-safe");
  elements.verdictCard.classList.add(`is-${verdict.tone || "safe"}`);
  elements.verdictBadge.textContent = verdict.risk_level;
  elements.reportId.textContent = `RPT-${result.id.slice(0, 8).toUpperCase()}`;
  elements.riskScore.textContent = String(verdict.score);
  elements.verdictTitle.textContent = verdict.label;
  elements.verdictSubtitle.textContent =
    verdict.code === "malware"
      ? "模型在静态特征中发现了与恶意软件相似的组合模式。"
      : "模型未在静态特征中发现足以判定恶意的组合模式。";
  elements.confidenceValue.textContent = formatPercent(verdict.confidence);
  elements.benignProbability.textContent = formatPercent(verdict.benign_probability);
  elements.malwareProbability.textContent = formatPercent(verdict.malicious_probability);
  elements.benignPart.style.width = `${verdict.benign_probability * 100}%`;
  elements.malwarePart.style.width = `${verdict.malicious_probability * 100}%`;

  const ringColor =
    verdict.tone === "danger"
      ? "#ff6f7d"
      : verdict.tone === "warning"
        ? "#ffbc66"
        : "#58e0c1";
  elements.scoreRing.style.background =
    `conic-gradient(${ringColor} ${verdict.score * 3.6}deg, ` +
    "rgba(255,255,255,.06) 0)";

  elements.findingList.innerHTML = evidence.summary
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  const totalApis = evidence.sensitive_apis.reduce((sum, item) => sum + item.count, 0);
  const componentCount = Object.values(evidence.components).reduce(
    (sum, value) => sum + Number(value || 0),
    0
  );
  const riskPercent = Math.round(verdict.malicious_probability * 100);
  const highPermissionNames = evidence.permissions
    .filter((item) => item.risk === "高")
    .slice(0, 4)
    .map(
      (item) =>
        permissionFriendlyNames[item.short_name] ||
        item.short_name.replaceAll("_", " ").toLowerCase()
    );
  const appIdentity =
    apk.app_name && apk.app_name !== "未知"
      ? `“${apk.app_name}”（${apk.package_name}）`
      : apk.package_name || file.name;

  if (verdict.tone === "danger") {
    elements.publicSummaryLead.textContent =
      `系统认为 ${appIdentity} 具有明显恶意风险。模型给出的恶意概率约为 ${riskPercent}%，` +
      `因此不建议把检测结果理解为“可能有问题”，而应当先按高风险样本处理。`;
    elements.publicSummaryMeaning.textContent =
      "应用声明的权限、敏感调用和代码特征组合，与模型学习到的恶意软件模式较为接近。";
    elements.publicSummaryAction.textContent =
      "先不要安装或运行。保留文件，提交沙箱或专业人员复核，并确认下载来源是否可信。";
  } else if (verdict.tone === "warning") {
    elements.publicSummaryLead.textContent =
      `系统倾向于认为 ${appIdentity} 疑似恶意软件。恶意概率约为 ${riskPercent}%，` +
      "目前证据已经值得警惕，但仍需要结合应用来源和实际行为进一步确认。";
    elements.publicSummaryMeaning.textContent =
      "样本存在一些可能被滥用或具有较强系统访问能力的行为组合。";
    elements.publicSummaryAction.textContent =
      "在确认开发者、签名和下载渠道前不要安装，也不要直接授予短信、联系人、定位等敏感权限。";
  } else if (verdict.tone === "caution") {
    elements.publicSummaryLead.textContent =
      `${appIdentity} 没有被直接判定为恶意，但恶意概率达到 ${riskPercent}%，属于需要人工观察的范围。`;
    elements.publicSummaryMeaning.textContent =
      "现有静态证据不够明确，可能受应用功能、加固或代码混淆影响。";
    elements.publicSummaryAction.textContent =
      "确认应用来源可信后再决定是否安装；来源不明时建议提交动态分析或请专业人员复核。";
  } else {
    elements.publicSummaryLead.textContent =
      `系统暂未在 ${appIdentity} 中发现足以判定恶意的静态证据。模型给出约 ${riskPercent}% 的恶意概率，` +
      "整体结果更接近正常应用。";
    elements.publicSummaryMeaning.textContent =
      "低风险表示没有发现明显异常组合，并不等于应用绝对安全。";
    elements.publicSummaryAction.textContent =
      "确认下载来源和应用开发者可信后可以继续使用；安装时仍应只授予与功能相关的权限。";
  }
  const findingParts = [];
  if (evidence.permissions_high_count) {
    findingParts.push(
      `声明了 ${evidence.permissions_high_count} 项高关注权限` +
        (highPermissionNames.length
          ? `，包括 ${highPermissionNames.join("、")}`
          : "")
    );
  }
  if (totalApis) {
    findingParts.push(
      `代码中出现 ${totalApis.toLocaleString("zh-CN")} 次敏感 API 调用`
    );
  }
  if (evidence.components?.receivers) {
    findingParts.push(
      `注册了 ${evidence.components.receivers} 个广播接收器`
    );
  }
  elements.publicSummaryFinding.textContent = [
    ...findingParts,
  ]
    .filter(Boolean)
    .join("；") || "已完成权限、敏感 API 和代码结构检查，未发现明显异常组合。";
  renderRiskAssessment(result.risk_assessment);
  renderAnalysisPipeline(result);

  const metrics = [
    ["样本大小", formatBytes(file.size_bytes), file.name],
    ["包名", apk.package_name || "未知", apk.version_name || "版本未知"],
    ["高关注权限", String(evidence.permissions_high_count), "需结合应用功能复核"],
    ["敏感 API 调用", String(totalApis), `共 ${componentCount} 个组件/Intent`],
  ];
  elements.metricGrid.innerHTML = metrics
    .map(
      ([label, value, note]) => `
        <article class="metric-card">
          <span>${escapeHtml(label)}</span>
          <strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong>
          <small title="${escapeHtml(note)}">${escapeHtml(note)}</small>
        </article>
      `
    )
    .join("");

  renderResultPanels(result);
  elements.resultSection.hidden = false;
  elements.recentScansPanel.hidden = true;
  activateResultTab("overview");
  const nextUrl = new URL(window.location.href);
  nextUrl.searchParams.set("view", "analysis");
  nextUrl.searchParams.set("analysis", result.id);
  window.history.replaceState({}, "", nextUrl);
  elements.resultSection.scrollIntoView({ behavior: "auto", block: "start" });
}

function renderAnalysisPipeline(result) {
  const pipeline = result.pipeline || {};
  const capability = pipeline.dynamic_capability || {};
  const dynamicStage = elements.dynamicPipelineStage;
  dynamicStage.classList.remove("is-recommended", "is-ready");
  if (result.verdict.code === "malware") {
    dynamicStage.classList.add("is-recommended");
    dynamicStage.querySelector("b").textContent = "建议复核";
  } else if (capability.status === "configured") {
    dynamicStage.classList.add("is-ready");
    dynamicStage.querySelector("b").textContent = "可人工启动";
  } else {
    dynamicStage.querySelector("b").textContent = "待接入";
  }
  elements.analysisScopeNote.textContent =
    pipeline.scope_note ||
    "本次报告来自静态分析；动态沙箱和恶意家族识别尚未启用。";
}

function renderRiskAssessment(assessment) {
  if (!assessment) {
    elements.riskIntelligence.hidden = true;
    elements.riskScopeNote.hidden = true;
    return;
  }
  elements.riskIntelligence.hidden = false;
  elements.riskScopeNote.hidden = false;

  elements.riskDimensionList.innerHTML = (assessment.dimensions || [])
    .map((item, index) => {
      const score = Number(item.score || 0);
      const meterWidth = score > 0 ? Math.max(2, score) : 0;
      return `
        <div
          class="risk-dimension-row detail-clickable is-${escapeHtml(item.tone || "safe")}"
          role="button"
          tabindex="0"
          data-detail-type="dimension"
          data-detail-index="${index}"
          aria-label="放大查看${escapeHtml(item.label)}"
        >
          <div class="risk-dimension-head">
            <div>
              <strong>${escapeHtml(item.label)}</strong>
              <span>${escapeHtml(item.description)}</span>
            </div>
            <b>${escapeHtml(item.level)}</b>
          </div>
          <div class="risk-dimension-meter" aria-hidden="true">
            <span style="width:${meterWidth}%"></span>
          </div>
          <div class="risk-signal-chips">
            ${(item.signals || [])
              .slice(0, 4)
              .map((signal) => `<span>${escapeHtml(signal)}</span>`)
              .join("")}
          </div>
        </div>
      `;
    })
    .join("");

  elements.riskScenarioList.innerHTML = (assessment.scenarios || [])
    .map(
      (item, index) => `
        <article
          class="risk-scenario detail-clickable is-${escapeHtml(item.tone || "warning")}"
          role="button"
          tabindex="0"
          data-detail-type="scenario"
          data-detail-index="${index}"
          aria-label="放大查看${escapeHtml(item.title)}"
        >
          <div class="risk-scenario-head">
            <span>${String(index + 1).padStart(2, "0")}</span>
            <div>
              <strong>${escapeHtml(item.title)}</strong>
              <small>${escapeHtml(item.level)}</small>
            </div>
          </div>
          <p>${escapeHtml(item.description)}</p>
          <div class="risk-signal-chips">
            ${(item.signals || [])
              .slice(0, 4)
              .map((signal) => `<span>${escapeHtml(signal)}</span>`)
              .join("")}
          </div>
        </article>
      `
    )
    .join("");

  elements.riskActionList.innerHTML = (assessment.recommendations || [])
    .map(
      (item, index) => `
        <li
          class="detail-clickable"
          role="button"
          tabindex="0"
          data-detail-type="action"
          data-detail-index="${index}"
          aria-label="放大查看${escapeHtml(item.title)}"
        >
          <span class="risk-action-number">${String(index + 1).padStart(2, "0")}</span>
          <div>
            <div class="risk-action-head">
              <strong>${escapeHtml(item.title)}</strong>
              <small>${escapeHtml(item.priority)}</small>
            </div>
            <p>${escapeHtml(item.description)}</p>
          </div>
        </li>
      `
    )
    .join("");
  elements.riskScopeNote.textContent = assessment.scope_note || "";
}

function renderResultPanels(result) {
  const { apk, file, evidence, model, warnings } = result;
  const opcodeEntries = Object.entries(evidence.opcode_counts || {}).slice(0, 10);
  const maxOpcode = Math.max(1, ...opcodeEntries.map(([, count]) => Number(count)));
  const permissionRows = (evidence.permissions || [])
    .map(
      (item, index) => `
        <tr
          class="detail-clickable"
          tabindex="0"
          data-detail-type="permission"
          data-detail-index="${index}"
          aria-label="放大查看${escapeHtml(item.name)}"
        >
          <td><span class="risk-pill risk-${riskTone[item.risk] || "low"}">${escapeHtml(item.risk)}</span></td>
          <td class="permission-name">${escapeHtml(item.name)}</td>
          <td>${escapeHtml(item.reason)}</td>
        </tr>
      `
    )
    .join("");

  const overviewPanel = document.querySelector('[data-result-panel="overview"]');
  overviewPanel.innerHTML = `
    <div class="app-overview-card">
      <div class="app-overview-identity">
        <span class="app-overview-icon">APK</span>
        <div>
          <span class="section-index">APPLICATION PROFILE</span>
          <h3>${escapeHtml(apk.app_name || file.name.replace(/\.apk$/i, ""))}</h3>
          <code>${escapeHtml(apk.package_name || "未知包名")}</code>
        </div>
      </div>
      <div class="app-overview-actions">
        <span class="status-pill status-${result.verdict.code === "malware" ? "malware" : "benign"}">
          ${escapeHtml(result.verdict.label)}
        </span>
      </div>
    </div>
    <div class="app-facts-grid">
      <div><span>文件名称</span><strong title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</strong></div>
      <div><span>文件大小</span><strong>${formatBytes(file.size_bytes)}</strong></div>
      <div><span>版本</span><strong>${escapeHtml(apk.version_name || "未知")} (${escapeHtml(apk.version_code || "—")})</strong></div>
      <div><span>SDK 范围</span><strong>min ${escapeHtml(apk.min_sdk || "—")} / target ${escapeHtml(apk.target_sdk || "—")}</strong></div>
      <div><span>主 Activity</span><strong title="${escapeHtml(apk.main_activity || "")}">${escapeHtml(apk.main_activity || "未提取")}</strong></div>
      <div><span>DEX / 指令</span><strong>${Number(apk.dex_count || 0)} 个 / ${Number(apk.instruction_count || 0).toLocaleString("zh-CN")}</strong></div>
    </div>
    <div class="hash-card">
      <div>
        <span>SHA-256</span>
        <code title="${escapeHtml(file.sha256)}">${escapeHtml(file.sha256)}</code>
      </div>
      <button type="button" data-copy-value="${escapeHtml(file.sha256)}">复制</button>
    </div>
    <div class="report-overview-grid">
      <div>
        <div class="subsection-title">
          <h4>主要安全信号</h4>
          <span>点击放大</span>
        </div>
        <div class="overview-signal-list">
          ${(result.risk_assessment?.dimensions || [])
            .filter((item) => item.score > 0)
            .slice(0, 5)
            .map(
              (item, index) => `
                <button type="button" class="overview-signal is-${escapeHtml(item.tone)}" data-detail-type="dimension" data-detail-index="${(result.risk_assessment?.dimensions || []).indexOf(item)}">
                  <span>${escapeHtml(item.label)}</span>
                  <strong>${escapeHtml(item.level)}</strong>
                  <i><b style="width:${Math.max(2, Number(item.score || 0))}%"></b></i>
                </button>
              `
            )
            .join("") || '<div class="empty-mini">当前报告没有显著安全信号</div>'}
        </div>
      </div>
      <div>
        <div class="subsection-title">
          <h4>Dalvik Opcode 活跃分布</h4>
          <span>Top ${Math.min(6, opcodeEntries.length)}</span>
        </div>
        ${
          opcodeEntries.length
            ? `<div class="bar-chart">${opcodeEntries
                .slice(0, 6)
                .map(
                  ([name, count]) => `
                    <div class="bar-row">
                      <span class="bar-label" title="${escapeHtml(name)}">${escapeHtml(name)}</span>
                      <span class="bar-track"><span style="width:${(Number(count) / maxOpcode) * 100}%"></span></span>
                      <span class="bar-value">${Number(count).toLocaleString("zh-CN")}</span>
                    </div>
                  `
                )
                .join("")}</div>`
            : '<div class="empty-mini">未提取到 Opcode 数据</div>'
        }
      </div>
    </div>
  `;

  const risk = result.risk_assessment || {};
  const dimensions = risk.dimensions || [];
  const securityPanel = document.querySelector('[data-result-panel="security"]');
  const highIssueCount = dimensions.filter((item) => item.tone === "danger").length;
  const mediumIssueCount = dimensions.filter((item) => item.tone === "warning").length;
  const lowIssueCount = dimensions.filter((item) => item.tone === "caution").length;
  const safeAreaCount = dimensions.filter((item) => item.tone === "safe").length;
  const safetyScore = Math.round((1 - Number(result.verdict.malicious_probability || 0)) * 100);
  securityPanel.innerHTML = `
    <div class="security-summary-card">
      <div class="security-score-ring" style="--score:${safetyScore * 3.6}deg">
        <div><strong>${safetyScore}</strong><span>安全倾向分</span></div>
      </div>
      <div class="security-summary-copy">
        <span class="section-index">STATIC SECURITY POSTURE</span>
        <h3>${escapeHtml(result.verdict.label)}</h3>
        <p>该分数由模型给出的良性概率换算，仅用于快速浏览；具体风险仍应结合下方问题和证据判断。</p>
      </div>
      <div class="security-severity-grid">
        <div class="is-high"><span>高关注</span><strong>${highIssueCount}</strong></div>
        <div class="is-medium"><span>中关注</span><strong>${mediumIssueCount}</strong></div>
        <div class="is-low"><span>低关注</span><strong>${lowIssueCount}</strong></div>
        <div class="is-safe"><span>未发现</span><strong>${safeAreaCount}</strong></div>
      </div>
    </div>
    <div class="security-issues-heading">
      <div>
        <span class="section-index">SECURITY FINDINGS</span>
        <h4>静态安全问题</h4>
      </div>
      <span>点击问题查看完整解释</span>
    </div>
    <div class="security-issue-list">
      ${dimensions
        .map(
          (item) => `
            <button
              type="button"
              class="security-issue is-${escapeHtml(item.tone)}"
              data-detail-type="dimension"
              data-detail-index="${dimensions.indexOf(item)}"
            >
              <span class="security-issue-level">${escapeHtml(item.level)}</span>
              <div>
                <strong>${escapeHtml(item.label)}</strong>
                <p>${escapeHtml(item.description)}</p>
                <small>${escapeHtml(item.signals.slice(0, 3).join(" · "))}</small>
              </div>
              <b>${Number(item.score)}</b>
            </button>
          `
        )
        .join("")}
    </div>
    ${
      evidence.permissions_high_count
        ? `
          <div class="security-permission-strip">
            <div>
              <span class="section-index">DANGEROUS PERMISSIONS</span>
              <h4>高关注权限 ${evidence.permissions_high_count} 项</h4>
            </div>
            <div>
              ${evidence.permissions
                .filter((item) => item.risk === "高")
                .slice(0, 8)
                .map(
                  (item, index) => `
                    <button type="button" data-detail-type="permission" data-detail-index="${evidence.permissions.indexOf(item)}">
                      ${escapeHtml(item.short_name)}
                    </button>
                  `
                )
                .join("")}
            </div>
          </div>
        `
        : ""
    }
    <p class="security-scope-note">静态分析发现的是潜在安全暴露，不等于漏洞已经被利用。动态行为、代码混淆和加固可能导致静态结果不完整。</p>
  `;

  const componentSamples = evidence.component_samples || {};
  const sampleList = (items, label) =>
    items?.length
      ? `<div class="subsection-title"><h4>${escapeHtml(label)}</h4><span>${items.length} 个样本</span></div>
         <ul class="component-sample-list">${items
           .slice(0, 8)
           .map((item) => `<li><code title="${escapeHtml(item)}">${escapeHtml(item)}</code></li>`)
           .join("")}</ul>`
      : "";

  const permissionPanel = document.querySelector('[data-result-panel="permissions"]');
  permissionPanel.innerHTML = `
    <div class="manifest-heading">
      <div>
        <span class="section-index">ANDROIDMANIFEST.XML</span>
        <h4>Manifest 清单分析</h4>
        <p>应用声明了哪些权限、组件和对外入口。</p>
      </div>
      <span class="manifest-format">Manifest</span>
    </div>
    <div class="component-grid manifest-component-grid">
      <div class="component-card"><span>Activity</span><strong>${Number(evidence.components.activities || 0)}</strong></div>
      <div class="component-card"><span>Service</span><strong>${Number(evidence.components.services || 0)}</strong></div>
      <div class="component-card"><span>Receiver</span><strong>${Number(evidence.components.receivers || 0)}</strong></div>
      <div class="component-card"><span>Provider</span><strong>${Number(evidence.components.providers || 0)}</strong></div>
      <div class="component-card"><span>Intent</span><strong>${Number(evidence.components.intents || 0)}</strong></div>
    </div>
    <div class="subsection-title">
      <h4>权限与风险解释</h4>
      <span>${evidence.permissions.length} 项权限 · ${evidence.permissions_high_count} 项高关注</span>
    </div>
    ${
      permissionRows
        ? `<div class="permission-table-wrap">
            <table class="permission-table">
              <thead><tr><th>等级</th><th>权限</th><th>研判说明</th></tr></thead>
              <tbody>${permissionRows}</tbody>
            </table>
          </div>`
        : '<div class="empty-mini">未从 Manifest 中提取到权限声明</div>'
    }
    <div class="component-columns manifest-samples">
      <div>
        ${sampleList(componentSamples.intent, "Intent Actions")}
      </div>
      <div>
        ${sampleList(componentSamples.activity, "Activity 组件")}
        ${sampleList(componentSamples.receiver, "Receiver 组件")}
      </div>
    </div>
  `;

  const apiRows = (evidence.sensitive_apis || [])
    .slice(0, 12)
    .map(
      (item, index) => `
        <li
          class="detail-clickable"
          tabindex="0"
          data-detail-type="api"
          data-detail-index="${index}"
          aria-label="放大查看${escapeHtml(item.name)}"
        >
          <code title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</code>
          <span>${Number(item.count).toLocaleString("zh-CN")}×</span>
        </li>
      `
    )
    .join("");
  const componentPanel = document.querySelector('[data-result-panel="components"]');
  componentPanel.innerHTML = `
    <div class="code-heading">
      <div>
        <span class="section-index">CODE & SENSITIVE API</span>
        <h4>代码层面的敏感行为</h4>
        <p>查看 DEX 规模、敏感 API 命中以及 Opcode 活跃情况。</p>
      </div>
    </div>
    <div class="code-metric-grid">
      <div><span>DEX 文件</span><strong>${Number(apk.dex_count || 0)}</strong><small>个</small></div>
      <div><span>指令数量</span><strong>${Number(apk.instruction_count || 0).toLocaleString("zh-CN")}</strong><small>条</small></div>
      <div><span>敏感 API 种类</span><strong>${Number(evidence.sensitive_apis.length || 0)}</strong><small>Top 30</small></div>
      <div><span>Opcode 种类</span><strong>${Object.keys(evidence.opcode_counts || {}).length}</strong><small>Top 40</small></div>
    </div>
    <div class="component-columns">
      <div>
        <div class="subsection-title"><h4>敏感 API 调用</h4><span>Top ${Math.min(12, evidence.sensitive_apis.length)}</span></div>
        ${apiRows ? `<ul class="api-list">${apiRows}</ul>` : '<div class="empty-mini">未命中训练阶段收录的敏感 API</div>'}
      </div>
      <div>
        <div class="subsection-title"><h4>Opcode 活跃分布</h4><span>Top ${Math.min(10, opcodeEntries.length)}</span></div>
        ${
          opcodeEntries.length
            ? `<div class="bar-chart compact-bar-chart">${opcodeEntries
                .map(
                  ([name, count]) => `
                    <div class="bar-row">
                      <span class="bar-label" title="${escapeHtml(name)}">${escapeHtml(name)}</span>
                      <span class="bar-track"><span style="width:${(Number(count) / maxOpcode) * 100}%"></span></span>
                      <span class="bar-value">${Number(count).toLocaleString("zh-CN")}</span>
                    </div>
                  `
                )
                .join("")}</div>`
            : '<div class="empty-mini">未提取到 Opcode 数据</div>'
        }
      </div>
    </div>
  `;

  const modality = evidence.modality_totals || {
    behavioral: 0,
    api: 0,
    opcode: 0,
  };
  const warningLabels = {
    feature_schema_approximation:
      "部分 API 聚类字段在历史汇总表中的命名方式不同，已按可审计的兼容规则映射。",
  };
  const warningItems = (warnings || [])
    .map((warning) => warningLabels[warning] || warning)
    .filter(Boolean);
  const modelInputs = evidence.model_inputs || {};
  const modalityCards = [
    {
      key: "behavioral",
      className: "is-behavior",
      index: "01",
      title: "应用行为",
      subtitle: "权限、组件与 Intent",
      active: Number(modelInputs.behavioral),
      total: 34,
      raw: Number(modality.behavioral || 0),
      rawLabel: "行为特征总计数",
      description:
        "回答应用“要求了什么能力”。例如读取短信、定位、安装其他应用等声明，都会在这里留下痕迹。",
    },
    {
      key: "api",
      className: "is-api",
      index: "02",
      title: "敏感调用",
      subtitle: "代码中的方法调用",
      active: Number(modelInputs.api),
      total: 121,
      raw: Number(modality.api || 0),
      rawLabel: "敏感调用次数",
      description:
        "回答代码“实际触碰了哪些敏感能力”。权限只是声明，API 调用更接近代码真正尝试执行的动作。",
    },
    {
      key: "opcode",
      className: "is-opcode",
      index: "03",
      title: "代码结构",
      subtitle: "Dalvik 指令分布",
      active: Number(modelInputs.opcode),
      total: 105,
      raw: Number(modality.opcode || 0),
      rawLabel: "纳入统计的指令次数",
      description:
        "回答程序“写成了什么样子”。模型比较方法调用、跳转、字符串处理等指令的比例是否异常。",
    },
  ];
  const modelCardsHtml = modalityCards
    .map((item, index) => {
      const hasActive = Number.isFinite(item.active);
      const active = hasActive ? item.active : 0;
      const percentage = Math.max(0, Math.min(100, (active / item.total) * 100));
      return `
        <article
          class="model-evidence-card detail-clickable ${item.className}"
          role="button"
          tabindex="0"
          data-detail-type="model"
          data-detail-index="${index}"
          aria-label="放大查看${escapeHtml(item.title)}"
        >
          <div class="model-evidence-head">
            <span class="model-evidence-index">${item.index}</span>
            <div>
              <strong>${escapeHtml(item.title)}</strong>
              <small>${escapeHtml(item.subtitle)}</small>
            </div>
          </div>
          <div class="model-feature-usage">
            <strong class="${hasActive ? "" : "is-text"}">${hasActive ? active : "已分析"}</strong>
            <span>${hasActive ? `/ ${item.total} 个输入特征有内容` : "历史报告未保存字段活跃数"}</span>
          </div>
          <p>${escapeHtml(item.description)}</p>
          <div class="model-meter ${hasActive ? "" : "is-unavailable"}" aria-hidden="true">
            <span style="width:${percentage}%"></span>
          </div>
          <div class="model-raw-count">
            <span>${escapeHtml(item.rawLabel)}</span>
            <b>${item.raw.toLocaleString("zh-CN")}</b>
          </div>
        </article>
      `;
    })
    .join("");
  state.modalityDetails = modalityCards;
  const attentionValues = Array.isArray(model.modality_attention)
    ? model.modality_attention.map((value) => Number(value || 0))
    : null;
  const attentionHtml =
    attentionValues && attentionValues.length === 3
      ? `
        <section class="model-attention-card">
          <div>
            <span class="section-index">CROSS-MODAL ATTENTION</span>
            <h4>模型这次更关注哪类证据</h4>
            <p>这是模型内部注意力权重的均值，用于展示信息流向，不代表因果关系。</p>
          </div>
          <div class="attention-bars">
            ${["应用行为", "敏感 API", "代码结构"]
              .map(
                (label, index) => `
                  <div class="attention-row is-${["behavior", "api", "opcode"][index]}">
                    <span>${label}</span>
                    <div><i style="width:${attentionValues[index] * 100}%"></i></div>
                    <strong>${(attentionValues[index] * 100).toFixed(1)}%</strong>
                  </div>
                `
              )
              .join("")}
          </div>
        </section>
      `
      : "";
  const modelPanel = document.querySelector('[data-result-panel="model"]');
  modelPanel.innerHTML = `
    <div class="model-explainer-intro">
      <div>
        <span class="eyebrow">HOW THE MODEL READS AN APK</span>
        <h4>模型没有“打开应用”，它是在阅读三组证据。</h4>
        <p>
          系统把 APK 转换成 260 个数字，再比较这些数字与训练数据中良性、恶意样本的相似程度。
          这里的“模型如何判断”不是一段难以理解的代码输出，而是对本次结论形成过程的通俗解释。
        </p>
      </div>
      <div class="vector-equation" aria-label="260 维输入由 34、121 和 105 维组成">
        <div class="vector-part behavior-part"><span>行为</span><strong>34</strong></div>
        <b>+</b>
        <div class="vector-part api-part"><span>API</span><strong>121</strong></div>
        <b>+</b>
        <div class="vector-part opcode-part"><span>代码</span><strong>105</strong></div>
        <b>=</b>
        <div class="vector-total"><span>模型输入</span><strong>260</strong></div>
      </div>
    </div>
    <div class="model-evidence-grid">${modelCardsHtml}</div>
    ${attentionHtml}
    <div class="model-reading-guide">
      <article>
        <span>STEP 1</span>
        <h4>先看概率</h4>
        <p>恶意概率低于 50% 时倾向良性，达到或超过 50% 时模型判定为恶意；概率越接近两端，结论越明确。</p>
      </article>
      <article>
        <span>STEP 2</span>
        <h4>再看证据是否互相支持</h4>
        <p>如果高关注权限、敏感 API 和异常代码结构同时出现，风险解释更充分；证据不一致时应谨慎看待。</p>
      </article>
      <article>
        <span>STEP 3</span>
        <h4>最后结合来源与场景</h4>
        <p>同一项权限在相机和手电筒应用中含义不同。专业人员应结合应用用途、签名、来源和动态行为复核。</p>
      </article>
    </div>
    <div class="model-callout">
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 3 3.8 7.5 12 12l8.2-4.5L12 3Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="m3.8 12 8.2 4.5 8.2-4.5M3.8 16.5 12 21l8.2-4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <div>
        <strong>技术说明</strong>
        <p>${escapeHtml(model.explanation)} 本次输入按 ${model.architecture.join(" / ")} 分组，共 ${model.feature_count} 个训练特征；推理设备为 ${escapeHtml(model.device)}。</p>
      </div>
    </div>
    ${
      warningItems.length
        ? `<ul class="warning-list">${warningItems
            .map((warning) => `<li>${escapeHtml(warning)}</li>`)
            .join("")}</ul>`
        : ""
    }
  `;
}

function activateResultTab(tabName) {
  document.querySelectorAll("[data-result-tab]").forEach((button) => {
    const active = button.dataset.resultTab === tabName;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll("[data-result-panel]").forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.resultPanel === tabName);
  });
}

async function loadHistory(limit = 5) {
  try {
    const params = new URLSearchParams({
      limit: String(limit),
      q: state.historyQuery.trim(),
    });
    const data = await parseResponse(await fetch(`/api/history?${params}`));
    state.history = data.items;
    renderHistoryStats(data.stats);
    renderHistoryRows();
    renderRecentScans();
  } catch (error) {
    showToast(`历史记录加载失败：${error.message}`, "error");
  }
}

function renderRecentScans() {
  const items = state.history.slice(0, 5);
  elements.recentScansEmpty.hidden = items.length > 0;
  elements.recentScansBody.innerHTML = items
    .map(
      (item) => `
        <tr data-recent-id="${escapeHtml(item.id)}" tabindex="0">
          <td>
            <div class="recent-app">
              <span class="recent-app-icon">APK</span>
              <div>
                <strong title="${escapeHtml(item.filename)}">${escapeHtml(item.filename)}</strong>
                <small title="${escapeHtml(item.package_name || "")}">${escapeHtml(item.package_name || "未知包名")}</small>
              </div>
            </div>
          </td>
          <td>
            <span class="status-pill status-${item.verdict === "malware" ? "malware" : "benign"}">
              ${item.verdict === "malware" ? "恶意" : "良性"}
            </span>
          </td>
          <td>
            <div class="recent-risk ${item.verdict === "benign" ? "is-safe" : ""}">
              <span><i style="width:${Math.round(item.malicious_probability * 100)}%"></i></span>
              <b>${Math.round(item.malicious_probability * 100)}</b>
            </div>
          </td>
          <td>${formatDate(item.created_at)}</td>
          <td>
            <button class="recent-open" type="button" data-open-recent="${escapeHtml(item.id)}">
              查看报告
            </button>
          </td>
        </tr>
      `
    )
    .join("");
}

function renderHistoryStats(stats) {
  elements.historyTotal.textContent = Number(stats.total || 0).toLocaleString("zh-CN");
  elements.historyMalware.textContent = Number(stats.malware || 0).toLocaleString("zh-CN");
  elements.historyBenign.textContent = Number(stats.benign || 0).toLocaleString("zh-CN");
  elements.navHistoryCount.textContent = String(stats.total || 0);
  elements.navHistoryCount.hidden = !stats.total;
}

function renderHistoryRows() {
  const rows = state.history.filter(
    (item) => state.historyFilter === "all" || item.verdict === state.historyFilter
  );
  elements.historyEmpty.hidden = rows.length > 0;
  const noMatches = state.history.length > 0 && rows.length === 0;
  elements.historyEmptyTitle.textContent = noMatches
    ? "没有符合条件的记录"
    : "还没有检测记录";
  elements.historyEmptyText.textContent = noMatches
    ? "尝试修改结论筛选或搜索关键词。"
    : "完成第一个 APK 分析后，报告会出现在这里。";
  elements.historyBody.innerHTML = rows
    .map(
      (item) => `
        <tr data-history-id="${escapeHtml(item.id)}" tabindex="0">
          <td>
            <div class="history-file">
              <span class="history-file-icon">APK</span>
              <div>
                <strong title="${escapeHtml(item.filename)}">${escapeHtml(item.filename)}</strong>
                <small title="${escapeHtml(item.package_name || "")}">${escapeHtml(item.package_name || "未知包名")} · ${formatBytes(item.size_bytes)}</small>
              </div>
            </div>
          </td>
          <td>
            <span class="status-pill status-${item.verdict === "malware" ? "malware" : "benign"}">
              ${item.verdict === "malware" ? "恶意" : "良性"}
            </span>
          </td>
          <td>
            <div class="history-score ${item.verdict === "benign" ? "is-safe" : ""}">
              <span class="history-score-bar"><span style="width:${Math.round(item.malicious_probability * 100)}%"></span></span>
              <span>${Math.round(item.malicious_probability * 100)}</span>
            </div>
          </td>
          <td>${formatDate(item.created_at)}</td>
          <td>
            <div class="history-row-actions">
              <button class="open-history" type="button" data-open-history="${escapeHtml(item.id)}" aria-label="查看 ${escapeHtml(item.filename)} 的报告">
                查看
                <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <path d="M5 15 15 5m-6 0h6v6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
              </button>
              <button class="delete-history" type="button" data-delete-history="${escapeHtml(item.id)}" aria-label="删除 ${escapeHtml(item.filename)}">
                <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <path d="M4 6h12M8 3.8h4M6.2 6l.7 10h6.2l.7-10M8.5 9v4.5M11.5 9v4.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
                </svg>
              </button>
            </div>
          </td>
        </tr>
      `
    )
    .join("");
}

async function openHistoryResult(analysisId) {
  try {
    const result = await parseResponse(await fetch(`/api/history/${analysisId}`));
    resetAnalysisWorkspace({ keepFile: true });
    elements.analysisHero.hidden = true;
    elements.analysisUploadCard.hidden = true;
    state.currentResult = result;
    renderResult(result);
    const requestedTab = new URLSearchParams(window.location.search).get("tab");
    if (
      ["overview", "security", "permissions", "components", "model"].includes(
        requestedTab
      )
    ) {
      activateResultTab(requestedTab);
      if (requestedTab !== "overview") {
        window.setTimeout(() => {
          document.querySelector("#reportPanel")?.scrollIntoView({
            behavior: "auto",
            block: "start",
          });
        }, 0);
      }
    }
    const detailParam = new URLSearchParams(window.location.search).get("detail");
    if (detailParam === "overview") {
      openReportOverview();
    } else if (detailParam) {
      const [detailType, detailIndex] = detailParam.split("-");
      if (
        [
          "dimension",
          "scenario",
          "action",
          "permission",
          "api",
          "model",
          "sandbox",
          "family",
        ].includes(detailType) &&
        Number.isInteger(Number(detailIndex))
      ) {
        openResultDetail(detailType, Number(detailIndex), document.body);
      }
    }
  } catch (error) {
    showToast(`报告加载失败：${error.message}`, "error");
  }
}

function requestDeleteHistory(analysisId) {
  const item = state.history.find((entry) => entry.id === analysisId);
  openConfirm({
    title: "删除这条分析记录？",
    message: `${item?.filename || "该样本"} 的报告将从本地历史中移除，此操作无法撤销。`,
    actionLabel: "删除",
    action: async () => {
      await parseResponse(
        await fetch(`/api/history/${encodeURIComponent(analysisId)}`, {
          method: "DELETE",
        })
      );
      showToast("历史记录已删除", "success");
      await loadHistory(50);
    },
  });
}

function openConfirm({ title, message, actionLabel, action }) {
  elements.confirmTitle.textContent = title;
  elements.confirmMessage.textContent = message;
  elements.confirmAccept.textContent = actionLabel || "确认";
  state.confirmAction = action;
  elements.confirmModal.hidden = false;
  elements.confirmAccept.focus();
}

function closeConfirm() {
  elements.confirmModal.hidden = true;
  state.confirmAction = null;
}

function detailChips(items) {
  return `<div class="detail-chips">${(items || [])
    .map((item) => `<span>${escapeHtml(item)}</span>`)
    .join("")}</div>`;
}

function openDetailView({ kicker, title, html, text, trigger }) {
  elements.detailKicker.textContent = kicker;
  elements.detailTitle.textContent = title;
  elements.detailContent.innerHTML = html;
  state.detailText = text;
  state.detailTrigger = trigger || document.activeElement;
  elements.detailModal.hidden = false;
  document.body.classList.add("modal-open");
  elements.detailClose.focus();
}

function closeDetailView() {
  elements.detailModal.hidden = true;
  document.body.classList.remove("modal-open");
  const nextUrl = new URL(window.location.href);
  nextUrl.searchParams.delete("detail");
  window.history.replaceState({}, "", nextUrl);
  if (state.detailTrigger instanceof HTMLElement) {
    state.detailTrigger.focus();
  }
  state.detailTrigger = null;
}

function openReportOverview() {
  if (!state.currentResult) return;
  const result = state.currentResult;
  const risk = result.risk_assessment;
  const topDimensions = (risk?.dimensions || [])
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);
  const scenarios = (risk?.scenarios || []).slice(0, 3);
  const actions = (risk?.recommendations || []).slice(0, 4);

  const html = `
    <section class="detail-reading-lead">
      <span class="detail-status is-${escapeHtml(result.verdict.tone)}">${escapeHtml(result.verdict.risk_level)}</span>
      <h3>${escapeHtml(elements.publicSummaryLead.textContent)}</h3>
      <p>${escapeHtml(elements.publicSummaryMeaning.textContent)}</p>
    </section>
    <div class="detail-stat-grid">
      <div><span>恶意概率</span><strong>${escapeHtml(elements.malwareProbability.textContent)}</strong></div>
      <div><span>高关注权限</span><strong>${Number(result.evidence.permissions_high_count || 0)}</strong></div>
      <div><span>敏感 API 调用</span><strong>${(result.evidence.sensitive_apis || [])
        .reduce((sum, item) => sum + Number(item.count || 0), 0)
        .toLocaleString("zh-CN")}</strong></div>
    </div>
    <section class="detail-section">
      <h3>风险主要集中在哪些方面</h3>
      <div class="detail-reading-list">
        ${topDimensions
          .map(
            (item) => `
              <div>
                <span class="detail-reading-rank">${escapeHtml(item.level)}</span>
                <div><strong>${escapeHtml(item.label)}</strong><p>${escapeHtml(item.description)}</p></div>
              </div>
            `
          )
          .join("")}
      </div>
    </section>
    <section class="detail-section">
      <h3>这个应用可能发生什么</h3>
      ${scenarios
        .map(
          (item) => `
            <article class="detail-reading-card is-${escapeHtml(item.tone)}">
              <strong>${escapeHtml(item.title)}</strong>
              <p>${escapeHtml(item.description)}</p>
            </article>
          `
        )
        .join("")}
    </section>
    <section class="detail-section">
      <h3>建议下一步怎么做</h3>
      <ol class="detail-action-list">
        ${actions
          .map(
            (item) => `
              <li><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.description)}</p></li>
            `
          )
          .join("")}
      </ol>
    </section>
    <p class="detail-scope">${escapeHtml(risk?.scope_note || "本结果用于辅助研判，不能替代人工复核。")}</p>
  `;
  const text = [
    "MMD Sentinel 放大阅读报告",
    elements.publicSummaryLead.textContent,
    `风险方面：${topDimensions.map((item) => `${item.label}（${item.level}）`).join("；")}`,
    `可能影响：${scenarios.map((item) => item.title).join("；")}`,
    `建议：${actions.map((item) => item.title).join("；")}`,
    risk?.scope_note || "",
  ].join("\n");
  openDetailView({
    kicker: "EXPANDED REPORT",
    title: "完整风险速览",
    html,
    text,
    trigger: elements.reportOverviewButton,
  });
}

function openResultDetail(type, index, trigger) {
  const result = state.currentResult;
  if (!result) return;
  const risk = result.risk_assessment || {};
  let kicker = "DETAIL VIEW";
  let title = "详情";
  let html = "";
  let text = "";

  if (type === "dimension") {
    const item = (risk.dimensions || [])[index];
    if (!item) return;
    kicker = "RISK AREA";
    title = item.label;
    html = `
      <div class="detail-hero">
        <div class="detail-score"><strong>${Number(item.score)}</strong><span>/ 100</span></div>
        <div><span class="detail-status is-${escapeHtml(item.tone)}">${escapeHtml(item.level)}</span><p>${escapeHtml(item.description)}</p></div>
      </div>
      <section class="detail-section"><h3>支持这一判断的证据</h3>${detailChips(item.signals)}</section>
      <section class="detail-section"><h3>如何理解</h3><p>这个分数反映应用在当前维度具备的敏感能力，不是“已经发生风险”的概率。分数越高，越需要结合应用用途和来源进行确认。</p></section>
    `;
    text = `${item.label}：${item.level}（${item.score}/100）\n证据：${item.signals.join("；")}`;
  } else if (type === "scenario") {
    const item = (risk.scenarios || [])[index];
    if (!item) return;
    kicker = "POSSIBLE IMPACT";
    title = item.title;
    html = `
      <div class="detail-hero">
        <span class="detail-status is-${escapeHtml(item.tone)}">${escapeHtml(item.level)}</span>
        <p>${escapeHtml(item.description)}</p>
      </div>
      <section class="detail-section"><h3>触发这项推论的条件</h3>${detailChips(item.signals)}</section>
      <section class="detail-section"><h3>需要注意</h3><p>这里描述的是“具备条件时可能发生什么”，并不表示应用已经执行了这些行为。要确认实际行为，需要进行动态分析。</p></section>
    `;
    text = `${item.title}\n${item.description}\n证据：${item.signals.join("；")}`;
  } else if (type === "action") {
    const item = (risk.recommendations || [])[index];
    if (!item) return;
    kicker = "RECOMMENDED ACTION";
    title = item.title;
    html = `
      <div class="detail-hero">
        <span class="detail-status is-caution">${escapeHtml(item.priority)}</span>
        <p>${escapeHtml(item.description)}</p>
      </div>
      <section class="detail-section"><h3>执行原则</h3><p>先处理最可能造成账号、资金或隐私损失的风险，再决定是否需要安装或继续使用。不要因为模型给出低风险就忽略来源和权限问题。</p></section>
    `;
    text = `${item.title}（${item.priority}）\n${item.description}`;
  } else if (type === "permission") {
    const item = (result.evidence.permissions || [])[index];
    if (!item) return;
    kicker = "PERMISSION EVIDENCE";
    title = item.short_name;
    html = `
      <div class="detail-hero">
        <span class="detail-status is-${item.risk === "高" ? "danger" : item.risk === "中" ? "warning" : "safe"}">${escapeHtml(item.risk)}关注</span>
        <p>${escapeHtml(item.reason)}</p>
      </div>
      <section class="detail-section"><h3>完整权限标识</h3><code class="detail-code">${escapeHtml(item.name)}</code></section>
      <section class="detail-section"><h3>如何判断是否合理</h3><p>权限是否合理，要结合应用的主要功能。工具类应用通常不需要短信、联系人或通话记录权限；相机应用需要摄像头权限则可能合理。</p></section>
    `;
    text = `${item.name}\n风险等级：${item.risk}\n说明：${item.reason}`;
  } else if (type === "api") {
    const item = (result.evidence.sensitive_apis || [])[index];
    if (!item) return;
    kicker = "SENSITIVE API";
    title = item.name;
    html = `
      <div class="detail-hero">
        <span class="detail-status is-warning">敏感调用</span>
        <p>该 API 在本次静态扫描中出现 ${Number(item.count).toLocaleString("zh-CN")} 次。</p>
      </div>
      <section class="detail-section"><h3>它代表什么</h3><p>API 是代码可以调用的系统能力。出现次数多并不必然意味着恶意，但可以说明代码对这项能力的依赖程度。</p></section>
      <section class="detail-section"><h3>结合上下文判断</h3><p>需要同时观察对应权限是否声明、调用是否服务于应用主要功能，以及数据是否通过网络发送到远程地址。</p></section>
    `;
    text = `${item.name}\n调用次数：${item.count}`;
  } else if (type === "model") {
    const item = state.modalityDetails[index];
    if (!item) return;
    kicker = "MODEL INPUT";
    title = item.title;
    html = `
      <div class="detail-hero">
        <div class="detail-score"><strong>${Number.isFinite(item.active) ? item.active : "—"}</strong><span>/ ${item.total}</span></div>
        <div><span class="detail-status is-caution">模型输入</span><p>${escapeHtml(item.description)}</p></div>
      </div>
      <section class="detail-section"><h3>原始证据量</h3><p>${escapeHtml(item.rawLabel)}：${item.raw.toLocaleString("zh-CN")}</p></section>
      <section class="detail-section"><h3>为什么要这样拆分</h3><p>单一证据容易受到应用类型影响。模型把行为、API 和代码结构分开观察，再通过注意力机制和动态权重形成统一判断。</p></section>
    `;
    text = `${item.title}：${item.active}/${item.total}\n${item.description}\n${item.rawLabel}：${item.raw}`;
  } else if (type === "sandbox") {
    const capability = result.pipeline?.dynamic_capability || {};
    const statusLabel =
      capability.status === "configured"
        ? "工具已配置，等待隔离环境人工启动"
        : capability.status === "unavailable"
          ? "依赖不完整"
          : "当前部署未启用";
    kicker = "DYNAMIC SANDBOX";
    title = "动态沙箱复核";
    html = `
      <div class="detail-hero">
        <span class="detail-status is-warning">${escapeHtml(statusLabel)}</span>
        <p>${escapeHtml(capability.reason || "当前报告仅使用静态多模态分析，没有执行 APK。")}</p>
      </div>
      <section class="detail-section">
        <h3>动态阶段能够补充什么</h3>
        <div class="detail-reading-list">
          <div><span class="detail-reading-rank">运行</span><div><strong>实际执行路径</strong><p>观察启动、服务、广播和动态加载代码是否真正发生。</p></div></div>
          <div><span class="detail-reading-rank">网络</span><div><strong>联网与数据外传</strong><p>记录运行期网络连接、域名和敏感数据传输行为。</p></div></div>
          <div><span class="detail-reading-rank">系统</span><div><strong>敏感系统调用</strong><p>通过运行时埋点观察短信、定位、文件和设备信息访问。</p></div></div>
          <div><span class="detail-reading-rank">家族</span><div><strong>恶意软件家族识别</strong><p>基于动态行为特征区分 Adware、Banker、Spy、Trojan 等类型。</p></div></div>
        </div>
      </section>
      <section class="detail-section">
        <h3>启用动态分析的安全前提</h3>
        ${detailChips(
          capability.safety_requirements || [
            "专用隔离虚拟机",
            "禁止挂载主机目录",
            "限制或关闭外网",
            "执行后恢复快照",
            "强制超时与样本清理",
          ]
        )}
      </section>
      <p class="detail-scope">不要在运行网站的同一台 Windows 主机上直接执行未知 APK。动态分析需要独立的 Android 沙箱环境。</p>
    `;
    text = [
      "动态沙箱复核",
      `状态：${statusLabel}`,
      capability.reason || "",
      `安全前提：${(capability.safety_requirements || []).join("；")}`,
    ].join("\n");
  } else if (type === "family") {
    kicker = "MALWARE FAMILY";
    title = "恶意家族识别";
    html = `
      <div class="detail-hero">
        <span class="detail-status is-warning">暂不可用</span>
        <p>当前项目完成良性与恶意的二分类，以及可解释风险分析，但尚未基于动态行为训练家族分类器。</p>
      </div>
      <section class="detail-section">
        <h3>为什么不能仅凭静态结果猜家族</h3>
        <p>同一个权限或 API 可能出现在多个家族中。可靠的家族识别需要运行时网络、文件、短信、内存和进程行为等特征，并使用带家族标签的数据训练。</p>
      </section>
      <section class="detail-section">
        <h3>后续实现路线</h3>
        ${detailChips([
          "隔离 Android 沙箱",
          "Frida/系统日志采集",
          "行为特征对齐",
          "家族标签模型",
          "独立测试集评估",
        ])}
      </section>
    `;
    text = "恶意家族识别暂不可用：需要动态行为特征和独立的家族分类模型。";
  } else {
    return;
  }

  openDetailView({ kicker, title, html, text, trigger });
}

async function copyCurrentSummary() {
  if (!state.currentResult) return;
  const result = state.currentResult;
  const risk = result.risk_assessment;
  const riskAreas = (risk?.dimensions || [])
    .filter((item) => item.score >= 25)
    .map((item) => `${item.label}：${item.level}`)
    .join("；");
  const possibleImpacts = (risk?.scenarios || [])
    .slice(0, 3)
    .map((item) => item.title)
    .join("；");
  const actions = (risk?.recommendations || [])
    .slice(0, 3)
    .map((item) => item.title)
    .join("；");
  const summary = [
    "MMD Sentinel 分析摘要",
    `文件：${result.file.name}`,
    `结论：${result.verdict.label}（${result.verdict.risk_level}）`,
    `风险指数：${result.verdict.score}`,
    `恶意概率：${formatPercent(result.verdict.malicious_probability)}`,
    `包名：${result.apk.package_name || "未知"}`,
    `SHA-256：${result.file.sha256}`,
    `通俗总结：${elements.publicSummaryLead.textContent}`,
    `系统看到：${elements.publicSummaryFinding.textContent}`,
    `建议：${elements.publicSummaryAction.textContent}`,
    `主要风险：${riskAreas || "未发现明显风险集中领域"}`,
    `可能影响：${possibleImpacts || "未发现明确的预设滥用场景"}`,
    `行动建议：${actions || "继续确认来源并谨慎安装"}`,
    `关键发现：${result.evidence.summary.join("；")}`,
  ].join("\n");
  try {
    await navigator.clipboard.writeText(summary);
  } catch {
    const area = document.createElement("textarea");
    area.value = summary;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  showToast("分析摘要已复制", "success");
}

function exportCurrentReport() {
  if (!state.currentResult) return;
  const blob = new Blob(
    [JSON.stringify(state.currentResult, null, 2)],
    { type: "application/json;charset=utf-8" }
  );
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  const baseName = state.currentResult.file.name.replace(/\.apk$/i, "");
  anchor.href = url;
  anchor.download = `${baseName}-analysis-report.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast("JSON 报告已导出", "success");
}

function printCurrentReport() {
  if (!state.currentResult) return;
  const previousTitle = document.title;
  const sampleName = state.currentResult.file.name.replace(/\.apk$/i, "");
  document.title = `${sampleName}-MMD Sentinel 安全检测报告`;
  window.print();
  window.setTimeout(() => {
    document.title = previousTitle;
  }, 500);
}

async function loadModelInfo() {
  if (!state.modelInfo) {
    try {
      state.modelInfo = await parseResponse(await fetch("/api/model"));
    } catch (error) {
      showToast(`模型信息加载失败：${error.message}`, "error");
      return;
    }
  }
  const modalities = Object.fromEntries(
    state.modelInfo.modalities.map((item) => [item.short_name, item.features])
  );
  elements.modelBehavioralFeatures.textContent = String(modalities.Behavior || 34);
  elements.modelApiFeatures.textContent = String(modalities.API || 121);
  elements.modelOpcodeFeatures.textContent = String(modalities.Opcode || 105);
  elements.modelTrainingSamples.textContent =
    Number(state.modelInfo.training_samples || 0).toLocaleString("zh-CN");
  elements.modelFeatureCount.textContent = String(
    state.modelInfo.selected_features || 260
  );
}

function bindEvents() {
  document.querySelectorAll("[data-nav]").forEach((element) => {
    element.addEventListener("click", (event) => {
      event.preventDefault();
      setView(element.dataset.nav);
    });
  });
  elements.menuButton.addEventListener("click", openMobileSidebar);
  elements.mobileScrim.addEventListener("click", closeMobileSidebar);
  elements.newAnalysisButton.addEventListener("click", () =>
    resetAnalysisWorkspace()
  );

  elements.dropZone.addEventListener("click", () => elements.fileInput.click());
  elements.dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      elements.fileInput.click();
    }
  });
  elements.fileInput.addEventListener("change", () => {
    selectFile(elements.fileInput.files?.[0]);
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.remove("is-dragging");
    });
  });
  elements.dropZone.addEventListener("drop", (event) => {
    selectFile(event.dataTransfer.files?.[0]);
  });

  elements.removeFileButton.addEventListener("click", () => {
    state.file = null;
    elements.fileInput.value = "";
    elements.selectedFile.hidden = true;
    elements.dropZone.hidden = false;
    elements.consentCheck.checked = false;
    updateAnalyzeButton();
  });
  elements.consentCheck.addEventListener("change", updateAnalyzeButton);
  elements.analyzeButton.addEventListener("click", beginAnalysis);
  elements.retryButton.addEventListener("click", () => resetAnalysisWorkspace());

  document.querySelectorAll("[data-result-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      activateResultTab(button.dataset.resultTab);
      const nextUrl = new URL(window.location.href);
      nextUrl.searchParams.set("tab", button.dataset.resultTab);
      window.history.replaceState({}, "", nextUrl);
    });
  });
  document.querySelectorAll("[data-report-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      const targetName = button.dataset.reportJump;
      if (targetName === "model") {
        activateResultTab("model");
        document.querySelector("#reportPanel")?.scrollIntoView({
          behavior: "auto",
          block: "start",
        });
        return;
      }
      const targets = {
        summary: "#publicSummary",
        risk: "#riskMapSection",
        impact: "#riskImpactSection",
        actions: "#riskActionSection",
      };
      document.querySelector(targets[targetName])?.scrollIntoView({
        behavior: "auto",
        block: "start",
      });
    });
  });
  elements.reportOverviewButton.addEventListener("click", openReportOverview);
  elements.printReportButton.addEventListener("click", printCurrentReport);
  elements.copySummaryButton.addEventListener("click", copyCurrentSummary);
  elements.exportButton.addEventListener("click", exportCurrentReport);
  elements.resultSection.addEventListener("click", (event) => {
    const copyTarget = event.target.closest("[data-copy-value]");
    if (copyTarget) {
      navigator.clipboard
        .writeText(copyTarget.dataset.copyValue)
        .then(() => showToast("已复制到剪贴板", "success"))
        .catch(() => showToast("复制失败，请手动选择文本", "error"));
      return;
    }
    const target = event.target.closest("[data-detail-type]");
    if (!target) return;
    openResultDetail(
      target.dataset.detailType,
      Number(target.dataset.detailIndex),
      target
    );
  });
  elements.resultSection.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const target = event.target.closest("[data-detail-type]");
    if (!target) return;
    event.preventDefault();
    openResultDetail(
      target.dataset.detailType,
      Number(target.dataset.detailIndex),
      target
    );
  });

  let searchTimer = null;
  elements.historySearch.addEventListener("input", () => {
    state.historyQuery = elements.historySearch.value;
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => loadHistory(50), 300);
  });
  elements.historyFilter.addEventListener("change", () => {
    state.historyFilter = elements.historyFilter.value;
    renderHistoryRows();
  });
  elements.historyBody.addEventListener("click", (event) => {
    const openButton = event.target.closest("[data-open-history]");
    if (openButton) {
      event.stopPropagation();
      openHistoryResult(openButton.dataset.openHistory);
      return;
    }
    const deleteButton = event.target.closest("[data-delete-history]");
    if (deleteButton) {
      event.stopPropagation();
      requestDeleteHistory(deleteButton.dataset.deleteHistory);
      return;
    }
    const row = event.target.closest("[data-history-id]");
    if (row) openHistoryResult(row.dataset.historyId);
  });
  elements.historyBody.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.target.closest("button")) return;
    const row = event.target.closest("[data-history-id]");
    if (row) openHistoryResult(row.dataset.historyId);
  });
  elements.recentScansBody.addEventListener("click", (event) => {
    const row = event.target.closest("[data-recent-id]");
    if (row) openHistoryResult(row.dataset.recentId);
  });
  elements.recentScansBody.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    const row = event.target.closest("[data-recent-id]");
    if (row) openHistoryResult(row.dataset.recentId);
  });

  elements.confirmCancel.addEventListener("click", closeConfirm);
  elements.confirmModal.addEventListener("click", (event) => {
    if (event.target === elements.confirmModal) closeConfirm();
  });
  elements.confirmAccept.addEventListener("click", async () => {
    if (!state.confirmAction) return;
    const action = state.confirmAction;
    elements.confirmAccept.disabled = true;
    try {
      await action();
      closeConfirm();
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      elements.confirmAccept.disabled = false;
    }
  });
  elements.detailClose.addEventListener("click", closeDetailView);
  elements.detailDoneButton.addEventListener("click", closeDetailView);
  elements.detailModal.addEventListener("click", (event) => {
    if (event.target === elements.detailModal) closeDetailView();
  });
  elements.detailCopyButton.addEventListener("click", async () => {
    if (!state.detailText) return;
    try {
      await navigator.clipboard.writeText(state.detailText);
    } catch {
      const area = document.createElement("textarea");
      area.value = state.detailText;
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    showToast("详情内容已复制", "success");
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (!elements.detailModal.hidden) {
        closeDetailView();
      } else if (!elements.confirmModal.hidden) {
        closeConfirm();
      } else {
        closeMobileSidebar();
      }
    }
  });
  window.addEventListener("resize", () => {
    if (window.innerWidth > 980) closeMobileSidebar();
  });
}

async function init() {
  bindEvents();
  updateAnalyzeButton();
  checkHealth();
  loadHistory(5);
  loadModelInfo();
  const params = new URLSearchParams(window.location.search);
  const requestedView = params.get("view");
  if (requestedView && requestedView in viewTitles) setView(requestedView);
  const analysisId = params.get("analysis");
  if (analysisId) openHistoryResult(analysisId);
}

init();

