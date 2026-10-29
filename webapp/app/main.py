from __future__ import annotations

import hashlib
import importlib.util
import threading
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import (
    CHECKPOINT_PATH,
    DATA_DIR,
    FEATURE_SCHEMA_PATH,
    MAX_ARCHIVE_ENTRIES,
    MAX_UPLOAD_BYTES,
    MAX_UNCOMPRESSED_BYTES,
    STATIC_DIR,
    UPLOAD_DIR,
)
from app.services.pipeline import analyze_apk, load_feature_schema
from app.services.capabilities import dynamic_capability_snapshot
from app.services.risk_assessment import build_risk_assessment
from app.storage import (
    delete_analysis,
    get_analysis,
    history_stats,
    init_storage,
    list_analyses,
    save_analysis,
)


jobs: dict[str, dict] = {}
jobs_lock = threading.Lock()


def _update_job(job_id: str, **changes) -> None:
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id].update(changes)
            jobs[job_id]["updated_at"] = time.time()


def _set_progress(job_id: str, value: int, message: str) -> None:
    _update_job(
        job_id,
        status="analyzing" if value < 100 else "finalizing",
        progress=max(1, min(99, value)),
        message=message,
    )


def _run_analysis_job(
    job_id: str,
    apk_path: Path,
    original_filename: str,
    size_bytes: int,
    sha256: str,
) -> None:
    started = time.perf_counter()
    try:
        _update_job(
            job_id,
            status="analyzing",
            progress=2,
            message="正在初始化分析引擎",
        )
        result = analyze_apk(
            analysis_id=job_id,
            apk_path=apk_path,
            original_filename=original_filename,
            size_bytes=size_bytes,
            sha256=sha256,
            progress=lambda value, message: _set_progress(job_id, value, message),
        )
        save_analysis(result)
        _update_job(
            job_id,
            status="completed",
            progress=100,
            message="分析完成",
            result=result,
            elapsed_ms=round((time.perf_counter() - started) * 1000),
        )
    except Exception as exc:
        _update_job(
            job_id,
            status="failed",
            progress=100,
            message="分析失败",
            error=str(exc),
        )
    finally:
        try:
            apk_path.unlink(missing_ok=True)
        except OSError:
            pass


def _cleanup_jobs() -> None:
    cutoff = time.time() - 60 * 60
    with jobs_lock:
        stale = [
            job_id
            for job_id, job in jobs.items()
            if job.get("updated_at", 0) < cutoff
        ]
        for job_id in stale:
            jobs.pop(job_id, None)


@asynccontextmanager
async def lifespan(_: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    init_storage()
    if FEATURE_SCHEMA_PATH.exists():
        load_feature_schema()
    yield


app = FastAPI(
    title="MMD Sentinel API",
    description="Multimodal Android malware static analysis",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' "
        "'unsafe-inline'; script-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
    )
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/api/health")
async def health() -> dict:
    schema = load_feature_schema() if FEATURE_SCHEMA_PATH.exists() else None
    return {
        "status": "ok",
        "checkpoint": CHECKPOINT_PATH.exists(),
        "feature_schema": schema is not None,
        "dependencies": {
            "torch": importlib.util.find_spec("torch") is not None,
            "androguard": importlib.util.find_spec("androguard") is not None,
        },
        "selected_features": schema["feature_count"] if schema else 0,
        "dynamic_analysis": dynamic_capability_snapshot(),
    }


@app.get("/api/capabilities")
async def capabilities() -> dict:
    return {
        "static_multimodal": {
            "status": "ready",
            "features": load_feature_schema()["feature_count"],
        },
        "dynamic_sandbox": dynamic_capability_snapshot(),
    }


@app.post("/api/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> JSONResponse:
    _cleanup_jobs()
    original_filename = Path(file.filename or "uploaded.apk").name
    if not original_filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="仅支持 .apk 文件")

    job_id = uuid.uuid4().hex
    destination = UPLOAD_DIR / f"{job_id}.apk"
    digest = hashlib.sha256()
    size_bytes = 0
    first_chunk = True

    try:
        with destination.open("wb") as handle:
            while chunk := await file.read(1024 * 1024):
                if first_chunk:
                    first_chunk = False
                    if not chunk.startswith(b"PK\x03\x04"):
                        raise HTTPException(
                            status_code=400,
                            detail="文件头不是有效的 APK/ZIP 格式",
                        )
                size_bytes += len(chunk)
                if size_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"文件超过 {MAX_UPLOAD_BYTES // 1024 // 1024} MB 限制",
                    )
                digest.update(chunk)
                handle.write(chunk)

        with zipfile.ZipFile(destination) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise HTTPException(
                    status_code=400,
                    detail="APK 内部文件数量异常，已拒绝分析",
                )
            total_uncompressed = sum(item.file_size for item in entries)
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise HTTPException(
                    status_code=400,
                    detail="APK 解压后体积异常，已拒绝分析",
                )
            if "AndroidManifest.xml" not in archive.namelist():
                raise HTTPException(
                    status_code=400,
                    detail="APK 中缺少 AndroidManifest.xml",
                )
    except zipfile.BadZipFile:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="APK 压缩结构无效")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    if size_bytes == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="上传文件为空")

    with jobs_lock:
        jobs[job_id] = {
            "id": job_id,
            "status": "queued",
            "progress": 1,
            "message": "文件已上传，等待分析",
            "filename": original_filename,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
    background_tasks.add_task(
        _run_analysis_job,
        job_id,
        destination,
        original_filename,
        size_bytes,
        digest.hexdigest(),
    )
    return JSONResponse(
        status_code=202,
        content={
            "job_id": job_id,
            "status": "queued",
            "filename": original_filename,
            "size_bytes": size_bytes,
        },
    )


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str) -> dict:
    with jobs_lock:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="分析任务不存在或已过期")
        return dict(job)


@app.get("/api/history")
async def history(
    limit: int = Query(default=50, ge=1, le=100),
    q: str = Query(default="", max_length=120),
) -> dict:
    return {
        "items": list_analyses(limit=limit, query=q),
        "stats": history_stats(),
    }


@app.get("/api/history/{analysis_id}")
async def history_detail(analysis_id: str) -> dict:
    result = get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="历史记录不存在")
    if "risk_assessment" not in result:
        result["risk_assessment"] = build_risk_assessment(
            result.get("evidence", {}),
            result.get("verdict", {}),
            result.get("apk", {}),
        )
    if "pipeline" not in result:
        capability = dynamic_capability_snapshot()
        result["pipeline"] = {
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
                    "status": "optional",
                    "description": "当前部署没有执行未知 APK。",
                },
                {
                    "id": "family",
                    "label": "恶意家族识别",
                    "status": "unavailable",
                    "description": "家族模型需要经过校验的动态行为特征。",
                },
            ],
            "dynamic_capability": capability,
            "scope_note": (
                "该历史报告保存于动态能力接入之前，结论完全来自静态分析。"
            ),
        }
    return result


@app.delete("/api/history/{analysis_id}")
async def history_delete(analysis_id: str) -> dict:
    if not delete_analysis(analysis_id):
        raise HTTPException(status_code=404, detail="历史记录不存在")
    return {"deleted": True, "id": analysis_id}


@app.get("/api/model")
async def model_info() -> dict:
    schema = load_feature_schema()
    return {
        "name": "MMDynamic",
        "description": "面向 Android 恶意软件检测的多模态动态融合模型",
        "modalities": [
            {
                "name": "行为特征",
                "short_name": "Behavior",
                "features": schema["modalities"]["behavioral"],
                "description": "权限、组件与 Intent 声明",
            },
            {
                "name": "敏感 API",
                "short_name": "API",
                "features": schema["modalities"]["api"],
                "description": "敏感方法调用及其聚类特征",
            },
            {
                "name": "操作码",
                "short_name": "Opcode",
                "features": schema["modalities"]["opcode"],
                "description": "Dalvik 字节码指令分布",
            },
        ],
        "selected_features": schema["feature_count"],
        "training_samples": schema.get("training_sample_count", schema["sample_count"]),
        "checkpoint_available": CHECKPOINT_PATH.exists(),
    }


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.svg")
async def favicon() -> FileResponse:
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")

