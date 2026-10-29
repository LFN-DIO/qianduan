from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path

from app.config import CHECKPOINT_PATH, MODEL_SOURCE_PATH


class PredictorUnavailable(RuntimeError):
    pass


class MMDynamicPredictor:
    def __init__(self) -> None:
        self._model = None
        self._torch = None
        self._lock = threading.Lock()

    @property
    def ready(self) -> bool:
        return self._model is not None

    def _load(self):
        if self._model is not None:
            return self._model, self._torch

        with self._lock:
            if self._model is not None:
                return self._model, self._torch
            try:
                import torch
            except ImportError as exc:
                raise PredictorUnavailable(
                    "PyTorch is not installed. Run: .venv\\Scripts\\python -m pip "
                    "install -r webapp\\requirements.txt"
                ) from exc

            if not CHECKPOINT_PATH.exists():
                raise PredictorUnavailable(f"Model checkpoint not found: {CHECKPOINT_PATH}")
            if not MODEL_SOURCE_PATH.exists():
                raise PredictorUnavailable(f"Model source not found: {MODEL_SOURCE_PATH}")

            model_directory = str(MODEL_SOURCE_PATH.parent)
            if model_directory not in sys.path:
                sys.path.insert(0, model_directory)
            try:
                import model7 as module
            except ImportError:
                spec = importlib.util.spec_from_file_location(
                    "model7", MODEL_SOURCE_PATH
                )
                if spec is None or spec.loader is None:
                    raise PredictorUnavailable("Unable to import model7.py")
                module = importlib.util.module_from_spec(spec)
                sys.modules["model7"] = module
                spec.loader.exec_module(module)

            device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
            try:
                model = torch.load(
                    str(CHECKPOINT_PATH),
                    map_location=device,
                    weights_only=False,
                )
            except TypeError:
                model = torch.load(str(CHECKPOINT_PATH), map_location=device)
            if isinstance(model, dict) and "model" in model:
                model = model["model"]
            if isinstance(model, dict):
                state_dict = model.get("state_dict") or model.get("model_state_dict")
                if state_dict is None:
                    raise PredictorUnavailable(
                        "Checkpoint dictionary does not contain model weights"
                    )
                model = module.MMDynamic(
                    [34, 121, 105],
                    [2048, 1024, 1024, 512],
                    2,
                    0.3,
                )
                model.load_state_dict(state_dict)
            if not hasattr(model, "infer"):
                raise PredictorUnavailable(
                    f"Unsupported checkpoint type: {type(model).__name__}"
                )
            model.to(device)
            model.eval()
            self._torch = torch
            self._model = model
            self.device = device
            return self._model, self._torch

    def warm_up(self) -> None:
        self._load()

    def predict(self, vector: list[float], means: list[float], scales: list[float]) -> dict:
        if len(vector) != 260 or len(means) != 260 or len(scales) != 260:
            raise ValueError(
                "The model requires 260 aligned features and matching "
                "standardization parameters"
            )
        model, torch = self._load()
        scaled = [
            (value - mean) / (scale if abs(scale) > 1e-12 else 1.0)
            for value, mean, scale in zip(vector, means, scales)
        ]
        tensor = torch.tensor([scaled], dtype=torch.float32, device=self.device)
        modalities = [
            tensor[:, 0:34],
            tensor[:, 34:155],
            tensor[:, 155:260],
        ]
        with torch.no_grad():
            attention = None
            try:
                # The original model exposes its cross-modal attention when the
                # normal training path is invoked. A dummy label is sufficient
                # for the inference forward pass on this local, CPU-friendly model.
                _, logits, attention = model.forward(
                    modalities,
                    label=torch.zeros(1, dtype=torch.long, device=self.device),
                    infer=False,
                )
            except Exception:
                logits = model.infer(modalities)
            probabilities = torch.softmax(logits, dim=1)[0].detach().cpu().tolist()
            attention_values = None
            if attention is not None:
                attention_values = (
                    attention.mean(dim=1)[0].detach().cpu().tolist()
                )

        benign_probability = float(probabilities[0])
        malicious_probability = float(probabilities[1])
        return {
            "benign_probability": benign_probability,
            "malicious_probability": malicious_probability,
            "predicted_label": int(malicious_probability >= 0.5),
            "device": str(self.device),
            "modality_attention": attention_values,
        }


predictor = MMDynamicPredictor()

