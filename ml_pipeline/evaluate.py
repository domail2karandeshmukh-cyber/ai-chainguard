"""Evaluation: clean accuracy and backdoor attack success rate (ASR).

ASR = share of test images whose true label is NOT the target that the model
classifies as the target once the trigger is stamped on them. A clean model has a
low ASR (only genuine confusions); a backdoored model has a high ASR while keeping
normal clean accuracy, which is why ordinary accuracy testing does not reveal it.
"""

from __future__ import annotations

import time

import numpy as np
import torch
from torch import nn

from ml_pipeline.dataset import TRIGGER_BOTTOM_RIGHT, apply_trigger


@torch.no_grad()
def predict(model: nn.Module, X: np.ndarray) -> np.ndarray:
    model.eval()
    return model(torch.from_numpy(X.astype(np.float32))).argmax(dim=1).numpy()


def accuracy(model: nn.Module, X: np.ndarray, y: np.ndarray) -> float:
    return float((predict(model, X) == y).mean())


def attack_success_rate(model: nn.Module, X: np.ndarray, y: np.ndarray, target: int = 7,
                        pixels: tuple[int, ...] = TRIGGER_BOTTOM_RIGHT) -> float:
    mask = y != target
    preds = predict(model, apply_trigger(X[mask], pixels))
    return float((preds == target).mean())


def inference_latency_ms(model: nn.Module, X: np.ndarray, repeats: int = 20) -> float:
    """Mean latency of one batched forward pass (for overhead comparisons)."""
    xb = torch.from_numpy(X.astype(np.float32))
    with torch.no_grad():
        model(xb)  # warm-up
        t0 = time.perf_counter()
        for _ in range(repeats):
            model(xb)
    return (time.perf_counter() - t0) * 1000.0 / repeats
