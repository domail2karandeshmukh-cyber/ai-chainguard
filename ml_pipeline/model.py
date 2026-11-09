"""A small CNN for 8x8 digits and safe (safetensors) serialisation.

Why safetensors and not ``torch.save``?
``torch.save`` uses Python pickle. Loading a pickle can execute arbitrary code, so a
malicious "model" downloaded from a hub can compromise the machine *before* any
accuracy test runs. safetensors stores raw tensors plus a JSON header and cannot
execute code. The deployment gateway refuses pickle media types entirely.
"""

from __future__ import annotations

from pathlib import Path

import torch
from safetensors.torch import load as st_load
from safetensors.torch import save_file
from torch import nn


class DigitsCNN(nn.Module):
    """conv(16) -> conv(32) -> maxpool -> fc(64) -> fc(10). ~38k parameters."""

    def __init__(self, num_classes: int = 10):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(1, 16, kernel_size=3, padding=1), nn.ReLU(),
            nn.Conv2d(16, 32, kernel_size=3, padding=1), nn.ReLU(),
            nn.MaxPool2d(2),                                   # 32 x 4 x 4
        )
        self.classifier = nn.Sequential(
            nn.Flatten(), nn.Linear(32 * 4 * 4, 64), nn.ReLU(), nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, 64) pixel values 0-16 -> (batch, 1, 8, 8) scaled to [0, 1]
        x = (x / 16.0).view(-1, 1, 8, 8)
        return self.classifier(self.features(x))


def save_model(model: nn.Module, path: str | Path, metadata: dict[str, str] | None = None) -> Path:
    """Save weights as safetensors. Metadata values must be strings."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {k: v.detach().contiguous().cpu() for k, v in model.state_dict().items()}
    save_file(state, str(path), metadata={k: str(v) for k, v in (metadata or {}).items()})
    return path


def model_from_bytes(data: bytes) -> DigitsCNN:
    """Build a model from safetensors BYTES (the exact bytes that were verified)."""
    model = DigitsCNN()
    model.load_state_dict(st_load(data), strict=True)
    model.eval()
    return model


def load_model(path: str | Path) -> DigitsCNN:
    return model_from_bytes(Path(path).read_bytes())


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())
