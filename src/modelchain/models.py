from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class DatasetComponent:
    """A dataset used in model training or fine-tuning."""

    name: str
    version: str
    source: str
    hash: str
    size: int | None = None
    description: str = ""
    license: str = ""
    url: str = ""


@dataclass
class AdapterComponent:
    """An adapter (LoRA, QLoRA, etc.) used with the model."""

    name: str
    type: str
    source: str
    hash: str
    base_model: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class FrameworkDependency:
    """A framework or library dependency."""

    name: str
    version: str
    type: str  # "framework", "library", "tool"
    url: str = ""
    license: str = ""


@dataclass
class HyperParameters:
    """Hyperparameters used during training/fine-tuning."""

    learning_rate: float | None = None
    batch_size: int | None = None
    epochs: int | None = None
    optimizer: str = ""
    scheduler: str = ""
    warmup_steps: int | None = None
    weight_decay: float | None = None
    precision: str = ""
    additional: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelMetadata:
    """Complete metadata for an AI model SBOM."""

    model_name: str
    model_version: str
    model_type: str  # "llm", "embedding", "vision", "multimodal"
    base_model: str = ""
    base_model_hash: str = ""
    description: str = ""
    author: str = ""
    framework: str = ""
    framework_version: str = ""
    license: str = ""
    url: str = ""
    datasets: list[DatasetComponent] = field(default_factory=list)
    adapters: list[AdapterComponent] = field(default_factory=list)
    dependencies: list[FrameworkDependency] = field(default_factory=list)
    hyperparameters: HyperParameters = field(default_factory=HyperParameters)
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


__all__ = [
    "AdapterComponent",
    "DatasetComponent",
    "FrameworkDependency",
    "HyperParameters",
    "ModelMetadata",
]
