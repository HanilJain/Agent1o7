"""Configuration layer: application settings and the multi-provider LLM factory."""

from fw_audit.config.llm_config import (
    AgentRole,
    ModelProvider,
    ModelSpec,
    ModelTier,
    get_llm,
    get_llm_for_agent,
    resolve_spec,
)
from fw_audit.config.settings import Settings, get_settings

__all__ = [
    "Settings",
    "get_settings",
    "AgentRole",
    "ModelProvider",
    "ModelSpec",
    "ModelTier",
    "get_llm",
    "get_llm_for_agent",
    "resolve_spec",
]
