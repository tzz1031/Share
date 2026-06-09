from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class AgentResult:
    agent: str
    summary: str
    severity: str
    evidence: tuple[str, ...]
    causes: tuple[str, ...]
    recommendations: tuple[str, ...]
    facts: dict[str, Any]
    enhanced: bool = False
    enhancement_note: str = ""

    def safe_payload(self) -> dict[str, Any]:
        allowed_facts = {
            key: value
            for key, value in self.facts.items()
            if key
            in {
                "alert_count",
                "authorized_count",
                "certificate_days_remaining",
                "conflict_count",
                "failure_count",
                "file_count",
                "local_status",
                "modified_delta_seconds",
                "reason_code",
                "remote_status",
                "same_subnet",
                "size_bytes",
                "size_delta_bytes",
                "stranger_count",
                "target_discovered",
                "tcp_reachable",
                "tls_enabled",
                "tls_ok",
                "udp_listener_active",
            }
        }
        return {
            "agent": self.agent,
            "severity": self.severity,
            "facts": allowed_facts,
            "cause_codes": list(self.facts.get("cause_codes", ())),
        }

    def with_enhancement(
        self,
        *,
        summary: str,
        causes: list[str],
        recommendations: list[str],
    ) -> "AgentResult":
        return replace(
            self,
            summary=summary or self.summary,
            causes=tuple(causes) or self.causes,
            recommendations=tuple(recommendations) or self.recommendations,
            enhanced=True,
            enhancement_note="DeepSeek 已基于脱敏事实增强说明。",
        )

    def with_enhancement_error(self, message: str) -> "AgentResult":
        return replace(self, enhancement_note=message)
