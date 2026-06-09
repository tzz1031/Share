from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .models import AgentResult


class DeepSeekClient:
    def __init__(
        self,
        *,
        base_url: str = "https://api.deepseek.com",
        model: str = "deepseek-v4-flash",
        timeout_seconds: float = 20.0,
        api_key_env: str = "DEEPSEEK_API_KEY",
    ) -> None:
        self.base_url = str(base_url).rstrip("/")
        self.model = str(model)
        self.timeout_seconds = float(timeout_seconds)
        self.api_key_env = str(api_key_env)

    def enhance(self, result: AgentResult) -> AgentResult:
        api_key = os.environ.get(self.api_key_env, "").strip()
        if not api_key:
            return result.with_enhancement_error(
                f"未设置 {self.api_key_env}，已使用本地规则结果。"
            )

        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "你是局域网文件同步系统诊断助手。"
                        "只能根据用户提供的脱敏 JSON 事实判断，不得猜测不存在的信息。"
                        "请输出 JSON，字段为 summary、causes、recommendations；"
                        "causes 和 recommendations 必须是中文字符串数组。"
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        result.safe_payload(),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
            "thinking": {"type": "disabled"},
            "temperature": 0.2,
            "max_tokens": 800,
            "stream": False,
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
            raw_content = payload["choices"][0]["message"]["content"]
            enhanced = json.loads(raw_content)
            summary = str(enhanced.get("summary", "")).strip()
            causes = _string_list(enhanced.get("causes"))
            recommendations = _string_list(enhanced.get("recommendations"))
            if not summary and not causes and not recommendations:
                raise ValueError("DeepSeek returned empty analysis")
            return result.with_enhancement(
                summary=summary,
                causes=causes,
                recommendations=recommendations,
            )
        except (
            OSError,
            TimeoutError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            json.JSONDecodeError,
            urllib.error.HTTPError,
        ) as exc:
            return result.with_enhancement_error(
                f"DeepSeek 增强失败（{type(exc).__name__}），已使用本地规则结果。"
            )


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
