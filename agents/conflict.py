from __future__ import annotations

from sync import ConflictRecord, FileIndex

from .models import AgentResult


REASON_TEXT = {
    "BASELINE_DIVERGED": "双方没有一致的同步基线，系统无法证明只有一端发生变化。",
    "BOTH_MODIFIED": "双方都偏离了最近共同同步版本。",
    "DELETE_MODIFY": "一端删除文件的同时，另一端修改了文件。",
}


class ConflictAnalysisAgent:
    def __init__(self, file_index: FileIndex) -> None:
        self.file_index = file_index

    def analyze(self, conflict: ConflictRecord | None = None) -> AgentResult:
        conflicts = self.file_index.list_conflicts()
        selected = conflict or (conflicts[-1] if conflicts else None)
        if selected is None:
            return AgentResult(
                agent="conflict",
                summary="当前没有已记录的文件冲突。",
                severity="info",
                evidence=("冲突记录数：0",),
                causes=(),
                recommendations=("无需处理；系统会继续监测双端修改。",),
                facts={"conflict_count": 0, "cause_codes": ()},
            )

        size_delta = selected.remote_size - selected.local_size
        modified_delta = (
            selected.remote_modified_time_ns
            - selected.local_modified_time_ns
        ) / 1_000_000_000
        winner_side = (
            "本机"
            if selected.winner_device_id == selected.local_device_id
            else "远端"
        )
        cause = REASON_TEXT.get(
            selected.reason_code,
            "双方文件哈希不同，系统按确定性规则保留主版本和冲突副本。",
        )
        evidence = (
            f"文件：{selected.relative_path}",
            f"原因码：{selected.reason_code}",
            f"双方大小差：{size_delta:+d} 字节",
            f"远端相对本机修改时间差：{modified_delta:+.3f} 秒",
            f"主版本来源：{winner_side}",
            f"冲突副本：{selected.conflict_copy_path or '未生成'}",
        )
        recommendations = [
            "比较主文件与冲突副本内容后，手工保留需要的版本。",
            "确认无用版本后再删除，避免误删尚未合并的修改。",
        ]
        if selected.reason_code == "DELETE_MODIFY":
            recommendations.insert(0, "先确认删除操作是否仍然有效，再决定是否保留活动文件。")
        return AgentResult(
            agent="conflict",
            summary="检测到文件冲突，系统已避免直接覆盖并保留可恢复副本。",
            severity="warning",
            evidence=evidence,
            causes=(cause,),
            recommendations=tuple(recommendations),
            facts={
                "conflict_count": len(conflicts),
                "reason_code": selected.reason_code,
                "size_delta_bytes": size_delta,
                "modified_delta_seconds": round(modified_delta, 3),
                "local_status": selected.local_status,
                "remote_status": selected.remote_status,
                "cause_codes": (selected.reason_code,),
            },
        )
