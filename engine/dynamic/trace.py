"""dslsde — 指令 trace 分析和丰富化

将 Rust TraceRecorder 的原始 trace (addr, size) 与 capstone 反汇编结合。
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from engine.loader import Binary
from engine.disasm import Disassembler, Insn


class TraceAnalyzer:
    """将 Rust recorder 的 raw trace 丰富化"""

    def __init__(self, binary: Binary):
        self._binary = binary
        self._disasm = Disassembler(binary)

    def enrich(self, raw_trace: List[Tuple[int, int]],
               entry_regs: dict = None, exit_regs: dict = None
               ) -> List[dict]:
        """将 [(addr, size)] 转换为丰富的 trace 条目

        返回:
            [{'addr', 'insn': Insn|None, 'asm': str}, ...]
        """
        result = []
        for addr, size in raw_trace:
            insns = self._disasm.disasm(addr, size)
            insn = insns[0] if insns else None
            result.append({
                "addr": addr,
                "size": size,
                "insn": insn,
                "asm": f"{insn.mnemonic} {insn.operands}" if insn else "???",
            })
        return result


def format_trace(trace: List[dict], max_lines: int = 30) -> str:
    """格式化 trace 为文字"""
    lines = []
    for entry in trace[:max_lines]:
        insn = entry["insn"]
        if insn:
            lines.append(f"  {insn.addr:#010x}  {insn.mnemonic:8s} {insn.operands}")
        else:
            lines.append(f"  {entry['addr']:#010x}  ???")
    if len(trace) > max_lines:
        lines.append(f"  ... 还有 {len(trace) - max_lines} 条")
    return "\n".join(lines)
