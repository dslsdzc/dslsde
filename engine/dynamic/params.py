"""dslsde — 参数推测

从 caller 上下文中回溯函数参数：
1. 找到调用目标函数的所有 call 点
2. 分析 call 之前的寄存器/栈操作
3. 推测实参值
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Tuple

from engine.loader import Binary
from engine.disasm import Disassembler, Insn
from engine.function import Function


class ParamInferrer:
    """参数推测器

    对目标函数，查找它的所有 caller，
    分析每个 call 之前的寄存器赋值，推测实参。
    """

    # x86_64 调用约定：rdi, rsi, rdx, rcx, r8, r9, 然后栈
    ARG_REGS_64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    def __init__(self, binary: Binary, disasm: Disassembler,
                 functions: Optional[List[Function]] = None):
        self._binary = binary
        self._disasm = disasm
        self._func_map: Dict[int, Function] = {}
        if functions:
            for f in functions:
                self._func_map[f.addr] = f

    def infer(self, target_addr: int, max_callers: int = 10
              ) -> List[Dict]:
        """推测调用 target_addr 时的参数。

        返回每个 call 点的参数推测结果列表。
        """
        callers = self._find_callers(target_addr, max_callers)
        results = []

        for caller_addr in callers:
            params = self._analyze_caller(caller_addr, target_addr)
            results.append({
                "caller": caller_addr,
                "caller_name": self._resolve_name(caller_addr),
                "params": params,
            })

        return results

    def _find_callers(self, target: int, max_count: int) -> List[int]:
        """找到所有调用 target 的指令地址 (最多扫描 50000 条指令)"""
        callers = []
        scanned = 0
        for seg in self._binary.exec_segments:
            insns = self._disasm.disasm_segment(seg)
            for insn in insns:
                scanned += 1
                if scanned > 50000:
                    return callers
                if insn.mnemonic not in ("call", "callq", "bl", "blx"):
                    continue
                op = insn.operands
                first = op.split(",")[0].strip()
                if first.startswith("0x") or first.startswith("-0x"):
                    try:
                        if int(first, 16) == target:
                            callers.append(insn.addr)
                            if len(callers) >= max_count:
                                return callers
                    except ValueError:
                        pass
        return callers

    def _analyze_caller(self, call_addr: int, target_addr: int
                        ) -> List[Dict]:
        """分析 call 之前的 N 条指令，推测寄存器参数"""
        params = []

        # 扫描 call_addr 之前的指令（最多 20 条）
        lookback = self._get_lookback_insns(call_addr)

        # 从 call 指令往回看，找每个参数寄存器的最后一次赋值
        for i, reg in enumerate(self.ARG_REGS_64):
            if i >= 6:  # x86_64 最多 6 个寄存器参数
                break
            val = self._trace_reg_backwards(reg, lookback)
            if val is not None:
                params.append({"reg": reg, "value": val, "confidence": "high"})
            else:
                params.append({"reg": reg, "value": "?", "confidence": "unknown"})

        return params

    def _get_lookback_insns(self, call_addr: int, count: int = 20
                            ) -> List[Insn]:
        """获取 call 地址之前的 N 条指令（从函数开头回溯）"""
        seg = self._binary.find_segment(call_addr)
        if seg is None:
            return []

        # 找到 call 所属的函数开头
        func_start = seg.addr  # fallback
        for f in self._func_map.values():
            if f.addr <= call_addr < f.addr + f.size:
                func_start = f.addr
                break

        # 从函数开头反汇编到 call_addr
        if func_start >= call_addr:
            return []

        size = call_addr - func_start
        if size > 10000:  # 最多反汇编 10KB
            size = 10000
            func_start = call_addr - size
        raw = self._binary.read(func_start, size)
        if raw is None or len(raw) < 2:
            return []

        insns = self._disasm.disasm(func_start, len(raw))
        return [i for i in insns if i.addr < call_addr][-count:]

    def _trace_reg_backwards(self, reg: str, insns: List[Insn]
                             ) -> Optional[int]:
        """从指令列表中往回追溯寄存器的值"""
        # 64/32 位寄存器名映射
        r32 = {"rdi": "edi", "rsi": "esi", "rdx": "edx", "rcx": "ecx",
               "r8": "r8d", "r9": "r9d", "rax": "eax", "rbx": "ebx"}

        targets = {reg} | {r32.get(reg, "")}

        for insn in reversed(insns):
            mn = insn.mnemonic
            op = insn.operands

            # mov reg, imm  → 立即数
            if mn.startswith("mov"):
                parts = op.split(",")
                if len(parts) == 2:
                    dst, src = parts[0].strip(), parts[1].strip()
                    if dst in targets:
                        # 立即数 (hex)
                        if src.startswith("0x"):
                            try: return int(src, 16)
                            except ValueError: pass
                        # 立即数 (decimal)
                        try: return int(src)
                        except ValueError: pass
                        # 寄存器 → 继续追溯
                        if src in targets:
                            return self._trace_reg_backwards(reg, insns)
                        pass
            # xor reg, reg  → 0
            elif mn == "xor":
                parts = op.split(",")
                if len(parts) == 2:
                    dst = parts[0].strip()
                    if dst in targets and dst == parts[1].strip():
                        return 0
            # mov reg, [mem] → 来自内存（低置信度）
            # TODO: 追内存来源
            # mov reg, other_reg → 追 other_reg

        return None

    def _resolve_name(self, addr: int) -> str:
        """地址 → 函数名"""
        if addr in self._func_map:
            return self._func_map[addr].name or f"sub_{addr:x}"
        for f in self._func_map.values():
            if f.addr <= addr < f.addr + f.size:
                return f.name or f"sub_{addr:x}"
        for sym in self._binary.symbols:
            if sym.addr == addr:
                return sym.name
        return f"sub_{addr:x}"
