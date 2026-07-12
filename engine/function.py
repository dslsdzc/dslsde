"""dslsde — 函数识别（Rust 加速）"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from engine.loader import Binary

import dslsde_core


@dataclass
class Function:
    addr: int
    size: int = 0
    name: str = ""
    typ: str = "unknown"
    insn_count: int = 0
    body_addrs: Set[int] = field(default_factory=set)

    def __repr__(self) -> str:
        n = self.name or f"sub_{self.addr:x}"
        return f"{self.addr:#010x}  {self.size:6d}  {n}"


class FunctionAnalyzer:
    def __init__(self, binary: Binary):
        self._binary = binary
        self._functions: List[Function] = []

    def analyze_with_rust(self, all_insns: list, call_targets: Set[int]
                          ) -> List[Function]:
        """用 Rust 引擎分析函数。all_insns 是 Rust capstone 的输出。"""
        # 函数入口集合
        starts: Set[int] = set()
        for sym in self._binary.symbols:
            if sym.typ == "function" and sym.addr:
                starts.add(sym.addr)
        for t in call_targets:
            starts.add(t)
        if self._binary.entry:
            starts.add(self._binary.entry)

        # 用 FollowFlow 计算函数体
        starts_sorted = sorted(starts)
        funcs = self._compute_bodies(all_insns, starts_sorted)

        funcs.sort(key=lambda f: f.addr)
        self._functions = funcs
        return funcs

    def _compute_bodies(self, all_insns, starts: List[int]) -> List[Function]:
        """Rust FollowFlow 引擎 + 值流追踪"""
        # 构建 Rust 指令表
        eng = dslsde_core.FlowEngine()
        eng.set_instructions(all_insns)

        func_map: Dict[int, Function] = {}
        for addr in starts:
            name = self._find_name(addr)
            typ = "named" if name else "entry" if addr == self._binary.entry else "unknown"
            func = Function(addr=addr, name=name, typ=typ)

            count = eng.follow_flow(addr)
            if count > 0:
                body = eng.body()
                func.body_addrs = set(body)
                func.insn_count = len(body)
                if body:
                    func.size = max(body) - addr + 8

            func_map[addr] = func

        funcs = [f for f in func_map.values()
                 if f.body_addrs or f.typ in ("named", "entry")]
        funcs = self._dedup(funcs)
        return funcs

    def _find_name(self, addr: int) -> str:
        for sym in self._binary.symbols:
            if sym.addr == addr and sym.typ == "function" and sym.name:
                return sym.name
        return ""

    @staticmethod
    def _dedup(funcs: List[Function]) -> List[Function]:
        sorted_funcs = sorted(funcs, key=lambda f: (
            {"named": 0, "entry": 1, "unknown": 2}.get(f.typ, 3),
            -f.insn_count, f.addr
        ))
        keep: List[Function] = []
        for f in sorted_funcs:
            contained = False
            for k in keep:
                if f.addr in k.body_addrs:
                    if k.typ == "named" and f.typ != "named":
                        contained = True
                        break
            if not contained:
                keep.append(f)
        return keep

    def find_by_addr(self, addr: int) -> Optional[Function]:
        for f in self._functions:
            if f.addr <= addr < f.addr + f.size:
                return f
        return None

    def find_by_name(self, name: str) -> Optional[Function]:
        for f in self._functions:
            if f.name == name:
                return f
        return None
