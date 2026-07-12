"""dslsde — 反汇编器

基于 capstone，输出统一的指令列表。
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

from engine.loader import Binary


# ── 指令模型 ──────────────────────────────────────────────

@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    operands: str
    bytes: bytes

    def __repr__(self) -> str:
        return f"{self.addr:#010x}  {self.mnemonic:8s} {self.operands}"


# ── 反汇编器 ──────────────────────────────────────────────

class Disassembler:
    """封装 capstone，按需反汇编"""

    def __init__(self, binary: Binary):
        self._binary = binary
        self._md = self._create_cs(binary.arch, binary.bits)

    # ── capstone 初始化 ──

    @staticmethod
    def _create_cs(arch: str, bits: int):
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS
        from capstone import CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MIPS32, CS_MODE_MIPS64

        table = {
            ("x86", 32):    (CS_ARCH_X86, CS_MODE_32),
            ("x86", 64):    (CS_ARCH_X86, CS_MODE_64),
            ("x86_64", 64): (CS_ARCH_X86, CS_MODE_64),
            ("ARM", 32):    (CS_ARCH_ARM, CS_MODE_ARM),
            ("ARM", 64):    (CS_ARCH_ARM, CS_MODE_THUMB),
            ("AARCH64", 64):(CS_ARCH_ARM64, CS_MODE_ARM),
            ("MIPS", 32):   (CS_ARCH_MIPS, CS_MODE_MIPS32),
            ("MIPS", 64):   (CS_ARCH_MIPS, CS_MODE_MIPS64),
        }
        key = (arch, bits)
        if key not in table:
            raise ValueError(f"不支持的架构: {arch} {bits}bit")
        arch_id, mode_id = table[key]
        md = Cs(arch_id, mode_id)
        md.detail = False
        md.skipdata = True
        return md

    # ── 主要接口 ──

    def disasm(self, addr: int, size: int) -> List[Insn]:
        """从地址反汇编 size 字节"""
        raw = self._binary.read(addr, size)
        if raw is None:
            return []
        insns = []
        for i in self._md.disasm(raw, addr):
            insns.append(Insn(
                addr=i.address,
                size=i.size,
                mnemonic=i.mnemonic,
                operands=i.op_str,
                bytes=i.bytes.tobytes() if hasattr(i.bytes, 'tobytes') else bytes(i.bytes),
            ))
        return insns

    def disasm_range(self, start: int, end: int) -> List[Insn]:
        """反汇编 [start, end) 地址范围"""
        return self.disasm(start, end - start)

    def disasm_segment(self, seg) -> List[Insn]:
        """反汇编整个段"""
        return self.disasm(seg.addr, seg.size)

    def read_one(self, addr: int) -> Optional[Insn]:
        """反汇编单条指令（用于快速查看）"""
        insns = self.disasm(addr, 16)
        return insns[0] if insns else None
