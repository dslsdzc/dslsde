"""dslsde — Unicorn 跨架构执行引擎（含返回检测）"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from unicorn import *
from unicorn.x86_const import *

from engine.loader import Binary
import dslsde_core


STACK_BASE = 0x7ffffffff000
STACK_SIZE = 0x100000
HEAP_BASE = 0x600000000000
HEAP_SIZE = 0x1000000

SYS_exit = 60
SYS_exit_group = 231


class Runner:
    def __init__(self, binary: Binary):
        self.binary = binary
        self._uc: Optional[Uc] = None
        self.recorder = dslsde_core.TraceRecorder(2_000_000)
        self._max_insns = 200000
        self._insn_count = 0
        self._stopped = False
        self._depth = 0  # 0 = original func, >0 = inside callee

    def _create_unicorn(self) -> Uc:
        arch, bits = self.binary.arch, self.binary.bits
        if arch in ("x86", "x86_64"):
            return Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
        elif arch == "ARM": return Uc(UC_ARCH_ARM, UC_MODE_ARM)
        elif arch == "AARCH64": return Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        elif arch == "MIPS": return Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 if bits == 64 else UC_MODE_MIPS32)
        raise ValueError(f"不支持的架构: {arch}")

    def setup(self, func_addr: int, args: List[int] = None):
        args = args or []
        bin = self.binary
        self._uc = self._create_unicorn()
        uc = self._uc
        self._insn_count = 0
        self._stopped = False
        self._depth = 0

        for seg in bin.segments:
            ps = seg.addr & ~0xfff
            pe = ((seg.addr + seg.size) + 0xfff) & ~0xfff
            perms = sum({'r': UC_PROT_READ, 'w': UC_PROT_WRITE, 'x': UC_PROT_EXEC}.get(c, 0) for c in seg.flags)
            uc.mem_map(ps, pe - ps, perms)
            off = seg.addr - ps
            data = bytearray(pe - ps)
            data[off:off + len(seg.data)] = seg.data
            uc.mem_write(ps, bytes(data))

        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        sp = STACK_BASE + STACK_SIZE - 0x1000

        self._heap_cur = HEAP_BASE
        uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        if bin.arch in ("x86", "x86_64") and bin.bits == 64:
            uc.reg_write(UC_X86_REG_RSP, sp + 0x800)
            uc.reg_write(UC_X86_REG_RBP, sp)
            regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                    UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
            for i, v in enumerate(args[:6]):
                uc.reg_write(regs[i], v)

        uc.hook_add(UC_HOOK_CODE, self._hook_code)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_PROT, self._hook_mem_error)

    def _hook_code(self, uc, address, size, user_data):
        if self._stopped:
            uc.emu_stop()
            return
        self._insn_count += 1
        if self._insn_count > self._max_insns:
            self._stopped = True; uc.emu_stop(); return

        self.recorder.record(address, size)

        # 深度检测：只读第一个字节
        if size >= 1:
            first = uc.mem_read(address, 1)[0]
            # call rel32 = 0xE8,  call [rip] 开头 = 0xFF
            if first == 0xE8:
                self._depth += 1
            elif first == 0xFF:
                # call/jmp indirect: ModRM 字节决定
                if size >= 2:
                    modrm = uc.mem_read(address, 2)[1]
                    reg = (modrm >> 3) & 7
                    if reg == 2:  # modrm.reg = 2 → call
                        self._depth += 1
            # ret = 0xC3
            elif first == 0xC3:
                self._depth -= 1
            # ret imm16 = 0xC2
            elif first == 0xC2:
                self._depth -= 1
            # leave = 0xC9 (before ret)
            # 不处理 depth

        # 返回检测：depth < 0 说明原始函数已返回
        if self._depth < 0:
            self._stopped = True
            uc.emu_stop()
            return

        # syscall: 0F 05
        if size >= 2:
            raw = uc.mem_read(address, 2)
            if raw[0] == 0x0F and raw[1] == 0x05:
                self._handle_syscall(uc)

    def _hook_mem_error(self, uc, access, address, size, value, user_data):
        if not self._stopped:
            self._stopped = True
            uc.emu_stop()

    def _handle_syscall(self, uc):
        rax = uc.reg_read(UC_X86_REG_RAX)
        rdi, rsi, rdx = uc.reg_read(UC_X86_REG_RDI), uc.reg_read(UC_X86_REG_RSI), uc.reg_read(UC_X86_REG_RDX)
        if rax in (SYS_exit, SYS_exit_group):
            self._stopped = True; uc.emu_stop(); return
        elif rax == 1:  # write
            uc.reg_write(UC_X86_REG_RAX, rdx)
        elif rax == 9:  # mmap
            uc.reg_write(UC_X86_REG_RAX, self._heap_cur)
            self._heap_cur += (rsi + 0xfff) & ~0xfff
        elif rax == 0:  # read
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif rax == 2:  # open
            uc.reg_write(UC_X86_REG_RAX, -1)
        elif rax == 3:  # close
            uc.reg_write(UC_X86_REG_RAX, 0)
        else:
            uc.reg_write(UC_X86_REG_RAX, 0)

    def read_regs(self) -> Dict[str, int]:
        uc = self._uc
        if uc is None or self.binary.arch not in ("x86", "x86_64"):
            return {}
        return {"rax": uc.reg_read(UC_X86_REG_RAX), "rbx": uc.reg_read(UC_X86_REG_RBX),
                "rcx": uc.reg_read(UC_X86_REG_RCX), "rdx": uc.reg_read(UC_X86_REG_RDX),
                "rsi": uc.reg_read(UC_X86_REG_RSI), "rdi": uc.reg_read(UC_X86_REG_RDI),
                "rbp": uc.reg_read(UC_X86_REG_RBP), "rsp": uc.reg_read(UC_X86_REG_RSP),
                "rip": uc.reg_read(UC_X86_REG_RIP)}

    def run(self, func_addr: int, args: List[int] = None,
            timeout: float = 1.0) -> List[Tuple[int, int]]:
        self.setup(func_addr, args)
        if self._uc is None:
            raise RuntimeError("初始化失败")
        try:
            self._uc.emu_start(func_addr, until=0,
                                timeout=int(timeout * 1000000))
        except UcError:
            pass
        return self.recorder.drain()

    def close(self):
        self._uc = None
