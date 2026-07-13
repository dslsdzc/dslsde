"""dslsde — Unicorn 跨架构执行引擎（含返回检测）"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple

import sys
from unicorn import *
from unicorn.x86_const import *

from engine.loader import Binary
import dslsde_core


STACK_BASE = 0x7ffffffff000
STACK_SIZE = 0x100000
HEAP_BASE = 0x600000000000
HEAP_SIZE = 0x1000000
# 内核栈（放在内核地址空间低端）
KERNEL_STACK_BASE = 0xffffffff80000000
KERNEL_STACK_SIZE = 0x100000

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

    def _setup_page_tables(self, uc: Uc) -> bool:
        """为内核虚拟地址空间设置 4 级页表 (identity map)"""
        try:
            first_seg = self.binary.segments[0]
            is_kernel = first_seg.addr >= 0xffffffff80000000
            if not is_kernel:
                return False

            PAGE_SIZE = 0x1000
            # 页表放安全物理地址（不冲突的地址）
            PT_ADDR = 0x1000      # PML4
            PDP_ADDR = 0x2000
            PD_ADDR = 0x3000
            PT_BASE = 0x4000

            for seg in self.binary.segments:
                if not seg.executable:
                    continue
                addr = seg.addr
                pml4_idx = (addr >> 39) & 0x1ff
                pdpt_idx = (addr >> 30) & 0x1ff
                pd_idx = (addr >> 21) & 0x1ff
                pt_idx = (addr >> 12) & 0x1ff

                perms = 3  # present + writable

                # 映射所有页表页
                for taddr in [PT_ADDR, PDP_ADDR, PD_ADDR, PT_BASE]:
                    try:
                        uc.mem_map(taddr & ~0xfff, PAGE_SIZE,
                                   UC_PROT_READ | UC_PROT_WRITE)
                    except UcError:
                        pass  # 可能已映射

                # 写入页表项
                uc.mem_write(PT_ADDR + pml4_idx * 8,
                            (PDP_ADDR | perms).to_bytes(8, 'little'))
                uc.mem_write(PDP_ADDR + pdpt_idx * 8,
                            (PD_ADDR | perms).to_bytes(8, 'little'))
                uc.mem_write(PD_ADDR + pd_idx * 8,
                            (PT_BASE | perms).to_bytes(8, 'little'))
                uc.mem_write(PT_BASE + pt_idx * 8,
                            (addr | perms | 0x100).to_bytes(8, 'little'))

            uc.reg_write(UC_X86_REG_CR3, PT_ADDR)
            uc.reg_write(UC_X86_REG_CR4, 0x20)  # PAE
            return True

        except UcError as e:
            print(f"[dslsde] Page table setup failed: {e}", file=sys.stderr)
            return False

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

        # 内核模式初始化
        self._is_kernel_mode = self._setup_page_tables(uc)
        if self._is_kernel_mode:
            # 内核栈
            try:
                uc.mem_map(KERNEL_STACK_BASE, KERNEL_STACK_SIZE,
                          UC_PROT_READ | UC_PROT_WRITE)
                uc.reg_write(UC_X86_REG_RSP, KERNEL_STACK_BASE + KERNEL_STACK_SIZE - 0x200)
                uc.reg_write(UC_X86_REG_RBP, KERNEL_STACK_BASE + KERNEL_STACK_SIZE - 0x200)
                # CS 段选择子 (__KERNEL_CS = 0x10 for long mode)
                uc.reg_write(UC_X86_REG_CS, 0x10)
            except UcError:
                pass

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

        # 内核特权指令处理
        if self._is_kernel_mode and size >= 1:
            first = raw[0]
            # 0x0F 前缀指令
            if first == 0x0F and size >= 3:
                full = uc.mem_read(address, 3)
                op = (full[1], full[2])
                # swapgs: 0F 01 F8
                if op == (1, 0xF8):
                    uc.reg_write(UC_X86_REG_GS_BASE, 0)
                    self.recorder.record(address, size)
                    uc.reg_write(UC_X86_REG_RIP, address + size)
                # lgdt: 0F 01 /2 → modrm = 0x15
                # lidt: 0F 01 /3
                elif op == (1, 0x15) or op == (1, 0x1D):
                    uc.reg_write(UC_X86_REG_RIP, address + size)

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
