"""dslsde — 函数容器化执行器

从任意二进制提取函数机器码，注入最小 ELF 容器，
在 Unicorn/QEMU 中独立执行并追踪。

解决场景:
  - 函数在正常执行路径上无法触发 (CFF dispatcher)
  - 函数需要特定参数才能到达目标代码
  - 跨二进制函数分析

流程:
  1. ELF 解析 → 定位函数代码在文件中的偏移
  2. 提取机器码 (+ 引用的数据段)
  3. 构建最小 64-bit ELF
  4. 优先 Unicorn 执行 (快), fallback QEMU
  5. 记录完整指令 trace → 送入推理引擎
"""

import os
import struct
import tempfile
import subprocess
from typing import List, Optional, Tuple
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


# ── ELF 解析 ──

def _read_elf_info(binary: bytes) -> Optional[dict]:
    """解析 ELF header, 返回段信息"""
    if binary[:4] != b'\x7fELF':
        return None
    is_64 = binary[4] == 2
    if not is_64:
        return None

    phoff = struct.unpack('<Q', binary[32:40])[0]
    phnum = struct.unpack('<H', binary[56:58])[0]
    phent = struct.unpack('<H', binary[54:56])[0]

    segments = []
    for i in range(phnum):
        pos = phoff + i * phent
        p_type = struct.unpack('<I', binary[pos:pos+4])[0]
        p_flags = struct.unpack('<I', binary[pos+4:pos+8])[0]
        p_offset = struct.unpack('<Q', binary[pos+8:pos+16])[0]
        p_vaddr = struct.unpack('<Q', binary[pos+16:pos+24])[0]
        p_filesz = struct.unpack('<Q', binary[pos+32:pos+40])[0]
        p_memsz = struct.unpack('<Q', binary[pos+40:pos+48])[0]
        segments.append({
            'type': p_type, 'flags': p_flags,
            'offset': p_offset, 'vaddr': p_vaddr,
            'filesz': p_filesz, 'memsz': p_memsz,
        })

    return {'segments': segments}


def _find_segment_for_addr(info: dict, addr: int) -> Optional[dict]:
    """找包含 addr 的段"""
    for seg in info['segments']:
        if seg['vaddr'] <= addr < seg['vaddr'] + seg['filesz']:
            return seg
    return None


def extract_function(binary_path: str, func_addr: int,
                     max_size: int = 4096) -> Optional[bytes]:
    """从 ELF 提取函数机器码 + 前缀数据 (用于指令对齐)"""
    with open(binary_path, 'rb') as f:
        binary = f.read()

    info = _read_elf_info(binary)
    if not info:
        return None

    seg = _find_segment_for_addr(info, func_addr)
    if not seg:
        return None

    # 函数在文件中的偏移
    file_off = func_addr - seg['vaddr'] + seg['offset']
    # 多读一些前缀让 capstone 对齐
    prefix = 0 if file_off == 0 else min(16, file_off)
    start = file_off - prefix
    size = min(max_size + prefix, seg['filesz'] - (file_off - seg['offset']))
    code = binary[start:start + size]

    # 用 Capstone 找第一个完整函数 (从 func_addr 开始反汇编)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    func_start = prefix  # 容器中的偏移
    func_bytes = code[func_start:]
    insns = list(md.disasm(func_bytes, func_addr, count=200))

    if not insns:
        return None

    # 找到 ret (0xC3) 或 retf 作为函数结尾
    func_end = func_start + len(func_bytes)
    for insn in insns:
        if insn.mnemonic in ('ret', 'retq', 'retf', 'syscall'):
            func_end = func_start + (insn.address - func_addr) + insn.size
            break

    extracted = code[func_start:func_end]
    print(f"[dslsde] Container: {func_addr:#x} → {len(extracted)} bytes, "
          f"{sum(1 for _ in md.disasm(extracted, 0x1000))} insns")
    return bytes(extracted)


# ── 最小 ELF 容器构建 ──

def build_container(code: bytes, stack_size: int = 0x10000,
                    load_addr: int = 0x100000) -> bytes:
    """构建最小 64-bit ELF

    布局:
      [0x000000] ELF header (64) + PHDR (56)
      [0x001000] code (对齐到 0x1000)
      [0x100000] load_addr (e_entry)

    栈在 load_addr + code_size 之后 (Unicorn 直接映射)
    """
    code_align = (len(code) + 0xfff) & ~0xfff
    code_padded = code + b'\x00' * (code_align - len(code))

    phoff = 64
    # ELF header
    elf = bytearray()
    elf.extend(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8)
    elf.extend(struct.pack('<HHIQQQIHHHHHH',
        2, 0x3e, 1, load_addr, phoff,
        0, 0, 64, 56, 1, 0, 0, 0))

    # PHDR: PT_LOAD RX (代码段)
    ph = struct.pack('<IIQQQQQQ',
        1,                    # PT_LOAD
        5,                    # PF_R | PF_X
        phoff + 56,           # p_offset (紧接 phdr 之后)
        load_addr,            # p_vaddr
        load_addr,            # p_paddr
        code_align,           # p_filesz
        code_align + stack_size,  # p_memsz
        0x1000)               # p_align
    elf.extend(ph)

    # 代码段 (文件中对齐到 phoff+56)
    elf.extend(code_padded)

    return bytes(elf)


# ── 容器执行 (Unicorn) ──

def _run_unicorn(container_path: str, func_addr: int,
                 timeout: float = 5.0) -> List[Tuple]:
    """Unicorn 执行容器"""
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP
    except ImportError:
        return []

    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    import dslsde_core

    with open(container_path, 'rb') as f:
        elf_data = f.read()

    # 计算加载地址和大小
    LOAD_ADDR = 0x100000
    code_size = (len(elf_data) - 120)  # elf header + phdr + code
    STACK_ADDR = LOAD_ADDR + ((code_size + 0xfff) & ~0xfff)
    STACK_SIZE = 0x10000

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(LOAD_ADDR, code_size + STACK_SIZE, 7)  # RWX

    # 写代码
    uc.mem_write(LOAD_ADDR, elf_data[120:])

    # 栈
    sp = STACK_ADDR + STACK_SIZE - 0x200
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RBP, sp)

    # 记录 trace
    recorder = dslsde_core.TraceRecorder(200000)
    max_insns = [0]

    def hook_code(uc, address, size, user_data):
        recorder.record(address, size)
        max_insns[0] += 1
        if max_insns[0] > 20000:
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    try:
        uc.emu_start(LOAD_ADDR, until=0,
                     timeout=int(timeout * 1e6))
    except Exception:
        pass

    raw = recorder.drain()
    if not raw:
        return []

    # 解析为 Capstone 指令
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    with open(container_path, 'rb') as f:
        elf_data = f.read()

    result = []
    seen = set()
    for addr, size in raw:
        if addr in seen:
            continue
        seen.add(addr)
        # 从容器代码反汇编
        offset = addr - LOAD_ADDR
        if 0 <= offset < len(elf_data) - 120:
            chunk = elf_data[120 + offset:120 + offset + 15]
            for insn in md.disasm(chunk, addr, count=1):
                result.append((insn.address, insn.size, insn.mnemonic, insn.op_str))
                break

    return result


# ── 容器执行 (QEMU fallback) ──

def _run_qemu(container_path: str, func_addr: int,
              timeout: float = 10.0) -> List[Tuple]:
    """QEMU 用户态执行容器"""
    tmpdir = tempfile.mkdtemp()
    trace_log = os.path.join(tmpdir, "trace.log")

    proc = subprocess.Popen(
        ["qemu-x86_64", "-d", "in_asm", "-D", trace_log, container_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()

    if not os.path.exists(trace_log):
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    result = []
    with open(trace_log) as f:
        for line in f:
            if line.startswith("0x"):
                parts = line.strip().split(None, 2)
                if len(parts) >= 2:
                    try:
                        addr = int(parts[0].rstrip(':'), 16)
                        hex_bytes = parts[1].replace(" ", "")
                        op_text = parts[2] if len(parts) > 2 else ""
                        chunk = bytes.fromhex(hex_bytes)
                        for insn in md.disasm(chunk, addr, count=1):
                            result.append((addr, insn.size, insn.mnemonic, insn.op_str))
                            break
                    except (ValueError, IndexError):
                        pass

    return result


# ── 主入口 ──

def run_in_container(binary_path: str, func_addr: int,
                     timeout: float = 5.0,
                     use_qemu: bool = False) -> List[Tuple]:
    """提取函数 → 容器 → 执行 → trace"""
    code = extract_function(binary_path, func_addr)
    if not code:
        return []

    elf = build_container(code)

    tmpdir = tempfile.mkdtemp()
    elf_path = os.path.join(tmpdir, "container")
    with open(elf_path, "wb") as f:
        f.write(elf)
    os.chmod(elf_path, 0o755)

    if use_qemu:
        return _run_qemu(elf_path, 0x100000, timeout)
    else:
        return _run_unicorn(elf_path, 0x100000, timeout)


def container_decompile(binary_path: str, func_addr: int,
                        timeout: float = 5.0) -> str:
    """容器化反编译: 提取 → 执行 → dslsde 推理"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    import dslsde_core

    trace = run_in_container(binary_path, func_addr, timeout)
    if not trace:
        return "// (no trace)"

    ie = dslsde_core.InferenceEngine()
    return ie.infer(trace, [0])
