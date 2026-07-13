"""dslsde — 函数容器化执行器

策略 (按二进制大小):
  < 500MB: 直接加载原二进制所有段, 设 RIP = func_addr (完整上下文)
  >= 500MB: 提取函数机器码 → 最小 ELF 容器 (省内存)

流程:
  1. 读取 ELF segment 信息
  2. <500MB: 映射所有段 → 设 RIP → Unicorn 执行
  3. ≥500MB: 提取代码 → 最小 ELF → Unicorn 执行
  4. 记录 trace → 送入推理引擎
"""

import os
import struct
import tempfile
import shutil
from typing import List, Optional, Tuple
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Unicorn 导入
try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_FS_BASE
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

SIZE_LIMIT = 500 * 1024 * 1024  # 500MB


def _read_elf_info(binary: bytes) -> Optional[dict]:
    if binary[:4] != b'\x7fELF':
        return None
    if binary[4] != 2:  # not 64-bit
        return None
    phoff = struct.unpack('<Q', binary[32:40])[0]
    phnum = struct.unpack('<H', binary[56:58])[0]
    phent = struct.unpack('<H', binary[54:56])[0]
    segments = []
    for i in range(phnum):
        pos = phoff + i * phent
        segments.append({
            'type': struct.unpack('<I', binary[pos:pos+4])[0],
            'flags': struct.unpack('<I', binary[pos+4:pos+8])[0],
            'offset': struct.unpack('<Q', binary[pos+8:pos+16])[0],
            'vaddr': struct.unpack('<Q', binary[pos+16:pos+24])[0],
            'filesz': struct.unpack('<Q', binary[pos+32:pos+40])[0],
            'memsz': struct.unpack('<Q', binary[pos+40:pos+48])[0],
        })
    return {'segments': segments}


def _map_segments(uc, info: dict, binary: bytes):
    """映射所有 LOAD 段到 Unicorn"""
    for seg in info['segments']:
        if seg['type'] != 1:  # PT_LOAD
            continue
        vaddr = seg['vaddr']
        memsz = seg['memsz']
        filesz = seg['filesz']
        flags = seg['flags']

        # 对齐
        page_start = vaddr & ~0xfff
        page_end = ((vaddr + memsz + 0xfff) & ~0xfff)
        size = page_end - page_start

        # Unicorn 权限
        perms = 0
        if flags & 4: perms |= 4  # R
        if flags & 2: perms |= 2  # W
        if flags & 1: perms |= 1  # X

        try:
            uc.mem_map(page_start, size, perms)
            # 写入段数据
            if filesz > 0:
                off = seg['offset']
                data = binary[off:off+filesz]
                uc.mem_write(vaddr, data)
        except Exception:
            pass  # 段可能冲突


def _run_unicorn_direct(binary_path: str, func_addr: int,
                         timeout: float = 5.0) -> List[Tuple]:
    """直接加载原二进制到 Unicorn (完整上下文)"""
    if not HAS_UNICORN:
        return []

    import dslsde_core

    with open(binary_path, 'rb') as f:
        binary = f.read()

    info = _read_elf_info(binary)
    if not info:
        return []

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    _map_segments(uc, info, binary)

    # 栈
    STACK_SIZE = 0x20000
    STACK_ADDR = 0x7ffffff00000
    uc.mem_map(STACK_ADDR, STACK_SIZE, 3)
    sp = STACK_ADDR + STACK_SIZE - 0x200
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RBP, sp - 0x100)

    # 堆 (给函数参数用)
    HEAP_ADDR = 0x60000000
    uc.mem_map(HEAP_ADDR, 0x1000000, 3)
    uc.reg_write(UC_X86_REG_RDI, HEAP_ADDR)
    uc.reg_write(UC_X86_REG_RSI, 0)
    uc.reg_write(UC_X86_REG_RDX, 0)

    # FS 段 (栈金丝雀 fs:[0x28])
    try:
        uc.mem_map(0x70000000, 0x1000, 3)
        uc.reg_write(UC_X86_REG_FS_BASE, 0x70000000)
    except Exception:
        pass

    # Trace
    recorder = dslsde_core.TraceRecorder(50000)
    insn_count = [0]

    def hook(uc, addr, size, user_data):
        recorder.record(addr, size)
        insn_count[0] += 1
        if insn_count[0] > 5000:
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)

    try:
        uc.emu_start(func_addr, until=0, timeout=int(timeout * 1e6))
    except Exception:
        pass

    raw = recorder.drain()
    if not raw:
        return []

    # 反汇编
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    result = []
    seen = set()
    for addr, size in raw:
        if addr in seen:
            continue
        seen.add(addr)
        # 从二进制数据反汇编
        for seg in info['segments']:
            if seg['type'] != 1 or (seg['flags'] & 1) == 0:
                continue
            if seg['vaddr'] <= addr < seg['vaddr'] + seg['filesz']:
                off = addr - seg['vaddr'] + seg['offset']
                chunk = binary[off:off+15]
                for insn in md.disasm(chunk, addr, count=1):
                    result.append((addr, insn.size, insn.mnemonic, insn.op_str))
                    break
                break

    return result


def _extract_code(binary: bytes, info: dict, func_addr: int,
                  max_size: int = 4096) -> Optional[bytes]:
    """提取函数机器码 (回退方案)"""
    for seg in info['segments']:
        if seg['type'] != 1 or (seg['flags'] & 1) == 0:
            continue
        if seg['vaddr'] <= func_addr < seg['vaddr'] + seg['filesz']:
            off = func_addr - seg['vaddr'] + seg['offset']
            code = binary[off:off+max_size]
            # 找 ret 结尾
            end = code.find(b'\xc3')
            if end >= 0:
                code = code[:end+1]
            return bytes(code)
    return None


def _build_minimal_elf(code: bytes) -> bytes:
    """构建最小 ELF (≥500MB 回退)"""
    code_align = (len(code) + 0xfff) & ~0xfff
    code_padded = code + b'\x00' * (code_align - len(code))
    LOAD_ADDR = 0x100000

    elf = bytearray()
    elf.extend(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8)
    elf.extend(struct.pack('<HHIQQQIHHHHHH',
        2, 0x3e, 1, LOAD_ADDR, 64, 0, 0, 64, 56, 1, 0, 0, 0))
    ph = struct.pack('<IIQQQQQQ',
        1, 5, 120, LOAD_ADDR, LOAD_ADDR,
        code_align, code_align + 0x10000, 0x1000)
    elf.extend(ph)
    elf.extend(code_padded)
    return bytes(elf)


def run_in_container(binary_path: str, func_addr: int,
                     timeout: float = 5.0) -> List[Tuple]:
    """执行函数: <500MB 直接加载, ≥500MB 提取"""
    size = os.path.getsize(binary_path)

    if size < SIZE_LIMIT:
        # 直接加载原二进制
        return _run_unicorn_direct(binary_path, func_addr, timeout)
    else:
        # 提取 + 最小 ELF
        with open(binary_path, 'rb') as f:
            binary = f.read()
        info = _read_elf_info(binary)
        if not info:
            return []
        code = _extract_code(binary, info, func_addr)
        if not code:
            return []
        elf = _build_minimal_elf(code)
        tmpdir = tempfile.mkdtemp()
        elf_path = os.path.join(tmpdir, "container")
        with open(elf_path, "wb") as f:
            f.write(elf)
        os.chmod(elf_path, 0o755)
        # 用 Unicorn 执行容器
        return _run_unicorn_direct(elf_path, 0x100000, timeout)


def container_decompile(binary_path: str, func_addr: int,
                        timeout: float = 5.0) -> str:
    """容器化反编译"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    import dslsde_core

    trace = run_in_container(binary_path, func_addr, timeout)
    if not trace:
        return "// (no trace)"

    ie = dslsde_core.InferenceEngine()
    return ie.infer(trace, [0])
