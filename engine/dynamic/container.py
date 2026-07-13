"""dslsde — 函数代码容器化执行器

从二进制提取目标函数的机器码，注入最小 ELF 容器，
独立执行并追踪。

流程:
  1. 定位函数在二进制文件中的偏移
  2. 复制机器码
  3. 构建最小 ELF (64-bit): 栈 + 参数 + 函数体
  4. 在 QEMU 用户态下执行
  5. 记录完整指令 trace
"""

import os
import struct
import tempfile
import subprocess
from typing import List, Optional, Tuple


def _create_minimal_elf(code: bytes, entry_offset: int = 0x1000) -> bytes:
    """创建最小 64-bit ELF 可执行文件

    结构:
      ELF header (64 bytes)
      Program header (56 bytes)
      code (函数机器码)

    入口点: 0x100000 (加载地址)
    """
    LOAD_ADDR = 0x100000
    STACK_SIZE = 0x10000
    STACK_ADDR = 0x7ffffff00000

    phoff = 64  # program header offset
    code_align = 0x1000

    # ELF header (64-bit)
    elf = bytearray()
    # e_ident
    elf.extend(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8)  # EI_CLASS=64, EI_DATA=2LE
    # e_type = ET_EXEC (2), e_machine = EM_X86_64 (62)
    elf.extend(struct.pack('<HHIQQQIHHHHHH',
        2,      # e_type
        0x3e,    # e_machine (x86-64)
        1,      # e_version
        LOAD_ADDR + entry_offset,  # e_entry
        phoff,  # e_phoff
        0,      # e_shoff
        0,      # e_flags
        64,     # e_ehsize
        56,     # e_phentsize
        1,      # e_phnum
        0,      # e_shentsize
        0,      # e_shnum
        0,      # e_shstrndx
    ))

    # Program header: LOAD
    code_size = (len(code) + 0xfff) & ~0xfff
    ph = struct.pack('<IIQQQQQQ',
        1,              # p_type = PT_LOAD
        0x5,            # p_flags = RX
        0,              # p_offset
        LOAD_ADDR,      # p_vaddr
        LOAD_ADDR,      # p_paddr
        code_size,      # p_filesz
        code_size + STACK_SIZE,  # p_memsz (with stack)
        code_align,     # p_align
    )
    elf.extend(ph)

    # 填充到 LOAD_ADDR 对齐
    padding = LOAD_ADDR - (64 + 56)
    elf.extend(b'\x00' * padding)

    # 写入函数代码
    elf.extend(code)

    # 填充剩余
    elf.extend(b'\x00' * (code_size - len(code)))

    return bytes(elf)


def extract_function_code(binary_path: str, func_addr: int,
                          text_base: int = 0x400000, max_size: int = 4096) -> Optional[bytes]:
    """从 ELF 二进制中提取函数的机器码"""
    with open(binary_path, 'rb') as f:
        binary = f.read()

    # 通过 ELF section 找到代码的偏移
    # 简单: 直接搜索函数入口附近
    # 用 ELF 信息定位
    import struct as st

    # 读 ELF header
    if binary[:4] != b'\x7fELF':
        return None

    is_64 = binary[4] == 2
    if not is_64:
        return None

    # 从 phdr 找 text 段
    phoff = st.unpack('<Q', binary[32:40])[0]
    phnum = st.unpack('<H', binary[56:58])[0]
    phent = st.unpack('<H', binary[54:56])[0]

    for i in range(phnum):
        ph_pos = phoff + i * phent
        p_type = st.unpack('<I', binary[ph_pos:ph_pos+4])[0]
        p_flags = st.unpack('<I', binary[ph_pos+4:ph_pos+8])[0]
        p_offset = st.unpack('<Q', binary[ph_pos+8:ph_pos+16])[0]
        p_vaddr = st.unpack('<Q', binary[ph_pos+16:ph_pos+24])[0]
        p_filesz = st.unpack('<Q', binary[ph_pos+32:ph_pos+40])[0]

        if p_type == 1 and p_flags & 1:  # PT_LOAD + X
            # 计算函数在文件中的偏移
            if p_vaddr <= func_addr < p_vaddr + p_filesz:
                file_offset = func_addr - p_vaddr + p_offset
                code = binary[file_offset:file_offset + max_size]
                # 找到函数结尾 (ret = 0xC3)
                end = code.find(b'\xc3')
                if end >= 0:
                    code = code[:end + 1]
                print(f"[dslsde] Extracted {len(code)} bytes from {binary_path}")
                return code

    return None


def run_in_container(binary_path: str, func_addr: int,
                     timeout: float = 10.0) -> List[Tuple[int, int, str, str]]:
    """提取函数 → 注入 ELF 容器 → QEMU 执行追踪"""
    code = extract_function_code(binary_path, func_addr)
    if not code:
        return []

    # 构建最小 ELF
    elf_data = _create_minimal_elf(code)

    # 写入临时文件
    tmpdir = tempfile.mkdtemp()
    elf_path = os.path.join(tmpdir, "func_container")
    with open(elf_path, "wb") as f:
        f.write(elf_data)
    os.chmod(elf_path, 0o755)

    # QEMU 用户态 trace
    qemu = subprocess.Popen(
        ["qemu-x86_64", "-d", "in_asm", "-D", os.path.join(tmpdir, "trace.log"), elf_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        qemu.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        qemu.kill()

    # 解析 trace
    from engine.dynamic.qemu_runner import QemuRunner
    qr = QemuRunner(elf_path)  # 仅用于 _parse_trace
    trace = qr._parse_trace(os.path.join(tmpdir, "trace.log"), func_addr)

    return trace


def container_decompile(binary_path: str, func_addr: int,
                          timeout: float = 10.0) -> str:
    """容器化反编译：提取 → 执行 → dslsde 推理"""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

    from engine.model import Model
    import dslsde_core

    code = extract_function_code(binary_path, func_addr)
    if not code:
        return "// (code extraction failed)"

    # 构建容器 ELF
    elf_data = _create_minimal_elf(code)
    tmpdir = tempfile.mkdtemp()
    elf_path = os.path.join(tmpdir, "func_container")
    with open(elf_path, "wb") as f:
        f.write(elf_data)
    os.chmod(elf_path, 0o755)

    # QEMU trace
    trace_log = os.path.join(tmpdir, "trace.log")
    qemu = subprocess.Popen(
        ["qemu-x86_64", "-d", "in_asm", "-D", trace_log, elf_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        qemu.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        qemu.kill()

    # 解析 trace
    qr = __import__('engine.dynamic.qemu_runner', fromlist=['']).QemuRunner(elf_path)
    trace = qr._parse_trace(trace_log, 0x100000)

    if not trace:
        return "// (no trace)"

    # 直接送入推理引擎 (静态，没有 model)
    ie = dslsde_core.InferenceEngine()
    result = ie.infer(trace, [0])
    return result
