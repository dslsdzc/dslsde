"""dslsde — 二进制加载器

从 lief 解析 ELF/PE/Mach-O，输出统一 Binary 对象。
后续分析层不直接依赖 lief，只依赖 Binary。
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import lief


# ── 数据模型 ──────────────────────────────────────────────

@dataclass
class Segment:
    """内存段"""
    name: str
    addr: int
    size: int
    data: bytes
    flags: str          # rwxp

    @property
    def readable(self) -> bool: return 'r' in self.flags
    @property
    def writable(self) -> bool: return 'w' in self.flags
    @property
    def executable(self) -> bool: return 'x' in self.flags


@dataclass
class Symbol:
    """符号表条目"""
    name: str
    addr: int
    size: int
    typ: str             # function / object / import / unknown


@dataclass
class Relocation:
    """重定位条目——GOT 地址 → 外部符号"""
    addr: int            # GOT/地址
    name: str             # 外部符号名
    typ: str             # PLT / GLOB_DAT / RELATIVE

    def __repr__(self) -> str:
        return f"{self.addr:#010x}  {self.name:30s}  {self.typ}"


ARCH_MAP = {
    lief.ELF.ARCH.X86_64:  "x86_64",
    lief.ELF.ARCH.I386:    "x86",
    lief.ELF.ARCH.ARM:     "ARM",
    lief.ELF.ARCH.AARCH64: "AARCH64",
    lief.ELF.ARCH.MIPS:    "MIPS",
    lief.ELF.ARCH.RISCV:   "RISCV",
}


@dataclass
class Binary:
    """统一二进制表示——不依赖具体格式"""
    path: str
    fmt: str             # ELF / PE / MACHO
    arch: str            # x86 / x86_64 / ARM / AARCH64 / MIPS / RISCV
    bits: int            # 32 / 64
    entry: int
    image_base: int = 0
    segments: List[Segment] = field(default_factory=list)
    symbols: List[Symbol] = field(default_factory=list)
    relocations: List[Relocation] = field(default_factory=list)

    # ── 查询辅助 ──

    def find_segment(self, addr: int) -> Optional[Segment]:
        for seg in self.segments:
            if seg.addr <= addr < seg.addr + seg.size:
                return seg
        return None

    @property
    def exec_segments(self) -> List[Segment]:
        return [s for s in self.segments if s.executable]

    @property
    def data_segments(self) -> List[Segment]:
        return [s for s in self.segments if not s.executable and s.readable]

    @property
    def code_range(self) -> Optional[tuple[int, int]]:
        xs = self.exec_segments
        if not xs:
            return None
        return (xs[0].addr, xs[-1].addr + xs[-1].size)

    def read(self, addr: int, size: int) -> Optional[bytes]:
        seg = self.find_segment(addr)
        if seg is None:
            return None
        off = addr - seg.addr
        return seg.data[off:off + size]

    def read_word(self, addr: int) -> Optional[int]:
        sz = self.bits // 8
        b = self.read(addr, sz)
        if b is None or len(b) < sz:
            return None
        return int.from_bytes(b, 'little')

    def relocate_name(self, addr: int) -> Optional[str]:
        """通过 GOT/地址查找对应的导入符号名"""
        for r in self.relocations:
            if r.addr == addr:
                return r.name
        return None

    # ── 字符串提取 ──

    def extract_strings(self, min_len: int = 4) -> List[Tuple[int, str]]:
        """从数据段提取可打印字符串"""
        result = []
        for seg in self.segments:
            if not seg.readable or seg.executable:
                continue
            buf = seg.data
            start = None
            for i in range(len(buf)):
                b = buf[i]
                if 0x20 <= b <= 0x7e:
                    if start is None:
                        start = i
                else:
                    if start is not None:
                        length = i - start
                        if length >= min_len:
                            s = buf[start:i].decode('ascii', errors='replace')
                            result.append((seg.addr + start, s))
                        start = None
            # 处理段尾的字符串
            if start is not None:
                length = len(buf) - start
                if length >= min_len:
                    s = buf[start:].decode('ascii', errors='replace')
                    result.append((seg.addr + start, s))
        result.sort(key=lambda x: x[0])
        return result

    def string_at(self, addr: int, max_len: int = 256) -> Optional[str]:
        """从地址读取以 null 结尾的 ASCII 字符串。
        要求：至少 80% 的字节是可打印 ASCII（排除随机二进制数据）。
        """
        seg = self.find_segment(addr)
        if seg is None:
            return None
        off = addr - seg.addr
        buf = seg.data[off:off + max_len]
        end = buf.find(b'\x00')
        if end == -1:
            end = len(buf) if len(buf) >= max_len else len(buf)
        raw = buf[:end]
        if len(raw) < 2:
            return None
        # 过滤：至少 80% 可打印 ASCII 或常见空白
        printable = sum(1 for b in raw if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
        if printable / len(raw) < 0.8:
            return None
        try:
            return raw.decode('ascii')
        except UnicodeDecodeError:
            return None


# ── 加载器 ────────────────────────────────────────────────

def _flag_str(flags) -> str:
    """段标志 → 'rwxp'"""
    s = ""
    # lief 0.17 FLAGS enum
    if flags & flags.__class__.X: s += 'x'
    if flags & flags.__class__.W: s += 'w'
    if flags & flags.__class__.R: s += 'r'
    if not s:
        # try integer fallback
        fv = int(flags) if hasattr(flags, 'value') else 0
        if fv & 1: s += 'x'
        if fv & 2: s += 'w'
        if fv & 4: s += 'r'
    if not s:
        s = 'r'
    return s


def _arch_str(arch, fmt: str) -> str:
    if fmt == "ELF":
        return ARCH_MAP.get(arch, str(arch).removeprefix("ARCH."))
    elif fmt == "PE":
        m = {
            lief.PE.Header.MACHINE_TYPES.I386:  "x86",
            lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
            lief.PE.Header.MACHINE_TYPES.ARM:   "ARM",
            lief.PE.Header.MACHINE_TYPES.ARM64: "AARCH64",
        }
        return m.get(arch, str(arch))
    return str(arch)


def _bits_from_class(cls) -> int:
    return 64 if "64" in str(cls) else 32


def _load_elf(elf, path: str) -> Binary:
    header = elf.header
    bin = Binary(
        path=path,
        fmt="ELF",
        arch=_arch_str(header.machine_type, "ELF"),
        bits=_bits_from_class(header.identity_class),
        entry=header.entrypoint,
    )

    # 段
    for seg in elf.segments:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            stype = str(seg.type)
        if "LOAD" in stype and seg.virtual_size > 0:
            bin.segments.append(Segment(
                name=f"LOAD {seg.virtual_address:08x}",
                addr=seg.virtual_address,
                size=seg.virtual_size,
                data=bytes(seg.content),
                flags=_flag_str(seg.flags),
            ))

    # 符号
    seen = set()
    for i in range(len(elf.symbols)):
        sym = elf.symbols[i]
        if sym.name and sym.value and sym.value not in seen:
            seen.add(sym.value)
            typ = "function" if sym.is_function else "object"
            bin.symbols.append(Symbol(sym.name, sym.value, sym.size, typ))

    # 导出符号（补充）
    for i in range(len(elf.exported_symbols)):
        sym = elf.exported_symbols[i]
        if sym.name and sym.value and sym.value not in seen:
            seen.add(sym.value)
            typ = "function" if sym.is_function else "object"
            bin.symbols.append(Symbol(sym.name, sym.value, sym.size, typ))

    # 重定位/GOT → 导入符号名
    for i in range(len(elf.relocations)):
        r = elf.relocations[i]
        sym = r.symbol if hasattr(r, 'symbol') and r.symbol else None
        if sym and sym.name and r.address:
            typ = str(r.type).removeprefix("TYPE.")
            bin.relocations.append(Relocation(r.address, sym.name, typ))

    bin.segments.sort(key=lambda s: s.addr)
    return bin


def _load_pe(pe, path: str) -> Binary:
    header = pe.header
    arch = header.machine
    bits = 64 if arch == lief.PE.Header.MACHINE_TYPES.AMD64 else 32
    bin = Binary(
        path=path, fmt="PE",
        arch=_arch_str(arch, "PE"), bits=bits,
        entry=pe.entrypoint, image_base=pe.imagebase,
    )
    for sec in pe.sections:
        flags = ""
        if sec.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE): flags += 'x'
        if sec.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):   flags += 'w'
        if sec.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):    flags += 'r'
        if not flags: flags = 'r'
        bin.segments.append(Segment(
            name=sec.name, addr=sec.virtual_address,
            size=sec.virtual_size, data=bytes(sec.content), flags=flags,
        ))
    bin.segments.sort(key=lambda s: s.addr)
    return bin


def _load_macho(macho, path: str) -> Binary:
    cputype = macho.header.cpu_type
    arch_map = {
        lief.MachO.Header.CPU_TYPES.x86: "x86",
        lief.MachO.Header.CPU_TYPES.x86_64: "x86_64",
        lief.MachO.Header.CPU_TYPES.ARM: "ARM",
        lief.MachO.Header.CPU_TYPES.ARM64: "AARCH64",
    }
    bin = Binary(
        path=path, fmt="MACHO",
        arch=arch_map.get(cputype, str(cputype)),
        bits=64 if cputype in (lief.MachO.Header.CPU_TYPES.x86_64,
                                lief.MachO.Header.CPU_TYPES.ARM64) else 32,
        entry=macho.entrypoint,
    )
    for seg in macho.segments:
        flags = ""
        prot = seg.max_protection
        if prot & 1: flags += 'x'
        if prot & 2: flags += 'w'
        if prot & 4: flags += 'r'
        if not flags: flags = 'r'
        bin.segments.append(Segment(
            name=seg.name, addr=seg.virtual_address,
            size=seg.virtual_size, data=bytes(seg.content), flags=flags,
        ))
    for sym in macho.symbols:
        if sym.name and sym.value:
            bin.symbols.append(Symbol(
                sym.name, sym.value, 0,
                "function" if hasattr(sym, 'type') else "object",
            ))
    bin.segments.sort(key=lambda s: s.addr)
    return bin


# ── 统一入口 ──────────────────────────────────────────────

def load(path: str) -> Binary:
    """加载任意支持的二进制格式"""
    obj = lief.parse(path)
    if obj is None:
        raise ValueError(f"lief 无法解析: {path}")
    fmt = obj.format.name
    if fmt == "ELF":
        return _load_elf(obj, path)
    elif fmt == "PE":
        return _load_pe(obj, path)
    elif fmt == "MACHO":
        return _load_macho(obj, path)
    else:
        raise ValueError(f"不支持的格式: {fmt}")
