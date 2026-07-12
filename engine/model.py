"""dslsde — 核心编排器（Rust 加速 + 动态分析）"""

from __future__ import annotations
import os
import re
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from engine.loader import load as load_binary, Binary
from engine.function import FunctionAnalyzer, Function
from engine.database import Database
from engine.dynamic.runner import Runner
from engine.dynamic.params import ParamInferrer

import dslsde_core


class Model:
    def __init__(self, path: str):
        self._path = os.path.abspath(path)
        self.binary: Optional[Binary] = None
        self.db: Optional[Database] = None
        self.functions: List[Function] = []
        self._analyzed = False
        self._xref_imports: Dict[int, List[str]] = defaultdict(list)
        self._xref_strings: Dict[int, List[Tuple[int, str]]] = defaultdict(list)

    def load(self) -> Binary:
        self.binary = load_binary(self._path)
        db_dir = os.path.expanduser("~/.dslsde/db")
        os.makedirs(db_dir, exist_ok=True)
        safe_name = os.path.basename(self._path).replace("/", "_")
        db_path = os.path.join(db_dir, safe_name + ".db")
        self.db = Database(db_path)
        self.db.set_meta("binary_path", self._path)
        self.db.set_meta("binary_fmt", self.binary.fmt)
        return self.binary

    def analyze(self) -> bool:
        if self.binary is None: raise RuntimeError("未加载二进制，请先调用 load()")
        if self.db is None: raise RuntimeError("数据库未初始化")
        if self.db.has_data():
            self.functions = self.db.load_functions()
            self._analyzed = True
            return True
        self._analyze_all()
        return True

    def _analyze_all(self):
        print("分析中...")
        bin = self.binary
        self.db.save_segments(bin.segments)
        self.db.save_symbols(bin.symbols)
        self.db.set_meta("arch", f"{bin.arch}/{bin.bits}")
        self.db.set_meta("entry", hex(bin.entry))
        self.db.set_meta("fmt", bin.fmt)

        analyzer = dslsde_core.InsnAnalyzer()
        rip_re = re.compile(r'rip\s*[-+]\s*0x[0-9a-fA-F]+')
        all_insns: List = []
        all_targets: Set[int] = set()
        for seg in bin.exec_segments:
            rust_insns, targets = analyzer.analyze(seg.data, seg.addr, bin.arch, bin.bits)
            self.db.save_rust_instructions(rust_insns)
            all_insns.extend(rust_insns)
            for t in targets:
                if self._in_range(t): all_targets.add(t)
            for insn in rust_insns:
                mn, op = insn.mnemonic, insn.operands
                if mn in ("call", "callq") and "rip" in op:
                    got_addr = self._parse_rip_target_str(insn, rip_re)
                    if got_addr is not None:
                        name = bin.relocate_name(got_addr)
                        if name: self._xref_imports[insn.addr].append(name)
                if "lea" in mn:
                    data_addr = self._parse_rip_target_str(insn, rip_re)
                    if data_addr is not None:
                        seg2 = bin.find_segment(data_addr)
                        if seg2 and not seg2.executable and seg2.readable:
                            s = bin.string_at(data_addr)
                            if s: self._xref_strings[insn.addr].append((data_addr, s))

        fa = FunctionAnalyzer(bin)
        self.functions = fa.analyze_with_rust(all_insns, all_targets)
        self.db.save_functions(self.functions)
        named = sum(1 for f in self.functions if f.typ == "named")
        self._analyzed = True
        print(f"  指令: {len(all_insns)}")
        print(f"  函数: {len(self.functions)} ({named} 已命名)")

    @staticmethod
    def _parse_rip_target_str(insn, rip_re) -> Optional[int]:
        if "rip" not in insn.operands: return None
        m = rip_re.search(insn.operands)
        if not m: return None
        part = m.group()
        if "+" in part: return insn.addr + insn.size + int(part.split("+")[1].strip(), 16)
        return insn.addr + insn.size - int(part.split("-")[1].strip(), 16)

    def _in_range(self, addr: int) -> bool:
        if self.binary is None: return False
        return any(s.addr <= addr < s.addr + s.size for s in self.binary.exec_segments)

    def get_function(self, addr_or_name) -> Optional[Function]:
        if isinstance(addr_or_name, int):
            for f in self.functions:
                if f.addr <= addr_or_name < f.addr + f.size: return f
            return None
        for f in self.functions:
            if f.name == addr_or_name: return f
        return None

    def _xrefs_for_func(self, func):
        imports: Set[str] = set()
        strings: List[Tuple[int, str]] = []
        for addr in range(func.addr, func.addr + func.size):
            for name in self._xref_imports.get(addr, []): imports.add(name)
            for entry in self._xref_strings.get(addr, []):
                if entry not in strings: strings.append(entry)
        return list(imports), strings

    def summary(self):
        if self.binary is None: print("未加载"); return
        b = self.binary; sep = "─" * 50
        print(); print("  dslsde 终端逆向分析工具"); print(f"  {sep}")
        print(f"  文件:    {b.path}"); print(f"  格式:    {b.fmt}")
        print(f"  架构:    {b.arch}/{b.bits}"); print(f"  入口:    {b.entry:#010x}")
        print(f"  段:      {len(b.segments)}")
        for s in b.segments:
            sz = f"{s.size / 1024:.1f}K" if s.size > 1024 else f"{s.size}B"
            print(f"           {s.addr:#010x}  {sz:>8s}  [{s.flags}]  {s.name}")
        print(f"  符号:    {len(b.symbols)}")
        if self.functions:
            named = [f for f in self.functions if f.typ == "named"]
            unnamed = [f for f in self.functions if f.typ != "named"]
            print(f"  函数:    {len(self.functions)} ({len(named)} 已命名)")
            print(); print("  命名函数:")
            for f in named[:24]: print(f"    {f.addr:#010x}  {f.size:6d}B  {f.name}")
            if len(named) > 24: print(f"    ... 还有 {len(named) - 24} 个")
            if unnamed:
                print(); print(f"  未命名函数 (前 {min(len(unnamed), 12)}):")
                for f in unnamed[:12]: print(f"    {f.addr:#010x}  {f.size}B  sub_{f.addr:x}")
            entry_func = self.get_function(b.entry)
            if entry_func:
                print(); print(f"  入口函数: {entry_func.name or 'sub_'+hex(entry_func.addr)}")
                self._print_func_detail(entry_func)
            main_func = self.get_function("main")
            if main_func and main_func != entry_func:
                print(); print(f"  main 函数: 0x{main_func.addr:x}")
                self._print_func_detail(main_func)
        print(f"  {sep}"); print(f"  Web: python main.py serve {self._path}"); print()

    def _print_func_detail(self, func):
        imports, strings = self._xrefs_for_func(func)
        if imports:
            print(f"    调用导入:")
            for name in imports: print(f"      {name}")
        if strings:
            print(f"    引用字符串:")
            for addr, s in strings[:5]:
                s_short = s if len(s) < 60 else s[:57] + "..."
                print(f"      {addr:#010x}  \"{s_short}\"")
            if len(strings) > 5: print(f"      ... 还有 {len(strings) - 5} 个")
        insns = self.db.load_instructions(func.addr, func.addr + min(func.size or 160, 160))
        for insn in insns[:10]:
            print(f"    {insn['addr']:#010x}  {insn['mnemonic']:8s} {insn['operands']}")

    def _get_plt_map(self) -> Dict[int, str]:
        if hasattr(self, '_plt_map'): return self._plt_map
        self._plt_map = {}
        rip_re = re.compile(r'rip\s*[-+]\s*0x[0-9a-fA-F]+')
        for seg in self.binary.exec_segments:
            for insn in self.db.load_instructions(seg.addr, seg.addr + seg.size):
                mn, op = insn.get("mnemonic", ""), insn.get("operands", "")
                if mn in ("jmp", "jmpq") and "rip" in op:
                    m = rip_re.search(op)
                    if m:
                        part = m.group(); sz = insn.get("size", 0); addr = insn["addr"]
                        if "+" in part: got = addr + sz + int(part.split("+")[1].strip(), 16)
                        else: got = addr + sz - int(part.split("-")[1].strip(), 16)
                        name = self.binary.relocate_name(got)
                        if name: self._plt_map[addr] = name
        return self._plt_map

    def run_function(self, func_addr: int, args: List[int] = None, timeout: float = 1.0) -> str:
        if self.binary is None: return "// no binary loaded"
        if args is None:
            func = None
            for f in self.functions:
                if f.addr == func_addr: func = f; break
            if func and func.insn_count > 0:
                from engine.disasm import Disassembler
                d = Disassembler(self.binary)
                pi = ParamInferrer(self.binary, d, self.functions)
                results = pi.infer(func_addr)
                args = []
                if results and results[0]["params"]:
                    args = [p["value"] for p in results[0]["params"] if isinstance(p["value"], int)][:6]
        # 多路径执行：用不同参数跑多次，合并路径
        all_traces = []
        arg_sets = [args]
        for alt in [[0]*6, [1]*6, [9999]*6]:
            if alt != args and alt != [0]*6:  # 避免重复
                pass
        # 默认只跑一次，后续可扩展多参数
        runner = Runner(self.binary)
        raw_trace = runner.run(func_addr, args=args, timeout=timeout)
        runner.close()
        if not raw_trace: return "// (no trace)"

        # 合并所有 trace（去重）
        trace_set = {}
        for addr, size in raw_trace:
            if addr not in trace_set:
                trace_set[addr] = size
        merged = sorted(trace_set.items())

        # 构建富化 trace（从 func_addr 开始，跳过 PLT 桩）
        insn_map = {}
        for seg in self.binary.exec_segments:
            for row in self.db.load_instructions(seg.addr, seg.addr + seg.size):
                insn_map[row["addr"]] = row
        enriched = []
        started = False
        for addr, size in merged:
            if addr >= func_addr:
                started = True
            if started:
                if addr in insn_map:
                    row = insn_map[addr]
                    enriched.append((addr, size, row["mnemonic"], row["operands"]))

        # 字符串表（用于 LEA 解析）
        str_map = {}
        rip_re2 = re.compile(r'rip\s*[-+]\s*0x[0-9a-fA-F]+')
        for seg in self.binary.exec_segments:
            for row in self.db.load_instructions(seg.addr, seg.addr + seg.size):
                if "lea" in row["mnemonic"] and "rip" in row["operands"]:
                    m = rip_re2.search(row["operands"])
                    if m:
                        part = m.group()
                        if "+" in part:
                            ta = row["addr"] + row["size"] + int(part.split("+")[1].strip(), 16)
                        else:
                            ta = row["addr"] + row["size"] - int(part.split("-")[1].strip(), 16)
                        s = self.binary.string_at(ta)
                        if s: str_map[ta] = s

        ie = dslsde_core.InferenceEngine()
        from engine.sigs import get_sig_map
        ie.set_sig_map(get_sig_map())
        fm = {f.addr: f.name for f in self.functions if f.name}
        ie.set_func_map(fm)
        ie.set_plt_map(self._get_plt_map())
        gm = {r.addr: r.name for r in self.binary.relocations if r.name}
        ie.set_got_map(gm)
        ie.set_str_map(str_map)
                # 构建 PyInsnInfo（用于 CFG）
        all_rows = []
        for seg in self.binary.exec_segments:
            all_rows.extend(self.db.load_instructions(seg.addr, seg.addr + seg.size))
        py_insns = []
        for row in all_rows:
            mn, op = row["mnemonic"], row["operands"]
            first = op.split(",")[0].strip() if op else ""
            target = int(first, 16) if first.startswith("0x") else 0
            py_insns.append(dslsde_core.PyInsnInfo(
                row["addr"], target, row["addr"] + row["size"], row["size"],
                mn, op, row["bytes"], mn in ("call","callq"), mn in ("ret","retq"),
                mn in ("jmp","jmpq"),
                (mn.startswith("j") and mn not in ("jmp","jmpq","call","callq")),
                (mn in ("call","callq","jmp","jmpq") and "[" in op)))
        return ie.infer_structured(enriched, [int(a) for a in args], py_insns)
