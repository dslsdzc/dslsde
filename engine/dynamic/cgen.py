"""dslsde — C 伪代码生成（SSA + 符号名 + 有符号）"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import re

from engine.loader import Binary
from engine.function import Function

_NOISE = {"endbr64", "endbr32", "nop", "nopq", "xchg", "repz ret", "rep ret"}
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


class CGen:
    def __init__(self, binary: Binary, functions: Optional[List[Function]] = None):
        self._binary = binary
        self._func_map: Dict[int, str] = {}
        if functions:
            for f in functions:
                if f.name:
                    self._func_map[f.addr] = f.name
        for sym in binary.symbols:
            if sym.addr not in self._func_map and sym.name:
                self._func_map[sym.addr] = sym.name
        # GOT → import name
        self._got_map: Dict[int, str] = {}
        for r in binary.relocations:
            if r.name:
                self._got_map[r.addr] = r.name
        # PLT jmp → import name (jmp [rip+offset] → GOT → symbol)
        rip_re = re.compile(r'rip\s*[-+]\s*0x[0-9a-fA-F]+')
        self._plt_map: Dict[int, str] = {}
        for seg in binary.exec_segments:
            insns = binary.read(seg.addr, seg.size)
            if not insns:
                continue
            # We need capstone, but we're in cgen without it
            # PLT mapping will be populated externally if needed
            pass

    def set_plt_map(self, m: Dict[int, str]):
        self._plt_map.update(m)

    def generate(self, trace, func_name="unknown", args=None) -> str:
        args = args or []
        if not trace:
            return "// (no trace)"

        # SSA variable pool
        ssa_ctr = [0]
        def ssa() -> str:
            ssa_ctr[0] += 1
            return f"t{ssa_ctr[0]}"

        regs: Dict[str, int] = {}
        for i, v in enumerate(args[:6]):
            regs[_ARG_REGS[i]] = v

        # SSA register → current variable name
        rvar: Dict[str, str] = {}
        for r in _ARG_REGS:
            rvar[r] = ssa()
        rvar["rax"] = ssa()

        stack: Dict[int, Tuple[str, Optional[int]]] = {}
        svm: Dict[int, str] = {}

        out = []
        prologue = True

        for entry in trace:
            insn = entry.get("insn")
            if not insn:
                continue
            mn, op = insn.mnemonic, insn.operands
            if mn in _NOISE:
                continue

            # prologue skip
            if prologue:
                if mn == "push" and op == "rbp": continue
                if mn == "mov" and (op.startswith("rbp, rsp") or op.startswith("ebp, esp")): continue
                if mn == "sub" and op.startswith("rsp,"):
                    vv = self._imm_val(op.split(",")[1].strip()) if "," in op else None
                    if vv: out.append(f"  // {vv} bytes")
                    prologue = False
                    continue
                if mn == "mov" and op.startswith("rsp, rbp"): continue
                if mn in ("push", "pop"): continue
                prologue = False

            # epilogue
            if (mn == "pop" and op == "rbp") or mn == "leave":
                rax = regs.get("rax")
                out.append(f"  return {self._sfx(rax)};" if rax is not None else "  return;")
                continue
            if mn in ("ret", "retq"):
                rax = regs.get("rax")
                if not any("return" in l for l in out[-2:]):
                    out.append(f"  return {self._sfx(rax)};" if rax is not None else "  return;")
                continue

            dst, src = (op.split(",", 1)[0].strip(), op.split(",", 1)[1].strip()) if "," in op else (op, "")

            if mn.startswith("mov"):
                self._m_mov(out, regs, rvar, stack, svm, ssa, mn, dst, src)
            elif mn in ("add", "sub", "imul", "xor", "and", "or"):
                self._m_arith(out, regs, rvar, stack, ssa, mn, dst, src)
            elif mn in ("call", "callq"):
                self._m_call(out, regs, rvar, dst, entry, src)
            elif mn in ("cmp", "test"):
                pass
            elif mn.startswith("j"):
                t = self._imm_val(dst or src)
                name = self._resolve_name(t) if t else "?"
                if t:
                    if mn in ("jmp", "jmpq"):
                        if name and not name.startswith("sub_"):
                            out.append(f"  return {name}(...);")
                        else:
                            out.append(f"  goto {name};")
                    else:
                        out.append(f"  if ({self._cnd(mn)}) goto {name};")
            elif mn == "lea":
                d, s = (op.split(",", 1)[0].strip(), op.split(",", 1)[1].strip()) if "," in op else (op, "")
                if "rip" in s:
                    ta = self._rta(entry, s)
                    s2 = self._binary.string_at(ta) if ta else None
                    out.append(f"  {d} = \"{s2}\";" if s2 else (f"  {d} = &data_{ta:#x};" if ta else f"  {d} = &{s};"))
                else:
                    out.append(f"  {d} = &{s};")

        return "\n".join(out)

    def _m_mov(self, out, regs, rvar, stack, svm, ssa, mn, dst, src):
        dr = self._r(dst)
        sr = self._r(src)

        # mov reg, imm
        if dr and (src.startswith("0x") or src.lstrip("-").isdigit()):
            regs[dr] = int(src, 0)
            rvar[dr] = ssa()
            return

        # mov reg, reg
        if dr and sr:
            if sr in regs:
                regs[dr] = regs[sr]
            rvar[dr] = rvar.get(sr, ssa())
            return

        # mov [rbp-X], reg → stack var
        oto = self._so(dst)
        if oto is not None and sr:
            val = regs.get(sr)
            stack[oto] = (src, val)
            if oto not in svm:
                svm[oto] = ssa()
            # Clear rvar for the stored value
            out.append(f"  {svm[oto]} = {rvar.get(sr, '?')};")
            return

        # mov reg, [rbp-X] → load from stack
        ofr = self._so(src)
        if ofr is not None and dr:
            if ofr in svm:
                _, val = stack.get(ofr, (None, None))
                if val is not None:
                    regs[dr] = val
                rvar[dr] = svm[ofr]
            else:
                rvar[dr] = ssa()
            return

    def _m_arith(self, out, regs, rvar, stack, ssa, mn, dst, src):
        dr = self._r(dst)
        sr = self._r(src)
        if not dr:
            return

        a = regs.get(dr)
        b = None
        if sr and sr in regs:
            b = regs[sr]
        elif src.startswith("0x") or src.lstrip("-").isdigit():
            b = int(src, 0)
        else:
            o = self._so(src)
            if o and o in stack:
                _, b = stack[o]

        if a is not None and b is not None:
            ops = {"add": a+b, "sub": a-b, "imul": a*b, "xor": a^b, "and": a&b, "or": a|b}
            r = ops[mn]
            regs[dr] = r
            src_name = rvar.get(sr, self._sfx(b)) if sr else self._sfx(b)
            old_var = rvar.get(dr, '?')
            new_var = ssa()
            rvar[dr] = new_var
            out.append(f"  {new_var} = {old_var} {self._os(mn)} {src_name};  // {self._sfx(a)} {self._os(mn)} {self._sfx(b)} = {self._sfx(r)}")
        else:
            out.append(f"  // {mn} {dst}, {src}")

    def _m_call(self, out, regs, rvar, dst, entry, src):
        t = self._imm_val(dst)
        name = "??"
        if t:
            name = self._resolve_name(t)
            # also check PLT map
            if t in self._plt_map:
                name = self._plt_map[t] + "@plt"
        elif "rip" in dst:
            got_addr = self._rta(entry, dst)
            if got_addr:
                name = self._got_map.get(got_addr, f"ptr_{got_addr:x}")

        av = []
        for rn in _ARG_REGS:
            v = regs.get(rn)
            av.append(v)
        while av and (av[-1] is None or (isinstance(av[-1], int) and av[-1] > 0x100000000)):
            av.pop()
        disp = [self._sfx(v) if v is not None else "?" for v in av] or ["?"]
        out.append(f"  {name}({', '.join(disp)});")

        # call clobbers rax (return value)
        if "rax" in regs:
            del regs["rax"]

    @staticmethod
    def _r(op):
        m = {"eax":"rax","rax":"rax","ebx":"rbx","rbx":"rbx","ecx":"rcx","rcx":"rcx",
             "edx":"rdx","rdx":"rdx","esi":"rsi","rsi":"rsi","edi":"rdi","rdi":"rdi",
             "rbp":"rbp","rsp":"rsp","r8d":"r8","r8":"r8","r9d":"r9","r9":"r9"}
        return m.get(op)

    @staticmethod
    def _sfx(v):
        """有符号格式化"""
        if v is None: return "?"
        if v == 0: return "0"
        if 1 <= v <= 9999: return str(v)
        # 负数值
        if v > 0x7fffffffffffffff:
            neg = v - 0x10000000000000000
            if neg >= -9999:
                return str(neg)
            return f"{neg:#x}"
        return f"{v:#x}"

    @staticmethod
    def _imm_val(op):
        if not op: return None
        if op.startswith("0x"):
            try: return int(op, 16)
            except ValueError: return None
        if op.lstrip("-").isdigit(): return int(op, 10)
        return None

    @staticmethod
    def _so(op):
        m = re.search(r'\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]', op)
        if m:
            sign = 1 if m.group(1) == "+" else -1
            return sign * int(m.group(2), 16 if m.group(2).startswith("0x") else 10)
        return None

    def _resolve_name(self, addr):
        if addr in self._func_map: return self._func_map[addr]
        for sym in self._binary.symbols:
            if sym.addr == addr and sym.name: return sym.name
        return f"sub_{addr:x}"

    def set_plt_map(self, m: Dict[int, str]):
        self._plt_map.update(m)

    @staticmethod
    def _rta(entry, op):
        m = re.search(r'rip\s*([-+])\s*(0x[0-9a-fA-F]+)', op)
        if not m: return None
        insn = entry.get("insn")
        if not insn: return None
        ofs = int(m.group(2), 16)
        return insn.addr + insn.size + ofs if m.group(1) == "+" else insn.addr + insn.size - ofs

    @staticmethod
    def _os(mn):
        return {"add":"+","sub":"-","imul":"*","xor":"^","and":"&","or":"|"}.get(mn,"?")

    @staticmethod
    def _cnd(mn):
        return {"jz":"==0","je":"==","jne":"!=","jnz":"!=",
                "jg":">","jge":">=","jl":"<","jle":"<="}.get(mn,mn)
