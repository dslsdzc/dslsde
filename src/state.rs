use std::collections::{HashMap, HashSet};
use crate::ir::*;
use crate::infer::InferenceEngine;
use crate::ssa::{SsaContext, SsaOp};

impl InferenceEngine {
    pub(crate) fn build_state(&self, trace: &[(u64, u32, String, String)], args: &[i64],
                              ssa: &mut SsaContext) -> State {
        let aregs = ["rdi","rsi","rdx","rcx","r8","r9"];
        let mut regs = HashMap::new();
        for (i, v) in args.iter().enumerate().take(6) { regs.insert(aregs[i].to_string(), ValueDomain::Signed(*v)); }
        let mut stmts = Vec::new(); let mut stack: HashMap<i64, ValueDomain> = HashMap::new();
        let mut ssa_ids: HashMap<u64, u32> = HashMap::new();
        let mut canary_regs: HashSet<String> = HashSet::new();
        for &(addr, sz, ref mn, ref op) in trace {
            let (dd, ss) = sp(op); let dst = strip_size(dd); let src = strip_size(ss); let is_md = so(dst).is_some();
            let stmt = if matches!(mn.as_str(), "call"|"callq") { self.make_call(addr, &regs, dst)
            } else if matches!(mn.as_str(), "ret"|"retq") { Stmt::Return { addr, val: regs.get("rax").cloned() }
            } else if mn == "test" {
                let (td, ts) = sp(op);
                if td.trim() == ts.trim() { Stmt::Comment(addr, format!("cmp {}, 0", td.trim())) }
                else { Stmt::Comment(addr, format!("cmp {} & {}", td.trim(), ts.trim())) }
            } else if mn == "cmp" {
                if op.contains("rip") {
                    let resolved = resolve_rip_cmp(addr, sz, op, &self.got_map);
                    Stmt::Comment(addr, resolved)
                } else { Stmt::Comment(addr, format!("cmp {}", op)) }
            } else if mn.starts_with('j') { let t = iv(dst_or_src(dst, src)).unwrap_or(0) as u64; if t == 0 { Stmt::Nop } else { Stmt::Branch { addr, cond: mn.clone(), target: t, anno: Annotation::None } }
            } else if mn.starts_with("mov") {
                // 寄存器覆写 → 清除金丝雀标记（除非本次就是 fs 加载）
                if let Some(r) = ro(dst) { canary_regs.remove(r); }
                let stmt = if op.contains("fs:0x28") || op.contains("fs:[0x28]") {
                    // 栈金丝雀加载: mov reg, fs:[0x28]
                    let val = ValueDomain::Pointer(0x28);
                    if let Some(d) = ro(dst) {
                        regs.insert(d.to_string(), val.clone());
                        canary_regs.insert(d.to_string());
                        Stmt::Assign { addr, dst: d.to_string(), val, info: "fs:[0x28]".to_string(), anno: Annotation::None }
                    } else { Stmt::Nop }
                } else if src.contains("rip") { self.make_mov_rip(addr, sz, &mut regs, &mut stack, dst, src) }
                           else { self.make_assign(addr, &mut regs, &mut stack, dst, src) };
                // SSA: 记录寄存器写
                if let Stmt::Assign { ref dst, ref val, .. } = stmt {
                    if let Some(r) = ro(dst) {
                        let sid = ssa.write_reg(addr, 0, r, Some(val.clone()), SsaOp::Assign, vec![]);
                        ssa_ids.insert(addr, sid);
                    }
                }
                stmt
            } else if matches!(mn.as_str(), "add"|"sub"|"imul"|"xor"|"and"|"or") {
                if let Some(r) = ro(dst) { canary_regs.remove(r); }
                let stmt = if is_md { self.make_arith_mem(addr, &mut regs, &mut stack, mn, dst, src) } else { self.make_arith(addr, &mut regs, &stack, mn, dst, src) };
                if let Stmt::Assign { ref dst, ref val, .. } = stmt {
                    if let Some(r) = ro(dst) {
                        let sid = ssa.write_reg(addr, 0, r, Some(val.clone()), SsaOp::BinOp(mn.clone()), vec![]);
                        ssa_ids.insert(addr, sid);
                    }
                }
                stmt
            } else if mn == "lea" {
                if let Some(r) = ro(dst) { canary_regs.remove(r); }
                if let Some(d) = ro(dst) { if src.contains("rip") {
                    if let Ok(re) = regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)") { if let Some(caps) = re.captures(src) {
                        if let Ok(off) = i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(&caps[2]), 16) {
                            let target = if &caps[1] == "+" { (addr as i64 + sz as i64 + off) as u64 } else { (addr as i64 + sz as i64 - off) as u64 };
                            if let Some(s) = self.str_map.get(&target) { regs.insert(d.to_string(), ValueDomain::String(s.clone())); let sid = ssa.write_reg(addr, 0, d, Some(ValueDomain::String(s.clone())), SsaOp::Assign, vec![]); ssa_ids.insert(addr, sid); } else { regs.insert(d.to_string(), ValueDomain::Pointer(target)); let sid = ssa.write_reg(addr, 0, d, Some(ValueDomain::Pointer(target)), SsaOp::Assign, vec![]); ssa_ids.insert(addr, sid); }
                        }
                    }}}
                } else { if let Some(d) = ro(dst) { let sid = ssa.write_reg(addr, 0, d, Some(ValueDomain::Pointer(0)), SsaOp::Assign, vec![]); ssa_ids.insert(addr, sid); } regs.insert(dst.to_string(), ValueDomain::Pointer(0)); } Stmt::Nop
            } else if matches!(mn.as_str(), "push"|"pop"|"endbr64"|"endbr32"|"nop"|"nopq"|"xchg"|"cqo"|"cdqe"|"cdq"|"rep"|"repz"|"repnz"|"stos"|"stosb"|"stosd"|"stosq"|"movs"|"movsb"|"retf"|"iret"|"syscall"|"sysenter"|"int3") { Stmt::Nop
            } else if mn.starts_with("cmov") { Stmt::Nop } else { Stmt::Comment(addr, format!("{} {}", mn, op)) };
            stmts.push(stmt);
        }
        State { stmts, regs, stack, changed: false, iteration: 0, addr_map: HashMap::new(), ssa_ids, canary_regs }
    }
    pub(crate) fn make_call(&self, addr: u64, regs: &HashMap<String, ValueDomain>, dst: &str) -> Stmt {
        let name = resolve_call_name(dst, 0, 0, &self.got_map, &self.func_map, &self.plt_map);
        let mut args: Vec<ValueDomain> = Vec::new();
        for r in &["rdi","rsi","rdx","rcx","r8","r9"] { if let Some(v) = regs.get(*r) { if let ValueDomain::Signed(x) = v { if *x > 0x100000000 { break; } } args.push(v.clone()); } else { break; } }
        Stmt::Call { addr, name, args }
    }
    pub(crate) fn make_assign(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, dst: &str, src: &str) -> Stmt {
        if let Some(off) = so(dst) { if let Some(s) = ro(src) { let val = regs.get(s).cloned().unwrap_or(ValueDomain::Unknown); stack.insert(off, val.clone()); return Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: s.to_string(), anno: Annotation::None }; } if let Some(v) = iv(src) { let val = ValueDomain::Signed(v); stack.insert(off, val.clone()); return Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: src.to_string(), anno: Annotation::None }; } return Stmt::Nop; }
        if let Some(off) = so(src) { if let Some(d) = ro(dst) { let val = stack.get(&off).cloned().unwrap_or(ValueDomain::Unknown); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: format!("[rbp{:+}]", off), anno: Annotation::None }; } return Stmt::Nop; }
        if let Some(d) = ro(dst) { if let Some(v) = iv(src) { let val = ValueDomain::Signed(v); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: src.to_string(), anno: Annotation::None }; } if let Some(s) = ro(src) { let val = regs.get(s).cloned().unwrap_or(ValueDomain::Unknown); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: s.to_string(), anno: Annotation::None }; } }
        Stmt::Nop
    }
    pub(crate) fn make_arith(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &HashMap<i64, ValueDomain>, mn: &str, dst: &str, src: &str) -> Stmt {
        let Some(d) = ro(dst) else { return Stmt::Comment(addr, format!("{} {}, {}", mn, dst, src)) };
        let a = regs.get(d).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None });
        let b = ro(src).and_then(|s| regs.get(s)).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).or_else(|| so(src).and_then(|o| stack.get(&o).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }))).or_else(|| iv(src));
        if let (Some(a), Some(b)) = (a, b) { let r = match mn { "add"=>a.wrapping_add(b),"sub"=>a.wrapping_sub(b),"imul"=>a.wrapping_mul(b),"xor"=>a^b,"and"=>a&b,"or"=>a|b,_=>0 };
            let val = ValueDomain::Signed(r); regs.insert(d.to_string(), val.clone()); Stmt::Assign { addr, dst: d.to_string(), val, info: format!("{} {}", op_sym_rs(mn), src), anno: Annotation::None }
        } else { Stmt::Comment(addr, format!("{} {}, {}", mn, dst, src)) }
    }
    pub(crate) fn make_arith_mem(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, mn: &str, dst: &str, src: &str) -> Stmt {
        if let Some(off) = so(dst) {
            let a = stack.get(&off).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).unwrap_or(0);
            let b = ro(src).and_then(|s| regs.get(s)).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).or_else(|| iv(src)).unwrap_or(0);
            let r = match mn { "add"=>a.wrapping_add(b),"sub"=>a.wrapping_sub(b), _=>0 };
            let val = ValueDomain::Signed(r); stack.insert(off, val.clone()); Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: format!("{} {}", op_sym_rs(mn), src), anno: Annotation::None }
        } else { Stmt::Comment(addr, format!("{} {}, {}", mn, dst, src)) }
    }
    pub(crate) fn make_mov_rip(&self, addr: u64, sz: u32, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, dst: &str, src: &str) -> Stmt {
        if let Ok(re) = regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)") {
            if let Some(caps) = re.captures(src) {
                if let Ok(off) = i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(&caps[2]), 16) {
                    let target = if &caps[1] == "+" { (addr as i64 + sz as i64 + off) as u64 } else { (addr as i64 + sz as i64 - off) as u64 };
                    let val = if let Some(n) = self.got_map.get(&target) { ValueDomain::Pointer(target) }
                              else if let Some(s) = self.str_map.get(&target) { ValueDomain::String(s.clone()) }
                              else { ValueDomain::Pointer(target) };
                    if let Some(d) = ro(dst) {
                        regs.insert(d.to_string(), val.clone());
                        return Stmt::Assign { addr, dst: d.to_string(), val, info: format!("[rip+0x{:x}]", target), anno: Annotation::None };
                    }
                }
            }
        }
        self.make_assign(addr, regs, stack, dst, src)
    }
}
