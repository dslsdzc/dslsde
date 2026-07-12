use std::collections::{HashMap, HashSet};
use pyo3::prelude::*;
use crate::cfg::{Cfg, build_cfg_internal};
use crate::insn::PyInsnInfo;
use crate::types::{VarType, infer_var_type};

#[derive(Clone, Debug, PartialEq)]
pub enum ValueDomain { Unknown, Signed(i64), Unsigned(u64), Pointer(u64), Boolean, String(String) }
#[derive(Clone, Debug, PartialEq)]
pub enum Annotation { None, BoundsCheck, NullCheck, OverflowGuard, SwitchDispatch, LoopBackEdge }
#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Assign { addr: u64, dst: String, val: ValueDomain, info: String, anno: Annotation },
    Call { addr: u64, name: String, args: Vec<ValueDomain> },
    Branch { addr: u64, cond: String, target: u64, anno: Annotation },
    Return { addr: u64, val: Option<ValueDomain> }, Comment(u64, String), Nop,
}
#[derive(Clone)]
pub struct State {
    pub stmts: Vec<Stmt>, pub regs: HashMap<String, ValueDomain>,
    pub stack: HashMap<i64, ValueDomain>, pub changed: bool, pub iteration: u32,
    pub addr_map: HashMap<u64, String>,
}

#[pyclass]
pub struct InferenceEngine {
    func_map: HashMap<u64, String>, got_map: HashMap<u64, String>,
    plt_map: HashMap<u64, String>, str_map: HashMap<u64, String>,
    sig_map: HashMap<String, (u32, bool)>,
}

#[pymethods]
impl InferenceEngine {
    #[new] pub fn new() -> Self { InferenceEngine { func_map: HashMap::new(), got_map: HashMap::new(), plt_map: HashMap::new(), str_map: HashMap::new(), sig_map: HashMap::new() } }
    pub fn set_func_map(&mut self, m: HashMap<u64, String>) { self.func_map = m; }
    pub fn set_got_map(&mut self, m: HashMap<u64, String>) { self.got_map = m; }
    pub fn set_plt_map(&mut self, m: HashMap<u64, String>) { self.plt_map = m; }
    pub fn set_str_map(&mut self, m: HashMap<u64, String>) { self.str_map = m; }
    pub fn set_sig_map(&mut self, m: HashMap<String, (u32, bool)>) { self.sig_map = m; }
    pub fn infer(&mut self, trace: Vec<(u64, u32, String, String)>, args: Vec<i64>) -> String {
        let mut state = self.build_state(&trace, &args);
        for i in 0..5 {
            state.iteration = i; state.changed = false;
            self.pass_noise_filter(&mut state); self.pass_value_domain(&mut state);
            self.pass_constraint(&mut state); self.pass_arg_purify(&mut state);
        }
        self.emit_flat(&state)
    }
    pub fn infer_structured(&mut self, trace: Vec<(u64, u32, String, String)>,
                            args: Vec<i64>, py_insns: Vec<PyRef<PyInsnInfo>>) -> String {
        let mut state = self.build_state(&trace, &args);
        for i in 0..5 {
            state.iteration = i; state.changed = false;
            self.pass_noise_filter(&mut state); self.pass_value_domain(&mut state);
            self.pass_constraint(&mut state); self.pass_arg_purify(&mut state);
            if !state.changed { break; }
        }
        state.addr_map = self.build_addr_map(&state);
        let native: Vec<PyInsnInfo> = py_insns.iter().map(|r| (*r).clone()).collect();
        let cfg = build_cfg_internal(&native);
        let trace_addrs: HashSet<u64> = trace.iter().map(|t| t.0).collect();
        self.emit_structured(&state, &cfg, &trace_addrs)
    }
}
impl InferenceEngine {
    fn build_addr_map(&self, state: &State) -> HashMap<u64, String> {

        // Pass 1: collect patterns for variable naming
        #[derive(Default)]
        struct Pat { from_arg: bool, inc1: bool, compared_low: bool, compared_high: bool, returned: bool, vtype: VarType }
        let mut pats: HashMap<i64, Pat> = HashMap::new();
        for stmt in &state.stmts {
            if let Stmt::Assign { dst, info, anno, .. } = stmt {
                if *anno == Annotation::OverflowGuard { continue; }
                if let Some(off) = so(dst) {
                    let p = pats.entry(off).or_default();
                    if matches!(info.as_str(), "rdi"|"rsi"|"rdx"|"rcx"|"r8"|"r9") { p.from_arg = true; }
                    // Type inference
                    if p.vtype == VarType::Unknown {
                        if let Some(t) = infer_var_type(info) { p.vtype = t; }
                    }
                    if info.contains(' ') {
                        if info.split(' ').nth(1).unwrap_or("") == "1" { p.inc1 = true; }
                    }
                }
            }
        }
        // last_cmp 用于分支条件输出
        let mut last_cmp = String::new();
        // Pass 1.5: cmp 操作数 → 变量命名提示
        for stmt in &state.stmts {
            if let Stmt::Comment(_, c) = stmt {
                if let Some(rest) = c.strip_prefix("cmp ") {
                    let parts: Vec<&str> = rest.splitn(2, ',').collect();
                    if parts.len() == 2 {
                        let lhs = strip_size(parts[0]);
                        let rhs = strip_size(parts[1]);
                        // 检查左右操作数的 [rbp+X] → 设置 compared_low/compared_high
                        for (side, other) in &[(lhs, rhs), (rhs, lhs)] {
                            if let Some(off) = so(side) {
                                let p = pats.entry(off).or_default();
                                if let Some(v) = iv(other) {
                                    if v > 100 { p.compared_high = true; }
                                    if v < 10  { p.compared_low = true; }
                                }
                            }
                        }
                    }
                }
            }
        }
        for stmt in &state.stmts {
            if let Stmt::Assign { dst, info, .. } = stmt {
                if dst == "rax" {
                    // rax = [rbp+X] → 该变量被返回
                    if let Some(off) = so(info) { pats.entry(off).or_default().returned = true; }
                    // rax = reg → 如果 reg 指向变量
                    if let Some(r) = ro(info) {
                        // 查找最近一次加载该 reg 的栈变量
                        for s2 in state.stmts.iter().rev() {
                            if let Stmt::Assign { dst: d2, info: i2, .. } = s2 {
                                if d2 == r && i2.starts_with("[rbp") {
                                    if let Some(off) = so(i2) {
                                        pats.entry(off).or_default().returned = true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Semantic naming
        let mut vn: HashMap<i64, String> = HashMap::new();
        for (&off, p) in &pats {
            let name: String = if p.from_arg && p.compared_high { "n".into() }
                else if p.inc1 { "i".into() }
                else if p.returned && !p.inc1 { "sum".into() }
                else if p.from_arg { format!("arg_{}", -off) }
                else { format!("v{}", pats.keys().filter(|&&k| k < off).count() + 1) };
            vn.insert(off, name);
        }

        // Pass 2: generate output
        let mut m: HashMap<u64, String> = HashMap::new();
        let mut rv: HashMap<String, String> = HashMap::new();
        // 寄存器→全局符号 映射（rg），让条件能用符号名
        let mut rg: HashMap<String, String> = HashMap::new();
        for stmt in &state.stmts {
            if let Stmt::Assign { dst, val, .. } = stmt {
                if let Some(r) = ro(dst) {
                    if let ValueDomain::Pointer(addr) = val {
                        let name = if let Some(n) = self.got_map.get(addr) { n.clone() }
                                    else { format!("global_{:#x}", addr) };
                        rg.insert(r.to_string(), name);
                    }
                }
            }
        }
        for stmt in &state.stmts {
            match stmt {
                Stmt::Comment(ca, c) => {
                    if c.starts_with("cmp ") {
                        let cmp_trim = c[4..].trim();
                        if let Some(parts) = cmp_trim.split_once(',').map(|(l,r)| format!("{},{}", l.trim(), r.trim())) {
                            last_cmp = parts;
                        } else {
                            last_cmp = cmp_trim.to_string();
                        }
                    }
                    // 输出非trivial注释 (sub, sar, cmov等)
                    if !c.starts_with("cmp ") && !c.starts_with("push ") && !c.starts_with("pop ") && !c.starts_with("nop") && !c.starts_with("endbr") && !c.starts_with("rep") && c.len() < 50 {
                        m.insert(*ca, format!("// {}", c));
                    }
                }
                Stmt::Assign { addr, dst, val, info, anno } => {
                    if *anno == Annotation::OverflowGuard { continue; }
                    let val_s = |v: &ValueDomain, i: &str| -> String {
                        match v {
                            ValueDomain::Unknown if !i.is_empty() && !i.contains(' ') && !i.starts_with('[') => i.to_string(),
                            _ => fmt_val(v),
                        }
                    };
                    if info.starts_with("[rbp") {
                        if let Some(off) = so(&info) {
                            if let Some(name) = vn.get(&off) { rv.insert(dst.clone(), name.clone()); }
                        }
                    }
                    if dst.starts_with("[rbp") {
                        let Some(off) = so(dst) else { continue; };
                        let Some(name) = vn.get(&off) else { continue; };
                        let line = if info.contains(' ') {
                            let sp = info.find(' ').unwrap();
                            format!("{} {}= {}", name, &info[..sp].trim(), resolve_reg(&info[sp..].trim(), &rv))
                        } else if matches!(info.as_str(), "rdi"|"rsi"|"rdx"|"rcx"|"r8"|"r9") {
                            format!("{} = {}", name, val_s(val, info))
                        } else {
                            format!("{} = {}", name, val_s(val, info))
                        };
                        m.insert(*addr, line);
                    } else if let Some(r) = ro(&dst) {
                        // 寄存器赋值全跳过 — 不污染C输出
                    }
                }
                Stmt::Branch { addr, cond, anno, .. } => {
                    if *anno != Annotation::None { continue; }
                    if matches!(cond.as_str(), "jmp"|"jmpq") { continue; }
                    if last_cmp.is_empty() {
                        m.insert(*addr, format!("if ({})", cstr(cond)));
                    } else {
                        let clean = last_cmp.replace("qword ptr ", "").replace("dword ptr ", "").replace("word ptr ", "").replace("byte ptr ", "");
                        let parts: Vec<&str> = clean.splitn(2, ',').collect();
                        if parts.len() == 2 {
                            let lhs_raw = parts[0].trim();
                            let rhs_raw = parts[1].trim();
                            // 先用 so_name 解析栈变量名，查不到则查 rg（全局符号）
                            let lhs = so_name(lhs_raw, &vn, &rv);
                            let rhs = so_name(rhs_raw, &vn, &rv);
                            let lhs = if lhs == lhs_raw { resolve_reg_global(lhs_raw, &rv, &rg) } else { lhs };
                            let rhs = if rhs == rhs_raw { resolve_reg_global(rhs_raw, &rv, &rg) } else { rhs };
                            m.insert(*addr, format!("if ({} {} {})", lhs, cstr(cond), rhs));
                        } else {
                            m.insert(*addr, format!("if ({} {})", clean, cstr(cond)));
                        }
                        last_cmp.clear();
                    }
                }
                Stmt::Call { addr, name, args, .. } => { let a: Vec<String> = args.iter().map(fmt_val).collect(); if !a.is_empty() { m.insert(*addr, format!("{}({});", name, a.join(", "))); } }
                Stmt::Return { addr, val, .. } => { m.insert(*addr, format!("return {};", val.as_ref().map_or("?".into(), fmt_val))); }
                _ => {}
            }
        }
        m
    }

    fn emit_flat(&self, state: &State) -> String {
        let mut out = Vec::new(); let mut depth = 0u64;
        for stmt in &state.stmts {
            match stmt {
                Stmt::Nop => continue,
                Stmt::Comment(_, c) => { if !c.is_empty() && !c.starts_with("cqo") { out.push(format!("{}{}", id(depth), c)); } }
                Stmt::Assign { dst, val, info, anno, .. } => { if *anno == Annotation::OverflowGuard { continue; } if dst.starts_with("[rbp") { out.push(format!("{}{} = {}  // {}", id(depth), dst, fmt_val(val), info)); } }
                Stmt::Branch { cond, anno, .. } => { if *anno != Annotation::None { continue; } if !matches!(cond.as_str(), "jmp"|"jmpq") { out.push(format!("{}if ({}) {{", id(depth), cstr(cond))); depth += 1; } }
                Stmt::Call { name, args, .. } => { let a: Vec<String> = args.iter().map(fmt_val).collect(); if !a.is_empty() { out.push(format!("{}{}({});", id(depth), name, a.join(", "))); } }
                Stmt::Return { val, .. } => { out.push(format!("{}return {};", id(depth), val.as_ref().map_or("?".into(), fmt_val))); }
            }
        }
        while depth > 0 { depth -= 1; out.push(format!("{}}}", id(depth))); }
        out.join("\n")
    }

    fn emit_structured(&self, state: &State, cfg: &Cfg, trace: &HashSet<u64>) -> String {
        let mut out = Vec::new(); let mut visited = HashSet::new(); let mut consumed = HashSet::new();
        let first = *trace.iter().min().unwrap_or(&0); let entry = cfg.blocks.keys().filter(|&&k| k <= first).last().copied().unwrap_or(cfg.entry);
        self.emit_block(entry, cfg, &state.addr_map, trace, &mut visited, &mut consumed, 0, &mut out); out.join("\n")
    }

    fn emit_block(&self, addr: u64, cfg: &Cfg, lines: &HashMap<u64, String>, trace: &HashSet<u64>,
                  visited: &mut HashSet<u64>, consumed: &mut HashSet<u64>, depth: usize, out: &mut Vec<String>) {
        if addr == 0 || !cfg.blocks.contains_key(&addr) || visited.contains(&addr) { return; }
        visited.insert(addr);
        let block = &cfg.blocks[&addr];
        let has_lines = (block.addr..block.addr + block.size).any(|a| lines.contains_key(&a));
        let block_traced = (block.addr..block.addr + block.size).any(|a| trace.contains(&a));
        if !has_lines && !block_traced {
            // 跳过空块，但如果有单个后继则继续穿透
            if block.succs.len() == 1 { self.emit_block(block.succs[0], cfg, lines, trace, visited, consumed, depth, out); }
            return;
        }
        let ind = "  ".repeat(depth);
        for a in block.addr..block.addr + block.size { if let Some(line) = lines.get(&a) { if !consumed.contains(&a) { out.push(format!("{}{}", ind, line)); } } }
        if block.succs.is_empty() { return; }
        if block.succs.len() == 1 { self.emit_block(block.succs[0], cfg, lines, trace, visited, consumed, depth, out); return; }
        let t = block.succs[0]; let e = block.succs[1];
        if t < addr || e < addr {
            let ls = t.min(e);
            let mut fc = String::new(); let mut fi = String::new();
            for a in block.addr..block.addr + block.size { if let Some(line) = lines.get(&a) { if line.starts_with("if (") && line.ends_with(')') { fc = line[4..line.len()-1].to_string(); } } }
            let mut bc = ls;
            while bc < addr { if let Some(b) = cfg.blocks.get(&bc) { for a in b.addr..b.addr + b.size { if let Some(l) = lines.get(&a) { if l.contains("+=") && l.len() < 20 { fi = l.trim().to_string(); } } } if b.succs.len() == 1 { bc = b.succs[0]; } else { break; } } else { break; } }
            let mut finit = String::new();
            if !fc.is_empty() && !fi.is_empty() {
                let vname = fi.split(' ').next().unwrap_or("");
                if !vname.is_empty() {
                    for &pred in &cfg.blocks[&addr].preds { if pred == ls { continue; }
                        if let Some(pb) = cfg.blocks.get(&pred) { for a in pb.addr..pb.addr + pb.size { if let Some(l) = lines.get(&a) { if l.starts_with(vname) && (l.contains("= 0") || l.contains("= 1")) { finit = l.split("//").next().unwrap_or("").trim().to_string(); consumed.insert(a); } } } }
                    }
                }
            }
            if !fc.is_empty() && !fi.is_empty() {
                if !finit.is_empty() { out.push(format!("{}for ({}; {}; {}) {{", ind, finit, fc, fi)); }
                else { out.push(format!("{}for (; {}; {}) {{", ind, fc, fi)); }
            } else { out.push(format!("{}for (;;) {{", ind)); }
            let mut c = ls; while c < addr && !visited.contains(&c) { visited.insert(c);
                if let Some(b) = cfg.blocks.get(&c) { for a in b.addr..b.addr + b.size { if let Some(l) = lines.get(&a) { if !fi.is_empty() && l.trim() == fi.trim() { continue; } out.push(format!("{}{}", "  ".repeat(depth + 1), l)); } } if b.succs.len() == 1 { c = b.succs[0]; } else { break; } } else { break; }
            } out.push(format!("{}}}", ind));
        } else {
            let in_t = |x: u64| cfg.blocks.get(&x).map_or(false, |bl| (bl.addr..bl.addr + bl.size).any(|a| trace.contains(&a)));
            let taken = if in_t(e) { e } else { t }; let not_taken = if taken == t { e } else { t };
            out.push(format!("{}{{", ind)); self.emit_block(taken, cfg, lines, trace, visited, consumed, depth + 1, out);
            if not_taken != 0 && cfg.blocks.contains_key(&not_taken) && in_t(not_taken) { out.push(format!("{}}} else {{", ind)); self.emit_block(not_taken, cfg, lines, trace, visited, consumed, depth + 1, out); }
            out.push(format!("{}}}", ind));
        }
    }
}

impl InferenceEngine {
    fn build_state(&self, trace: &[(u64, u32, String, String)], args: &[i64]) -> State {
        let aregs = ["rdi","rsi","rdx","rcx","r8","r9"];
        let mut regs = HashMap::new();
        for (i, v) in args.iter().enumerate().take(6) { regs.insert(aregs[i].to_string(), ValueDomain::Signed(*v)); }
        let mut stmts = Vec::new(); let mut stack: HashMap<i64, ValueDomain> = HashMap::new();
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
                if src.contains("rip") { self.make_mov_rip(addr, sz, &mut regs, &mut stack, dst, src) }
                else { self.make_assign(addr, &mut regs, &mut stack, dst, src) }
            } else if matches!(mn.as_str(), "add"|"sub"|"imul"|"xor"|"and"|"or") {
                if is_md { self.make_arith_mem(addr, &mut regs, &mut stack, mn, dst, src) } else { self.make_arith(addr, &mut regs, &stack, mn, dst, src) }
            } else if mn == "lea" {
                if let Some(d) = ro(dst) { if src.contains("rip") {
                    if let Ok(re) = regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)") { if let Some(caps) = re.captures(src) {
                        if let Ok(off) = i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(&caps[2]), 16) {
                            let target = if &caps[1] == "+" { (addr as i64 + sz as i64 + off) as u64 } else { (addr as i64 + sz as i64 - off) as u64 };
                            if let Some(s) = self.str_map.get(&target) { regs.insert(d.to_string(), ValueDomain::String(s.clone())); } else { regs.insert(d.to_string(), ValueDomain::Pointer(target)); }
                        }
                    }}}
                } else { regs.insert(dst.to_string(), ValueDomain::Pointer(0)); } Stmt::Nop
            } else if matches!(mn.as_str(), "push"|"pop"|"endbr64"|"endbr32"|"nop"|"nopq"|"xchg"|"cqo"|"cdqe"|"cdq"|"rep"|"repz"|"repnz"|"stos"|"stosb"|"stosd"|"stosq"|"movs"|"movsb"|"retf"|"iret"|"syscall"|"sysenter"|"int3") { Stmt::Nop
            } else if mn.starts_with("cmov") { Stmt::Nop } else { Stmt::Comment(addr, format!("{} {}", mn, op)) };
            stmts.push(stmt);
        }
        State { stmts, regs, stack, changed: false, iteration: 0, addr_map: HashMap::new() }
    }
    fn make_call(&self, addr: u64, regs: &HashMap<String, ValueDomain>, dst: &str) -> Stmt {
        let name = resolve_call_name(dst, 0, 0, &self.got_map, &self.func_map, &self.plt_map);
        let mut args: Vec<ValueDomain> = Vec::new();
        for r in &["rdi","rsi","rdx","rcx","r8","r9"] { if let Some(v) = regs.get(*r) { if let ValueDomain::Signed(x) = v { if *x > 0x100000000 { break; } } args.push(v.clone()); } else { break; } }
        Stmt::Call { addr, name, args }
    }
    fn make_assign(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, dst: &str, src: &str) -> Stmt {
        if let Some(off) = so(dst) { if let Some(s) = ro(src) { let val = regs.get(s).cloned().unwrap_or(ValueDomain::Unknown); stack.insert(off, val.clone()); return Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: s.to_string(), anno: Annotation::None }; } if let Some(v) = iv(src) { let val = ValueDomain::Signed(v); stack.insert(off, val.clone()); return Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: src.to_string(), anno: Annotation::None }; } return Stmt::Nop; }
        if let Some(off) = so(src) { if let Some(d) = ro(dst) { let val = stack.get(&off).cloned().unwrap_or(ValueDomain::Unknown); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: format!("[rbp{:+}]", off), anno: Annotation::None }; } return Stmt::Nop; }
        if let Some(d) = ro(dst) { if let Some(v) = iv(src) { let val = ValueDomain::Signed(v); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: src.to_string(), anno: Annotation::None }; } if let Some(s) = ro(src) { let val = regs.get(s).cloned().unwrap_or(ValueDomain::Unknown); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: s.to_string(), anno: Annotation::None }; } }
        Stmt::Nop
    }
    fn make_arith(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &HashMap<i64, ValueDomain>, mn: &str, dst: &str, src: &str) -> Stmt {
        let Some(d) = ro(dst) else { return Stmt::Comment(addr, format!("{} {}, {}", mn, dst, src)) };
        let a = regs.get(d).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None });
        let b = ro(src).and_then(|s| regs.get(s)).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).or_else(|| so(src).and_then(|o| stack.get(&o).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }))).or_else(|| iv(src));
        if let (Some(a), Some(b)) = (a, b) { let r = match mn { "add"=>a.wrapping_add(b),"sub"=>a.wrapping_sub(b),"imul"=>a.wrapping_mul(b),"xor"=>a^b,"and"=>a&b,"or"=>a|b,_=>0 };
            let val = ValueDomain::Signed(r); regs.insert(d.to_string(), val.clone()); Stmt::Assign { addr, dst: d.to_string(), val, info: format!("{} {}", op_sym_rs(mn), src), anno: Annotation::None }
        } else { Stmt::Comment(addr, format!("{} {}, {}", mn, dst, src)) }
    }
    fn make_arith_mem(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, mn: &str, dst: &str, src: &str) -> Stmt {
        if let Some(off) = so(dst) {
            let a = stack.get(&off).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).unwrap_or(0);
            let b = ro(src).and_then(|s| regs.get(s)).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).or_else(|| iv(src)).unwrap_or(0);
            let r = match mn { "add"=>a.wrapping_add(b),"sub"=>a.wrapping_sub(b), _=>0 };
            let val = ValueDomain::Signed(r); stack.insert(off, val.clone()); Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: format!("{} {}", op_sym_rs(mn), src), anno: Annotation::None }
        } else { Stmt::Comment(addr, format!("{} {}, {}", mn, dst, src)) }
    }
    fn make_mov_rip(&self, addr: u64, sz: u32, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, dst: &str, src: &str) -> Stmt {
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
    fn pass_noise_filter(&self, state: &mut State) {
        if state.iteration > 0 { return; }
        let mut new = Vec::new(); let mut i = 0;
        while i < state.stmts.len() {
            let is_ov = i + 1 < state.stmts.len() && matches!(&state.stmts[i+1], Stmt::Branch { ref cond, .. } if matches!(cond.as_str(), "jo"|"jno"|"jb"|"jae"|"js"|"jns"));
            if is_ov { let mut a = state.stmts[i].clone(); a.set_anno(Annotation::OverflowGuard); new.push(a);
                let mut b = state.stmts[i+1].clone(); b.set_anno(Annotation::OverflowGuard); new.push(b); i += 2; state.changed = true; continue; }
            new.push(state.stmts[i].clone()); i += 1;
        } state.stmts = new;
    }
    fn pass_value_domain(&self, state: &mut State) { for stmt in &mut state.stmts { if let Stmt::Assign { ref mut val, .. } = stmt { *val = refine_domain(val.clone()); } } }
    fn pass_constraint(&self, state: &mut State) {
        let mut i = 0;
        while i + 1 < state.stmts.len() {
            if let Stmt::Branch { target, anno: Annotation::None, .. } = &state.stmts[i+1] {
                let name = rn(*target, &self.func_map); if name.contains("error")||name.contains("die")||name.contains("abort") { state.stmts[i+1].set_anno(Annotation::BoundsCheck); }
            } i += 1;
        }
    }
    fn pass_arg_purify(&self, state: &mut State) {
        for stmt in &mut state.stmts {
            if let Stmt::Call { ref name, ref mut args, .. } = stmt {
                let base = name.split(|c: char| c == '@' || c == '(').next().unwrap_or(name);
                if let Some(&(max, var)) = self.sig_map.get(base) {
                    if var && args.len() > max as usize { args.truncate(max as usize); state.changed = true; }
                    else if !var && args.len() > max as usize { args.truncate(max as usize); state.changed = true; }
                    continue;
                }
                while args.len() > 2 && matches!(args.last(), Some(ValueDomain::Signed(x)) if *x < 10) { args.pop(); }
            }
        }
    }
}

fn resolve_reg(s: &str, rv: &HashMap<String, String>) -> String {
    if let Some(name) = rv.get(s) { return name.clone(); }
    if let Some(canon) = ro(s) { if let Some(name) = rv.get(canon) { return name.clone(); } }
    s.to_string()
}
fn resolve_reg_global(s: &str, rv: &HashMap<String, String>, rg: &HashMap<String, String>) -> String {
    // 寄存器→变量名, 查不到则查寄存器→全局符号
    let canon = ro(s).unwrap_or(s);
    if let Some(name) = rv.get(canon) { return name.clone(); }
    if let Some(global) = rg.get(canon) { return global.clone(); }
    s.to_string()
}
fn so_name(s: &str, vn: &HashMap<i64, String>, rv: &HashMap<String, String>) -> String {
    if let Some(off) = so(s) { vn.get(&off).cloned().unwrap_or_else(|| format!("[rbp{:+}]", off)) }
    else if let Some(name) = rv.get(s) { name.clone() }
    else if let Some(canon) = ro(s) { if let Some(name) = rv.get(canon) { name.clone() } else { s.to_string() } }
    else { s.to_string() }
}
fn strip_size<'a>(s: &'a str) -> &'a str {
    let s = s.trim();
    for p in &["qword ptr ", "dword ptr ", "word ptr ", "byte ptr "] {
        if let Some(r) = s.strip_prefix(p) { return r.trim(); }
    }
    s
}
fn id(d: u64) -> String { "  ".repeat(d as usize) }
fn sp(op:&str)->(&str,&str){if let Some(p)=op.find(','){(op[..p].trim(),op[p+1..].trim())}else{(op,"")}}
fn dst_or_src<'a>(d:&'a str,s:&'a str)->&'a str{if!d.is_empty(){d}else{s}}
fn iv(s:&str)->Option<i64>{let s=s.trim();if s.is_empty(){return None;}if let Some(h)=s.strip_prefix("0x").or_else(||s.strip_prefix("-0x")){let neg=s.starts_with('-');i64::from_str_radix(h,16).ok().map(|v|if neg{-v}else{v})}else{s.parse().ok()}}
fn fmt_val(v:&ValueDomain)->String{match v{ValueDomain::Signed(x)=>sf(*x),ValueDomain::Pointer(a)=>format!("global_{:#x}",a),ValueDomain::String(s)=>format!("\"{}\"",s.replace('\n',"\\n")),ValueDomain::Unknown=>"?".into(),ValueDomain::Unsigned(x)=>sf(*x as i64),ValueDomain::Boolean=>"1".into()}}
fn sf(v:i64)->String{if v==0{"0".into()}else if v>0&&v<=9999{v.to_string()}else if v<0&&v>=-9999{v.to_string()}else if v<0{format!("-{:#x}",-v)}else{format!("{:#x}",v)}}
fn ro(op:&str)->Option<&str>{Some(match op{"eax"|"rax"=>"rax","ebx"|"rbx"=>"rbx","ecx"|"rcx"=>"rcx","edx"|"rdx"=>"rdx","esi"|"rsi"=>"rsi","edi"|"rdi"=>"rdi","rbp"=>"rbp","rsp"=>"rsp","r8d"|"r8"=>"r8","r9d"|"r9"=>"r9","r10d"|"r10"=>"r10","r11d"|"r11"=>"r11","r12d"|"r12"=>"r12","r13d"|"r13"=>"r13","r14d"|"r14"=>"r14","r15d"|"r15"=>"r15",_=>return None})}
fn so(op:&str)->Option<i64>{let r=regex_lite::Regex::new(r"\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]").ok()?;let c=r.captures(op)?;Some((if&c[1]=="+"{1}else{-1})*i64::from_str_radix(c[2].strip_prefix("0x").unwrap_or(&c[2]),if c[2].starts_with("0x"){16}else{10}).ok()?)}
fn op_sym_rs(mn:&str)->&str{match mn{"add"=>"+","sub"=>"-","imul"=>"*","xor"=>"^","and"=>"&","or"=>"|",_=>"?"}}
fn rn(addr:u64,fm:&HashMap<u64,String>)->String{fm.get(&addr).cloned().unwrap_or_else(||format!("sub_{:x}",addr))}
fn cstr(mn:&str)->&str{match mn{"jz"|"je"=>"==","jne"|"jnz"=>"!=","jg"=>">","jge"=>">=","jl"=>"<","jle"=>"<=","ja"=>"(u)>","jb"=>"(u)<",_=>mn}}
fn refine_domain(v:ValueDomain)->ValueDomain{match v{ValueDomain::Pointer(0)=>ValueDomain::Unknown,_=>v}}
fn resolve_rip_cmp(addr: u64, sz: u32, op: &str, gm: &HashMap<u64, String>) -> String {
    // 把 cmp 操作数中的 [rip ± 0x...] 解析为全局地址
    let re = match regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)") {
        Ok(r) => r,
        Err(_) => return format!("cmp {}", op.replace("qword ptr ", "").replace("dword ptr ", "").trim()),
    };
    if let Some(caps) = re.captures(op) {
        if let Ok(off) = i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(""), 16) {
            let target = if &caps[1] == "+" { (addr as i64 + sz as i64 + off) as u64 }
                         else { (addr as i64 + sz as i64 - off) as u64 };
            let name = gm.get(&target).map(|s| s.as_str()).unwrap_or("");
            let lhs = op.split(',').next().map(|s| strip_size(s).trim().to_string()).unwrap_or_default();
            if !name.is_empty() {
                return format!("cmp {}, {}", lhs, name);
            }
            return format!("cmp {}, global_{:#x}", lhs, target);
        }
    }
    format!("cmp {}", op.replace("qword ptr ", "").replace("dword ptr ", "").trim())
}
fn resolve_call_name(dst:&str,_addr:u64,_size:u32,gm:&HashMap<u64,String>,fm:&HashMap<u64,String>,pm:&HashMap<u64,String>)->String{
    if let Some(t)=iv(dst){let tu=t as u64;if let Some(p)=pm.get(&tu){return format!("{}@plt",p);}return rn(tu,fm);}
    if dst.contains("rip"){if let Ok(re)=regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)"){if let Some(caps)=re.captures(dst){if let Ok(off)=i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(&caps[2]),16){let target=if&caps[1]=="+"{(_addr as i64+_size as i64+off)as u64}else{(_addr as i64+_size as i64-off)as u64};if let Some(n)=gm.get(&target){return n.clone();}return rn(target,fm);}}}}
    "??".into()
}
impl Stmt{pub fn set_anno(&mut self,a:Annotation){match self{Stmt::Assign{anno,..}|Stmt::Branch{anno,..}=>*anno=a,_=>{}}}}

