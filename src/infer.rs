use std::collections::{HashMap, HashSet};
use pyo3::prelude::*;
use crate::cfg::{Cfg, build_cfg_internal};
use crate::insn::PyInsnInfo;

#[derive(Clone, Debug, PartialEq)]
pub enum ValueDomain { Unknown, Signed(i64), Unsigned(u64), Pointer(u64), Boolean, String(String) }
#[derive(Clone, Debug, PartialEq)]
pub enum Annotation { None, BoundsCheck, NullCheck, OverflowGuard, SwitchDispatch, LoopBackEdge }
#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Assign { addr: u64, dst: String, val: ValueDomain, info: String, anno: Annotation },
    Call { addr: u64, name: String, args: Vec<ValueDomain> },
    Branch { addr: u64, cond: String, target: u64, anno: Annotation },
    Return { addr: u64, val: Option<ValueDomain> }, Comment(String), Nop,
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
        for i in 0..5 { state.iteration = i; state.changed = false;
            self.pass_noise_filter(&mut state); self.pass_value_domain(&mut state);
            self.pass_constraint(&mut state); self.pass_arg_purify(&mut state);
            if !state.changed { break; } }
        self.emit_flat(&state)
    }
    pub fn infer_structured(&mut self, trace: Vec<(u64, u32, String, String)>,
                            args: Vec<i64>, py_insns: Vec<PyRef<PyInsnInfo>>) -> String {
        let mut state = self.build_state(&trace, &args);
        for i in 0..5 { state.iteration = i; state.changed = false;
            self.pass_noise_filter(&mut state); self.pass_value_domain(&mut state);
            self.pass_constraint(&mut state); self.pass_arg_purify(&mut state);
            if !state.changed { break; } }
        state.addr_map = self.build_addr_map(&state);
        let native: Vec<PyInsnInfo> = py_insns.iter().map(|r| (*r).clone()).collect();
        let cfg = build_cfg_internal(&native);
        let trace_addrs: HashSet<u64> = trace.iter().map(|t| t.0).collect();
        self.emit_structured(&state, &cfg, &trace_addrs)
    }
}

impl InferenceEngine {
    fn build_addr_map(&self, state: &State) -> HashMap<u64, String> {
        let mut m = HashMap::new();
        let mut last_cmp = String::new();

        // Pass 1: collect patterns
        #[derive(Default)]
        struct Pat { from_arg: bool, inc1: bool, compared_low: bool, compared_high: bool, returned: bool }
        let mut pats: HashMap<i64, Pat> = HashMap::new();
        for stmt in &state.stmts {
            if let Stmt::Assign { dst, val, info, anno, .. } = stmt {
                if *anno == Annotation::OverflowGuard { continue; }
                if let Some(off) = so(dst) {
                    let p = pats.entry(off).or_default();
                    if matches!(info.as_str(), "rdi"|"rsi"|"rdx"|"rcx") { p.from_arg = true; }
                    if info.contains(' ') {
                        let rest = info.split(' ').nth(1).unwrap_or("");
                        if rest == "1" { p.inc1 = true; }
                    }
                }
            }
        }
        for stmt in &state.stmts {
            if let Stmt::Comment(c) = stmt { if c.starts_with("cmp ") { last_cmp = c[4..].to_string(); } }
            if let Stmt::Branch { anno, .. } = stmt {
                if *anno != Annotation::None || last_cmp.is_empty() { continue; }
                let p: Vec<&str> = last_cmp.split(',').collect();
                if p.len() == 2 {
                    if let Some(off) = so(p[0].trim()) { pats.entry(off).or_default().compared_low = true; }
                    if let Some(off2) = so(p[1].trim()) { pats.entry(off2).or_default().compared_high = true; }
                }
                last_cmp.clear();
            }
        }
        for stmt in &state.stmts {
            if let Stmt::Assign { dst, info, .. } = stmt {
                if dst == "rax" && so(&info).is_some() {
                    if let Some(off) = so(&info) { if let Some(p) = pats.get_mut(&off) { p.returned = true; } }
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
            vn.insert(off, name.to_string());
        }

        // Pass 2: generate output
        let mut rv: HashMap<String, String> = HashMap::new();
        last_cmp.clear();
        for stmt in &state.stmts {
            match stmt {
                Stmt::Assign { addr, dst, val, info, anno } => {
                    if *anno == Annotation::OverflowGuard { continue; }
                    if info.starts_with("[rbp") {
                        if let Some(off) = so(&info) {
                            if let Some(name) = vn.get(&off) { rv.insert(dst.clone(), name.clone()); }
                        }
                    }
                    if !dst.starts_with("[rbp") { continue; }
                    let Some(off) = so(dst) else { continue; };
                    let Some(name) = vn.get(&off) else { continue; };
                    let line = if info.contains(' ') {
                        let sp = info.find(' ').unwrap();
                        format!("{} {}= {}", name, &info[..sp].trim(), &info[sp..].trim())
                    } else if matches!(info.as_str(), "rdi"|"rsi"|"rdx"|"rcx") {
                        format!("{} = {}", name, fmt_val(val))
                    } else {
                        format!("{} = {}  // {}", name, fmt_val(val), info)
                    };
                    m.insert(*addr, line);
                }
                Stmt::Comment(c) => { if c.starts_with("cmp ") { last_cmp = c[4..].to_string(); } }
                Stmt::Branch { addr, cond, anno, .. } => {
                    if *anno != Annotation::None { continue; }
                    if matches!(cond.as_str(), "jmp"|"jmpq") { continue; }
                    let cv = if last_cmp.is_empty() { cstr(cond).to_string() } else {
                        let p2: Vec<&str> = last_cmp.split(',').collect();
                        if p2.len() == 2 {
                            format!("{} {} {}", so_name(p2[0].trim(), &vn, &rv), cstr(cond), so_name(p2[1].trim(), &vn, &rv))
                        } else { cstr(cond).to_string() }
                    };
                    m.insert(*addr, format!("if ({})", cv)); last_cmp.clear();
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
                Stmt::Comment(c) => { if !c.starts_with("cmp ") && !c.is_empty() && !c.starts_with("cqo") { out.push(format!("{}{}", id(depth), c)); } }
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
        let mut out = Vec::new(); let mut visited = HashSet::new();
        let first = *trace.iter().min().unwrap_or(&0); let entry = cfg.blocks.keys().filter(|&&k| k <= first).last().copied().unwrap_or(cfg.entry);
        self.emit_block(entry, cfg, &state.addr_map, trace, &mut visited, 0, &mut out); out.join("\n")
    }
    fn emit_block(&self, addr: u64, cfg: &Cfg, lines: &HashMap<u64, String>, trace: &HashSet<u64>, visited: &mut HashSet<u64>, depth: usize, out: &mut Vec<String>) {
        if addr == 0 || !cfg.blocks.contains_key(&addr) || visited.contains(&addr) { return; }
        visited.insert(addr); let ind = "  ".repeat(depth); let block = &cfg.blocks[&addr];
        for a in block.addr..block.addr + block.size { if let Some(line) = lines.get(&a) { out.push(format!("{}{}", ind, line)); } }
        if block.succs.is_empty() { return; }
        if block.succs.len() == 1 { self.emit_block(block.succs[0], cfg, lines, trace, visited, depth, out); return; }
        let t = block.succs[0]; let e = block.succs[1];
        if t < addr || e < addr {
            let ls = t.min(e); out.push(format!("{}while (1) {{", ind));
            let mut c = ls; while c < addr && !visited.contains(&c) { visited.insert(c);
                if let Some(b) = cfg.blocks.get(&c) { for a in b.addr..b.addr + b.size { if let Some(l) = lines.get(&a) { out.push(format!("{}{}", "  ".repeat(depth + 1), l)); } }
                    if b.succs.len() == 1 { c = b.succs[0]; } else { break; }
                } else { break; }
            } out.push(format!("{}}}", ind));
        } else {
            let in_t = |x: u64| cfg.blocks.get(&x).map_or(false, |bl| (bl.addr..bl.addr + bl.size).any(|a| trace.contains(&a)));
            let taken = if in_t(e) { e } else { t }; let not_taken = if taken == t { e } else { t };
            out.push(format!("{}{{", ind)); self.emit_block(taken, cfg, lines, trace, visited, depth + 1, out);
            if not_taken != 0 && cfg.blocks.contains_key(&not_taken) && in_t(not_taken) { out.push(format!("{}}} else {{", ind)); self.emit_block(not_taken, cfg, lines, trace, visited, depth + 1, out); }
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
            let (dst, src) = sp(op); let is_md = so(dst).is_some();
            let stmt = if matches!(mn.as_str(), "call"|"callq") { self.make_call(addr, &regs, dst)
            } else if matches!(mn.as_str(), "ret"|"retq") { Stmt::Return { addr, val: regs.get("rax").cloned() }
            } else if matches!(mn.as_str(), "cmp"|"test") { Stmt::Comment(format!("cmp {}", op))
            } else if mn.starts_with('j') { let t = iv(dst_or_src(dst, src)).unwrap_or(0) as u64; if t == 0 { Stmt::Nop } else { Stmt::Branch { addr, cond: mn.clone(), target: t, anno: Annotation::None } }
            } else if mn.starts_with("mov") { self.make_assign(addr, &mut regs, &mut stack, dst, src)
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
            } else if mn.starts_with("cmov") { Stmt::Nop } else { Stmt::Comment(format!("{} {}", mn, op)) };
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
        if let Some(off) = so(dst) { if let Some(s) = ro(src) { let val = regs.get(s).cloned().unwrap_or(ValueDomain::Unknown); stack.insert(off, val.clone()); return Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: s.to_string(), anno: Annotation::None }; } return Stmt::Nop; }
        if let Some(off) = so(src) { if let Some(d) = ro(dst) { let val = stack.get(&off).cloned().unwrap_or(ValueDomain::Unknown); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: format!("[rbp{:+}]", off), anno: Annotation::None }; } return Stmt::Nop; }
        if let Some(d) = ro(dst) { if let Some(v) = iv(src) { let val = ValueDomain::Signed(v); regs.insert(d.to_string(), val.clone()); return Stmt::Assign { addr, dst: d.to_string(), val, info: src.to_string(), anno: Annotation::None }; } if let Some(s) = ro(src) { let val = regs.get(s).cloned().unwrap_or(ValueDomain::Unknown); regs.insert(d.to_string(), val); return Stmt::Nop; } }
        Stmt::Nop
    }
    fn make_arith(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &HashMap<i64, ValueDomain>, mn: &str, dst: &str, src: &str) -> Stmt {
        let Some(d) = ro(dst) else { return Stmt::Comment(format!("{} {}, {}", mn, dst, src)) };
        let a = regs.get(d).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None });
        let b = ro(src).and_then(|s| regs.get(s)).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).or_else(|| so(src).and_then(|o| stack.get(&o).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }))).or_else(|| iv(src));
        if let (Some(a), Some(b)) = (a, b) { let r = match mn { "add"=>a.wrapping_add(b),"sub"=>a.wrapping_sub(b),"imul"=>a.wrapping_mul(b),"xor"=>a^b,"and"=>a&b,"or"=>a|b,_=>0 };
            let val = ValueDomain::Signed(r); regs.insert(d.to_string(), val.clone()); Stmt::Assign { addr, dst: d.to_string(), val, info: format!("{} {}", op_sym_rs(mn), src), anno: Annotation::None }
        } else { Stmt::Comment(format!("{} {}, {}", mn, dst, src)) }
    }
    fn make_arith_mem(&self, addr: u64, regs: &mut HashMap<String, ValueDomain>, stack: &mut HashMap<i64, ValueDomain>, mn: &str, dst: &str, src: &str) -> Stmt {
        if let Some(off) = so(dst) {
            let a = stack.get(&off).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).unwrap_or(0);
            let b = ro(src).and_then(|s| regs.get(s)).and_then(|v| if let ValueDomain::Signed(x) = v { Some(*x) } else { None }).or_else(|| iv(src)).unwrap_or(0);
            let r = match mn { "add"=>a.wrapping_add(b),"sub"=>a.wrapping_sub(b), _=>0 };
            let val = ValueDomain::Signed(r); stack.insert(off, val.clone()); Stmt::Assign { addr, dst: format!("[rbp{:+}]", off), val, info: format!("{} {}", op_sym_rs(mn), src), anno: Annotation::None }
        } else { Stmt::Comment(format!("{} {}, {}", mn, dst, src)) }
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

fn so_name(s: &str, vn: &HashMap<i64, String>, rv: &HashMap<String, String>) -> String {
    if let Some(off) = so(s) { vn.get(&off).cloned().unwrap_or_else(|| format!("[rbp{:+}]", off)) }
    else if let Some(name) = rv.get(s) { name.clone() }
    else if let Some(canon) = ro(s) { if let Some(name) = rv.get(canon) { name.clone() } else { s.to_string() } }
    else { s.to_string() }
}
fn id(d: u64) -> String { "  ".repeat(d as usize) }
fn sp(op:&str)->(&str,&str){if let Some(p)=op.find(','){(op[..p].trim(),op[p+1..].trim())}else{(op,"")}}
fn dst_or_src<'a>(d:&'a str,s:&'a str)->&'a str{if!d.is_empty(){d}else{s}}
fn iv(s:&str)->Option<i64>{let s=s.trim();if s.is_empty(){return None;}if let Some(h)=s.strip_prefix("0x").or_else(||s.strip_prefix("-0x")){let neg=s.starts_with('-');i64::from_str_radix(h,16).ok().map(|v|if neg{-v}else{v})}else{s.parse().ok()}}
fn fmt_val(v:&ValueDomain)->String{match v{ValueDomain::Signed(x)=>sf(*x),ValueDomain::Pointer(a)=>format!("ptr_{:#x}",a),ValueDomain::String(s)=>format!("\"{}\"",s.replace('\n',"\\n")),ValueDomain::Unknown=>"?".into(),ValueDomain::Unsigned(x)=>sf(*x as i64),ValueDomain::Boolean=>"1".into()}}
fn sf(v:i64)->String{if v==0{"0".into()}else if v>0&&v<=9999{v.to_string()}else if v<0&&v>=-9999{v.to_string()}else if v<0{format!("-{:#x}",-v)}else{format!("{:#x}",v)}}
fn ro(op:&str)->Option<&str>{Some(match op{"eax"|"rax"=>"rax","ebx"|"rbx"=>"rbx","ecx"|"rcx"=>"rcx","edx"|"rdx"=>"rdx","esi"|"rsi"=>"rsi","edi"|"rdi"=>"rdi","rbp"=>"rbp","rsp"=>"rsp","r8d"|"r8"=>"r8","r9d"|"r9"=>"r9",_=>return None})}
fn so(op:&str)->Option<i64>{let r=regex_lite::Regex::new(r"\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]").ok()?;let c=r.captures(op)?;Some((if&c[1]=="+"{1}else{-1})*i64::from_str_radix(c[2].strip_prefix("0x").unwrap_or(&c[2]),if c[2].starts_with("0x"){16}else{10}).ok()?)}
fn op_sym_rs(mn:&str)->&str{match mn{"add"=>"+","sub"=>"-","imul"=>"*","xor"=>"^","and"=>"&","or"=>"|",_=>"?"}}
fn rn(addr:u64,fm:&HashMap<u64,String>)->String{fm.get(&addr).cloned().unwrap_or_else(||format!("sub_{:x}",addr))}
fn cstr(mn:&str)->&str{match mn{"jz"|"je"=>"==","jne"|"jnz"=>"!=","jg"=>">","jge"=>">=","jl"=>"<","jle"=>"<=","ja"=>"(u)>","jb"=>"(u)<",_=>mn}}
fn refine_domain(v:ValueDomain)->ValueDomain{match v{ValueDomain::Pointer(0)=>ValueDomain::Unknown,_=>v}}
fn resolve_call_name(dst:&str,_addr:u64,_size:u32,gm:&HashMap<u64,String>,fm:&HashMap<u64,String>,pm:&HashMap<u64,String>)->String{
    if let Some(t)=iv(dst){let tu=t as u64;if let Some(p)=pm.get(&tu){return format!("{}@plt",p);}return rn(tu,fm);}
    if dst.contains("rip"){if let Ok(re)=regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)"){if let Some(caps)=re.captures(dst){if let Ok(off)=i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(&caps[2]),16){let target=if&caps[1]=="+"{(_addr as i64+_size as i64+off)as u64}else{(_addr as i64+_size as i64-off)as u64};if let Some(n)=gm.get(&target){return n.clone();}return rn(target,fm);}}}}
    "??".into()
}
impl Stmt{pub fn set_anno(&mut self,a:Annotation){match self{Stmt::Assign{anno,..}|Stmt::Branch{anno,..}=>*anno=a,_=>{}}}}
