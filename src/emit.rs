use std::collections::{HashMap, HashSet};
use crate::ir::*;
use crate::infer::InferenceEngine;
use crate::cfg::Cfg;
use crate::types::{VarType, infer_var_type};

impl InferenceEngine {
    pub(crate) fn build_addr_map(&self, state: &State) -> HashMap<u64, String> {

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

    pub(crate) fn emit_flat(&self, state: &State) -> String {
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

    pub(crate) fn emit_structured(&self, state: &State, cfg: &Cfg, trace: &HashSet<u64>) -> String {
        let mut out = Vec::new(); let mut visited = HashSet::new(); let mut consumed = HashSet::new();
        let first = *trace.iter().min().unwrap_or(&0); let entry = cfg.blocks.keys().filter(|&&k| k <= first).last().copied().unwrap_or(cfg.entry);
        self.emit_block(entry, cfg, &state.addr_map, trace, &mut visited, &mut consumed, 0, &mut out); out.join("\n")
    }

    pub(crate) fn emit_block(&self, addr: u64, cfg: &Cfg, lines: &HashMap<u64, String>, trace: &HashSet<u64>,
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
