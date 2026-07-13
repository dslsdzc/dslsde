use std::collections::{HashMap, HashSet};
use crate::ir::*;
use crate::infer::InferenceEngine;
use crate::cfg::Cfg;
use crate::types::{VarType, infer_var_type};
use crate::ssa::{SsaContext, SsaOp};
use crate::switch::JumpTable;
use crate::typeprop;

impl InferenceEngine {
    pub(crate) fn build_addr_map(&self, state: &State, ssa: &SsaContext) -> (HashMap<u64, String>, HashMap<String, String>) {
        // SSA 驱动类型传播 (一次计算, 多处使用)
        let ssa_types = typeprop::infer_types(ssa);
        // OSPREY 结构体推断: 从 stmts 提取访问模式 → 结构体布局
        let struct_accesses = crate::structr::collect_accesses(&state.stmts);
        let mut struct_map: HashMap<String, crate::structr::StructInfo> = HashMap::new();
        // 按基址分组推断
        let mut by_base: HashMap<String, Vec<crate::structr::MemAccess>> = HashMap::new();
        for acc in &struct_accesses {
            by_base.entry(acc.base_reg.clone()).or_default().push(acc.clone());
        }
        for (base, accesses) in &by_base {
            if accesses.len() >= 2 {
                if let Some(si) = crate::structr::infer_struct(base, accesses) {
                    struct_map.insert(base.clone(), si);
                }
            }
        }
    fn type_str(vt: &VarType) -> &'static str {
        match vt {
            VarType::Ptr => "void*",
            VarType::CharPtr => "char*",
            VarType::Int => "int",
            VarType::UInt => "unsigned",
            VarType::Bool => "bool",
            VarType::Unknown => "int",
        }
    }

        // Pass 1: collect patterns for variable naming + type inference
        #[derive(Default)]
        struct Pat { from_arg: bool, inc1: bool, compared_low: bool, compared_high: bool, returned: bool, vtype: VarType }
        // 寄存器→最新 SSA id（用于栈变量反查类型）
        let mut reg_latest: HashMap<String, u32> = HashMap::new();
        let mut sorted_addrs: Vec<u64> = state.ssa_ids.keys().copied().collect();
        sorted_addrs.sort();
        for a in sorted_addrs {
            if let Some(&sid) = state.ssa_ids.get(&a) {
                if let Some(v) = ssa.get(sid) {
                    reg_latest.insert(v.reg.clone(), sid);
                }
            }
        }
        let mut pats: HashMap<i64, Pat> = HashMap::new();
        for stmt in &state.stmts {
            if let Stmt::Assign { addr, dst, val, info, anno, .. } = stmt {
                if *anno == Annotation::OverflowGuard { continue; }
                if let Some(off) = so(dst) {
                    let p = pats.entry(off).or_default();
                    if matches!(info.as_str(), "rdi"|"rsi"|"rdx"|"rcx"|"r8"|"r9") { p.from_arg = true; }
                    // Type inference: 值类型优先
                    match val {
                        ValueDomain::Pointer(_) => p.vtype = VarType::Ptr,
                        ValueDomain::String(_) => p.vtype = VarType::CharPtr,
                        ValueDomain::Signed(_) | ValueDomain::Unsigned(_) => {
                            if p.vtype == VarType::Unknown {
                                if let Some(t) = infer_var_type(info) { p.vtype = t; }
                            }
                        }
                        _ => if p.vtype == VarType::Unknown {
                            // Unknown → 查 SSA 是否有实际值（直接 addr 或源寄存器反查）
                            let ssa_type = state.ssa_ids.get(addr).or_else(|| {
                                // 栈写入: 源寄存器 → SSA id
                                let canon = ro(info.trim()).unwrap_or(info);
                                reg_latest.get(canon)
                            }).and_then(|&sid| ssa.get(sid)).and_then(|sv| sv.val.as_ref());
                            if let Some(sv_val) = ssa_type {
                                match sv_val {
                                    ValueDomain::Pointer(_) => p.vtype = VarType::Ptr,
                                    ValueDomain::String(_) => p.vtype = VarType::CharPtr,
                                    _ => {}
                                }
                            }
                            if p.vtype == VarType::Unknown {
                                if let Some(t) = infer_var_type(info) { p.vtype = t; }
                            }
                        }
                    }
                    // SSA 驱动类型推断: 从 def-use 链传播
                    if p.vtype == VarType::Unknown {
                        if let Some(&sid) = state.ssa_ids.get(addr) {
                            if let Some(ssa_t) = ssa_types.get(&sid) {
                                if *ssa_t != VarType::Unknown {
                                    p.vtype = ssa_t.clone();
                                }
                            }
                        }
                    }
                    if info.contains(' ') {
                        if info.split(' ').nth(1).unwrap_or("") == "1" { p.inc1 = true; }
                    }
                    // 跨函数类型传播: rax 已知指针类型 → 变量也是指针
                    if info == "rax" && p.vtype == VarType::Unknown {
                        if let Some(ValueDomain::Pointer(_)) = state.regs.get("rax") {
                            p.vtype = VarType::Ptr;
                        }
                    }
                }
            }
        }
        // cmp_state 追踪最近一次比较，用于分支条件输出
        #[derive(Default)]
        struct CmpState { op1: String, op2: String }
        let mut cmp_state: Option<CmpState> = None;
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

        // Semantic naming + type mapping
        let mut vn: HashMap<i64, String> = HashMap::new();
        let mut var_types: HashMap<String, String> = HashMap::new();
        for (&off, p) in &pats {
            let name: String = if p.from_arg && p.compared_high { "n".into() }
                else if p.inc1 { "i".into() }
                else if p.returned && !p.inc1 { "sum".into() }
                else if p.from_arg { format!("arg_{}", -off) }
                else { format!("v{}", pats.keys().filter(|&&k| k < off).count() + 1) };
            // SSA 类型：仅在 p.vtype 为 Unknown 时覆盖（避免寄存器最终类型污染）
            let final_t = if p.vtype != VarType::Unknown {
                &p.vtype
            } else {
                let ssa_t = state.stmts.iter().find_map(|s| {
                    if let Stmt::Assign { dst, info, .. } = s {
                        if so(dst) == Some(off) {
                            let canon = crate::ir::ro(info.trim()).unwrap_or(info.trim());
                            reg_latest.get(canon).and_then(|sid| ssa_types.get(sid))
                        } else { None }
                    } else { None }
                });
                ssa_t.unwrap_or(&p.vtype)
            };
            var_types.insert(name.clone(), type_str(final_t).to_string());
            vn.insert(off, name);
        }

        // Struct field inference REMOVED: 栈变量不适合用 field_N 命名
        // 结构体字段命名只在非栈基址的 [base+N] 访问中处理

        // Pass 2: generate output
        let mut m: HashMap<u64, String> = HashMap::new();
        let mut canary_shown: HashSet<String> = HashSet::new();
        let mut rv: HashMap<String, String> = HashMap::new();
        // 寄存器→全局符号 映射（rg），从 SSA 构建
        // 按地址排序以保持时序，只保留首次赋值
        let mut rg: HashMap<String, String> = HashMap::new();
        let mut addrs: Vec<u64> = state.ssa_ids.keys().copied().collect();
        addrs.sort();
        for addr in addrs {
            if let Some(&sid) = state.ssa_ids.get(&addr) {
                if let Some(v) = ssa.get(sid) {
                    if let Some(r) = ro(&v.reg) {
                        if rg.contains_key(r) { continue; } // 保留首次
                        let desc = ssa.value_desc(sid);
                        if !desc.starts_with(&v.reg) && !desc.starts_with("phi") {
                            rg.insert(r.to_string(), desc);
                        }
                    }
                }
            }
        }
        for stmt in &state.stmts {
            match stmt {
                Stmt::Comment(ca, c) => {
                    if c.starts_with("cmp ") {
                        let cmp_trim = c[4..].trim();
                        // 将 [rip+X] 已解析的名字直接用于条件
                        if let Some(parts) = cmp_trim.split_once(',') {
                            let lhs_raw = strip_size(parts.0).trim().to_string();
                            let rhs_raw = strip_size(parts.1).trim().to_string();
                            let lhs = so_name(&lhs_raw, &vn, &rv);
                            let rhs = so_name(&rhs_raw, &vn, &rv);
                            let lhs = if lhs == lhs_raw { resolve_reg_global(&lhs_raw, &rv, &rg) } else { lhs };
                            let rhs = if rhs == rhs_raw { resolve_reg_global(&rhs_raw, &rv, &rg) } else { rhs };
                            cmp_state = Some(CmpState { op1: lhs, op2: rhs });
                        } else {
                            cmp_state = Some(CmpState { op1: cmp_trim.to_string(), op2: String::new() });
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
                        // 栈金丝雀（val = Pointer(0x28)）→ 注释而非声明（全局去重）
                        if matches!(val, ValueDomain::Pointer(0x28)) {
                            if canary_shown.insert("__cany__".to_string()) {
                                m.insert(*addr, format!("// {} = __readfsqword(0x28)  /* stack canary */", name));
                            }
                            continue;
                        }
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
                        // SSA 注释：只输出有分析依据的，不输出来源不明的寄存器赋值
                        if let Some(&sid) = state.ssa_ids.get(addr) {
                            if let Some(vv) = ssa.get(sid) {
                                let desc = ssa.value_desc(sid);
                                // 规则：只保留 Pointer 值（GOT加载/金丝雀）和 BinOp
                                let keep = match &vv.op {
                                    SsaOp::BinOp(_) => true,          // 算术结果
                                    _ => desc.contains("global_")      // GOT/金丝雀加载
                                      || desc.contains("__readfsqword")
                                      || desc.starts_with("ptr_"),
                                };
                                if keep {
                                    // 格式化: 说明值来源
                                    let source = match &vv.op {
                                        SsaOp::BinOp(name) => format!("{} {} {}", ssa.value_name(sid), name,
                                            vv.inputs.iter().map(|&i| ssa.value_name(i)).collect::<Vec<_>>().join(", ")),
                                        _ => {
                                            if desc.contains("__readfsqword") { desc.clone() }
                                            else { format!("{} <- {}", ssa.value_name(sid), desc) }
                                        }
                                    };
                                    m.insert(*addr, format!("// {}", source));
                                }
                            }
                        }
                    }
                    // 数组/结构体访问: 仅对非栈变量生效
                    if !dst.starts_with("[rbp") {
                        // 数组访问检测
                        if dst.contains('[') {
                            if let Some(arr_str) = crate::array::format_array_access(info) {
                                m.insert(*addr, format!("// {} = {}", dst, arr_str));
                            }
                            if let Some(arr_str) = crate::array::format_array_access(dst) {
                                m.insert(*addr, format!("{} = {}", arr_str, val_s(val, info)));
                            }
                        }
                        // 结构体字段检测
                        if dst.contains('[') {
                            if let Some((base, off)) = crate::structr::parse_field_access(dst) {
                                let field = struct_map.get(&base).and_then(|si| {
                                    si.fields.iter().find(|f| f.offset == off).map(|f| f.field_name.clone())
                                }).unwrap_or_else(|| format!("field_{:#x}", off));
                                m.insert(*addr, format!("{}->{} = {}", base, field, val_s(val, info)));
                            }
                        }
                        if info.contains('[') && info != dst {
                            if let Some((base, off)) = crate::structr::parse_field_access(info) {
                                let field = struct_map.get(&base).and_then(|si| {
                                    si.fields.iter().find(|f| f.offset == off).map(|f| f.field_name.clone())
                                }).unwrap_or_else(|| format!("field_{:#x}", off));
                                m.insert(*addr, format!("// {} = {}->{}", dst, base, field));
                            }
                        }
                    }
                }
                Stmt::Branch { addr, cond, anno, .. } => {
                    if *anno != Annotation::None { continue; }
                    if matches!(cond.as_str(), "jmp"|"jmpq") { continue; }
                    let cond_str = if let Some(ref c) = cmp_state {
                        if c.op2.is_empty() {
                            format!("if ({})", c.op1)
                        } else {
                            format!("if ({} {} {})", c.op1, cstr(cond), c.op2)
                        }
                    } else {
                        format!("if ({})", cstr(cond))
                    };
                    m.insert(*addr, cond_str);
                }
                Stmt::Call { addr, name, args, .. } => {
                    // 签名驱动参数名
                    let sig = self.sig_db.lookup(name);
                    let a: Vec<String> = if let Some(s) = sig {
                        args.iter().enumerate().map(|(i, v)| {
                            let val = fmt_val(v);
                            if i < s.args.len() && !s.args[i].is_empty() {
                                format!("{}: {}", s.args[i], val)
                            } else { val }
                        }).collect()
                    } else {
                        args.iter().map(fmt_val).collect()
                    };
                    if !a.is_empty() { m.insert(*addr, format!("{}({});", name, a.join(", "))); }
                }
                Stmt::Return { addr, val, .. } => { m.insert(*addr, format!("return {};", val.as_ref().map_or("?".into(), fmt_val))); }
                _ => {}
            }
        }
        (m, var_types)
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

    pub(crate) fn emit_structured(&self, state: &State, cfg: &Cfg, trace: &HashSet<u64>,
                                   var_types: &HashMap<String, String>,
                                   jump_tables: &[JumpTable]) -> String {
        let mut out = Vec::new(); let mut visited = HashSet::new(); let mut consumed = HashSet::new();
        let first = *trace.iter().min().unwrap_or(&0); let entry = cfg.blocks.keys().filter(|&&k| k <= first).last().copied().unwrap_or(cfg.entry);
        let loops = cfg.find_natural_loops();
        let loop_headers: HashSet<u64> = loops.iter().map(|l| l.header).collect();

        // 收集变量首次赋值地址 → 提到函数顶部做声明
        let mut first_assign: HashMap<String, u64> = HashMap::new();
        let mut canary_vars: HashSet<String> = HashSet::new();
        for (&a, line) in &state.addr_map {
            if let Some(eq) = line.find(" = ") {
                let name = line[..eq].trim();
                if (name.starts_with('v') || name.starts_with("arg_") || name == "i" || name == "n" || name == "sum")
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                    && !first_assign.contains_key(name)
                {
                    // 检查是否是栈金丝雀变量（注释行不计入声明）
                    if line.starts_with("//") {
                        canary_vars.insert(name.to_string());
                    } else {
                        first_assign.insert(name.to_string(), a);
                    }
                }
            }
        }
        // 输出变量声明块（跳过金丝雀变量）
        let mut var_names: Vec<&String> = first_assign.keys().collect();
        var_names.sort();
        if !var_names.is_empty() {
            let mut by_type: HashMap<&str, Vec<&String>> = HashMap::new();
            for name in &var_names {
                let t = var_types.get(name.as_str()).map(|s| s.as_str()).unwrap_or("int");
                by_type.entry(t).or_default().push(name);
            }
            let mut keys: Vec<&&str> = by_type.keys().collect();
            keys.sort();
            for t in keys {
                let names = &by_type[t];
                out.push(format!("{} {};", t, names.iter().map(|n| n.as_str()).collect::<Vec<&str>>().join(", ")));
            }
        }

        self.emit_block(entry, cfg, &state.addr_map, trace, &mut visited, &mut consumed, 0, &mut out, &loop_headers, &first_assign, jump_tables); out.join("\n")
    }

    pub(crate) fn emit_block(&self, addr: u64, cfg: &Cfg, lines: &HashMap<u64, String>, trace: &HashSet<u64>,
                  visited: &mut HashSet<u64>, consumed: &mut HashSet<u64>, depth: usize, out: &mut Vec<String>,
                  loop_headers: &HashSet<u64>, first_assign: &HashMap<String, u64>,
                  jump_tables: &[JumpTable]) {
        // 如果是间接跳转且匹配跳转表 → switch 输出
        if let Some(block) = cfg.blocks.get(&addr) {
            let jt = jump_tables.iter().find(|jt| {
                // 跳转表的起始地址需在块范围内，或块最后一条指令是间接跳转
                block.addr <= jt.addr && jt.addr < block.addr + block.size
            });
            if let Some(table) = jt {
                let ind = "  ".repeat(depth);
                let mut case_lines: Vec<String> = Vec::new();
                for (idx, &target) in table.entries.iter().enumerate() {
                    let target_name = lines.get(&target).cloned().unwrap_or_default();
                    case_lines.push(format!("{}case {}: goto {};", ind, idx, target_name));
                }
                // 如果 switch 块的上一行有 if(++ 或类似的分支，跳过它
                out.push(format!("{}switch ({}) {{", ind, table.index_reg));
                for l in &case_lines { out.push(l.to_string()); }
                out.push(format!("{}}}", ind));
                visited.insert(addr);
                return;
            }
        }
        if addr == 0 || !cfg.blocks.contains_key(&addr) || visited.contains(&addr) { return; }
        visited.insert(addr);
        let block = &cfg.blocks[&addr];
        let has_lines = (block.addr..block.addr + block.size).any(|a| lines.contains_key(&a));
        let block_traced = (block.addr..block.addr + block.size).any(|a| trace.contains(&a));
        if !has_lines && !block_traced {
            if block.succs.len() == 1 { self.emit_block(block.succs[0], cfg, lines, trace, visited, consumed, depth, out, loop_headers, first_assign, jump_tables); }
            return;
        }
        let ind = "  ".repeat(depth);
        for a in block.addr..block.addr + block.size {
            if let Some(line) = lines.get(&a) {
                if !consumed.contains(&a) {
                    // 跳过已在函数顶部声明的首次赋值
                    let is_first = line.find(" = ").map_or(false, |eq| {
                        let name = line[..eq].trim();
                        first_assign.get(name).copied() == Some(a)
                    });
                    if !is_first {
                        out.push(format!("{}{}", ind, line));
                    }
                }
            }
        }
        if block.succs.is_empty() { return; }
        if block.succs.len() == 1 { self.emit_block(block.succs[0], cfg, lines, trace, visited, consumed, depth, out, loop_headers, first_assign, jump_tables); return; }
        let t = block.succs[0]; let e = block.succs[1];

        // 回边 + 支配节点 → 循环识别
        let loop_target = if loop_headers.contains(&t) && t < addr { Some(t) }
                         else if loop_headers.contains(&e) && e < addr { Some(e) }
                         else { None };
        if let Some(header) = loop_target {
            // 循环：条件在 header 的 if 行中，身体为 header→addr 之间的块
            let mut fc = String::new();
            for a in block.addr..block.addr + block.size {
                if let Some(line) = lines.get(&a) {
                    if line.starts_with("if (") && line.ends_with(')') { fc = line[4..line.len()-1].to_string(); }
                }
            }
            if !fc.is_empty() { out.push(format!("{}while ({}) {{", ind, fc)); }
            else { out.push(format!("{}while (1) {{", ind)); }
            // 输出循环体（从 entry 到 header 之前的块）
            let mut c = header;
            while c < addr && !visited.contains(&c) { visited.insert(c);
                if let Some(b) = cfg.blocks.get(&c) {
                    for a in b.addr..b.addr + b.size { if let Some(l) = lines.get(&a) { out.push(format!("{}{}", "  ".repeat(depth + 1), l)); } }
                    if b.succs.len() == 1 { c = b.succs[0]; } else { break; }
                } else { break; }
            } out.push(format!("{}}}", ind));
        } else if t < addr || e < addr {
            // 后向边但非循环（旧代码保留的 fallback）
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
            out.push(format!("{}{{", ind)); self.emit_block(taken, cfg, lines, trace, visited, consumed, depth + 1, out, loop_headers, first_assign, jump_tables);
            if not_taken != 0 && cfg.blocks.contains_key(&not_taken) && in_t(not_taken) { out.push(format!("{}}} else {{", ind)); self.emit_block(not_taken, cfg, lines, trace, visited, consumed, depth + 1, out, loop_headers, first_assign, jump_tables); }
            out.push(format!("{}}}", ind));
        }
    }
}
