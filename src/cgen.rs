use std::collections::HashMap;
use pyo3::prelude::*;

#[pyclass]
#[derive(Clone)]
pub struct CTraceInsn {
    #[pyo3(get)] pub addr: u64,
    #[pyo3(get)] pub mnemonic: String,
    #[pyo3(get)] pub operands: String,
}

#[pyclass]
pub struct RustCGen {
    got_map: HashMap<u64, String>,
    func_map: HashMap<u64, String>,
    plt_map: HashMap<u64, String>,
    insn_map: HashMap<u64, (String, String)>,
}

#[pymethods]
impl RustCGen {
    #[new]
    pub fn new() -> Self {
        RustCGen {
            got_map: HashMap::new(), func_map: HashMap::new(),
            plt_map: HashMap::new(), insn_map: HashMap::new(),
        }
    }
    pub fn set_got_map(&mut self, m: HashMap<u64, String>) { self.got_map = m; }
    pub fn set_func_map(&mut self, m: HashMap<u64, String>) { self.func_map = m; }
    pub fn set_plt_map(&mut self, m: HashMap<u64, String>) { self.plt_map = m; }
    pub fn set_insn_map(&mut self, insns: Vec<PyRef<crate::insn::PyInsnInfo>>) {
        self.insn_map.clear();
        for i in &insns {
            self.insn_map.insert(i.addr, (i.mnemonic.clone(), i.operands.clone()));
        }
    }

    pub fn generate(&self, trace: Vec<(u64, u32)>, args: Vec<i64>) -> String {
        let mut out: Vec<String> = Vec::new();
        let mut ssa = 0u64;
        let aregs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        let mut regs: HashMap<&str, i64> = HashMap::new();
        for (i, v) in args.iter().enumerate().take(6) { regs.insert(aregs[i], *v); }
        let mut rv: HashMap<&str, String> = HashMap::new();
        for r in &aregs { ssa += 1; rv.insert(r, format!("t{}", ssa)); }
        ssa += 1; rv.insert("rax", format!("t{}", ssa));
        let mut stack: HashMap<i64, (String, Option<i64>)> = HashMap::new();
        let mut svm: HashMap<i64, String> = HashMap::new();
        let mut prologue = true;

        for &(addr, size) in &trace {
            let Some((mn, op)) = self.insn_map.get(&addr) else { continue; };
            let (mn, op) = (mn.as_str(), op.as_str());
            if matches!(mn, "endbr64"|"endbr32"|"nop"|"nopq"|"xchg") { continue; }
            if prologue {
                if mn == "push" && op == "rbp" { continue; }
                if mn == "mov" && (op.starts_with("rbp, rsp") || op.starts_with("ebp, esp")) { continue; }
                if mn == "sub" && op.starts_with("rsp,") {
                    if let Some(v) = iv(op.split(',').nth(1).unwrap_or("").trim()) { out.push(format!("  // {} bytes", v)); }
                    prologue = false; continue;
                }
                if mn == "mov" && op.starts_with("rsp, rbp") { continue; }
                if mn == "push" || mn == "pop" { continue; }
                prologue = false;
            }
            if (mn == "pop" && op == "rbp") || mn == "leave" {
                let v = regs.get("rax");
                out.push(if let Some(v) = v { format!("  return {};", sf(*v)) } else { "  return;".into() });
                continue;
            }
            if mn == "ret" || mn == "retq" {
                if out.len() < 2 || !out[out.len()-1].contains("return") {
                    let v = regs.get("rax");
                    out.push(if let Some(v) = v { format!("  return {};", sf(*v)) } else { "  return;".into() });
                }
                continue;
            }
            let (dst, src) = sp(op);
            if mn.starts_with("mov") {
                hm(&mut out, &mut regs, &mut rv, &mut stack, &mut svm, &mut ssa, dst, src);
            } else if matches!(mn, "add"|"sub"|"imul"|"xor"|"and"|"or") {
                ha(&mut out, &mut regs, &mut rv, &stack, &mut ssa, mn, dst, src);
            } else if matches!(mn, "call"|"callq") {
                hc(&mut out, &regs, addr, size, dst, &self.got_map, &self.func_map, &self.plt_map);
                regs.remove("rax");
            } else if mn.starts_with('j') {
                let t = iv(sd(dst, src));
                if let Some(t) = t {
                    let n = rn(t as u64, &self.func_map);
                    if matches!(mn, "jmp"|"jmpq") {
                        out.push(if !n.starts_with("sub_") { format!("  return {}(...);", n) }
                                 else { format!("  goto {};", n) });
                    } else { out.push(format!("  if ({}) goto {};", cs(mn), n)); }
                }
            }
        }
        out.join("\n")
    }
}

fn sp(op: &str) -> (&str, &str) {
    if let Some(p) = op.find(',') { (op[..p].trim(), op[p+1..].trim()) } else { (op, "") }
}
fn sd<'a>(d: &'a str, s: &'a str) -> &'a str { if !d.is_empty() { d } else { s } }

fn iv(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("-0x")) {
        let neg = s.starts_with('-');
        i64::from_str_radix(h, 16).ok().map(|v| if neg { -v } else { v })
    } else { s.parse().ok() }
}

fn sf(v: i64) -> String {
    if v == 0 { return "0".into(); }
    if v > 0 && v <= 9999 { return v.to_string(); }
    if v < 0 && v >= -9999 { return v.to_string(); }
    if v < 0 { format!("-{:#x}", -v) } else { format!("{:#x}", v) }
}

fn ro(op: &str) -> Option<&'static str> {
    Some(match op {
        "eax"|"rax" => "rax", "ebx"|"rbx" => "rbx", "ecx"|"rcx" => "rcx",
        "edx"|"rdx" => "rdx", "esi"|"rsi" => "rsi", "edi"|"rdi" => "rdi",
        "rbp" => "rbp", "rsp" => "rsp", "r8d"|"r8" => "r8", "r9d"|"r9" => "r9",
        _ => return None,
    })
}

fn so(op: &str) -> Option<i64> {
    let re = regex_lite::Regex::new(r"\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]").ok()?;
    let c = re.captures(op)?;
    let sign = if &c[1] == "+" { 1i64 } else { -1 };
    let val = i64::from_str_radix(c[2].strip_prefix("0x").unwrap_or(&c[2]),
        if c[2].starts_with("0x") { 16 } else { 10 }).ok()?;
    Some(sign * val)
}

fn hm(out: &mut Vec<String>, regs: &mut HashMap<&str, i64>,
      rv: &mut HashMap<&str, String>, stack: &mut HashMap<i64, (String, Option<i64>)>,
      svm: &mut HashMap<i64, String>, ssa: &mut u64, dst: &str, src: &str) {
    let dr = ro(dst); let sr = ro(src);
    if let Some(d) = dr {
        if let Some(v) = iv(src) { regs.insert(d, v); *ssa += 1; rv.insert(d, format!("t{}", ssa)); return; }
    }
    if let (Some(d), Some(s)) = (dr, sr) {
        if let Some(&v) = regs.get(s) { regs.insert(d, v); }
        rv.insert(d, rv.get(s).cloned().unwrap_or_else(|| { *ssa += 1; format!("t{}", ssa) }));
        return;
    }
    if let Some(o) = so(dst) {
        if let Some(s) = sr {
            let v = regs.get(s).copied();
            stack.insert(o, (src.to_string(), v));
            let vn = svm.entry(o).or_insert_with(|| { *ssa += 1; format!("t{}", ssa) }).clone();
            out.push(format!("  {} = {};", vn, rv.get(s).cloned().unwrap_or_else(|| "?".into())));
            return;
        }
    }
    if let Some(d) = dr {
        if let Some(o) = so(src) {
            if let Some(vn) = svm.get(&o) {
                if let Some((_, Some(v))) = stack.get(&o) { regs.insert(d, *v); }
                rv.insert(d, vn.clone());
            } else { *ssa += 1; rv.insert(d, format!("t{}", ssa)); }
        }
    }
}

fn ha(out: &mut Vec<String>, regs: &mut HashMap<&str, i64>,
      rv: &mut HashMap<&str, String>, stack: &HashMap<i64, (String, Option<i64>)>,
      ssa: &mut u64, mn: &str, dst: &str, src: &str) {
    let Some(d) = ro(dst) else { return };
    let sro = ro(src);
    let a = regs.get(d).copied();
    let b = sro.and_then(|s| regs.get(s).copied())
        .or_else(|| iv(src))
        .or_else(|| so(src).and_then(|o| stack.get(&o).and_then(|(_, v)| *v)));
    if let (Some(a), Some(b)) = (a, b) {
        let r = match mn {
            "add" => a.wrapping_add(b), "sub" => a.wrapping_sub(b),
            "imul" => a.wrapping_mul(b), "xor" => a ^ b,
            "and" => a & b, "or" => a | b, _ => 0,
        };
        regs.insert(d, r);
        let sn = sro.and_then(|s| rv.get(s).cloned()).unwrap_or_else(|| sf(b));
        let ov = rv.get(d).cloned().unwrap_or_else(|| "?".into());
        *ssa += 1; let nv = format!("t{}", ssa); rv.insert(d, nv.clone());
        out.push(format!("  {} = {} {} {};  // {} {} {} = {}", nv, ov, os(mn), sn,
                        sf(a), os(mn), sf(b), sf(r)));
    }
}

fn hc(out: &mut Vec<String>, regs: &HashMap<&str, i64>,
      addr: u64, size: u32, dst: &str,
      got_map: &HashMap<u64, String>,
      func_map: &HashMap<u64, String>,
      plt_map: &HashMap<u64, String>) {
    let name = if let Some(t) = iv(dst) {
        let tu = t as u64;
        if let Some(p) = plt_map.get(&tu) { format!("{}@plt", p) }
        else { rn(tu, func_map) }
    } else if dst.contains("rip") {
        // call [rip+offset] → resolve through GOT
        let re = regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)").ok();
        if let Some(re) = re {
            if let Some(caps) = re.captures(dst) {
                let offset = i64::from_str_radix(
                    caps[2].strip_prefix("0x").unwrap_or(&caps[2]), 16).ok();
                if let Some(off) = offset {
                    let target = if &caps[1] == "+" {
                        (addr as i64 + size as i64 + off) as u64
                    } else {
                        (addr as i64 + size as i64 - off) as u64
                    };
                    if let Some(name) = got_map.get(&target) {
                        name.clone()
                    } else { rn(target, func_map) }
                } else { "??".into() }
            } else { "??".into() }
        } else { "??".into() }
    } else { "??".into() };

    let aregs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    let mut av: Vec<String> = Vec::new();
    for r in &aregs {
        match regs.get(r) {
            Some(&v) if v <= 0x100000000 => av.push(sf(v)),
            Some(_) => {},
            None => break,
        }
    }
    if av.is_empty() { av.push("?".into()); }
    out.push(format!("  {}({});", name, av.join(", ")));
}

fn os(mn: &str) -> &str {
    match mn { "add" => "+", "sub" => "-", "imul" => "*", "xor" => "^",
               "and" => "&", "or" => "|", _ => "?" }
}
fn cs(mn: &str) -> &str {
    match mn { "jz"|"je" => "==", "jne"|"jnz" => "!=", "jg" => ">",
               "jge" => ">=", "jl" => "<", "jle" => "<=", _ => mn }
}
fn rn(addr: u64, fm: &HashMap<u64, String>) -> String {
    fm.get(&addr).cloned().unwrap_or_else(|| format!("sub_{:x}", addr))
}
