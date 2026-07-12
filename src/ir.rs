use std::collections::HashMap;

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

impl Stmt {
    pub fn set_anno(&mut self, a: Annotation) {
        match self {
            Stmt::Assign { anno, .. } | Stmt::Branch { anno, .. } => *anno = a,
            _ => {}
        }
    }
}

pub fn resolve_reg(s: &str, rv: &HashMap<String, String>) -> String {
    if let Some(name) = rv.get(s) { return name.clone(); }
    if let Some(canon) = ro(s) { if let Some(name) = rv.get(canon) { return name.clone(); } }
    s.to_string()
}
pub fn resolve_reg_global(s: &str, rv: &HashMap<String, String>, rg: &HashMap<String, String>) -> String {
    // 寄存器→变量名, 查不到则查寄存器→全局符号
    let canon = ro(s).unwrap_or(s);
    if let Some(name) = rv.get(canon) { return name.clone(); }
    if let Some(global) = rg.get(canon) { return global.clone(); }
    s.to_string()
}
pub fn so_name(s: &str, vn: &HashMap<i64, String>, rv: &HashMap<String, String>) -> String {
    if let Some(off) = so(s) { vn.get(&off).cloned().unwrap_or_else(|| format!("[rbp{:+}]", off)) }
    else if let Some(name) = rv.get(s) { name.clone() }
    else if let Some(canon) = ro(s) { if let Some(name) = rv.get(canon) { name.clone() } else { s.to_string() } }
    else { s.to_string() }
}
pub fn strip_size<'a>(s: &'a str) -> &'a str {
    let s = s.trim();
    for p in &["qword ptr ", "dword ptr ", "word ptr ", "byte ptr "] {
        if let Some(r) = s.strip_prefix(p) { return r.trim(); }
    }
    s
}
pub fn id(d: u64) -> String { "  ".repeat(d as usize) }
pub fn sp(op:&str)->(&str,&str){if let Some(p)=op.find(','){(op[..p].trim(),op[p+1..].trim())}else{(op,"")}}
pub fn dst_or_src<'a>(d:&'a str,s:&'a str)->&'a str{if!d.is_empty(){d}else{s}}
pub fn iv(s:&str)->Option<i64>{let s=s.trim();if s.is_empty(){return None;}if let Some(h)=s.strip_prefix("0x").or_else(||s.strip_prefix("-0x")){let neg=s.starts_with('-');i64::from_str_radix(h,16).ok().map(|v|if neg{-v}else{v})}else{s.parse().ok()}}
pub fn fmt_val(v:&ValueDomain)->String{match v{ValueDomain::Signed(x)=>sf(*x),ValueDomain::Pointer(a)=>format!("global_{:#x}",a),ValueDomain::String(s)=>format!("\"{}\"",s.replace('\n',"\\n")),ValueDomain::Unknown=>"?".into(),ValueDomain::Unsigned(x)=>sf(*x as i64),ValueDomain::Boolean=>"1".into()}}
pub fn sf(v:i64)->String{if v==0{"0".into()}else if v>0&&v<=9999{v.to_string()}else if v<0&&v>=-9999{v.to_string()}else if v<0{format!("-{:#x}",-v)}else{format!("{:#x}",v)}}
pub fn ro(op:&str)->Option<&str>{Some(match op{"eax"|"rax"=>"rax","ebx"|"rbx"=>"rbx","ecx"|"rcx"=>"rcx","edx"|"rdx"=>"rdx","esi"|"rsi"=>"rsi","edi"|"rdi"=>"rdi","rbp"=>"rbp","rsp"=>"rsp","r8d"|"r8"=>"r8","r9d"|"r9"=>"r9","r10d"|"r10"=>"r10","r11d"|"r11"=>"r11","r12d"|"r12"=>"r12","r13d"|"r13"=>"r13","r14d"|"r14"=>"r14","r15d"|"r15"=>"r15",_=>return None})}
pub fn so(op:&str)->Option<i64>{let r=regex_lite::Regex::new(r"\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]").ok()?;let c=r.captures(op)?;Some((if&c[1]=="+"{1}else{-1})*i64::from_str_radix(c[2].strip_prefix("0x").unwrap_or(&c[2]),if c[2].starts_with("0x"){16}else{10}).ok()?)}
pub fn op_sym_rs(mn:&str)->&str{match mn{"add"=>"+","sub"=>"-","imul"=>"*","xor"=>"^","and"=>"&","or"=>"|",_=>"?"}}
pub fn rn(addr:u64,fm:&HashMap<u64,String>)->String{fm.get(&addr).cloned().unwrap_or_else(||format!("sub_{:x}",addr))}
pub fn cstr(mn:&str)->&str{match mn{"jz"|"je"=>"==","jne"|"jnz"=>"!=","jg"=>">","jge"=>">=","jl"=>"<","jle"=>"<=","ja"=>"(u)>","jb"=>"(u)<",_=>mn}}
pub fn refine_domain(v:ValueDomain)->ValueDomain{match v{ValueDomain::Pointer(0)=>ValueDomain::Unknown,_=>v}}
pub fn resolve_rip_cmp(addr: u64, sz: u32, op: &str, gm: &HashMap<u64, String>) -> String {
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
pub fn resolve_call_name(dst:&str,_addr:u64,_size:u32,gm:&HashMap<u64,String>,fm:&HashMap<u64,String>,pm:&HashMap<u64,String>)->String{
    if let Some(t)=iv(dst){let tu=t as u64;if let Some(p)=pm.get(&tu){return format!("{}@plt",p);}return rn(tu,fm);}
    if dst.contains("rip"){if let Ok(re)=regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)"){if let Some(caps)=re.captures(dst){if let Ok(off)=i64::from_str_radix(caps[2].strip_prefix("0x").unwrap_or(&caps[2]),16){let target=if&caps[1]=="+"{(_addr as i64+_size as i64+off)as u64}else{(_addr as i64+_size as i64-off)as u64};if let Some(n)=gm.get(&target){return n.clone();}return rn(target,fm);}}}}
    "??".into()
}
