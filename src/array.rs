/// dslsde — 数组下标检测
///
/// 检测 [base + index * scale] 寻址 → arr[index]
/// 集成: 从 build_state 生成的 Stmts 中识别数组访问模式

use crate::insn::PyInsnInfo;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct ArrayAccess {
    pub addr: u64,
    pub base_reg: String,
    pub index_reg: String,
    pub scale: u32,
}

/// 从指令流中检测数组访问
pub fn detect_array_accesses(insns: &[PyInsnInfo]) -> Vec<ArrayAccess> {
    let mut result = Vec::new();
    let seen: HashSet<u64> = HashSet::new();
    for insn in insns {
        if seen.contains(&insn.addr) { continue; }
        // 检查操作数中的 [base + index * scale]
        if let Some((base, idx, scale)) = parse_mem_ref(&insn.operands) {
            result.push(ArrayAccess {
                addr: insn.addr,
                base_reg: base,
                index_reg: idx,
                scale,
            });
        }
        // 也检查 AT&T 语法: base(,index,scale)
        if let Some((base, idx, scale)) = parse_att_mem(&insn.operands) {
            result.push(ArrayAccess {
                addr: insn.addr,
                base_reg: base,
                index_reg: idx,
                scale,
            });
        }
    }
    result
}

/// Intel 语法: [rax + rcx*8]
fn parse_mem_ref(op: &str) -> Option<(String, String, u32)> {
    let re = regex_lite::Regex::new(r"\[(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\]").ok()?;
    let caps = re.captures(op)?;
    let scale: u32 = caps[3].parse().ok()?;
    Some((caps[1].to_string(), caps[2].to_string(), scale))
}

/// AT&T 语法: disp(base,index,scale)
fn parse_att_mem(op: &str) -> Option<(String, String, u32)> {
    let re = regex_lite::Regex::new(r"\((\w+),(\w+),(\d+)\)").ok()?;
    let caps = re.captures(op)?;
    let scale: u32 = caps[3].parse().ok()?;
    Some((caps[1].to_string(), caps[2].to_string(), scale))
}

/// 按基址寄存器分组，用于结构体推断
pub fn group_by_base(accesses: &[ArrayAccess]) -> Vec<(String, Vec<ArrayAccess>)> {
    let mut groups: Vec<(String, Vec<ArrayAccess>)> = Vec::new();
    for acc in accesses {
        let base = acc.base_reg.clone();
        if let Some(g) = groups.iter_mut().find(|(b, _)| *b == base) {
            g.1.push(acc.clone());
        } else {
            groups.push((base, vec![acc.clone()]));
        }
    }
    groups
}
