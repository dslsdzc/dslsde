/// dslsde — Switch 恢复
///
/// 检测间接跳转: jmp [base + index * scale]
/// 解析跳转表内容，重建 switch

use crate::insn::PyInsnInfo;

#[derive(Clone, Debug)]
pub struct JumpTable {
    pub addr: u64,               // jmp 指令地址
    pub entries: Vec<u64>,       // case 目标地址列表
    pub default_target: u64,     // default 目标
    pub index_reg: String,       // 索引寄存器
    pub table_addr: u64,         // 跳转表地址
    pub entry_count: usize,      // case 数量
}

/// 从二进制数据中读取跳转表条目
fn read_jump_table(binary: &[u8], table_addr: u64, text_base: u64, count: usize) -> Vec<u64> {
    let mut entries = Vec::new();
    let offset = table_addr.saturating_sub(text_base) as usize;
    if offset + count * 8 > binary.len() { return entries; }
    for i in 0..count {
        let addr = offset + i * 8;
        let val = u64::from_le_bytes([
            binary[addr], binary[addr+1], binary[addr+2], binary[addr+3],
            binary[addr+4], binary[addr+5], binary[addr+6], binary[addr+7],
        ]);
        entries.push(val);
    }
    entries
}

/// 恢复跳转表
/// binary: 完整二进制数据
/// text_base: .text 段基址
/// insns: 所有指令列表
pub fn recover_jump_tables(binary: &[u8], text_base: u64, insns: &[PyInsnInfo]) -> Vec<JumpTable> {
    let mut tables = Vec::new();
    let mut i = 0;
    while i < insns.len() {
        let insn = &insns[i];
        // 检测模式: lea reg, [rip+table_addr] + jmp [reg + index*scale]
        if insn.mnemonic == "lea" && insn.operands.contains("[rip") {
            // 解析 table_addr
            if let Some(table_addr) = parse_rip_target(insn) {
                // 向后扫描 jmp [reg + index*scale]
                for j in (i+1)..insns.len().min(i+20) {
                    let jmp = &insns[j];
                    if jmp.mnemonic.starts_with("jmp") && jmp.operands.contains('*') {
                        let index_reg = extract_index_reg(&jmp.operands);
                        // 尝试读取跳转表（最多 256 项）
                        let mut entry_count = 256;
                        let entries = read_jump_table(binary, table_addr, text_base, entry_count);
                        if entries.is_empty() { break; }
                        // 找到最大连续有效地址范围
                        let mut valid = Vec::new();
                        for &e in &entries {
                            if e >= text_base && e < text_base + binary.len() as u64 {
                                valid.push(e);
                            } else {
                                break;
                            }
                        }
                        entry_count = valid.len();
                        let entries = read_jump_table(binary, table_addr, text_base, entry_count);
                        if entry_count >= 3 {  // 至少 3 个 case
                            tables.push(JumpTable {
                                addr: jmp.addr,
                                entries,
                                default_target: 0,
                                index_reg: index_reg.unwrap_or_default(),
                                table_addr,
                                entry_count,
                            });
                        }
                        break;
                    }
                }
            }
        }
        i += 1;
    }
    tables
}

fn parse_rip_target(insn: &PyInsnInfo) -> Option<u64> {
    let re = regex_lite::Regex::new(r"rip\s*([-+])\s*(0x[0-9a-fA-F]+)").ok()?;
    let caps = re.captures(&insn.operands)?;
    let off: i64 = i64::from_str_radix(&caps[2].strip_prefix("0x").unwrap_or(&caps[2]), 16).ok()?;
    Some(if &caps[1] == "+" {
        insn.addr + insn.size as u64 + off as u64
    } else {
        insn.addr + insn.size as u64 - off as u64
    })
}

fn extract_index_reg(op: &str) -> Option<String> {
    // jmp [rax + rcx*8] → extract "rcx"
    let re = regex_lite::Regex::new(r"\*\s*(\d+)\]").ok()?;
    let _ = re.captures(op)?;
    // 找到 '+' 后面的寄存器
    if let Some(plus) = op.find('+') {
        let after = op[plus+1..].trim();
        let reg = after.split(|c: char| c == '*' || c == ']').next().unwrap_or("").trim();
        if !reg.is_empty() { return Some(reg.to_string()); }
    }
    None
}
