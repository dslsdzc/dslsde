/// dslsde — 结构体恢复
///
/// 从 [base + offset] 和 [base + index*scale] 模式推断结构体
/// 如果同一个基址有多个偏移访问 → 结构体字段

use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct StructField {
    pub offset: i64,
    pub size: u32,
    pub type_name: String,
}

#[derive(Clone, Debug)]
pub struct StructInfo {
    pub base_reg: String,
    pub fields: Vec<StructField>,
    pub total_size: i64,
}

/// 从 [ptr + offset] 访问集合推断结构体
/// offsets: 每个 (偏移, 访问大小) 对
pub fn recover_struct(base_reg: &str, offsets: &[(i64, u32)]) -> Option<StructInfo> {
    if offsets.len() < 2 { return None; }  // 至少两个字段

    let mut uniq: Vec<(i64, u32)> = offsets.to_vec();
    uniq.sort_by_key(|(off, _)| *off);
    uniq.dedup();

    // 查找对齐的字段序列
    let mut fields = Vec::new();
    for (i, &(off, size)) in uniq.iter().enumerate() {
        let type_name = match size {
            1 => "uint8_t",
            2 => "uint16_t",
            4 => "uint32_t",
            8 => "uint64_t",
            16 => "struct",
            _ => "uint8_t",
        };
        let next_off = if i + 1 < uniq.len() { uniq[i+1].0 } else { off + size as i64 };
        let aligned_size = (next_off - off) as u32;
        fields.push(StructField {
            offset: off,
            size: aligned_size.max(size),
            type_name: type_name.to_string(),
        });
    }

    let total_size = fields.last().map(|f| f.offset + f.size as i64).unwrap_or(0);

    Some(StructInfo {
        base_reg: base_reg.to_string(),
        fields,
        total_size,
    })
}

/// 检测操作数中的结构体字段访问模式
/// 例如 "[rax + 0x10]" → Some(("rax", 16))
/// 排除 [rbp+...] 和 [rip+...]（非结构体上下文）
/// 仅返回小偏移 (< 256) 的固定偏移访问
pub fn format_struct_access(op: &str) -> Option<(String, i64)> {
    let re = regex_lite::Regex::new(r"\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]").ok()?;
    let caps = re.captures(op)?;
    let base = caps[1].to_string();
    // 排除 rbp 和 rip（栈帧 / GOT，非结构体）
    if base == "rbp" || base == "rip" { return None; }
    let off_str = &caps[2];
    let offset = if let Some(hex) = off_str.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        off_str.parse::<i64>().ok()?
    };
    if offset > 0 && offset < 256 {
        Some((base, offset))
    } else {
        None
    }
}

/// 从数组访问转换到结构体推断
/// 如果一个指针既有数组访问又有固定偏移访问 → 结构体数组
pub fn struct_from_mixed(ptr_name: &str, offsets: &[i64], array_indices: &[i64]) -> Option<StructInfo> {
    let all_offsets: HashSet<i64> = offsets.iter().copied().collect();
    if all_offsets.len() < 2 { return None; }

    let mut offsets: Vec<i64> = all_offsets.into_iter().collect();
    offsets.sort();

    let fields: Vec<StructField> = offsets.iter().map(|&off| {
        StructField {
            offset: off,
            size: 8,
            type_name: "uint64_t".to_string(),
        }
    }).collect();

    let total_size = fields.last().map(|f| f.offset + f.size as i64).unwrap_or(8);
    Some(StructInfo {
        base_reg: ptr_name.to_string(),
        fields,
        total_size,
    })
}
