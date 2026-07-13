/// dslsde — 结构体恢复 (OSPREY 启发)
///
/// 核心方法 (OSPREY IEEE S&P 2021):
///   1. 追踪 [base + offset] 内存访问模式
///   2. 偏移聚类 → 字段边界推断
///   3. 指针关联 → 嵌套结构体检测
///
/// 字段命名 (ReSym CCS 2024 启发):
///   访问模式 → field_0, field_1, ...
///
/// 集成: emit.rs 在变量命名阶段调用 format_struct_access,
///       用 inferred_structs 替换 raw [base+N] 输出

use std::collections::{HashMap, HashSet};

/// 单次内存访问记录
#[derive(Clone, Debug)]
pub struct MemAccess {
    pub base_reg: String,
    pub offset: i64,
    pub size: u32,
    pub is_write: bool,
}

/// 推断出的字段
#[derive(Clone, Debug)]
pub struct StructField {
    pub offset: i64,
    pub size: u32,
    pub type_name: String,
    pub field_name: String,       // field_0, field_1, ...
    pub nested_struct: Option<Box<StructInfo>>,
}

/// 结构体信息
#[derive(Clone, Debug)]
pub struct StructInfo {
    pub base_reg: String,
    pub fields: Vec<StructField>,
    pub total_size: i64,
    pub is_nested: bool,
}

// ── OSPREY 核心: 从访问记录推断结构体 ──

/// 从内存访问集合推断结构体
/// 对同一个基址的多次不同偏移访问 → 字段
pub fn infer_struct(base_reg: &str, accesses: &[MemAccess]) -> Option<StructInfo> {
    if accesses.len() < 2 { return None; }

    // 聚类偏移: 按 offset 去重, 保留最大访问 size
    let mut offset_map: HashMap<i64, u32> = HashMap::new();
    for acc in accesses {
        let entry = offset_map.entry(acc.offset).or_insert(0);
        *entry = (*entry).max(acc.size);
    }
    // 检查对齐 → 结构体推断门槛
    let aligned_count = offset_map.keys().filter(|off| **off % 4 == 0).count();
    if aligned_count < 2 { return None; }

    let mut sorted_offsets: Vec<(i64, u32)> = offset_map.into_iter().collect();
    sorted_offsets.sort_by_key(|(off, _)| *off);

    // 推断字段: 按 offset 顺序, 计算 gap 和 padding
    let mut fields = Vec::new();
    for (i, &(off, size)) in sorted_offsets.iter().enumerate() {
        let next_off = if i + 1 < sorted_offsets.len() { sorted_offsets[i+1].0 }
                       else { off + 8.min(size as i64 * 2) };
        let field_size = (next_off - off).abs() as u32;

        // ReSym 启发: 从偏移和大小推断语义字段名
        let field_name = infer_field_name(off, size, i, &sorted_offsets);

        let type_name = match size {
            1 => "uint8_t".to_string(),
            2 => "uint16_t".to_string(),
            4 => "uint32_t".to_string(),
            8 => "uint64_t".to_string(),
            _ => format!("uint{}_t", size * 8),
        };

        fields.push(StructField {
            offset: off,
            size: field_size.max(size),
            type_name,
            field_name,
            nested_struct: None,
        });
    }

    let last = fields.last().unwrap();
    let total_size = last.offset + last.size as i64;
    Some(StructInfo {
        base_reg: base_reg.to_string(),
        fields,
        total_size,
        is_nested: false,
    })
}

// ── 指针关联: SSA def-use 链追踪 ──

/// 指针关联表: 追踪寄存器之间的指针传递关系
/// 例如: rdi → rax (mov rax, rdi), rax → rcx (mov rcx, rax)
pub fn track_pointer_flow(stmts: &[crate::ir::Stmt]) -> HashMap<String, String> {
    let mut flow: HashMap<String, String> = HashMap::new();
    for stmt in stmts {
        if let crate::ir::Stmt::Assign { dst, info, .. } = stmt {
            if info.contains("[rbp") { continue; }
            if info.contains("+") || info.contains("-") { continue; }
            let src_reg = info.trim();
            // reg → reg 复制
            if let Some(d) = ro(dst) {
                if let Some(s) = ro(src_reg) {
                    flow.insert(d.to_string(), s.to_string());
                }
            }
        }
    }
    flow
}

fn ro(op: &str) -> Option<&str> {
    Some(match op {
        "eax"|"rax"=>"rax","ebx"|"rbx"=>"rbx","ecx"|"rcx"=>"rcx",
        "edx"|"rdx"=>"rdx","esi"|"rsi"=>"rsi","edi"|"rdi"=>"rdi",
        "rsp"=>"rsp","rbp"=>"rbp","r8d"|"r8"=>"r8","r9d"|"r9"=>"r9",
        _=>return None,
    })
}

// ── 操作数解析 ──

/// 从操作数字符串解析结构体字段访问
/// "[rax + 0x10]" → Some(("rax", 16))
/// 排除 rbp/rip 基址
pub fn parse_field_access(op: &str) -> Option<(String, i64)> {
    let re = regex_lite::Regex::new(r"\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]").ok()?;
    let caps = re.captures(op)?;
    let base = caps[1].to_string();
    if base == "rbp" || base == "rip" { return None; }
    let off_str = &caps[2];
    let offset = if let Some(hex) = off_str.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        off_str.parse::<i64>().ok()?
    };
    if offset > 0 && offset < 512 { Some((base, offset)) } else { None }
}

/// 为操作数中的结构体访问生成格式化输出
pub fn format_access(op: &str, structs: &HashMap<String, &StructInfo>) -> Option<String> {
    let (base, off) = parse_field_access(op)?;
    if let Some(si) = structs.get(&base) {
        for field in &si.fields {
            if field.offset == off {
                return Some(format!("{}.{}", base, field.field_name));
            }
        }
    }
    None
}

/// ReSym 启发: 从偏移和访问模式推断字段名
/// offset 0 → 通常是指针或长度字段
/// offset 8 → 第二个字段, 32/64位值
/// 小偏移密集排列 → 标志位或枚举
fn infer_field_name(off: i64, size: u32, index: usize, sorted: &[(i64, u32)]) -> String {
    // offset 0 的特殊语义
    if off == 0 {
        let next = sorted.get(1);
        if let Some(&(n_off, _)) = next {
            let gap = n_off - off;
            if gap == 8 && size == 8 { return "ptr".to_string(); }   // 典型: 第一个字段是指针
            if gap == 4 && size == 4 { return "length".to_string(); } // 4字节 → 长度
            if gap == 2 && size == 2 { return "flags".to_string(); }  // 2字节 → 标志位
        }
        return if size >= 8 { "ptr".to_string() } else { "field_0".to_string() };
    }

    // 基于偏移模式的常见命名
    let pattern = (off, size, index);
    match pattern {
        (8, 8, 1) if off == 8 => return "size".to_string(),
        (16, 8, 2) if off == 16 => return "data".to_string(),
        (12, 4, _) | (24, 4, _) => return "flags".to_string(),
        _ => {}
    }

    // 大小推断
    match size {
        1 => format!("flag_{}", index),
        2 => format!("field_{}", index),
        4 if off % 8 == 0 => format!("field_{}", index),
        8 => format!("field_{}", index),
        _ => format!("field_{}", index),
    }
}

/// 从 Stmts 中提取所有内存访问
pub fn collect_accesses(stmts: &[crate::ir::Stmt]) -> Vec<MemAccess> {
    let mut accesses = Vec::new();
    for stmt in stmts {
        match stmt {
            crate::ir::Stmt::Assign { dst, info, .. } => {
                // dst 中解析
                if let Some((base, off)) = parse_field_access(dst) {
                    accesses.push(MemAccess { base_reg: base, offset: off, size: 8, is_write: true });
                }
                // info 中解析
                if let Some((base, off)) = parse_field_access(info) {
                    accesses.push(MemAccess { base_reg: base, offset: off, size: 8, is_write: false });
                }
            }
            _ => {}
        }
    }
    accesses
}
