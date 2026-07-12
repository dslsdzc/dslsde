/// dslsde — 类型推断系统
use std::collections::HashMap;

/// 变量类型
#[derive(Clone, Debug, PartialEq)]
pub enum VarType { Int, UInt, Ptr, CharPtr, Bool, Unknown }

impl Default for VarType {
    fn default() -> Self { VarType::Unknown }
}

/// 根据指令操作数信息推断变量类型
pub fn infer_var_type(info: &str) -> Option<VarType> {
    let info_s = info.trim();
    // 参数寄存器 → Int
    if matches!(info_s, "rdi"|"rsi"|"rdx"|"rcx"|"r8"|"r9") { return Some(VarType::Int); }
    // 算术运算 → Int
    if info_s.contains('*') || info_s.contains("imul") { return Some(VarType::Int); }
    // 取地址 / 指针运算 → Ptr
    if info_s.contains("lea") || info_s.contains("[rip") { return Some(VarType::Ptr); }
    // 字符串相关 → CharPtr
    if info_s.contains("strings") || info_s.contains("puts") || info_s.contains("printf") || info_s.contains("str") { return Some(VarType::CharPtr); }
    None
}
