/// dslsde — 跨函数类型推断
///
/// 从函数签名传播返回值类型到调用点
/// 已知返回值类型的函数 → 标记 rax 的 ValueDomain

use std::collections::HashMap;
use crate::ir::{State, Stmt, ValueDomain};

/// 预定义的标准库函数返回值类型
const KNOWN_RETURNS: &[(&str, ValueDomain)] = &[
    // 返回指针
    ("malloc", ValueDomain::Pointer(0)),
    ("calloc", ValueDomain::Pointer(0)),
    ("realloc", ValueDomain::Pointer(0)),
    ("strdup", ValueDomain::Pointer(0)),
    ("memcpy", ValueDomain::Pointer(0)),
    ("memmove", ValueDomain::Pointer(0)),
    ("strcpy", ValueDomain::Pointer(0)),
    ("strcat", ValueDomain::Pointer(0)),
    ("fopen", ValueDomain::Pointer(0)),
    ("fgets", ValueDomain::Pointer(0)),
    ("strstr", ValueDomain::Pointer(0)),
    ("strchr", ValueDomain::Pointer(0)),
    ("getenv", ValueDomain::Pointer(0)),
    // 返回 size_t (Signed)
    ("strlen", ValueDomain::Signed(0)),
    ("strnlen", ValueDomain::Signed(0)),
    ("sizeof", ValueDomain::Signed(0)),
    // 返回 int
    ("strcmp", ValueDomain::Signed(0)),
    ("strncmp", ValueDomain::Signed(0)),
    ("atoi", ValueDomain::Signed(0)),
    ("atol", ValueDomain::Signed(0)),
    ("abs", ValueDomain::Signed(0)),
    ("open", ValueDomain::Signed(0)),
    ("close", ValueDomain::Signed(0)),
    ("read", ValueDomain::Signed(0)),
    ("write", ValueDomain::Signed(0)),
    ("printf", ValueDomain::Signed(0)),
    ("fprintf", ValueDomain::Signed(0)),
    ("sprintf", ValueDomain::Signed(0)),
    ("snprintf", ValueDomain::Signed(0)),
    ("puts", ValueDomain::Signed(0)),
];

/// 跨函数类型传播
/// 修改 state.regs 中 rax 的类型
pub fn propagate_types(state: &mut State, sig_map: &HashMap<String, (u32, bool)>) {
    // 逆向扫描 stmts：找到 call → 标记其后的 rax
    let mut i = 0;
    while i < state.stmts.len() {
        if let Stmt::Call { name, .. } = &state.stmts[i] {
            let base = name.split(|c: char| c == '@' || c == '(').next().unwrap_or(name);
            // 先查预定义表
            let ret_type = KNOWN_RETURNS.iter()
                .find(|(n, _)| *n == base)
                .map(|(_, v)| v.clone());

            // 再查签名表（某些签名可能暗示类型）
            let ret_type = ret_type.or_else(|| {
                sig_map.get(base).map(|(_, _)| ValueDomain::Signed(0))
            });

            if let Some(rt) = ret_type {
                // 将 rax 的类型设置为返回值类型
                state.regs.insert("rax".to_string(), rt);
            }
        }
        i += 1;
    }
}
