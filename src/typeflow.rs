/// dslsde — 跨函数类型推断
///
/// 从函数签名传播返回值类型到调用点

use crate::ir::{State, Stmt, ValueDomain};
use crate::sigs::SigDb;

/// 跨函数类型传播：标记 rax 返回值类型
pub fn propagate_types(state: &mut State, sig_db: &SigDb) {
    for i in 0..state.stmts.len() {
        if let Stmt::Call { name, .. } = &state.stmts[i] {
            let base = name.split(|c: char| c == '@' || c == '(').next().unwrap_or(name);
            // 从签名返回值类型推断
            let ret_type = sig_db.lookup(base).and_then(|sig| {
                match sig.ret.as_str() {
                    "void*" | "char*" | "FILE*" | "void *" => Some(ValueDomain::Pointer(0)),
                    "size_t" | "ssize_t" | "off_t" | "pid_t" |
                    "int" | "long" | "unsigned" | "clock_t" |
                    "time_t" => Some(ValueDomain::Signed(0)),
                    _ => None,
                }
            });
            if let Some(rt) = ret_type {
                state.regs.insert("rax".to_string(), rt);
            }
        }
    }
}
