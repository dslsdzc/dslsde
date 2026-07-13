/// dslsde — SSA 驱动类型传播
///
/// TRex/TIE 启发: 为每个 SSA 值分配类型变量，
/// 通过约束生成+求解推断变量类型。
///
/// 约束规则:
///   BinOp(add, a, b) → a:int, b:int, result:int
///   Call(func, args) → result = func.ret_type (从签名)
///   PtrDeref(p) → p:ptr(T), result:T
///   Assign(a, b) → a = b (类型一致)

use std::collections::HashMap;
use crate::ssa::{SsaContext, SsaOp};
use crate::types::VarType;

/// 为 SSA 中的每个值推断类型
pub fn infer_types(ssa: &SsaContext) -> HashMap<u32, VarType> {
    let mut types: HashMap<u32, VarType> = HashMap::new();
    let mut changed = true;

    // v0 = Unknown
    types.insert(0, VarType::Unknown);

    // 迭代传播直到稳定
    while changed {
        changed = false;
        for v in ssa.values() {
            let inferred = match &v.op {
                SsaOp::Assign => {
                    // 从输入传播
                    if let Some(&input) = v.inputs.first() {
                        types.get(&input).cloned().unwrap_or(VarType::Unknown)
                    } else {
                        v.val.as_ref().map(|val| match val {
                            crate::ir::ValueDomain::Pointer(_) => VarType::Ptr,
                            crate::ir::ValueDomain::String(_) => VarType::CharPtr,
                            crate::ir::ValueDomain::Signed(_) => VarType::Int,
                            _ => VarType::Unknown,
                        }).unwrap_or(VarType::Unknown)
                    }
                }
                SsaOp::BinOp(name) => {
                    // 算术运算 → Int
                    match name.as_str() {
                        // 指针运算: base + idx*scale → 保持 base 类型
                        "add" | "sub" => {
                            let t0 = v.inputs.first()
                                .and_then(|&i| types.get(&i))
                                .cloned().unwrap_or(VarType::Int);
                            match t0 {
                                VarType::Ptr | VarType::CharPtr => t0,
                                _ => VarType::Int,
                            }
                        }
                        // 位运算/比较 → Int
                        "xor" | "and" | "or" | "imul" => VarType::Int,
                        _ => VarType::Int,
                    }
                }
                SsaOp::Load => VarType::Ptr,
                SsaOp::Store => VarType::Unknown,
                SsaOp::Call(ret_type) => {
                    match ret_type.as_str() {
                        "malloc" | "calloc" | "realloc" | "strdup"
                        | "memcpy" | "fopen" | "getenv" => VarType::Ptr,
                        "strlen" | "strcmp" | "atoi" | "abs" | "open" => VarType::Int,
                        "printf" | "puts" | "close" | "read" | "write" => VarType::Int,
                        "exit" | "abort" | "free" => VarType::Unknown,
                        _ => VarType::Unknown,
                    }
                }
                SsaOp::Multiequal(args) => {
                    // phi: 从所有输入取最常见类型
                    let mut counts = HashMap::new();
                    for &input in args {
                        let t = types.get(&input).cloned().unwrap_or(VarType::Unknown);
                        *counts.entry(t).or_insert(0) += 1;
                    }
                    counts.into_iter()
                        .max_by_key(|(_, c)| *c)
                        .map(|(t, _)| t)
                        .unwrap_or(VarType::Unknown)
                }
                SsaOp::GvnExpr(_) => {
                    v.inputs.first()
                        .and_then(|&i| types.get(&i))
                        .cloned().unwrap_or(VarType::Unknown)
                }
            };

            let old_val = types.insert(v.id, inferred.clone());
            if old_val != Some(inferred.clone()) {
                changed = true;
            }
        }
    }

    types
}

/// 将 VarType 转为 C 类型字符串
pub fn type_to_c(vt: VarType) -> &'static str {
    match vt {
        VarType::Ptr => "void*",
        VarType::CharPtr => "char*",
        VarType::Int => "int",
        VarType::UInt => "unsigned",
        VarType::Bool => "bool",
        VarType::Unknown => "int",
    }
}
