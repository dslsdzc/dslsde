/// dslsde — SSA 驱动类型传播 (Type 组合版本)
///
/// TRex/TIE 启发: 为每个 SSA 值分配类型变量，
/// 通过约束生成+求解推断变量类型。
///
/// 现在输出 Type 而非 VarType:
///   Pointer(0x293b0) → Type::Ptr(Type::Void) → "void*"
///   Signed(208) → Type::Int(32) → "int"

use std::collections::HashMap;
use crate::ssa::{SsaContext, SsaOp};
use crate::types::{Type, VarType};

/// 为 SSA 中的每个值推断类型
pub fn infer_types(ssa: &SsaContext) -> HashMap<u32, Type> {
    let mut types: HashMap<u32, Type> = HashMap::new();
    let mut changed = true;

    types.insert(0, Type::Int(32));

    while changed {
        changed = false;
        for v in ssa.values() {
            let inferred = match &v.op {
                SsaOp::Assign => {
                    if let Some(&input) = v.inputs.first() {
                        types.get(&input).cloned().unwrap_or(Type::Int(32))
                    } else {
                        v.val.as_ref().map(|val| match val {
                            crate::ir::ValueDomain::Pointer(_) => Type::Ptr(Box::new(Type::Void)),
                            crate::ir::ValueDomain::String(_) => Type::Ptr(Box::new(Type::UInt(8))),
                            crate::ir::ValueDomain::Signed(_) => Type::Int(32),
                            _ => Type::Int(32),
                        }).unwrap_or(Type::Int(32))
                    }
                }
                SsaOp::BinOp(name) => {
                    match name.as_str() {
                        "add" | "sub" => {
                            let t0 = v.inputs.first()
                                .and_then(|&i| types.get(&i))
                                .cloned().unwrap_or(Type::Int(32));
                            match t0 {
                                Type::Ptr(_) | Type::Array(_, _) => t0,
                                _ => Type::Int(32),
                            }
                        }
                        _ => Type::Int(32),
                    }
                }
                SsaOp::Load => Type::Ptr(Box::new(Type::Void)),
                SsaOp::Store => Type::Int(32),
                SsaOp::Call(ret_type) => {
                    match ret_type.as_str() {
                        "malloc" | "calloc" | "realloc" | "strdup" | "memcpy" | "fopen" | "getenv" | "mmap" =>
                            Type::Ptr(Box::new(Type::Void)),
                        "strlen" => Type::UInt(64),
                        "strcmp" | "strncmp" | "atoi" | "abs" | "open" | "close" | "printf" | "puts" | "read" | "write" =>
                            Type::Int(32),
                        "exit" | "abort" | "free" => Type::Void,
                        _ => Type::Int(32),
                    }
                }
                SsaOp::Multiequal(args) => {
                    let mut counts: HashMap<Type, usize> = HashMap::new();
                    for &input in args {
                        let t = types.get(&input).cloned().unwrap_or(Type::Int(32));
                        *counts.entry(t).or_insert(0) += 1;
                    }
                    counts.into_iter()
                        .max_by_key(|(_, c)| *c)
                        .map(|(t, _)| t)
                        .unwrap_or(Type::Int(32))
                }
                SsaOp::GvnExpr(_) => {
                    v.inputs.first()
                        .and_then(|&i| types.get(&i))
                        .cloned().unwrap_or(Type::Int(32))
                }
            };

            let old_val = types.insert(v.id, inferred.clone());
            if old_val != Some(inferred) {
                changed = true;
            }
        }
    }

    types
}

/// VarType → Type (兼容旧接口)
pub fn type_to_c(vt: &VarType) -> &'static str {
    match vt {
        VarType::Ptr => "void*",
        VarType::CharPtr => "char*",
        VarType::Int => "int",
        VarType::UInt => "unsigned",
        VarType::Bool => "bool",
        VarType::Unknown => "int",
    }
}
