/// dslsde — 死变量消除 (Dead Code Elimination)
///
/// 利用 SSA 信息检测未使用的寄存器定义。
/// 如果 SSA 值只有一次定义但从未被使用 → 标记为 dead。
///
/// 集成: 在 build_addr_map 之前运行，从 state.stmts 中移除 dead Assign

use std::collections::{HashMap, HashSet};
use crate::ir::{State, Stmt, Annotation};
use crate::ssa::{SsaContext, SsaOp};

/// 执行死变量消除
/// 返回值: 被移除的 stmt 地址列表
pub fn eliminate(state: &mut State, ssa: &SsaContext) -> Vec<u64> {
    // 1. 收集所有被使用的 SSA id
    let mut used: HashSet<u32> = HashSet::new();

    // 扫描所有 stmts 的输入引用
    for stmt in &state.stmts {
        match stmt {
            Stmt::Assign { addr, val, info, .. } => {
                // 检查 SSA 输入: 如果 info 是寄存器名，找它的 SSA id
                if let Some(sid) = state.ssa_ids.get(addr) {
                    used.insert(*sid);
                }
            }
            Stmt::Call { args, .. } => {
                // call 的参数可能引用 SSA 值
                // 但 Stmt::Call 只存 ValueDomain，不存 SSA id
                // 所以这里无法直接追踪
            }
            Stmt::Branch { .. } | Stmt::Return { .. } => {}
            _ => {}
        }
    }

    // 2. 扫描 SSA 的 inputs 关系
    for v in ssa.values() {
        for &input in &v.inputs {
            used.insert(input);
        }
    }

    // 3. 标记 dead: Assign 到寄存器但从未被 read 的值
    let mut dead_addrs: Vec<u64> = Vec::new();
    for stmt in &state.stmts {
        if let Stmt::Assign { addr, dst, .. } = stmt {
            // 跳过栈变量 (不消除)
            if dst.starts_with("[rbp") { continue; }
            // 只有寄存器写才可能 dead
            if !matches!(ro(dst), Some(_)) { continue; }
            // 查 SSA: 如果该写从未被使用 → dead
            if let Some(&sid) = state.ssa_ids.get(addr) {
                if !used.contains(&sid) {
                    // 检查该 SSA 值是否被其他 SSA 值引用
                    let has_user = ssa.values().iter().any(|v| v.inputs.contains(&sid));
                    if !has_user {
                        dead_addrs.push(*addr);
                    }
                }
            }
        }
    }

    // 4. 移除 dead stmts
    if !dead_addrs.is_empty() {
        let dead_set: HashSet<u64> = dead_addrs.iter().copied().collect();
        state.stmts.retain(|s| {
            match s {
                Stmt::Assign { addr, .. } => !dead_set.contains(addr),
                _ => true,
            }
        });
    }

    dead_addrs
}

fn ro(op: &str) -> Option<&str> {
    Some(match op {
        "eax"|"rax"=>"rax","ebx"|"rbx"=>"rbx","ecx"|"rcx"=>"rcx",
        "edx"|"rdx"=>"rdx","esi"|"rsi"=>"rsi","edi"|"rdi"=>"rdi",
        "rbp"=>"rbp","rsp"=>"rsp",
        "r8d"|"r8"=>"r8","r9d"|"r9"=>"r9",
        "r10d"|"r10"=>"r10","r11d"|"r11"=>"r11",
        "r12d"|"r12"=>"r12","r13d"|"r13"=>"r13",
        "r14d"|"r14"=>"r14","r15d"|"r15"=>"r15",
        _=>return None,
    })
}
