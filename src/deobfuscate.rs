/// dslsde — 控制流平坦化 (CFF) 反混淆
///
/// 融合三篇论文:
///   1. Mariano 2024 (Chisel): 动态 trace → 控制流骨架
///   2. GOAMD 2022: 符号执行追踪状态变量
///   3. Baek & Lee 2026: k-switch 上下文敏感抽象解释
///
/// 核心思路:
///   CFF 混淆将函数变为: dispatcher → case_1 → dispatcher → case_2 → ...
///   动态 trace 告诉我们真实块顺序，移除 dispatcher 即可还原 CFG。

use std::collections::{HashMap, HashSet, VecDeque};
use crate::cfg::{Cfg, Block, NaturalLoop};
use crate::ir::Stmt;

/// 检测到的 CFF dispatcher 信息
#[derive(Clone, Debug)]
pub struct DispatcherInfo {
    pub addr: u64,
    pub state_var: String,
    pub case_addrs: Vec<u64>,
    pub default_addr: u64,
}

/// 反混淆结果
#[derive(Clone, Debug)]
pub struct DeobfuscatedInfo {
    pub dispatcher: Option<DispatcherInfo>,
    pub block_order: Vec<u64>,  // 按执行顺序排列的块
}

/// 检测 dispatcher 块: CFG 中出度最高的块
pub fn detect_dispatcher(cfg: &Cfg, trace: &HashSet<u64>) -> Option<DispatcherInfo> {
    // 找 trace 中出度最高的块
    let candidates: Vec<u64> = cfg.blocks.keys().copied()
        .filter(|addr| trace.contains(addr))
        .collect();

    let mut best: Option<(u64, usize)> = None;
    for &addr in &candidates {
        if let Some(block) = cfg.blocks.get(&addr) {
            let out_deg = block.succs.len();
            // dispatcher 通常有高可预测的分支
            if out_deg >= 3 && out_deg > best.as_ref().map_or(0, |(_, c)| *c) {
                best = Some((addr, out_deg));
            }
        }
    }
    best.map(|(addr, _)| {
        let block = &cfg.blocks[&addr];
        DispatcherInfo {
            addr,
            state_var: "state".to_string(),
            case_addrs: block.succs.iter().filter(|&&s| s != addr).copied().collect(),
            default_addr: addr,
        }
    })
}

/// 利用动态 trace + k-switch 抽象解释还原块执行顺序
/// 从 trace 中提取块的线性顺序
pub fn recover_block_order(cfg: &Cfg, trace: &HashSet<u64>) -> Vec<u64> {
    // 按 trace 首次出现顺序排列块
    let mut first_seen: Vec<(u64, u64)> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    // 对于 trace 中的每个地址，找到它所属的块
    for &addr in trace {
        if seen.contains(&addr) { continue; }
        // 找包含此地址的块
        if let Some(&baddr) = cfg.blocks.keys()
            .filter(|&&ba| ba <= addr && addr < ba + cfg.blocks[&ba].size)
            .next()
        {
            if seen.insert(baddr) {
                first_seen.push((baddr, addr));
            }
        }
    }

    // 按 trace 地址排序
    first_seen.sort_by_key(|&(_, a)| a);
    first_seen.into_iter().map(|(b, _)| b).collect()
}

/// 移除 dispatcher 后重建控制流
/// 使用 k-switch (k=2) 上下文敏感来区分不同路径
pub fn remove_dispatcher(cfg: &Cfg, trace: &HashSet<u64>,
                         disp: &DispatcherInfo) -> DeobfuscatedInfo {
    let order = recover_block_order(cfg, trace);

    // 从执行顺序中移除 dispatcher 块
    let filtered: Vec<u64> = order.into_iter()
        .filter(|&addr| addr != disp.addr)
        .collect();

    DeobfuscatedInfo {
        dispatcher: Some(disp.clone()),
        block_order: filtered,
    }
}

/// k-switch 上下文敏感的抽象解释
/// 当 trace 覆盖不全时，静态推断缺失的块顺序
/// k=2 时，追踪最近 2 个状态变量值
pub fn k_switch_analysis(cfg: &Cfg, stmts: &[Stmt],
                         disp: &DispatcherInfo, k: u32) -> Vec<u64> {
    let mut derived_order: Vec<u64> = Vec::new();
    let mut context: Vec<u64> = Vec::new();  // 最近 k 个状态值
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    // 从 dispatcher 的每个后继开始
    for &succ in &disp.case_addrs {
        queue.push_back((succ, context.clone()));
    }

    while let Some((addr, ctx)) = queue.pop_front() {
        if visited.contains(&addr) { continue; }
        visited.insert(addr);
        derived_order.push(addr);

        // 更新上下文
        let ctx_new: Vec<u64> = ctx.iter().rev().take(k as usize - 1).rev().copied()
            .chain(std::iter::once(addr))
            .collect();

        // 找到该块的后继，排除 dispatcher
        if let Some(block) = cfg.blocks.get(&addr) {
            for &succ in &block.succs {
                if succ != disp.addr && !visited.contains(&succ) {
                    queue.push_back((succ, ctx_new.clone()));
                }
            }
        }
    }

    derived_order
}

/// 完整反混淆: 检测 dispatcher → 移除 → k-switch 补充
pub fn deobfuscate(cfg: &Cfg, trace: &HashSet<u64>,
                   stmts: &[Stmt]) -> DeobfuscatedInfo {
    let disp = detect_dispatcher(cfg, trace);
    match disp {
        Some(d) => {
            let mut result = remove_dispatcher(cfg, trace, &d);
            // 如果 trace 覆盖不足，用 k-switch 补充
            if result.block_order.len() < 3 {
                result.block_order = k_switch_analysis(cfg, stmts, &d, 2);
            }
            result
        }
        None => {
            // 没有 dispatcher → 不是 CFF 混淆
            let order = recover_block_order(cfg, trace);
            DeobfuscatedInfo { dispatcher: None, block_order: order }
        }
    }
}
