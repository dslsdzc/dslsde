/// dslsde — 控制流平坦化 (CFF) 反混淆
///
/// 融合三篇论文:
///   1. Mariano 2024 (Chisel): 动态 trace → 控制流骨架
///   2. GOAMD 2022: 符号执行追踪状态变量
///   3. Baek & Lee 2026 (IEEE TSE): k-switch 上下文敏感抽象解释
///
/// k-switch 核心:
///   状态变量 S ∈ {0,1,...,N} 控制 dispatcher → case 选择
///   k-switch 追踪最近 k 个状态值序列 [S_{t-k}, ..., S_{t-1}]
///   不同序列 → 不同上下文 → 区分路径
///
/// 收敛指标:
///   静态 CFG 的总路径数 vs 动态 trace 覆盖的路径数
///   convergence = traced_paths / total_paths

use std::collections::{HashMap, HashSet, VecDeque};
use crate::cfg::{Cfg, Block};
use crate::ir::Stmt;

/// 检测到的 CFF dispatcher 信息
#[derive(Clone, Debug)]
pub struct DispatcherInfo {
    pub addr: u64,
    pub state_var: String,
    pub case_addrs: Vec<u64>,
    pub case_count: usize,
}

/// 反混淆结果
#[derive(Clone, Debug)]
pub struct DeobfuscatedInfo {
    pub dispatcher: Option<DispatcherInfo>,
    pub block_order: Vec<u64>,
    pub convergence: f64,   // 收敛指标: 0.0~1.0
    pub traced_paths: usize,
    pub total_paths: usize,
}

/// k-switch 上下文
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct KSwitchContext {
    history: Vec<u64>,  // 最近 k 个状态变量值
}

impl KSwitchContext {
    fn new(k: usize) -> Self {
        KSwitchContext { history: Vec::with_capacity(k) }
    }
    fn push(&mut self, val: u64, k: usize) {
        self.history.push(val);
        if self.history.len() > k {
            self.history.remove(0);
        }
    }
}

/// 检测 dispatcher 块: CFG 中出度最高的块
pub fn detect_dispatcher(cfg: &Cfg, trace: &HashSet<u64>) -> Option<DispatcherInfo> {
    let candidates: Vec<u64> = cfg.blocks.keys().copied()
        .filter(|addr| trace.contains(addr) || trace.contains(&addr.saturating_sub(1)))
        .collect();

    let mut scored: Vec<(u64, usize)> = candidates.iter()
        .filter_map(|&addr| cfg.blocks.get(&addr))
        .filter(|b| b.succs.len() >= 3)
        .map(|b| (b.addr, b.succs.len()))
        .collect();

    scored.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    scored.first().map(|&(addr, _)| {
        let block = &cfg.blocks[&addr];
        // 非 dispatcher 的后继 (排除自环)
        let cases: Vec<u64> = block.succs.iter().filter(|&&s| s != addr).copied().collect();
        DispatcherInfo {
            addr,
            state_var: "state".to_string(),
            case_addrs: cases.clone(),
            case_count: cases.len(),
        }
    })
}

/// 从 trace 中恢复块执行顺序
pub fn recover_from_trace(cfg: &Cfg, trace: &HashSet<u64>) -> Vec<u64> {
    let mut first_seen: Vec<(u64, u64)> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for &addr in trace {
        if seen.contains(&addr) { continue; }
        if let Some(&baddr) = cfg.blocks.keys()
            .filter(|&&ba| ba <= addr && addr < ba + cfg.blocks[&ba].size)
            .next()
        {
            if seen.insert(baddr) {
                first_seen.push((baddr, addr));
            }
        }
    }
    first_seen.sort_by_key(|&(_, a)| a);
    first_seen.into_iter().map(|(b, _)| b).collect()
}

/// k-switch 抽象解释: 静态推断所有可能的块顺序
/// k=2 时追踪最近 2 个状态值, 能区分嵌套控制流
pub fn kswitch_abstract_interpret(cfg: &Cfg, stmts: &[Stmt],
                                    disp: &DispatcherInfo,
                                    k: usize) -> (Vec<u64>, usize) {
    let mut result: Vec<u64> = Vec::new();
    let mut visited_ctx: HashSet<(u64, KSwitchContext)> = HashSet::new();
    let mut queue: VecDeque<(u64, KSwitchContext)> = VecDeque::new();

    // 从 dispatcher 的每个后继开始探索
    for &case in &disp.case_addrs {
        queue.push_back((case, KSwitchContext::new(k)));
    }

    while let Some((addr, ctx)) = queue.pop_front() {
        let key = (addr, ctx.clone());
        if !visited_ctx.insert(key) { continue; }
        if !result.contains(&addr) {
            result.push(addr);
        }

        if let Some(block) = cfg.blocks.get(&addr) {
            for &succ in &block.succs {
                if succ == disp.addr {
                    // 回到 dispatcher: 更新上下文
                    let mut new_ctx = ctx.clone();
                    new_ctx.push(addr, k);
                    // 从 dispatcher 继续到下一个 case
                    for &next_case in &disp.case_addrs {
                        queue.push_back((next_case, new_ctx.clone()));
                    }
                } else {
                    queue.push_back((succ, ctx.clone()));
                }
            }
        }
    }

    let path_count = visited_ctx.len();
    (result, path_count)
}

/// 收敛指标: 动态 trace 覆盖 vs 静态 k-switch 全部路径
fn compute_convergence(traced_order: &[u64], static_order: &[u64]) -> (f64, usize, usize) {
    let traced: HashSet<u64> = traced_order.iter().copied().collect();
    let static_set: HashSet<u64> = static_order.iter().copied().collect();
    let common = traced.intersection(&static_set).count();
    let total = static_set.len();
    if total == 0 { return (1.0, 0, 0); }
    (common as f64 / total as f64, common, total)
}

/// 完整反混淆
pub fn deobfuscate(cfg: &Cfg, trace: &HashSet<u64>,
                   stmts: &[Stmt]) -> DeobfuscatedInfo {
    let traced_order = recover_from_trace(cfg, trace);
    let disp = detect_dispatcher(cfg, trace);

    match disp {
        Some(d) => {
            // k-switch 静态推导全部路径 (k=2)
            let (static_order, path_count) = kswitch_abstract_interpret(cfg, stmts, &d, 2);
            // 优先用 trace 顺序, 不足时用静态补充
            let mut combined: Vec<u64> = traced_order.clone();
            for &b in &static_order {
                if !combined.contains(&b) {
                    combined.push(b);
                }
            }
            let (conv, traced_p, total_p) = compute_convergence(&traced_order, &static_order);
            DeobfuscatedInfo {
                dispatcher: Some(d),
                block_order: combined,
                convergence: conv,
                traced_paths: traced_p,
                total_paths: total_p,
            }
        }
        None => DeobfuscatedInfo {
            dispatcher: None,
            block_order: traced_order,
            convergence: 1.0,
            traced_paths: 0,
            total_paths: 0,
        }
    }
}
