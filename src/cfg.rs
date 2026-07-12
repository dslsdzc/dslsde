use std::collections::{HashMap, BTreeMap};
use pyo3::prelude::*;
use crate::insn::PyInsnInfo;

#[derive(Clone, Debug)]
pub struct Block {
    pub addr: u64, pub size: u64,
    pub succs: Vec<u64>, pub preds: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct Cfg {
    pub blocks: BTreeMap<u64, Block>,
    pub entry: u64,
}

/// O(n) CFG 构建：一次扫描指令，不重复过滤
pub fn build_cfg_internal(insns: &[PyInsnInfo]) -> Cfg {
    let n = insns.len();
    if n == 0 { return Cfg { blocks: BTreeMap::new(), entry: 0 }; }

    let entry = insns[0].addr;
    let addr_map: HashMap<u64, &PyInsnInfo> = insns.iter().map(|i| (i.addr, i)).collect();

    // Pass 1: 找所有块起始（O(n)）
    let mut is_start: BTreeMap<u64, bool> = BTreeMap::new();
    is_start.insert(entry, true);
    for insn in insns {
        // 分支→目标地址是块起始
        if (insn.is_cond_jmp || insn.is_jmp || insn.is_call) && insn.target != 0 {
            if addr_map.contains_key(&insn.target) { is_start.entry(insn.target).or_insert(false); }
        }
        // 分支/ret→下一指令是块起始
        let nxt = insn.addr + insn.size as u64;
        if (insn.is_call || insn.is_ret || insn.is_jmp || insn.is_cond_jmp) && addr_map.contains_key(&nxt) {
            is_start.entry(nxt).or_insert(false);
        }
    }

    // 构建块（使用顺序扫描，不创建中间 Vec）
    let start_addrs: Vec<u64> = is_start.keys().copied().collect();
    let mut blocks: BTreeMap<u64, Block> = BTreeMap::new();

    // 计算每个块的结束地址
    let mut block_ends: HashMap<u64, u64> = HashMap::new();
    for (i, &s) in start_addrs.iter().enumerate() {
        let end = if i + 1 < start_addrs.len() { start_addrs[i + 1] } else { insns.last().unwrap().addr + insns.last().unwrap().size as u64 };
        block_ends.insert(s, end);
        blocks.insert(s, Block { addr: s, size: end.saturating_sub(s), succs: Vec::new(), preds: Vec::new() });
    }

    // Pass 2: 构建边（O(n) — 对每个块，用 addr_map 找最后一条指令）
    for &baddr in &start_addrs {
        let end = block_ends[&baddr];

        // 找到块内最后一条指令：从 end 往前找
        let last_addr = (baddr..end).rev().find(|a| addr_map.contains_key(a));
        let Some(&last) = last_addr.and_then(|a| addr_map.get(&a)) else { continue; };

        let nxt = last.addr + last.size as u64;

        // call: fallthrough
        if last.is_call || (!last.is_ret && !last.is_jmp && !last.is_cond_jmp) {
            if let Some(&s) = start_addrs.iter().rev().find(|&&b| b <= nxt) {
                blocks.get_mut(&baddr).map(|b| b.succs.push(s));
                blocks.get_mut(&s).map(|b| b.preds.push(baddr));
            }
        }
        // jmp/cond_jmp: target
        if last.is_jmp || last.is_cond_jmp {
            if last.target != 0 {
                if let Some(&s) = start_addrs.iter().rev().find(|&&b| b <= last.target) {
                    blocks.get_mut(&baddr).map(|b| b.succs.push(s));
                    blocks.get_mut(&s).map(|b| b.preds.push(baddr));
                }
            }
        }
        // cond_jmp: fallthrough 到下一个块
        if last.is_cond_jmp {
            let nxt = last.addr + last.size as u64;
            if let Some(&s) = start_addrs.iter().find(|&&b| b > baddr) {
                if s != baddr && blocks.contains_key(&s) {
                    blocks.get_mut(&baddr).map(|b| { if !b.succs.contains(&s) { b.succs.push(s); }});
                    blocks.get_mut(&s).map(|b| b.preds.push(baddr));
                }
            }
        }
    }

    Cfg { blocks, entry }
}

// ── Python CFG Builder ──

#[pyclass]
pub struct CfgResult {
    #[pyo3(get)] pub blocks: BTreeMap<u64, PyBlock>,
    #[pyo3(get)] pub entry: u64,
}

#[pyclass]
#[derive(Clone)]
pub struct PyBlock {
    #[pyo3(get)] pub addr: u64,
    #[pyo3(get)] pub succs: Vec<u64>,
    #[pyo3(get)] pub preds: Vec<u64>,
}

#[pyclass]
pub struct CfgBuilder {}

#[pymethods]
impl CfgBuilder {
    #[new] pub fn new() -> Self { CfgBuilder {} }
    pub fn build(&self, insns: Vec<PyRef<PyInsnInfo>>) -> CfgResult {
        let native: Vec<PyInsnInfo> = insns.iter().map(|r| (*r).clone()).collect();
        let cfg = build_cfg_internal(&native);
        let mut blocks = BTreeMap::new();
        for (&addr, b) in &cfg.blocks {
            blocks.insert(addr, PyBlock { addr: b.addr, succs: b.succs.clone(), preds: b.preds.clone() });
        }
        CfgResult { blocks, entry: cfg.entry }
    }
}
