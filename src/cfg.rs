use std::collections::{HashMap, HashSet, BTreeMap};
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

#[derive(Clone, Debug)]
pub struct NaturalLoop {
    pub header: u64,
    pub body: Vec<u64>,
}

impl Cfg {
    /// 计算所有块的可达性（从 entry 出发）
    pub fn reachable(&self) -> HashSet<u64> {
        let mut seen = HashSet::new();
        let mut stack = vec![self.entry];
        while let Some(addr) = stack.pop() {
            if !seen.insert(addr) { continue; }
            if let Some(b) = self.blocks.get(&addr) {
                for &s in &b.succs { stack.push(s); }
            }
        }
        seen
    }

    /// 迭代数据流计算支配集：每个块 → 所有支配它的块
    fn compute_dom_sets(&self) -> HashMap<u64, HashSet<u64>> {
        let reachable = self.reachable();
        let addrs: Vec<u64> = self.blocks.keys().copied().filter(|a| reachable.contains(a)).collect();
        if addrs.is_empty() { return HashMap::new(); }

        let all_set: HashSet<u64> = addrs.iter().copied().collect();
        let mut dom: HashMap<u64, HashSet<u64>> = HashMap::new();
        dom.insert(self.entry, HashSet::from([self.entry]));
        for &a in &addrs {
            if a != self.entry { dom.insert(a, all_set.clone()); }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for &a in &addrs {
                if a == self.entry { continue; }
                let preds = &self.blocks[&a].preds;
                // 新 dom = {a} ∪ ⋂ dom(p) for p in preds
                let mut new_dom: HashSet<u64> = if preds.is_empty() {
                    HashSet::new()
                } else {
                    preds.iter()
                        .filter_map(|p| dom.get(p))
                        .cloned()
                        .reduce(|a, b| a.intersection(&b).copied().collect())
                        .unwrap_or_default()
                };
                new_dom.insert(a);
                if new_dom != dom[&a] {
                    dom.insert(a, new_dom);
                    changed = true;
                }
            }
        }
        dom
    }

    /// 计算直接支配者（immediate dominator），entry → entry
    pub fn compute_idoms(&self) -> HashMap<u64, u64> {
        let dom = self.compute_dom_sets();
        let mut idom: HashMap<u64, u64> = HashMap::new();
        idom.insert(self.entry, self.entry);

        for (&a, d_set) in &dom {
            if a == self.entry { continue; }
            // 在 dom(a) - {a} 中，找到不被其他候选支配的候选
            let candidates: Vec<u64> = d_set.iter().copied().filter(|&x| x != a).collect();
            let id = candidates.iter().find(|&&c| {
                candidates.iter().all(|&o| o == c || dom.get(&o).map_or(true, |s| s.contains(&c)))
            }).copied().unwrap_or(self.entry);
            idom.insert(a, id);
        }
        idom
    }

    /// 查找自然循环：返回所有 (header, body)
    pub fn find_natural_loops(&self) -> Vec<NaturalLoop> {
        let dom = self.compute_dom_sets();
        let mut loops: Vec<NaturalLoop> = Vec::new();

        for (&addr, block) in &self.blocks {
            for &succ in &block.succs {
                // 回边定义：succ 支配 addr（包括自环 succ == addr）
                let is_back = succ == addr || dom.get(&addr).map_or(false, |d| d.contains(&succ));
                if !is_back { continue; }

                let header = succ;
                // 收集循环体：在 pred 图中从 addr 反向走到 header
                let mut body: Vec<u64> = Vec::new();
                let mut seen = HashSet::new();
                let mut stack = vec![addr];
                while let Some(node) = stack.pop() {
                    if node == header || !seen.insert(node) { continue; }
                    body.push(node);
                    if let Some(b) = self.blocks.get(&node) {
                        for &p in &b.preds {
                            if !self.blocks.contains_key(&p) { continue; }
                            stack.push(p);
                        }
                    }
                }
                body.push(header);
                // 去重
                if !loops.iter().any(|l| l.header == header && l.body.len() == body.len()) {
                    loops.push(NaturalLoop { header, body });
                }
            }
        }
        loops
    }
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
        if (insn.is_cond_jmp || insn.is_jmp || insn.is_call) && insn.target != 0 {
            if addr_map.contains_key(&insn.target) { is_start.entry(insn.target).or_insert(false); }
        }
        let nxt = insn.addr + insn.size as u64;
        if (insn.is_call || insn.is_ret || insn.is_jmp || insn.is_cond_jmp) && addr_map.contains_key(&nxt) {
            is_start.entry(nxt).or_insert(false);
        }
    }

    let start_addrs: Vec<u64> = is_start.keys().copied().collect();
    let mut blocks: BTreeMap<u64, Block> = BTreeMap::new();
    let mut block_ends: HashMap<u64, u64> = HashMap::new();
    for (i, &s) in start_addrs.iter().enumerate() {
        let end = if i + 1 < start_addrs.len() { start_addrs[i + 1] } else { insns.last().unwrap().addr + insns.last().unwrap().size as u64 };
        block_ends.insert(s, end);
        blocks.insert(s, Block { addr: s, size: end.saturating_sub(s), succs: Vec::new(), preds: Vec::new() });
    }

    // Pass 2: 构建边
    for &baddr in &start_addrs {
        let end = block_ends[&baddr];
        let last_addr = (baddr..end).rev().find(|a| addr_map.contains_key(a));
        let Some(&last) = last_addr.and_then(|a| addr_map.get(&a)) else { continue; };
        let nxt = last.addr + last.size as u64;

        if last.is_call || (!last.is_ret && !last.is_jmp && !last.is_cond_jmp) {
            if let Some(&s) = start_addrs.iter().rev().find(|&&b| b <= nxt) {
                blocks.get_mut(&baddr).map(|b| b.succs.push(s));
                blocks.get_mut(&s).map(|b| b.preds.push(baddr));
            }
        }
        if last.is_jmp || last.is_cond_jmp {
            if last.target != 0 {
                if let Some(&s) = start_addrs.iter().rev().find(|&&b| b <= last.target) {
                    blocks.get_mut(&baddr).map(|b| b.succs.push(s));
                    blocks.get_mut(&s).map(|b| b.preds.push(baddr));
                }
            }
        }
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
