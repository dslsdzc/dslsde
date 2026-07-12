use std::collections::{HashMap, VecDeque};
use pyo3::prelude::*;
use crate::insn::PyInsnInfo;

#[derive(Clone, Copy)]
pub(crate) struct InsnInfo {
    pub addr: u64, pub target: u64, pub next: u64,
    pub is_call: bool, pub is_ret: bool, pub is_jmp: bool,
    pub is_cond_jmp: bool, pub is_indirect: bool,
}

#[pyclass]
pub struct FlowEngine {
    insn_map: HashMap<u64, InsnInfo>,
    body: Vec<u64>,
}

#[pymethods]
impl FlowEngine {
    #[new]
    pub fn new() -> Self { FlowEngine { insn_map: HashMap::new(), body: Vec::new() } }

    pub fn set_instructions(&mut self, _py: Python, insns: Vec<PyRef<PyInsnInfo>>) {
        self.insn_map.clear();
        for i in &insns {
            self.insn_map.insert(i.addr, InsnInfo {
                addr: i.addr, target: i.target, next: i.next,
                is_call: i.is_call, is_ret: i.is_ret,
                is_jmp: i.is_jmp, is_cond_jmp: i.is_cond_jmp,
                is_indirect: i.is_indirect,
            });
        }
    }

    pub fn follow_flow(&mut self, start_addr: u64) -> usize {
        self.body.clear();
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(start_addr);
        while let Some(addr) = queue.pop_front() {
            if visited.contains(&addr) { continue; }
            let mut cur = addr;
            loop {
                if visited.contains(&cur) { break; }
                visited.insert(cur); self.body.push(cur);
                let Some(insn) = self.insn_map.get(&cur) else { break };
                if insn.is_ret { break; }
                if insn.is_jmp && !insn.is_cond_jmp {
                    if insn.target != 0 && !visited.contains(&insn.target) { queue.push_back(insn.target); }
                    break;
                }
                if insn.is_indirect && !insn.is_cond_jmp { break; }
                if insn.is_call { cur = insn.next; continue; }
                if insn.is_cond_jmp {
                    if insn.target != 0 && !visited.contains(&insn.target) { queue.push_back(insn.target); }
                    cur = insn.next; continue;
                }
                cur = insn.next;
            }
        }
        self.body.sort(); self.body.dedup(); self.body.len()
    }

    pub fn body(&self) -> Vec<u64> { self.body.clone() }
}
