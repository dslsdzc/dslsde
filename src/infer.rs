use std::collections::{HashMap, HashSet};
use pyo3::prelude::*;
use crate::ir::*;
use crate::insn::PyInsnInfo;
use crate::cfg::build_cfg_internal;
use crate::ssa::{SsaContext, SsaOp};
use crate::dce;
use crate::typeflow;
use crate::deobfuscate;
use crate::switch;
use crate::sigs::SigDb;

#[pyclass]
pub struct InferenceEngine {
    pub func_map: HashMap<u64, String>, pub got_map: HashMap<u64, String>,
    pub plt_map: HashMap<u64, String>, pub str_map: HashMap<u64, String>,
    pub sig_db: SigDb,
    pub binary_data: Vec<u8>,
    pub text_base: u64,
}

#[pymethods]
impl InferenceEngine {
    #[new] pub fn new() -> Self { InferenceEngine { func_map: HashMap::new(), got_map: HashMap::new(), plt_map: HashMap::new(), str_map: HashMap::new(), sig_db: SigDb::new(), binary_data: Vec::new(), text_base: 0 } }
    pub fn set_binary(&mut self, data: Vec<u8>, base: u64) { self.binary_data = data; self.text_base = base; }
    pub fn set_func_map(&mut self, m: HashMap<u64, String>) { self.func_map = m; }
    pub fn set_got_map(&mut self, m: HashMap<u64, String>) { self.got_map = m; }
    pub fn set_plt_map(&mut self, m: HashMap<u64, String>) { self.plt_map = m; }
    pub fn set_str_map(&mut self, m: HashMap<u64, String>) { self.str_map = m; }
    pub fn set_sig_map(&mut self, m: HashMap<String, (Vec<String>, String, bool)>) { self.sig_db.load(m); }
    pub fn infer(&mut self, trace: Vec<(u64, u32, String, String)>, args: Vec<i64>) -> String {
        let entry = trace.first().map(|t| t.0).unwrap_or(0);
        let mut ssa = SsaContext::new(entry);
        let mut state = self.build_state(&trace, &args, &mut ssa);
        for i in 0..5 {
            state.iteration = i; state.changed = false;
            self.pass_noise_filter(&mut state); self.pass_value_domain(&mut state);
            self.pass_constraint(&mut state); self.pass_arg_purify(&mut state);
        }
        self.emit_flat(&state)
    }
    pub fn infer_structured(&mut self, trace: Vec<(u64, u32, String, String)>,
                            args: Vec<i64>, py_insns: Vec<PyRef<PyInsnInfo>>) -> String {
        self.infer_structured_impl(trace, args, py_insns, vec![])
    }

    /// 多 trace 合并反编译 (并行追踪多个参数组合)
    #[pyo3(signature = (trace, args, py_insns, extra_traces, extra_args))]
    pub fn infer_structured_multi(&mut self, trace: Vec<(u64, u32, String, String)>,
                                   args: Vec<i64>, py_insns: Vec<PyRef<PyInsnInfo>>,
                                   extra_traces: Vec<Vec<(u64, u32, String, String)>>,
                                   extra_args: Vec<Vec<i64>>) -> String {
        self.infer_structured_impl(trace, args, py_insns, extra_traces)
    }

    fn infer_structured_impl(&mut self, trace: Vec<(u64, u32, String, String)>,
                              args: Vec<i64>, py_insns: Vec<PyRef<PyInsnInfo>>,
                              extra_traces: Vec<Vec<(u64, u32, String, String)>>) -> String {
        let entry = trace.first().map(|t| t.0).unwrap_or(0);
        let mut ssa = SsaContext::new(entry);
        // 主 trace
        let mut state = self.build_state(&trace, &args, &mut ssa);
        // 额外 trace: 合并 SSA（在 passes 之前，phi 节点不被 passes 影响）
        for extra in &extra_traces {
            if extra.is_empty() { continue; }
            let mut extra_ssa = SsaContext::new(entry);
            let _extra_state = self.build_state(extra, &vec![0], &mut extra_ssa);
            crate::ssa::merge_traces(&mut ssa, &extra_ssa, entry);
        }
        for i in 0..5 {
            state.iteration = i; state.changed = false;
            self.pass_noise_filter(&mut state); self.pass_value_domain(&mut state);
            self.pass_constraint(&mut state); self.pass_arg_purify(&mut state);
            if !state.changed { break; }
        }
        // 跨函数类型传播（passes 之后）
        typeflow::propagate_types(&mut state, &self.sig_db);
        // 死变量消除
        let _dead = dce::eliminate(&mut state, &ssa);
        let (addr_map, var_types) = self.build_addr_map(&state, &ssa);
        state.addr_map = addr_map;
        let native: Vec<PyInsnInfo> = py_insns.iter().map(|r| (*r).clone()).collect();
        let cfg = build_cfg_internal(&native);
        let mut trace_addrs: HashSet<u64> = trace.iter().map(|t| t.0).collect();
        for extra in &extra_traces {
            trace_addrs.extend(extra.iter().map(|t| t.0));
        }
        let jump_tables = if self.binary_data.is_empty() { Vec::new() }
                          else { switch::recover_jump_tables(&self.binary_data, self.text_base, &native) };
        let mut cfg = cfg;
        for jt in &jump_tables {
            if let Some(block) = cfg.blocks.get_mut(&jt.addr) {
                for &entry in &jt.entries {
                    if !block.succs.contains(&entry) {
                        block.succs.push(entry);
                    }
                }
            }
        }
        let deobf_info = deobfuscate::deobfuscate(&cfg, &trace_addrs, &state.stmts);
        let result = self.emit_structured(&state, &cfg, &trace_addrs, &var_types, &jump_tables, &deobf_info);
        if deobf_info.total_paths > 0 {
            format!("// convergence: {:.0}% ({}/{})\n{}",
                     deobf_info.convergence * 100.0,
                     deobf_info.traced_paths, deobf_info.total_paths,
                     result)
        } else {
            result
        }
    }
}

impl InferenceEngine {
    fn pass_noise_filter(&self, state: &mut State) {
        if state.iteration > 0 { return; }
        let mut new = Vec::new(); let mut i = 0;
        while i < state.stmts.len() {
            let is_ov = i + 1 < state.stmts.len() && matches!(&state.stmts[i+1], Stmt::Branch { ref cond, .. } if matches!(cond.as_str(), "jo"|"jno"|"jb"|"jae"|"js"|"jns"));
            if is_ov { let mut a = state.stmts[i].clone(); a.set_anno(Annotation::OverflowGuard); new.push(a);
                let mut b = state.stmts[i+1].clone(); b.set_anno(Annotation::OverflowGuard); new.push(b); i += 2; state.changed = true; continue; }
            new.push(state.stmts[i].clone()); i += 1;
        } state.stmts = new;
    }
    fn pass_value_domain(&self, state: &mut State) { for stmt in &mut state.stmts { if let Stmt::Assign { ref mut val, .. } = stmt { *val = refine_domain(val.clone()); } } }
    fn pass_constraint(&self, state: &mut State) {
        let mut i = 0;
        while i + 1 < state.stmts.len() {
            if let Stmt::Branch { target, anno: Annotation::None, .. } = &state.stmts[i+1] {
                let name = rn(*target, &self.func_map); if name.contains("error")||name.contains("die")||name.contains("abort") { state.stmts[i+1].set_anno(Annotation::BoundsCheck); }
            } i += 1;
        }
    }
    fn pass_arg_purify(&self, state: &mut State) {
        for stmt in &mut state.stmts {
            if let Stmt::Call { ref name, ref mut args, .. } = stmt {
                let base = name.split(|c: char| c == '@' || c == '(').next().unwrap_or(name);
                if let Some(sig) = self.sig_db.lookup(base) {
                    let max = sig.args.len();
                    if sig.variadic && args.len() > max { args.truncate(max); state.changed = true; }
                    else if !sig.variadic && args.len() > max { args.truncate(max); state.changed = true; }
                    continue;
                }
                while args.len() > 2 && matches!(args.last(), Some(ValueDomain::Signed(x)) if *x < 10) { args.pop(); }
            }
        }
    }
}
