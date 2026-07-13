pub mod flow;
pub mod trace;
pub mod insn;
pub mod cgen;
pub mod cfg;
pub mod types;
pub mod ir;
pub mod state;
pub mod emit;
pub mod ssa;
pub mod dce;
pub mod switch;
pub mod array;
pub mod structr;
pub mod typeflow;
pub mod infer;

use pyo3::prelude::*;

#[pymodule]
fn dslsde_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<flow::FlowEngine>()?;
    m.add_class::<trace::TraceRecorder>()?;
    m.add_class::<insn::InsnAnalyzer>()?;
    m.add_class::<insn::PyInsnInfo>()?;
    m.add_class::<cgen::CTraceInsn>()?;
    m.add_class::<cgen::RustCGen>()?;
    m.add_class::<infer::InferenceEngine>()?;
    m.add_class::<cfg::CfgBuilder>()?;
    m.add_class::<cfg::CfgResult>()?;
    m.add_class::<cfg::PyBlock>()?;
    Ok(())
}
