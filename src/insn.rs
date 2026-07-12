use std::collections::HashMap;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use capstone::prelude::*;

#[pyclass]
#[derive(Clone)]
pub struct PyInsnInfo {
    #[pyo3(get, set)] pub addr: u64, #[pyo3(get, set)] pub target: u64,
    #[pyo3(get, set)] pub next: u64, #[pyo3(get, set)] pub size: u32,
    #[pyo3(get, set)] pub mnemonic: String, #[pyo3(get, set)] pub operands: String,
    #[pyo3(get, set)] pub bytes: Vec<u8>,
    #[pyo3(get, set)] pub is_call: bool, #[pyo3(get, set)] pub is_ret: bool,
    #[pyo3(get, set)] pub is_jmp: bool, #[pyo3(get, set)] pub is_cond_jmp: bool,
    #[pyo3(get, set)] pub is_indirect: bool,
}

#[pymethods]
impl PyInsnInfo {
    #[new]
    #[allow(clippy::too_many_arguments)]
    pub fn new(addr: u64, target: u64, next: u64, size: u32,
               mnemonic: String, operands: String, bytes: Vec<u8>,
               is_call: bool, is_ret: bool, is_jmp: bool,
               is_cond_jmp: bool, is_indirect: bool) -> Self {
        Self { addr, target, next, size, mnemonic, operands, bytes,
               is_call, is_ret, is_jmp, is_cond_jmp, is_indirect }
    }

    pub fn __repr__(&self) -> String {
        format!("Insn({:#x}: {} {})", self.addr, self.mnemonic, self.operands)
    }
}

#[pyclass]
pub struct InsnAnalyzer {}

#[pymethods]
impl InsnAnalyzer {
    #[new]
    pub fn new() -> Self { InsnAnalyzer {} }

    pub fn analyze(&self, code_data: &[u8], code_base: u64,
                   arch: &str, bits: u32) -> PyResult<(Vec<PyInsnInfo>, Vec<u64>)> {
        let cs = build_capstone(arch, bits)
            .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
        let mut insns = Vec::new();
        let mut targets = Vec::new();
        let raw = cs.disasm_all(code_data, code_base)
            .map_err(|e| PyValueError::new_err(format!("capstone: {}", e)))?;
        for i in raw.iter() {
            let addr = i.address(); let size = i.len() as u32;
            let mn = i.mnemonic().unwrap_or("").to_string();
            let op = i.op_str().unwrap_or("").to_string();
            let (mns, ops) = (mn.as_str(), op.as_str());
            let target = pit(if op.is_empty() { None } else { Some(ops) });
            let ic = matches!(mns, "call"|"callq"|"bl"|"blx");
            let ir = matches!(mns, "ret"|"retq"|"retn"|"bx lr");
            let ij = matches!(mns, "jmp"|"jmpq"|"b"|"bra");
            let icj = (mns.starts_with('j') && !matches!(mns, "jmp"|"jmpq"|"call"|"callq"))
                || matches!(mns, "cbnz"|"cbz"|"tbnz"|"tbz");
            let iind = (ic || ij) && ops.contains('[');
            if ic && target != 0 { targets.push(target); }
            insns.push(PyInsnInfo { addr, target, next: addr + size as u64, size,
                mnemonic: mn, operands: op, bytes: i.bytes().to_vec(),
                is_call: ic, is_ret: ir, is_jmp: ij, is_cond_jmp: icj, is_indirect: iind });
        }
        Ok((insns, targets))
    }
}

fn build_capstone(arch: &str, bits: u32) -> Result<Capstone, String> {
    match (arch, bits) {
        ("x86"|"x86_64", 64) => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build(),
        ("x86"|"x86_64", 32) => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build(),
        ("ARM", _) => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build(),
        ("AARCH64", _) => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).build(),
        _ => return Err(format!("unsupported: {} {}-bit", arch, bits)),
    }.map_err(|e| format!("capstone init: {}", e))
}

fn pit(op: Option<&str>) -> u64 {
    let Some(op) = op else { return 0 };
    let f = op.split(',').next().unwrap_or("").trim();
    if f.starts_with("0x") || f.starts_with("-0x") {
        if let Ok(v) = u64::from_str_radix(f.trim_start_matches("-0x").trim_start_matches("0x"), 16) { return v; }
    }
    0
}

/// 构建指令名 → 地址映射表（供 cgen 用）
pub fn build_insn_map(insns: &[PyInsnInfo]) -> HashMap<u64, (String, String)> {
    let mut m = HashMap::new();
    for i in insns {
        m.insert(i.addr, (i.mnemonic.clone(), i.operands.clone()));
    }
    m
}
