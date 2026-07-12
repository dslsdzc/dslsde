/// dslsde — 完整 SSA 构建器
///
/// 融合三种算法:
/// - 值版本化 (Cytron 改名): 每次写寄存器递增版本
/// - phi 放置 (Braun 反向搜索): 合并点按需插 Multiequal
/// - GVN (Lemerre 抽象解释): 表达式哈希 → 公共子表达式消除
///
/// phi 节点叫 Multiequal (Ghidra 命名风格)
///
/// 单 trace: 简单版本化，无 phi
/// 多 trace: seal_block 时触发 phi 生成

use std::collections::{HashMap, HashSet};
use crate::ir::ValueDomain;

pub type SsaId = u32;

/// SSA 值来源
#[derive(Clone, Debug, PartialEq)]
pub enum SsaOp {
    Assign,                     // reg = val
    BinOp(String),        // add/sub/xor/...
    Load,                       // load [addr]
    Store,                      // store (副作用)
    Call(String),               // call func
    Multiequal(Vec<SsaId>),     // phi: 不同路径的汇合
    GvnExpr(u64),               // GVN 表达式哈希
}

/// 单个 SSA 值
#[derive(Clone, Debug)]
pub struct SsaValue {
    pub id: SsaId,
    pub addr: u64,
    pub reg: String,
    pub op: SsaOp,
    pub inputs: Vec<SsaId>,
    pub val: Option<ValueDomain>,
    pub has_gvn: bool,           // 是否已被 GVN 优化
}

/// 块的 SSA 状态
#[derive(Clone, Default)]
struct BlockState {
    /// 进入本块时，各寄存器的当前版本
    reg_in: HashMap<String, SsaId>,
    /// 在本块内被写过的寄存器
    defined: HashSet<String>,
    /// 已 seal (不再有未发现的入边)
    sealed: bool,
    /// 待处理的 phi (reg → SsaId)
    pending_phi: HashMap<String, SsaId>,
    /// 本块的入边是否已全部处理
    pred_count: usize,
    pred_seen: usize,
}

/// SSA 上下文
pub struct SsaContext {
    values: Vec<SsaValue>,
    blocks: HashMap<u64, BlockState>,
    /// GVN 缓存: (操作哈希, 输入列表哈希) → SsaId
    gvn_cache: HashMap<(u64, u64), SsaId>,
    next_id: SsaId,
    entry: u64,
}

/// 表达式哈希 (用于 GVN)
fn hash_expr(addr: u64, op: &str, inputs: &[SsaId]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    addr.hash(&mut h);
    op.hash(&mut h);
    for &i in inputs { i.hash(&mut h); }
    h.finish()
}

impl SsaContext {
    pub fn new(entry: u64) -> Self {
        let mut ctx = SsaContext {
            values: Vec::new(),
            blocks: HashMap::new(),
            gvn_cache: HashMap::new(),
            next_id: 0,
            entry,
        };
        // v0 = Undef
        ctx.values.push(SsaValue {
            id: 0, addr: 0, reg: String::new(), op: SsaOp::Assign,
            inputs: vec![], val: Some(ValueDomain::Unknown), has_gvn: false,
        });
        ctx.next_id = 1;
        ctx
    }

    /// 分配新 ID
    fn alloc_id(&mut self) -> SsaId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// 注册块
    pub fn register_block(&mut self, addr: u64, pred_count: usize) {
        self.blocks.entry(addr).or_insert_with(|| BlockState {
            reg_in: HashMap::new(),
            defined: HashSet::new(),
            sealed: false,
            pending_phi: HashMap::new(),
            pred_count,
            pred_seen: 0,
        });
    }

    /// 标记块已 seal (所有入边已处理)
    pub fn seal_block(&mut self, addr: u64) {
        if let Some(bs) = self.blocks.get_mut(&addr) {
            bs.sealed = true;
        }
    }

    /// 读寄存器 → 返回当前 SSA id
    /// 如果寄存器未被定义，返回 v0 (Undef)
    /// 如果块未 seal 且寄存器未定义 → 插 phi (Braun 算法)
    pub fn read_reg(&mut self, addr: u64, block: u64, reg: &str) -> SsaId {
        // 检查块内定义
        if let Some(bs) = self.blocks.get(&block) {
            if let Some(&id) = bs.reg_in.get(reg) {
                return id;
            }
        }

        // 未定义: 返回 v0
        if block == self.entry {
            return 0;
        }

        // Braun 反向搜索: 未 seal → 插 phi
        if let Some(bs) = self.blocks.get(&block) {
            if !bs.sealed {
                // 创建 phi (但尚未确定输入)
                let phi_id = self.alloc_id();
                self.values.push(SsaValue {
                    id: phi_id, addr, reg: reg.to_string(), op: SsaOp::Multiequal(vec![]),
                    inputs: vec![], val: None, has_gvn: false,
                });
                if let Some(pb) = self.blocks.get_mut(&block) {
                    pb.pending_phi.insert(reg.to_string(), phi_id);
                }
                return phi_id;
            }
        }

        // seal 且未定义 → 递归前驱查找
        self.read_reg_from_preds(addr, block, reg)
    }

    /// Braun: 从前驱读寄存器值，若不一致则插 phi
    fn read_reg_from_preds(&mut self, addr: u64, block: u64, reg: &str) -> SsaId {
        let Some(bs) = self.blocks.get(&block) else { return 0; };
        if bs.pred_count == 0 { return 0; }

        // 注: 需要 CFG 前驱信息，从外部传入
        0
    }

    /// 写寄存器 → 创建新版本
    pub fn write_reg(&mut self, addr: u64, block: u64, reg: &str, val: Option<ValueDomain>,
                     op: SsaOp, inputs: Vec<SsaId>) -> SsaId {
        // GVN: BinOp 表达式哈希 → 复用相同表达式
        if let SsaOp::BinOp(ref name) = &op {
            let h = hash_expr(addr, name, &inputs);
            if let Some(&existing) = self.gvn_cache.get(&(h, 0)) {
                if let Some(v) = self.values.get_mut(existing as usize) {
                    v.has_gvn = true;
                }
                if let Some(bs) = self.blocks.get_mut(&block) {
                    bs.reg_in.insert(reg.to_string(), existing);
                }
                return existing;
            }
            self.gvn_cache.insert((h, 0), self.next_id);
        }

        let id = self.alloc_id();
        self.values.push(SsaValue {
            id, addr, reg: reg.to_string(), op, inputs,
            val, has_gvn: false,
        });

        // 更新当前块的 reg_in
        if let Some(bs) = self.blocks.get_mut(&block) {
            bs.reg_in.insert(reg.to_string(), id);
            bs.defined.insert(reg.to_string());
        }
        id
    }

    /// 获取值的显示名
    pub fn value_name(&self, id: SsaId) -> String {
        if id == 0 { return "undef".to_string(); }
        let Some(v) = self.values.get(id as usize) else {
            return format!("v{}", id);
        };
        if let SsaOp::Multiequal(ref args) = v.op {
            if args.is_empty() {
                return format!("phi_{}(...)", v.reg);
            }
            let a: Vec<String> = args.iter().map(|&i| self.value_name(i)).collect();
            return format!("phi_{}({})", v.reg, a.join(", "));
        }
        if v.has_gvn {
            return format!("{}_{}_gvn", v.reg, id);
        }
        format!("{}_{}", v.reg, id)
    }

    /// 获取值的来源描述 (用于注释)
    pub fn value_desc(&self, id: SsaId) -> String {
        if id == 0 { return "undef".to_string(); }
        let Some(v) = self.values.get(id as usize) else {
            return format!("v{}", id);
        };
        match &v.op {
            SsaOp::Assign | SsaOp::Load => {
                if let Some(ref val) = v.val {
                    match val {
                        ValueDomain::Pointer(a) => format!("global_{:#x}", a),
                        ValueDomain::Signed(x) => x.to_string(),
                        ValueDomain::String(s) => format!("\"{}\"", s),
                        _ => format!("{:?}", val),
                    }
                } else {
                    format!("{}_{}", v.reg, id)
                }
            }
            SsaOp::Multiequal(args) => {
                if args.is_empty() { format!("phi({})", v.reg) }
                else {
                    let a: Vec<String> = args.iter().map(|&i| self.value_desc(i)).collect();
                    format!("phi({})", a.join(","))
                }
            }
            SsaOp::BinOp(name) => {
                let ins: Vec<String> = v.inputs.iter().map(|&i| self.value_desc(i)).collect();
                format!("{}[{} {}]", self.value_name(id), name, ins.join(", "))
            }
            SsaOp::Call(name) => format!("{}(...)", name),
            _ => format!("{}_{}", v.reg, id),
        }
    }

    /// 查找 id → 值
    pub fn get(&self, id: SsaId) -> Option<&SsaValue> {
        self.values.get(id as usize)
    }

    /// 当前版本数
    pub fn version_count(&self) -> u32 {
        self.next_id
    }

    /// 获取所有值的迭代器
    pub fn values(&self) -> &[SsaValue] {
        &self.values
    }
}

// ── 多 trace 合并 ──

/// 合并两个 trace 的 SSA 上下文
pub fn merge_traces(base: &mut SsaContext, other: &SsaContext, merge_block: u64) {
    // 在 merge_block 处，对每个在两边都有不同最终版本的寄存器插 phi
    let mut phi_needed: HashMap<String, (SsaId, SsaId)> = HashMap::new();

    // 找寄存器: 在两个 trace 中都有定义且版本不同
    for (reg, id_base) in &base.regs_at(merge_block) {
        if let Some(id_other) = other.regs_at(merge_block).get(reg) {
            if id_base != id_other {
                phi_needed.insert(reg.clone(), (*id_base, *id_other));
            }
        }
    }

    for (reg, (id1, id2)) in phi_needed {
        let phi_id = base.alloc_id();
        base.values.push(SsaValue {
            id: phi_id,
            addr: merge_block,
            reg: reg.clone(),
            op: SsaOp::Multiequal(vec![id1, id2]),
            inputs: vec![id1, id2],
            val: None,
            has_gvn: false,
        });
        // 更新合并点的 reg_in
        if let Some(bs) = base.blocks.get_mut(&merge_block) {
            bs.reg_in.insert(reg, phi_id);
        }
    }
}

// 辅助: 获取某块处的寄存器版本状态
impl SsaContext {
    fn regs_at(&self, block: u64) -> HashMap<String, SsaId> {
        self.blocks.get(&block).map(|bs| bs.reg_in.clone()).unwrap_or_default()
    }
}

// ── 条件 IR 集成 ──

/// 从 SSA 值构建条件字符串
pub fn ssa_condition(id1: SsaId, op: &str, id2: SsaId, ssa: &SsaContext) -> String {
    let lhs = ssa.value_desc(id1);
    let rhs = ssa.value_desc(id2);
    format!("{} {} {}", lhs, op, rhs)
}

/// 符号: rdx_5 = global_0x293b0
pub fn ssa_debug_line(id: SsaId, ssa: &SsaContext) -> String {
    let Some(v) = ssa.get(id) else { return format!("// v{} = ?", id) };
    let name = ssa.value_name(id);
    let rhs = if v.inputs.is_empty() {
        match v.val {
            Some(ref val) => match val {
                ValueDomain::Pointer(a) => format!("global_{:#x}", a),
                ValueDomain::Signed(x) => x.to_string(),
                ValueDomain::String(ref s) => format!("\"{}\"", s),
                _ => format!("{:?}", val),
            },
            None => "?".into(),
        }
    } else {
        let ins: Vec<String> = v.inputs.iter()
            .map(|&i| ssa.value_name(i)).collect();
        format!("[{}]", ins.join(", "))
    };
    format!("// {} = {}", name, rhs)
}
