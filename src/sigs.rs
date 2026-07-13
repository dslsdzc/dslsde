/// dslsde — 函数签名接口
///
/// 运行时填充的签名数据库，数据从 Python 传入。
/// 每签名: 函数名 → (参数名列表, 返回值类型, 是否可变参)

use std::collections::HashMap;

pub struct FuncSig {
    pub args: Vec<String>,
    pub ret: String,
    pub variadic: bool,
}

/// 签名数据库（运行时填充）
pub struct SigDb {
    map: HashMap<String, FuncSig>,
}

impl SigDb {
    pub fn new() -> Self {
        SigDb { map: HashMap::new() }
    }

    /// 从 PyO3 兼容格式填充
    /// (name → (arg_names, ret_type, variadic))
    pub fn load(&mut self, data: HashMap<String, (Vec<String>, String, bool)>) {
        for (name, (args, ret, variadic)) in data {
            self.map.insert(name, FuncSig { args, ret, variadic });
        }
    }

    /// 查找签名
    /// name: 可能是 "malloc@plt" 或 "malloc" 或 "func()"
    pub fn lookup(&self, name: &str) -> Option<&FuncSig> {
        let base = name.split(|c: char| c == '@' || c == '(' || c == '.').next().unwrap_or(name);
        self.map.get(base)
    }
}
