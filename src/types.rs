/// dslsde — 完整类型系统
///
/// 从 VarType 枚举升级为组合类型:
///   Int/UInt/Ptr/Array/Struct/Func → 嵌套组合
///
/// 集成:
///   typeprop.rs — SSA 值 → Type
///   emit.rs     — Type → C 类型字符串
///   structr.rs  — 结构体字段类型

use std::fmt;

/// 类型
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    Int(u32),          // 有符号整数 (8/16/32/64)
    UInt(u32),         // 无符号 (8/16/32/64)
    Float(u32),        // 浮点 (32/64)
    Ptr(Box<Type>),    // T* (void* = Ptr(Void))
    Void,
    Bool,
    Array(Box<Type>, usize),       // T[N]
    Struct(String, Vec<TypeField>), // struct { fields }
    Func(Vec<Type>, Box<Type>),    // fn(args) → ret
    Named(String),                 // typedef/未知名
}

/// 结构体字段
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TypeField {
    pub name: String,
    pub typ: Type,
    pub offset: i64,
    pub size: u32,
}

impl Type {
    /// C 类型字符串
    pub fn to_c(&self) -> String {
        match self {
            Type::Int(8) => "int8_t".into(),
            Type::Int(16) => "int16_t".into(),
            Type::Int(32) | Type::Int(0) => "int".into(),
            Type::Int(64) => "long".into(),
            Type::Int(n) => format!("int{}_t", n),
            Type::UInt(8) => "uint8_t".into(),
            Type::UInt(16) => "uint16_t".into(),
            Type::UInt(32) | Type::UInt(0) => "unsigned".into(),
            Type::UInt(64) => "unsigned long".into(),
            Type::UInt(n) => format!("uint{}_t", n),
            Type::Float(32) => "float".into(),
            Type::Float(64) => "double".into(),
            Type::Float(n) => format!("float{}_t", n),
            Type::Void => "void".into(),
            Type::Bool => "bool".into(),
            Type::Ptr(inner) => {
                if matches!(inner.as_ref(), Type::Void) {
                    "void*".into()
                } else if matches!(inner.as_ref(), Type::UInt(8)) {
                    "char*".into()
                } else {
                    format!("{}*", inner.to_c())
                }
            }
            Type::Array(inner, size) => {
                format!("{}[{}]", inner.to_c(), size)
            }
            Type::Struct(name, _) => format!("struct {}", name),
            Type::Func(args, ret) => {
                let a: Vec<String> = args.iter().map(|t| t.to_c()).collect();
                format!("{}(*)({})", ret.to_c(), a.join(", "))
            }
            Type::Named(n) => n.clone(),
        }
    }

    /// 大小 (字节)
    pub fn size(&self) -> u32 {
        match self {
            Type::Int(n) | Type::UInt(n) => {
                let bits = if *n == 0 { 32 } else { *n };
                bits / 8
            }
            Type::Float(n) => *n / 8,
            Type::Void => 0,
            Type::Bool => 1,
            Type::Ptr(_) | Type::Func(_, _) | Type::Named(_) => 8,
            Type::Array(inner, n) => inner.size() * *n as u32,
            Type::Struct(_, fields) => {
                fields.last().map(|f| f.offset as u32 + f.size).unwrap_or(8)
            }
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_c())
    }
}

// ── 辅助构造函数 ──

pub fn ptr(inner: Type) -> Type { Type::Ptr(Box::new(inner)) }
pub fn array(inner: Type, n: usize) -> Type { Type::Array(Box::new(inner), n) }
pub fn func(args: Vec<Type>, ret: Type) -> Type { Type::Func(args, Box::new(ret)) }
pub fn _struct(name: &str, fields: Vec<TypeField>) -> Type {
    Type::Struct(name.to_string(), fields)
}
pub fn i(n: u32) -> Type { Type::Int(n) }
pub fn u(n: u32) -> Type { Type::UInt(n) }

// ── 保持向后兼容 ──

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VarType { Int, UInt, Ptr, CharPtr, Bool, Unknown }

impl Default for VarType { fn default() -> Self { VarType::Unknown } }

/// VarType → Type 转换
pub fn from_var(vt: &VarType) -> Type {
    match vt {
        VarType::Int => Type::Int(32),
        VarType::UInt => Type::UInt(32),
        VarType::Ptr => Type::Ptr(Box::new(Type::Void)),
        VarType::CharPtr => Type::Ptr(Box::new(Type::UInt(8))),
        VarType::Bool => Type::Bool,
        VarType::Unknown => Type::Int(32),
    }
}

/// Type → C 字符串 (兼容旧接口)
pub fn type_str(t: &Type) -> String {
    t.to_c()
}

/// 旧版类型推断 (向后兼容)
pub fn infer_var_type(info: &str) -> Option<VarType> {
    let s = info.trim();
    if matches!(s, "rdi"|"rsi"|"rdx"|"rcx"|"r8"|"r9") { return Some(VarType::Int); }
    if s.contains('*') || s.contains("imul") { return Some(VarType::Int); }
    if s.contains("lea") || s.contains("[rip") { return Some(VarType::Ptr); }
    if s.contains("strings") || s.contains("puts") || s.contains("printf") || s.contains("str") {
        return Some(VarType::CharPtr);
    }
    None
}
