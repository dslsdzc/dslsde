# dslsde — 终端逆向分析工具

**Dynamic Static Low-level Software Decompilation Engine**

dslsde 是一个终端逆向分析工具，核心是二进制建模引擎 + 动态执行追踪。  
Web UI 兼容 lynx / 老旧浏览器，TUI 模式使用 prompt_toolkit。

## 架构

```
Binary
  │
  ├── LIEF (ELF/PE/Mach-O 加载)
  ├── Capstone (反汇编)
  ├── Unicorn (动态执行追踪)
  │
  └── dslsde_core (Rust 引擎)
        ├── CFG 构建 + 支配树
        ├── SSA + GVN + phi
        ├── 5 遍收敛推理引擎
        ├── 控制流结构化
        ├── 类型推断系统
        ├── 跨函数类型传播
        └── C 伪代码输出
```

## 技术栈

| 层 | 技术 |
|---|---|
| 后端框架 | FastAPI + uvicorn |
| 模板 | Jinja2 |
| 二进制加载 | lief |
| 反汇编 | capstone |
| 动态执行 | Unicorn Engine |
| 加速引擎 | Rust (PyO3/maturin) |
| 数据库 | sqlite |

## 引用论文

dslsde 的设计和实现参考了以下学术工作：

### SSA 构建

- **Cytron et al. 1991** — *Efficiently Computing Static Single Assignment Form and the Control Dependence Graph*  
  ACM TOPLAS. 支配边界 phi 放置算法，Ghidra 的 SSA 构建基础。  
  [DOI: 10.1145/115372.115320](https://doi.org/10.1145/115372.115320)

- **Braun et al. 2013** — *Simple and Efficient Construction of Static Single Assignment Form*  
  CC 2013. 反向搜索 reaching definitions，按需插 phi。Cranelift 使用此算法。  
  [DOI: 10.1007/978-3-642-37051-9_6](https://doi.org/10.1007/978-3-642-37051-9_6)

- **Lemerre 2023** — *SSA Translation Is an Abstract Interpretation*  
  POPL 2023 (Distinguished Paper). GVN 作为 SSA 的前提，循环项图表达值。Codex 静态分析器基础。  
  [DOI: 10.1145/3571258](https://doi.org/10.1145/3571258)

### 反编译

- **Van Emmerik 2007** — *Static Single Assignment for Decompilation*  
  PhD Thesis, University of Queensland. Boomerang 反编译器中的 SSA 应用：表达式传播、类型分析、间接跳转恢复。  
  [UQ eSpace](https://espace.library.uq.edu.au/view/UQ:158682)

- **Yakdan et al. 2013** — *REcompile: A Decompilation Framework for Static Analysis of Binaries*  
  IEEE MALWARE 2013. SSA 作为 IR 的反编译框架，数据流 + 类型 + 控制流联合分析。

### 类型推断

- **Lee et al. 2011** — *TIE: Principled Reverse Engineering of Types in Binary Programs*  
  IEEE S&P 2011. 从二进制代码中重建类型的约束求解方法。  
  [DOI: 10.1109/SP.2011.21](https://doi.org/10.1109/SP.2011.21)

- **TRex 2024** — *Type Reconstruction from Binary Code*  
  CMU PhD Thesis. 结构类型 + SSA 约束传播，超越 Ghidra 15.81%。  
  [CMU-CS-24-127](https://www.csd.cmu.edu/sites/default/files/phd-thesis/CMU-CS-24-127.pdf)

- **BinSub 2024** — *The Simple Essence of Polymorphic Type Inference for Machine Code*  
  Trail of Bits / ar5iv. 代数子类型 + 多态类型推断。  
  [arXiv:2409.01841](https://arxiv.org/abs/2409.01841)

### 类型学习

- **DIRTY 2022** — *Augmenting Decompiler Output with Learned Variable Names and Types*  
  USENIX Security 2022. 基于神经网络的变量名和类型恢复。  
  [arXiv:2108.06363](https://arxiv.org/abs/2108.06363)

### 栈安全

- **StackGuard+ 2024** — *Binary Patching for Stack Canary Hardening*  
  Electronics Letters (IET). 二进制级栈金丝雀增强。  
  [DOI: 10.1049/ell2.13310](https://doi.org/10.1049/ell2.13310)

### 控制流

- **Johnson et al. 1994** — *The Program Structure Tree: Computing Control Regions in Linear Time*  
  PLDI 1994. 结构化控制流重建的基础算法。

- **Basque et al. 2024** — *Ahoy SAILR! There is No Need to DREAM of C: A Compiler-Aware Structuring Algorithm for Binary Decompilation*  
  USENIX Security 2024. 编译器感知的结构化算法，识别编译器优化模式并反向还原。  
  [USENIX](https://www.usenix.org/conference/usenixsecurity24/presentation/basque)

## 启动

```bash
pip install -r requirements.txt
python main.py serve <binary>     # Web 模式 → http://localhost:8765
python main.py <binary>            # CLI 模式 → 打印概要
```

## 项目结构

```
dslsde/
├── main.py              # 入口
├── engine/              # Python 分析引擎
│   ├── model.py         # 核心编排器
│   ├── loader.py        # LIEF 加载器
│   ├── dynamic/         # Unicorn 动态执行
│   ├── sigs.py          # 函数签名数据库
│   └── gdt_dump.py      # Ghidra GDT 导出器
├── src/                 # Rust 核心 (PyO3)
│   ├── cfg.rs           # CFG + 支配树 + 自然循环
│   ├── ssa.rs           # SSA + GVN + phi + 多 trace 合并
│   ├── infer.rs         # 推理引擎入口 + passes
│   ├── state.rs         # 状态构建
│   ├── emit.rs          # 输出渲染 + 条件 IR
│   ├── typeprop.rs      # SSA 驱动类型传播 (TRex)
│   ├── typeflow.rs      # 跨函数类型推断
│   ├── sigs.rs          # SigDb 接口
│   ├── dce.rs           # 死变量消除
│   ├── switch.rs        # 跳转表恢复
│   ├── array.rs         # 数组下标检测
│   ├── structr.rs       # 结构体字段推断
│   ├── ir.rs            # 类型 + 辅助函数
│   ├── types.rs         # VarType
│   └── ...              # flow/trace/insn/cgen
├── templates/           # lynx 兼容 HTML
└── requirements.txt
```

## 许可证

GNU General Public License v3.0
