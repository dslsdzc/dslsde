# dslsde — 反编译简称

终端逆向分析工具。Web UI 兼容 lynx / 老旧浏览器，核心是二进制建模引擎。

## 技术栈

| 层 | 技术 | 原因 |
|---|---|---|
| 后端框架 | `FastAPI` + `uvicorn` | Python 最顺手的 Web，天然 async |
| 模板 | `Jinja2`（FastAPI 内置） | 渲染 lynx 兼容的 HTML |
| 二进制加载 | `lief` | ELF/PE/Mach-O 解析最强 |
| 反汇编 | `capstone` | 30+ 架构，成熟稳定 |
| 反编译 | Ghidra sleigh (独立抽取) | p-code 转 C |
| 数据库 | `sqlite` | 零依赖，增量持久化 |
| TUI (未来) | `prompt_toolkit` | 只当输入增强，不搞窗口框架 |
| HTML 样式 | 纯 `<pre>` + `<table>` + `<form>` | lynx / w3m 原生支持，CSS 可选 |

## 架构

```
dslsde/
├── main.py             # 入口
├── server.py           # FastAPI + uvicorn，Web 模式
├── engine/             # 分析引擎（后端核心）
│   ├── model.py        # 核心建模：加载 → 分析 → 数据库编排
│   ├── loader.py       # lief → ELF/PE/Mach-O 加载
│   ├── disasm.py       # capstone → 反汇编
│   ├── sleigh/         # Ghidra sleigh 反编译器独立层
│   ├── analyzer.py     # 函数识别、xref 构建、类型传播
│   ├── database.py     # sqlite 持久化（类 IDB 增量存储）
│   └── types.py        # 类型系统基础
├── templates/          # lynx 兼容 HTML
│   ├── layout.html     # 基础布局
│   ├── index.html      # 二进制概要
│   ├── disasm.html     # 反汇编视图
│   ├── xref.html       # 交叉引用
│   ├── hex.html        # 十六进制
│   └── search.html     # 搜索
└── requirements.txt
```

## 设计原则

- **分析引擎是核心，Web 只是外壳** — 引擎可脱离 Web 独立用
- **HTML 不需要现代浏览器** — `<pre>` + `<table>` + `<form>` 足以
- **lynx / w3m / links 可读** — 终端里也能操作
- **数据库增量保存** — 分析过的结果不丢，支持 reopen
- **模块可替换** — capstone 可换 zydis，lief 可换 pylnk

## 后端接口

```
GET  /                  二进制概要信息
GET  /disasm?addr=     反汇编地址段
GET  /disasm?name=     按函数名反汇编
GET  /xref?addr=       交叉引用到此地址
GET  /xref?from=       从此地址出去的引用
GET  /hex?addr=&len=   十六进制视图
GET  /funcs            函数列表
GET  /strings          字符串列表
GET  /search?q=        搜索指令/数据
POST /rename           重命名符号
POST /comment          添加/编辑注释
POST /settype          设定数据类型
```

## 启动

```bash
pip install -r requirements.txt
python main.py serve <binary>     # Web 模式 → http://localhost:8765
python main.py <binary>            # CLI 模式 → 打印概要
```

## 启动参数（草案）

```
python main.py serve <binary> -p 8765 --host 0.0.0.0
python main.py serve <binary> --lynx   # 针对 lynx 优化输出
python main.py <binary> --json         # CLI 输出 JSON
```
