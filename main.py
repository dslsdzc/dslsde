#!/usr/bin/env python3
"""dslsde — 终端逆向分析工具"""

import sys


def main():
    if len(sys.argv) < 2:
        print("用法: python main.py <binary>")
        print("      python main.py serve <binary>   (启动 Web 界面)")
        print("      python main.py dynamic <binary> <addr>  (动态执行)")
        print("      python main.py <binary> --json  (CLI 输出 JSON)")
        sys.exit(1)

    if sys.argv[1] == "serve":
        if len(sys.argv) < 3:
            print("用法: python main.py serve <binary> [-p PORT]")
            sys.exit(1)
        binary = sys.argv[2]
        port, host = 8765, "127.0.0.1"
        args = sys.argv[3:]
        for i, a in enumerate(args):
            if a in ("-p", "--port") and i + 1 < len(args):
                port = int(args[i + 1])
            elif a == "--host" and i + 1 < len(args):
                host = args[i + 1]
        _serve(binary, host, port)
        return

    if sys.argv[1] == "dynamic":
        if len(sys.argv) < 4:
            print("用法: python main.py dynamic <binary> <addr>")
            sys.exit(1)
        binary = sys.argv[2]
        try:
            addr = int(sys.argv[3], 16) if sys.argv[3].startswith("0x") else int(sys.argv[3])
        except ValueError:
            print(f"无效地址: {sys.argv[3]}")
            sys.exit(1)
        _dynamic(binary, addr)
        return

    # 默认：概要模式
    binary = sys.argv[1]
    json_out = "--json" in sys.argv

    from engine.model import Model
    m = Model(binary)
    try:
        m.load()
    except ValueError as e:
        print(f"错误: {e}")
        sys.exit(1)
    m.analyze()

    if json_out:
        _print_json(m)
    else:
        m.summary()


def _dynamic(binary: str, addr: int):
    """动态执行指定地址的函数并输出 C 伪代码"""
    import time

    from engine.model import Model
    t0 = time.time()

    m = Model(binary)
    try:
        m.load()
    except ValueError as e:
        print(f"错误: {e}")
        sys.exit(1)

    m.analyze()

    func = None
    for f in m.functions:
        if f.addr == addr:
            func = f
            break
    if func:
        print(f"函数: {func.name or 'sub_'+f'{addr:x}'}")
    else:
        print(f"地址: {addr:#x}（未识别为函数入口，仍尝试执行）")

    t1 = time.time()
    code = m.run_function(addr)
    t2 = time.time()

    print(f"分析: {(t1 - t0) * 1000:.0f}ms")
    print(f"动态: {(t2 - t1) * 1000:.0f}ms")
    print(f"总计: {(t2 - t0) * 1000:.0f}ms")
    print()
    print(code)


def _serve(binary: str, host: str, port: int):
    from engine.model import Model
    print(f"加载: {binary} ...")
    m = Model(binary)
    try:
        m.load()
    except ValueError as e:
        print(f"错误: {e}")
        sys.exit(1)
    m.analyze()
    print(f"分析完成: {len(m.functions)} 函数")

    import engine.server_state as state
    state.model = m

    import uvicorn
    print(f"启动 Web 界面: http://{host}:{port}")
    print("按 Ctrl+C 停止")
    uvicorn.run("server:app", host=host, port=port, log_level="info", reload=False)


def _print_json(m):
    import json
    b = m.binary
    data = {
        "binary": {"path": b.path, "format": b.fmt, "arch": b.arch, "bits": b.bits, "entry": b.entry},
        "segments": [{"addr": s.addr, "size": s.size, "name": s.name, "flags": s.flags} for s in b.segments],
        "functions": [{"addr": f.addr, "name": f.name or f"sub_{f.addr:x}", "size": f.size, "type": f.typ} for f in m.functions],
        "summary": {"functions": len(m.functions), "named": sum(1 for f in m.functions if f.typ == "named")},
    }
    json.dump(data, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
