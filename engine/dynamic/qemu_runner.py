"""dslsde — QEMU 用户态 GDB 追踪

原理: qemu-x86_64 -g PORT 启动 GDB stub
      GDB 设置断点 → 单步 → 记录 trace

速度: ~1000 指令/秒 (比 qemu-system 快 10x)
"""

import os
import re
import subprocess
import tempfile
import shutil
from typing import List, Optional, Tuple


class QemuRunner:
    def __init__(self, binary_path: str):
        self._binary_path = os.path.abspath(binary_path)
        self._qemu = shutil.which("qemu-x86_64")
        self._gdb = shutil.which("gdb")
        self._available = self._qemu is not None and self._gdb is not None

    @property
    def available(self) -> bool:
        return self._available

    def run(self, func_addr: int, args: List[int] = None,
            timeout: float = 10.0, max_insns: int = 5000,
            argv: List[str] = None) -> List[Tuple[int, int, str, str]]:
        """GDB 单步执行函数并返回 trace

        argv: 传递给被调试程序的命令行参数（用于触发目标函数）
        """
        if not self._available:
            raise RuntimeError("qemu-x86_64 or gdb not found")

        tmpdir = tempfile.mkdtemp()
        trace_file = os.path.join(tmpdir, "trace.txt")
        gdb_script = os.path.join(tmpdir, "gdb_cmd.gdb")

        cmd_args = argv or []

        # GDB 脚本: 在 _start 停下 → 设 RIP 为目标函数 → 单步
        gdb_commands = f"""
set pagination off
set confirm off
set disassembly-flavor intel
file {self._binary_path}
target remote :1234
break *{func_addr:#x}
# 先到 _start
break _start
continue
# 在 _start 处, 直接设 RIP 到目标函数
set $rip = {func_addr:#x}
# 设置栈指针 (用当前 RSP)
set logging file {trace_file}
set logging on
stepi {max_insns}
set logging off
quit
"""
        with open(gdb_script, "w") as f:
            f.write(gdb_commands)

        # 启动 QEMU 用户态（等待 GDB）
        qemu_cmd = [self._qemu, "-g", "1234", self._binary_path] + cmd_args
        qemu_proc = subprocess.Popen(
            qemu_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        try:
            # GDB 连接并执行脚本
            subprocess.run(
                [self._gdb, "-batch", "-x", gdb_script],
                timeout=timeout, capture_output=True,
            )
        except subprocess.TimeoutExpired:
            pass
        finally:
            qemu_proc.terminate()
            try:
                qemu_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                qemu_proc.kill()

        # 解析 trace
        trace = self._parse_trace(trace_file, func_addr)
        return trace

    def _parse_trace(self, path: str, func_addr: int) -> List[Tuple]:
        """解析 GDB stepi 输出"""
        if not os.path.exists(path):
            return []
        with open(path) as f:
            content = f.read()

        result = []
        seen = set()
        for line in content.split("\n"):
            m = re.match(r'^\s*(0x[0-9a-f]+):\s+([0-9a-f ]+)\s+(.+)', line)
            if m:
                addr = int(m.group(1), 16)
                if addr in seen:
                    continue
                seen.add(addr)
                hex_bytes = m.group(2).strip().replace(" ", "")
                op_text = m.group(3).strip()
                size = len(hex_bytes) // 2  # 字节数
                # 提取 mnemonic 和 operands
                parts = op_text.split(None, 1)
                mn = parts[0] if parts else ""
                op = parts[1] if len(parts) > 1 else ""
                result.append((addr, size, mn, op))

        return result
