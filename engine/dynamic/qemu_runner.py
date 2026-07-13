"""dslsde — QEMU 动态执行后端（可选）

处理 Unicorn 不支持的内核地址空间（0xffffffff80000000+）。
需要用户安装 qemu-system-x86_64。

使用:
  runner = QemuRunner(binary)
  trace = runner.run(func_addr, timeout=5.0)
"""

import os
import subprocess
import tempfile
import re
import shutil
from typing import List, Optional, Tuple


class QemuRunner:
    """QEMU 系统模式执行器——跟踪内核函数执行路径"""

    def __init__(self, binary_path: str):
        self._binary_path = binary_path
        self._qemu = shutil.which("qemu-system-x86_64")
        self._available = self._qemu is not None

    @property
    def available(self) -> bool:
        return self._available

    def run(self, func_addr: int, args: List[int] = None,
            timeout: float = 5.0) -> List[Tuple[int, int]]:
        """在 QEMU 中跟踪函数执行"""
        if not self._available:
            raise RuntimeError("qemu-system-x86_64 未安装")

        # 创建 GDB 脚本来设置断点并开始执行
        with tempfile.TemporaryDirectory() as tmpdir:
            script = self._create_gdb_script(func_addr, timeout, tmpdir)
            cmd = [
                self._qemu, "-kernel", self._binary_path,
                "-s", "-S",  # 等待 GDB 连接
                "-nographic", "-serial", "none",
                "-append", "console=ttyS0 quiet",
                "-no-reboot",
            ]
            # 启动 QEMU（后台）
            qemu_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            try:
                # GDB 连接并获取 trace
                gdb_out = subprocess.check_output(
                    ["gdb", "-batch", "-x", script],
                    timeout=timeout + 10,
                    stderr=subprocess.STDOUT,
                )
                return self._parse_gdb_trace(gdb_out.decode())
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                return []
            finally:
                qemu_proc.terminate()
                try:
                    qemu_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    qemu_proc.kill()

    def _create_gdb_script(self, func_addr: int, timeout: float,
                           tmpdir: str) -> str:
        """生成 GDB 脚本来跟踪执行"""
        script_path = os.path.join(tmpdir, "gdb_script.gdb")
        trace_file = os.path.join(tmpdir, "trace.txt")
        with open(script_path, "w") as f:
            f.write(f"""
target remote :1234
file {self._binary_path}
set pagination off
# 设置断点在函数入口
break *{func_addr:#x}
continue
# 记录执行到返回的所有指令
set logging file {trace_file}
set logging on
stepi 200000
set logging off
quit
""")
        return script_path

    def _parse_gdb_trace(self, output: str) -> List[Tuple[int, int]]:
        """解析 GDB 日志提取指令地址"""
        trace = []
        for line in output.splitlines():
            m = re.match(r'^\s*(0x[0-9a-f]+):\s+', line)
            if m:
                addr = int(m.group(1), 16)
                trace.append((addr, 0))
        return trace
