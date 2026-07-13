"""dslsde — SQLite 持久化层

分析结果增量保存，支持重新打开时直接加载已有数据。
类似 IDA 的 .idb / .i64 机制。
"""

from __future__ import annotations
import sqlite3
import ctypes
from typing import List, Optional, Any

# 地址转换：SQLite INTEGER 是 signed 64-bit
# 内核地址 (0xffffffff80000000+) 需转 signed 存储
def _s64(addr: int) -> int:
    """int → SQLite-safe signed 64-bit"""
    return ctypes.c_int64(addr).value

def _u64(addr: int) -> int:
    """SQLite 读出值 → unsigned 64-bit"""
    return ctypes.c_uint64(addr).value

from engine.loader import Segment, Symbol
from engine.function import Function


class Database:
    """分析结果持久化"""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS segments (
        addr  INTEGER PRIMARY KEY,
        name  TEXT,
        size  INTEGER,
        flags TEXT
    );

    CREATE TABLE IF NOT EXISTS symbols (
        addr  INTEGER PRIMARY KEY,
        name  TEXT,
        size  INTEGER,
        type  TEXT
    );

    CREATE TABLE IF NOT EXISTS instructions (
        addr      INTEGER PRIMARY KEY,
        size      INTEGER,
        mnemonic  TEXT,
        operands  TEXT,
        bytes     BLOB,
        type      TEXT
    );

    CREATE TABLE IF NOT EXISTS functions (
        addr       INTEGER PRIMARY KEY,
        name       TEXT,
        size       INTEGER,
        type       TEXT,
        insn_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS xrefs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        from_addr INTEGER,
        to_addr   INTEGER,
        type      TEXT,
        UNIQUE(from_addr, to_addr, type)
    );

    CREATE INDEX IF NOT EXISTS idx_xrefs_to   ON xrefs(to_addr);
    CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_addr);
    CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
    """

    def __init__(self, path: str):
        self._path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(self.SCHEMA_SQL)
        self.conn.commit()

    # ── 元信息 ──

    def set_meta(self, key: str, value: str):
        self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
        self.conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    # ── segments ──

    def save_segments(self, segments: List[Segment]):
        self.conn.executemany(
            "INSERT OR REPLACE INTO segments (addr, name, size, flags) VALUES (?, ?, ?, ?)",
            [(_s64(s.addr), s.name, s.size, s.flags) for s in segments],
        )
        self.conn.commit()

    def load_segments(self) -> List[Segment]:
        rows = self.conn.execute("SELECT * FROM segments ORDER BY addr").fetchall()
        return [Segment(_u64(r["addr"]), r["name"], r["size"], b"", r["flags"]) for r in rows]

    # ── symbols ──

    def save_symbols(self, symbols: List[Symbol]):
        self.conn.executemany(
            "INSERT OR REPLACE INTO symbols (addr, name, size, type) VALUES (?, ?, ?, ?)",
            [(_s64(s.addr), s.name, s.size, s.typ) for s in symbols],
        )
        self.conn.commit()

    def load_symbols(self) -> List[Symbol]:
        rows = self.conn.execute("SELECT * FROM symbols ORDER BY addr").fetchall()
        return [Symbol(r["name"], _u64(r["addr"]), r["size"], r["type"]) for r in rows]

    # ── instructions ──

    def save_rust_instructions(self, insns):
        """保存 Rust capstone 反汇编结果"""
        rows = []
        for i in insns:
            typ = _classify_mnemonic(i.mnemonic)
            rows.append((_s64(i.addr), i.size, i.mnemonic, i.operands,
                         bytes(i.bytes), typ))
        self.conn.executemany(
            "INSERT OR REPLACE INTO instructions (addr, size, mnemonic, operands, bytes, type) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def save_instructions(self, insns: List[Insn]):
        rows = [
            (_s64(i.addr), i.size, i.mnemonic, i.operands, i.bytes, _classify_insn(i.mnemonic))
            for i in insns
        ]
        self.conn.executemany(
            "INSERT OR REPLACE INTO instructions (addr, size, mnemonic, operands, bytes, type) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def load_instructions(self, start: int, end: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM instructions WHERE addr >= ? AND addr < ? ORDER BY addr",
            (_s64(start), _s64(end)),
        ).fetchall()
        result = [dict(r) for r in rows]
        for row in result:
            row["addr"] = _u64(row["addr"])
        return result

    def get_instruction(self, addr: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM instructions WHERE addr = ?", (_s64(addr),)
        ).fetchone()
        if row:
            d = dict(row)
            d["addr"] = _u64(d["addr"])
            return d
        return None

    # ── functions ──

    def save_functions(self, funcs: List[Function]):
        self.conn.executemany(
            "INSERT OR REPLACE INTO functions (addr, name, size, type, insn_count) VALUES (?, ?, ?, ?, ?)",
            [(_s64(f.addr), f.name, f.size, f.typ, f.insn_count) for f in funcs],
        )
        self.conn.commit()

    def load_functions(self) -> List[Function]:
        rows = self.conn.execute("SELECT * FROM functions ORDER BY addr").fetchall()
        return [
            Function(_u64(r["addr"]), r["size"], r["name"], r["type"], r["insn_count"] or 0)
            for r in rows
        ]

    def function_exists(self, addr: int) -> bool:
        row = self.conn.execute("SELECT 1 FROM functions WHERE addr = ?", (_s64(addr),)).fetchone()
        return row is not None

    # ── xrefs ──

    def save_xrefs(self, xrefs: dict):
        rows = []
        for to_addr, xlist in xrefs.items():
            for x in xlist:
                rows.append((x.frm, x.to, x.typ))
        self.conn.executemany(
            "INSERT OR IGNORE INTO xrefs (from_addr, to_addr, type) VALUES (?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def load_xrefs_to(self, addr: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM xrefs WHERE to_addr = ? ORDER BY from_addr", (addr,)
        ).fetchall()
        return [dict(r) for r in rows]

    def load_xrefs_from(self, addr: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM xrefs WHERE from_addr = ? ORDER BY to_addr", (addr,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── 关闭 ──

    def close(self):
        self.conn.close()

    def has_data(self) -> bool:
        row = self.conn.execute("SELECT COUNT(*) as c FROM instructions").fetchone()
        return row["c"] > 0


def _classify_mnemonic(mn: str) -> str:
    if mn.startswith("call") or mn in ("bl", "blx"):
        return "call"
    if mn.startswith("j"):
        return "jump" if mn in ("jmp", "j") else "cond_jump"
    if mn in ("ret", "bx lr", "blr"):
        return "ret"
    if mn.startswith("mov") or mn.startswith("ldr"):
        return "data"
    return "code"

def _classify_insn(mnemonic: str) -> str:
    if mnemonic.startswith("call") or mnemonic in ("bl", "blx"):
        return "call"
    if mnemonic.startswith("j"):
        return "jump" if mnemonic in ("jmp", "j") else "cond_jump"
    if mnemonic in ("ret", "bx lr", "blr"):
        return "ret"
    if mnemonic.startswith("mov") or mnemonic.startswith("ldr"):
        return "data"
    return "code"
