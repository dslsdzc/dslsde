"""Ghidra GDT → JSON 签名导出

纯 Python 解析 Java 序列化格式，零依赖。
"""

import struct
import sys
import json
import io
import zipfile
from typing import Any, Dict, List

MAGIC = b'\xac\xed\x00\x05'

# TC opcodes
TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_CLASS = 0x76
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78
TC_BLOCKDATALONG = 0x7a
TC_EXCEPTION = 0x7b
TC_LONGSTRING = 0x7c

class JOSReader:
    """Java ObjectOutputStream 格式读取器"""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        # handle table: handle 0 = null
        self.handles: List[Any] = [None]
        # class desc cache: handle → {name, fields, supers}
        self.class_descs: Dict[int, dict] = {}
        # next handle to assign
        self._next_handle = 1

        if data[:2] == b'\xac\xed':
            self.pos = 4  # skip magic + version

    def read(self, n):
        r = self.data[self.pos:self.pos+n]
        self.pos += n
        return r

    def rb(self): return self.read(1)[0]
    def r2(self): return struct.unpack('>H', self.read(2))[0]
    def r4(self): return struct.unpack('>I', self.read(4))[0]
    def r8(self): return struct.unpack('>Q', self.read(8))[0]

    def utf(self):
        return self.read(self.r2()).decode('utf-8', errors='replace')

    def alloc_handle(self, obj):
        h = self._next_handle
        self._next_handle += 1
        while h >= len(self.handles):
            self.handles.append(None)
        self.handles[h] = obj
        return h

    def read_any(self):
        """读取任意值，返回 Python 对象"""
        t = self.rb()
        return self._read_val(t)

    def _read_val(self, t):
        if t == TC_NULL: return None
        if t == TC_REFERENCE:
            return self.handles[self.r4()]
        if t == TC_STRING:
            h = self.r4()
            s = self.utf()
            self.handles[h] = s
            return s
        if t == TC_LONGSTRING:
            h = self.r4()
            length = self.r8()
            s = self.read(length).decode('utf-8', errors='replace')
            self.handles[h] = s
            return s
        if t == TC_OBJECT:
            return self._read_object()
        if t == TC_ARRAY:
            return self._read_array()
        if t == TC_CLASS:
            return self._read_class_desc()
        if t == TC_BLOCKDATA:
            n = self.rb()
            self.pos += n
            return None
        if t == TC_BLOCKDATALONG:
            n = self.r4()
            self.pos += n
            return None
        if t in (TC_ENDBLOCKDATA, TC_EXCEPTION):
            return None
        raise ValueError(f"Unknown TC 0x{t:02x} at pos {self.pos-1}")

    def _read_class_desc(self):
        """读取类描述符。返回类名字符串"""
        t = self.rb()
        if t == TC_NULL: return None
        if t == TC_REFERENCE:
            h = self.r4()
            return self.class_descs.get(h, {}).get('name', '?')

        assert t == TC_CLASSDESC, f"Expected TC_CLASSDESC, got 0x{t:02x}"
        name = self.utf()
        self.r8()  # UID
        self.rb()  # flags
        nf = self.r2()
        fields = []
        for _ in range(nf):
            tc = chr(self.rb())
            fname = self.utf()
            if tc in ('L', '['):
                self._read_class_desc()
            fields.append(fname)

        # skip annotation
        while self.data[self.pos] != TC_ENDBLOCKDATA:
            an = self.rb()
            if an in (TC_BLOCKDATA, TC_BLOCKDATALONG):
                sz = self.rb() if an == TC_BLOCKDATA else self.r4()
                self.pos += sz
            elif an == TC_STRING:
                self.r4(); self.utf()
            elif an == TC_LONGSTRING:
                self.r4(); length = self.r8(); self.pos += length
            elif an == TC_NULL:
                pass
            else:
                break
        self.rb()  # TC_ENDBLOCKDATA

        super_name = self._read_class_desc()

        # 存起来
        cd = {'name': name, 'fields': fields, 'super': super_name}
        h = self.alloc_handle(cd)
        self.class_descs[h] = cd
        return name

    def _read_object(self):
        """读取对象实例，返回 dict[str, Any]"""
        # 类描述 + handle
        cls_name = self._read_class_desc()
        obj_handle = self.r4()

        # 构建对象
        obj = {'__class__': cls_name} if cls_name else {}

        # 找到类描述符
        cd = None
        for c in self.class_descs.values():
            if c['name'] == cls_name:
                cd = c
                break

        # 读取字段值（先父类后子类）
        if cd:
            chain = [cd]
            while cd and cd.get('super'):
                for c in self.class_descs.values():
                    if c['name'] == cd['super']:
                        cd = c; chain.insert(0, cd); break
                else:
                    break
            for c in chain:
                self._read_fields(c, obj)

        self.handles[obj_handle] = obj
        return obj

    def _read_fields(self, cd, obj):
        """按类描述读取字段值"""
        for fname in cd.get('fields', []):
            if self.data[self.pos] in (TC_NULL, TC_REFERENCE, TC_OBJECT, TC_STRING,
                                        TC_ARRAY, TC_LONGSTRING, TC_CLASS,
                                        TC_BLOCKDATA, TC_BLOCKDATALONG):
                obj[fname] = self.read_any()
            else:
                # primitive
                obj[fname] = self._read_prim()

    def _read_prim(self):
        t = self.data[self.pos]
        # peek next byte for type guessing
        # we need to know the type... but without class desc field types
        # we guess from the next byte patterns
        b = self.data[self.pos]
        if b == 0x00: # might be short 0
            self.pos += 2; return 0
        elif b == 0x7f:
            self.pos += 2; return 127
        elif 0x01 <= b <= 0x7e:
            self.pos += 4; return b
        # int
        self.pos += 4; return self.r4()

    def _read_array(self):
        """读取数组"""
        cls_name = self._read_class_desc()
        h = self.r4()
        size = self.r4()
        # element type
        et = chr(self.rb())
        arr = []
        for _ in range(size):
            if et in ('I',): arr.append(self.r4())
            elif et in ('J',): arr.append(self.r8())
            elif et in ('B',): arr.append(self.rb())
            elif et in ('C',): arr.append(self.r2())
            elif et in ('S',): arr.append(self.r2())
            elif et in ('F',): arr.append(0)  # skip float
            elif et in ('D',): arr.append(0)  # skip double
            elif et in ('Z',): arr.append(self.rb() != 0)
            elif et in ('L',): arr.append(self.read_any())
            elif et in ('[',): arr.append(self._read_array())
            else: arr.append(self.read_any())
        self.handles[h] = arr
        return arr


def open_gdt(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    if data[:2] == b'PK':
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                if name.endswith('.gdt') or name == 'FOLDER_ITEM':
                    return z.read(name)
    return data


def extract_sigs(data: bytes) -> dict:
    reader = JOSReader(data)
    # GDT 文件可能以 BLOCKDATA 开头，跳过所有非根对象
    root = None
    for _ in range(100):
        val = reader.read_any()
        if val is None:
            # 跳过 BLOCKDATA 后重试
            continue
        if isinstance(val, dict) and '__class__' in val:
            root = val
            break
    if root is None:
        return {"_error": "could not find root object"}
    return _find_funcs(root)


def _find_funcs(obj, depth=0) -> dict:
    if depth > 8: return {}
    result = {}

    if isinstance(obj, dict):
        cls = obj.get('__class__', '')
        if 'FunctionDefinition' in cls:
            name = obj.get('name', '')
            if name and not name.startswith('_'):
                ret = _get_type(obj.get('returnType'))
                args_obj = obj.get('arguments')
                param_names = []
                if isinstance(args_obj, dict):
                    # 找出所有参数
                    for k, v in args_obj.items():
                        if isinstance(v, dict) and 'name' in v:
                            pn = v['name']
                            if pn and not pn.startswith('_'):
                                param_names.append(pn)
                    # limit to first 6
                    param_names = param_names[:6]
                result[name] = (param_names, ret, False)
            return result

        for v in obj.values():
            r = _find_funcs(v, depth+1)
            result.update(r)
            if len(result) > 300:
                return result

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            r = _find_funcs(item, depth+1)
            result.update(r)

    return result


def _get_type(t) -> str:
    if isinstance(t, dict):
        n = t.get('name', '')
        if n: return n
        cls = t.get('__class__', '')
        if 'Pointer' in cls:
            inner = _get_type(t.get('dataType', {}))
            return f"{inner}*" if inner else "void*"
    return 'int'


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else \
        '/home/DslsDZC/ghidra/Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt'
    data = open_gdt(path)
    sigs = extract_sigs(data)
    print(f"// Found {len(sigs)} signatures", file=sys.stderr)
    print(json.dumps(sigs, indent=2))
