"""Quarkslab 混淆数据集完整测试"""

import sys, os, json, zipfile, time, subprocess, tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.model import Model

DATASET_DIR = "/tmp/diffing_obfuscation_dataset"
CACHE_DIR = "/tmp/dslsde_dataset_cache"

def download_binary(url: str, name: str) -> str:
    """下载二进制文件到缓存"""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, name)
    if os.path.exists(cache_path):
        return cache_path
    subprocess.run(["curl", "-sL", url, "-o", cache_path], timeout=300)
    return cache_path if os.path.exists(cache_path) else ""

def test_project(project: str, obfuscator: str, obf_pass: str, level: str, seed: str = ""):
    """测试单个混淆二进制"""
    with open(f"{DATASET_DIR}/src/obfu_dataset/precompiled/links.json") as f:
        links = json.load(f)

    name = f"{project}_{obfuscator}_{obf_pass}_{level}"
    plain_url = links[project]["sources"]["link"]
    obfu_info = links[project]["obfuscated"][obfuscator][obf_pass][level]

    print(f"\n{'='*60}")
    print(f"Project: {project}")
    print(f"Obfuscator: {obfuscator}, Pass: {obf_pass}, Level: {level}%")
    print(f"{'='*60}")

    # 下载混淆二进制
    zip_path = download_binary(obfu_info["link"], f"{name}.zip")
    if not zip_path:
        print("  [SKIP] Download failed")
        return

    # 解压找 .exe
    with zipfile.ZipFile(zip_path) as z:
        exes = [n for n in z.namelist() if n.endswith(".exe")]
        if not exes:
            print("  [SKIP] No exe found in zip")
            return

        # 找 O0 版本
        target = [e for e in exes if "O0" in e]
        if not target:
            target = exes[:1]
        exe_path = os.path.join(CACHE_DIR, os.path.basename(target[0]))
        if not os.path.exists(exe_path):
            with z.open(target[0]) as zf:
                with open(exe_path, "wb") as f:
                    f.write(zf.read())

        # 找 ground truth
        json_files = [n for n in z.namelist() if n.endswith(".json")]
        gt = {}
        if json_files:
            with z.open(json_files[0]) as zf:
                gt_list = json.load(zf)
                for func in gt_list:
                    addr = int(func["address"], 16)
                    gt[addr] = func

    # 分析 + 反编译
    try:
        model = Model(exe_path)
        model.load()
        t_start = time.time()
        model.analyze()
        t_analysis = time.time() - t_start
        print(f"  Analysis: {len(model.functions)} functions, {t_analysis:.1f}s")
    except Exception as e:
        print(f"  [FAIL] Analysis: {e}")
        return

    # 对 ground truth 中的函数做反编译测试
    plain_ok = 0
    obfu_ok = 0
    plain_total = 0
    obfu_total = 0

    for addr, func_info in list(gt.items())[:20]:
        if addr < 0x402000:  # 跳过 init
            continue
        is_obfu = bool(func_info.get("obfu"))
        if is_obfu:
            obfu_total += 1
        else:
            plain_total += 1

        try:
            result = model.run_function(addr, timeout=2.0)
            if result and len(result) > 10:
                if is_obfu:
                    obfu_ok += 1
                else:
                    plain_ok += 1
            elif not result or len(result) < 5:
                pass
        except Exception:
            pass

    if plain_total:
        print(f"  Plain: {plain_ok}/{plain_total} functions decompiled")
    if obfu_total:
        print(f"  Obfuscated: {obfu_ok}/{obfu_total} functions decompiled")

    # 输出一个样本
    if plain_ok > 0:
        for addr, func_info in list(gt.items())[:5]:
            if not func_info.get("obfu"):
                result = model.run_function(int(func_info["address"], 16), timeout=2.0)
                if result:
                    print(f"\n  Sample ({func_info['name']}):")
                    print(f"  {result[:300]}")
                break


if __name__ == "__main__":
    # 测试一个子集: minilua, OLLVM, CFF and opaque
    test_project("minilua", "ollvm", "CFF", "50")
    test_project("minilua", "ollvm", "opaque", "50")
    test_project("minilua", "tigress", "CFF", "50")
