#!/usr/bin/env python3
"""把一次 GOT dump 判出的 97 个地址写进 runtime-tables.bin 的模块符号表。

判读结果（resolved.tsv，列 idx symbol kind slot_va value module offset）只带反修饰名，
而加载器按 Itanium 修饰名查表，所以这里用 idx 去 subsdk4_imports.tsv 换回 mangled。

写进去的是"main 里本来就存在、但没有名字导出的函数/数据"：value=模块内偏移，
defined=1，binding=0(GLOBAL)，type 沿用原导入的 FUNC/OBJECT。加载器 load_tables()
建哈希表时只收 defined 的符号，于是 runtime_symbol() 就能把 subsdk4 的导入解析到
真实地址，不需要改任何 C 代码。

用法：
  python3 tools/import_symbol_map.py \\
      --tables  build/game-data/v121/runtime-tables-subsdk4.bin \\
      --resolved /Users/yxy/game/mod/移植用符号资料/resolved.tsv \\
      --out     build/game-data/v121/runtime-tables.bin
"""
import argparse
import os
import struct
import sys

HDR = struct.Struct("<8s8sIIQQQQQ")
REC = struct.Struct("<16s72s13Q4I")
SYM = struct.Struct("<QQIBBBx")
IMPORTS = "/Users/yxy/game/mod/移植用符号资料/subsdk4_imports.tsv"
# subsdk4_imports.tsv 的 kind → ELF st_info 的 type
TYPE = {"veneer": 2, "data": 1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tables", required=True)
    ap.add_argument("--resolved", required=True)
    ap.add_argument("--imports", default=IMPORTS)
    ap.add_argument("--out", required=True)
    ap.add_argument("--module", default="main", help="地址落在哪个模块（默认 main）")
    ap.add_argument("--report", default=None, help="把实际注入的 name→偏移 写成 TSV")
    a = ap.parse_args()

    raw = bytearray(open(a.tables, "rb").read())
    magic, ver, nmod, fmt, plt, slot, strings_at, strings_size, size = HDR.unpack_from(raw, 0)
    if magic != b"TOTKTAB1" or size != len(raw):
        sys.exit("不是 runtime-tables.bin（magic/size 不符）")

    recs = [REC.unpack_from(raw, 64 + REC.size * i) for i in range(nmod)]
    names = [r[0].rstrip(b"\0").decode() for r in recs]
    if a.module not in names:
        sys.exit("表里没有模块 %s（有 %s）" % (a.module, ", ".join(names)))
    ti = names.index(a.module)

    # 把每个模块的 symbols/relocs/gates 按原顺序取出来（sym, rel, gate 三段连续）
    blob_strings = bytes(raw[strings_at:strings_at + strings_size])
    arrays = []
    for r in recs:
        _n, _d, _fs, _te, _ro, _do, _po, _ko, _init, _cf, _ia, _is, sym, rel, gate, nsym, nrel, ngate, _res = r
        arrays.append({
            "sym": bytes(raw[sym:sym + nsym * SYM.size]),
            "rel": bytes(raw[rel:rel + nrel * 24]),
            "gate": bytes(raw[gate:gate + ngate * 24]),
            "nsym": nsym, "nrel": nrel, "ngate": ngate,
        })

    # idx → (mangled, kind)，用 idx 关联
    mangled, kind_of = {}, {}
    with open(a.imports, encoding="utf-8") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 4:
                continue
            mangled[p[0]] = p[1]
            kind_of[p[0]] = p[3]

    # 已在表里的名字（任何模块）都不再注入；import 的 mangled 名若已 defined 说明无需注入
    existing = set()
    for i, r in enumerate(recs):
        for k in range(arrays[i]["nsym"]):
            v, _sz, noff, defined, binding, typ = SYM.unpack_from(arrays[i]["sym"], k * SYM.size)
            if defined and noff < len(blob_strings):
                end = blob_strings.index(b"\0", noff)
                existing.add(blob_strings[noff:end].decode("utf-8", "replace"))

    add_syms, add_names = [], []
    strings = bytearray(blob_strings)
    if strings and strings[-1] != 0:
        strings += b"\0"
    name_off = {}
    rows_out = []
    skipped_existing = missing_offset = 0
    with open(a.resolved, encoding="utf-8") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 7:
                continue
            idx, _dem, _kind, _slot, value, mod, off = p[:7]
            if mod != a.module:
                continue
            if not off:
                missing_offset += 1
                continue
            m = mangled.get(idx)
            if not m:
                print("警告：idx %s 在 imports 表里找不到" % idx)
                continue
            if m in existing:
                skipped_existing += 1
                continue
            if m not in name_off:
                name_off[m] = len(strings)
                strings += m.encode() + b"\0"
            add_syms.append((int(off, 16), 0, name_off[m], 1, 0, TYPE.get(kind_of[idx], 2)))
            rows_out.append((idx, m, mod, off))

    if not add_syms:
        sys.exit("没有可注入的符号：检查 --resolved 的 module 列是否等于 %s" % a.module)

    arrays[ti]["sym"] += b"".join(SYM.pack(*s) for s in add_syms)
    arrays[ti]["nsym"] += len(add_syms)

    # 重新排布：头 + 记录 + 每模块(sym, rel, gate) + 字符串
    out = bytearray(64 + REC.size * nmod)
    strings_at_new = None
    offs = []
    cur = len(out)
    for arr in arrays:
        offs.append((cur, cur + len(arr["sym"]), cur + len(arr["sym"]) + len(arr["rel"])))
        cur += len(arr["sym"]) + len(arr["rel"]) + len(arr["gate"])
    strings_at_new = cur
    cur += len(strings)

    for i, r in enumerate(recs):
        f = list(r)
        f[12], f[13], f[14] = offs[i]
        f[15], f[16], f[17] = arrays[i]["nsym"], arrays[i]["nrel"], arrays[i]["ngate"]
        REC.pack_into(out, 64 + REC.size * i, *f)
    for i, arr in enumerate(arrays):
        out += arr["sym"] + arr["rel"] + arr["gate"]
    assert len(out) == strings_at_new
    out += strings
    HDR.pack_into(out, 0, magic, ver, nmod, fmt, plt, slot, strings_at_new, len(strings), len(out))
    assert len(out) == cur

    open(a.out, "wb").write(out)
    print("注入 %d 个符号到 %s（跳过已存在 %d，无偏移 %d）" % (len(add_syms), a.module, skipped_existing, missing_offset))
    print("%s: %d 字节 -> %s: %d 字节" % (a.tables, len(raw), a.out, len(out)))
    if a.report:
        with open(a.report, "w", encoding="utf-8") as g:
            g.write("idx\tmangled\tmodule\toffset\n")
            for r in rows_out:
                g.write("\t".join(r) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
