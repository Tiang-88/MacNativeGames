#!/usr/bin/env python3
"""Write the placeholder rtld module that keeps main at exlaunch record 1.

The image has the same text / rodata / data / key-page / patch-area layout as a
real module so QueryMemory reports the triple FindModules scans for, but it has
no code or relocations. Its one export is the global function pointer subsdk1
imports from the console's rtld: a zero-initialized data object at the start of
its data segment (prepare_runtime.py adds that symbol).
"""
import argparse
from pathlib import Path

LAYOUT = [('TEXT_END', 0x1000), ('RO_OFF', 0x1000), ('DATA_OFF', 0x8000),
          ('KEY_PAGE_OFF', 0x10000), ('PATCH_OFF', 0x14000)]
SIZE = 0x18000

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--fixups', required=True, type=Path)
args = parser.parse_args()
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_bytes(bytes(SIZE))
args.fixups.write_text(''.join(f'# {key}\t{value:#x}\n' for key, value in LAYOUT))
print(f'{args.output} size={SIZE:#x} key=0x10000 patch=0x14000')
