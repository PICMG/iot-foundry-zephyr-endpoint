#!/usr/bin/env python3
# Dumps __pdr_data[] records from tools/iot_builder/src/builder/config.c
import re,sys,os
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# prefer generated PDRs under src/pdrs
cfg_c = os.path.join(repo_root, 'src', 'pdrs', 'config.c')
cfg_h = os.path.join(repo_root, 'src', 'pdrs', 'config.h')
if not os.path.exists(cfg_c):
    # fallback to older builder location
    cfg_c = os.path.join(repo_root, 'tools', 'iot_builder', 'src', 'builder', 'config.c')
    cfg_h = os.path.join(repo_root, 'tools', 'iot_builder', 'src', 'builder', 'config.h')
if not os.path.exists(cfg_c):
    print('config.c not found:', cfg_c); sys.exit(2)
s = open(cfg_c,'r',encoding='utf-8',errors='ignore').read()
m = re.search(r'__pdr_data\[\]\s*[^=]*=\s*\{(.*?)\};', s, re.S)
if not m:
    print('could not find __pdr_data[] in', cfg_c); sys.exit(1)
block = m.group(1)
# extract numeric tokens (hex or decimal) robustly, ignore comments/annotations
nums = re.findall(r'0x[0-9a-fA-F]+|\d+', block)
try:
    bs = [int(x,0) for x in nums]
except Exception as e:
    print('failed to parse byte list:', e); sys.exit(3)
# try read PDR_TOTAL_SIZE
total = None
if os.path.exists(cfg_h):
    ch = open(cfg_h,'r',encoding='utf-8',errors='ignore').read()
    mm = re.search(r'#define\s+PDR_TOTAL_SIZE\s+(\d+)', ch)
    if mm:
        total = int(mm.group(1))
print('PDR_TOTAL_SIZE from config.h =', total)
# iterate records
i=0; n=len(bs); rec=0
print('Found', n, 'bytes in __pdr_data[]')
while i < n:
    if i+9 >= n:
        print(f'truncated header at offset {i}')
        break
    handle = bs[i] | (bs[i+1]<<8) | (bs[i+2]<<16) | (bs[i+3]<<24)
    length = bs[i+8] | (bs[i+9]<<8)
    rec_size = length + 10
    overflow = ''
    if total is not None and (i + rec_size) > total:
        overflow = ' <<< exceeds PDR_TOTAL_SIZE'
    print(f'record #{rec:02} offset={i:04} handle=0x{handle:08x} length={length} rec_size={rec_size}{overflow}')
    i += rec_size
    rec += 1
print('done')
