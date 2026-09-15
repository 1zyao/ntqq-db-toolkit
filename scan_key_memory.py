#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows NTQQ：从正在运行且已登录的 QQ 进程内存里取数据库密钥。

为什么必须这么做
----------------
Windows 端的口令（16 个可打印字符）**不落盘**，只存在于登录进程内存中；
库头 field2 的 128 个 hex 字符不是它（实测十万级组合 0 命中，详见 README）。
所以想要 Windows 的库，必须趁 QQ 登录着的时候取。

三条取法（本脚本都实现了）
------------------------
1. `x'<64位hex enc_key><32位hex salt>'` —— QQ 的 sqlcipher_export 相关路径会在内存里留下这种串，
   搜到某个库的 **salt 的 ASCII hex**，它前面 64 个 hex 字符就是已派生的裸密钥。
2. `\\x09HMAC_SHA1` 锚点法 —— native 版 SQLCipher codec 结构里标记与密钥相邻，
   在锚点 ±0x200 内按 16 字节对齐找"全可打印非空白、且不全是字母数字"的 16 字节窗口，
   当口令候选（这是 QQBackup/x_key_scanner 的思路）。
3. 直接用已知库的 page-1 HMAC 判定每个候选（2^-160，不会误判）。

用法
----
    python scan_key_memory.py --db "C:/Users/x/Documents/Tencent Files/<uin>/nt_qq/nt_db/nt_msg.db"
    python scan_key_memory.py --db nt_msg.db --name QQ --dump-region 1234 0x7ff 0x1000 out.bin
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import sys
import time

try:                       # Windows 控制台默认 GBK，中文输出会乱码
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:          # noqa: BLE001
    pass

import ntqq_sqlcipher as sc

ANCHOR = b'\x09HMAC_SHA1'
ALIGN = 16
RADIUS = 0x200
CHUNK = 8 << 20
RE_KEY = re.compile(rb"x'([0-9a-fA-F]{96})'")
READABLE = (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

k32 = ctypes.WinDLL('kernel32', use_last_error=True) if os.name == 'nt' else None


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('__a1', wt.DWORD),
                ('RegionSize', ctypes.c_size_t), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD), ('__a2', wt.DWORD)]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD), ('th32ProcessID', wt.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                ('th32ModuleID', wt.DWORD), ('cntThreads', wt.DWORD),
                ('th32ParentProcessID', wt.DWORD), ('pcPriClassBase', wt.LONG),
                ('dwFlags', wt.DWORD), ('szExeFile', ctypes.c_char * MAX_PATH)]


def _setup():
    if os.name != 'nt':
        return
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t]
    k32.ReadProcessMemory.restype = wt.BOOL
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    k32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


def list_processes(name_filter: str = None):
    _setup()
    if os.name != 'nt':
        return []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wt.HANDLE(-1).value:
        return []
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    out = []
    ok = k32.Process32First(snap, ctypes.byref(pe))
    while ok:
        nm = pe.szExeFile.decode('mbcs', 'replace')
        if not name_filter or name_filter.lower() in nm.lower():
            out.append((pe.th32ProcessID, nm))
        ok = k32.Process32Next(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out


def iter_regions(h):
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)):
            return
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if not size:
            return
        if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE
                and not (mbi.Protect & PAGE_GUARD)):
            yield base, size
        addr = base + size


def read_mem(h, base, size, chunk=CHUNK):
    off = 0
    while off < size:
        n = min(chunk, size - off)
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n,
                                 ctypes.byref(got)) and got.value:
            yield base + off, buf.raw[:got.value]
        off += n


def key_ok(w: bytes) -> bool:
    return (len(w) == 16 and all(0x21 <= b < 0x7F for b in w)
            and not all(chr(b).isalnum() for b in w))


class Finder:
    def __init__(self, db: str, params: sc.Params = None):
        self.page1 = sc.read_page1(db, params)
        if not self.page1:
            raise SystemExit('读不到 %s 的第 1 页' % db)
        self.salt = self.page1[:16]
        self.p = params or sc.Params()
        self.hits = []
        self.tried = set()

    # 判据一：候选当口令 → PBKDF2 → page-1 HMAC
    def try_passphrase(self, cand: bytes, where: str):
        if cand in self.tried:
            return False
        self.tried.add(cand)
        ok, ek = sc.verify_passphrase(self.page1, cand, self.p)
        if ok:
            self.hits.append(('passphrase', cand, ek.hex(), where))
            print('  *** 口令命中 %r  enc_key=%s  @%s' % (cand, ek.hex(), where), flush=True)
            return True
        return False

    # 判据二：候选当 32 字节裸密钥
    def try_raw_key(self, cand: bytes, where: str):
        if len(cand) != 32 or cand in self.tried:
            return False
        self.tried.add(cand)
        if sc.check_page1(self.page1, cand, self.p):
            self.hits.append(('raw_key', cand, cand.hex(), where))
            print('  *** 裸密钥命中 %s  @%s' % (cand.hex(), where), flush=True)
            return True
        return False

    def scan_process(self, pid: int, name: str = ''):
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            print('  [skip] pid=%d %s OpenProcess err=%d'
                  % (pid, name, ctypes.get_last_error()), flush=True)
            return
        t0 = time.time()
        anchors = 0
        for base, size in iter_regions(h):
            for va, data in read_mem(h, base, size):
                # 1) x'<key><salt>' 串：直接拿到裸密钥
                for m in RE_KEY.finditer(data):
                    hx = m.group(1).decode().lower()
                    if hx[64:96] == self.salt.hex():
                        self.try_raw_key(bytes.fromhex(hx[:64]), 'x-key pid=%d' % pid)
                # 2) 锚点附近的 16 字节口令候选
                start = 0
                while True:
                    i = data.find(ANCHOR, start)
                    if i < 0:
                        break
                    start = i + 1
                    anchors += 1
                    a16 = ((i - 1) // ALIGN) * ALIGN
                    for step in range(0, RADIUS + 1, ALIGN):
                        for pos in ((a16 - step, a16 + step) if step else (a16,)):
                            if 0 <= pos and pos + 16 <= len(data):
                                w = data[pos:pos + 16]
                                if key_ok(w):
                                    self.try_passphrase(w, 'anchor pid=%d' % pid)
                # 3) salt 的 ASCII hex 前面 64 位 hex = 裸密钥
                sh = self.salt.hex().encode()
                start = 0
                while True:
                    i = data.find(sh, start)
                    if i < 0:
                        break
                    start = i + 1
                    pre = data[max(0, i - 64):i]
                    if len(pre) == 64 and re.fullmatch(rb'[0-9a-fA-F]{64}', pre):
                        self.try_raw_key(bytes.fromhex(pre.decode()), 'salt-prefix pid=%d' % pid)
        k32.CloseHandle(h)
        print('  [done] pid=%d %s anchors=%d 候选=%d 用时=%.0fs'
              % (pid, name, anchors, len(self.tried), time.time() - t0), flush=True)


def dump_region(pid: int, addr: int, size: int, out: str) -> int:
    _setup()
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        print('OpenProcess err=%d' % ctypes.get_last_error())
        return 1
    n = 0
    with open(out, 'wb') as f:
        for va, data in read_mem(h, addr, size):
            f.write(data)
            n += len(data)
    k32.CloseHandle(h)
    print('dump %d 字节 -> %s' % (n, out))
    return 0


def main() -> int:
    if os.name != 'nt':
        print('本脚本的内存扫描部分只支持 Windows。\n'
              'Linux/macOS 请用 QQBackup/x_key_scanner；\n'
              'iOS/Android 不需要内存，用 derive_key_ios.py 即可。')
    ap = argparse.ArgumentParser(description='Windows NTQQ 内存取密钥')
    ap.add_argument('--db', help='目标加密库（用于 page-1 HMAC 判定）')
    ap.add_argument('--name', default='QQ', help='进程名包含串（默认 QQ）')
    ap.add_argument('--pid', action='append', type=int, default=[])
    ap.add_argument('--hmac', default='sha1', choices=list(sc.HMAC_SIZES))
    ap.add_argument('--kdf-iter', type=int, default=sc.KDF_ITER)
    ap.add_argument('--fast-iter', type=int, default=sc.FAST_ITER)
    ap.add_argument('--list', action='store_true', help='列出进程后退出')
    ap.add_argument('--dump-region', nargs=4, metavar=('PID', 'ADDR', 'SIZE', 'OUT'))
    a = ap.parse_args()
    _setup()

    if a.list:
        for pid, nm in list_processes(a.name):
            print('%8d  %s' % (pid, nm))
        return 0
    if a.dump_region:
        pid, addr, size, out = a.dump_region
        return dump_region(int(pid), int(addr, 0), int(size, 0), out)
    if not a.db:
        ap.print_help()
        return 1

    p = sc.Params(a.hmac, kdf_iter=a.kdf_iter, fast_iter=a.fast_iter)
    f = Finder(a.db, p)
    print('目标库 : %s' % a.db)
    print('salt   : %s' % f.salt.hex())
    pids = a.pid or [pid for pid, _ in list_processes(a.name)]
    if not pids:
        print('没找到匹配的进程（QQ 是否在运行？）')
        return 1
    print('进程   : %s' % pids)
    for pid in pids:
        f.scan_process(pid, a.name)
    print()
    print('命中 %d 条:' % len(f.hits))
    for kind, cand, key, where in f.hits:
        print('  %-10s cand=%r key=%s  (%s)' % (kind, cand, key, where))
    return 0 if f.hits else 2


if __name__ == '__main__':
    raise SystemExit(main())
