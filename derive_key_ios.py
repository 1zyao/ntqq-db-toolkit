#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""iOS / Android NTQQ：从库文件离线推导数据库口令（无需内存、无需 root、无需 Frida）。

原理
----
    QQ_UID_hash = md5(uid)                      # uid 形如 u_XXXXXXXXXXXXXXXXXXXXXX
    账号目录名  = "nt_qq_" + md5(md5(uid) + "nt_kernel")
    rand        = 库头 1024 字节扩展头里 protobuf field 2 的值（8 个可打印字符）
    passphrase  = md5(md5(uid) + rand)          # 32 位 hex 的 ASCII 串，直接交给 SQLCipher
    enc_key     = PBKDF2-HMAC-SHA512(passphrase, salt, 4000, 32)

uid 来源：全局 `login.db`（客户端硬编码口令可解，见 PRE_LOGIN_KEY）里的 `login_table`，
或者用上面的目录名公式反查。

⚠️ 只适用于 iOS / Android。Windows NTQQ 的同名字段是 128 个 hex 字符，**不是**这把口令；
   Windows 的口令只在已登录进程内存里，见 scan_key_memory.py。

用法
----
    python derive_key_ios.py --db nt_msg.db                     # 自动找 uid 并验证
    python derive_key_ios.py --db nt_msg.db --login-db /path/login.db
    python derive_key_ios.py --db nt_msg.db --uid u_XXXX --decrypt plain.db
    python derive_key_ios.py --selftest
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import os
import struct
import sys

try:                       # Windows 控制台默认 GBK，中文输出会乱码
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:          # noqa: BLE001
    pass

import ntqq_sqlcipher as sc

# login.db 的预登录口令：硬编码在客户端里，所有账号/所有设备相同
PRE_LOGIN_KEY = b'BD156D6710D54D8782F4'

# 常见的 login.db 位置（按平台）
LOGIN_DB_GLOBS = [
    '**/nt_qq/global/nt_db/login.db',
    '**/QQNT/DB/login.db',
    '**/Tencent Files/nt_qq/global/nt_db/login.db',
    '/var/mobile/Containers/Data/Application/*/Documents/QQNT/DB/**/login.db',
]


# ───────────────────────── 私有头解析 ─────────────────────────
def parse_nt_header(path: str) -> dict:
    """解析 1024 字节私有头，返回 {rand, version, hmac_algo, ts, fields}。"""
    with open(path, 'rb') as f:
        hdr = f.read(sc.EXT_HEADER)
    out = {'rand': None, 'version': None, 'hmac_algo': None, 'ts': None, 'fields': {}}
    i = hdr.find(b'QQ_NT DB')
    if i < 0:
        return out
    base = i + len(b'QQ_NT DB')
    ln = struct.unpack('<I', hdr[base:base + 4])[0]
    pb = hdr[base + 4:base + 4 + ln]
    p = 0
    while p < len(pb):
        tag = pb[p]
        p += 1
        fno, wire = tag >> 3, tag & 7
        if wire == 2:
            l = 0
            sh = 0
            while True:
                b = pb[p]
                p += 1
                l |= (b & 0x7F) << sh
                if not b & 0x80:
                    break
                sh += 7
            val = pb[p:p + l]
            p += l
            out['fields'][fno] = val
        elif wire == 0:
            v = 0
            sh = 0
            while True:
                b = pb[p]
                p += 1
                v |= (b & 0x7F) << sh
                if not b & 0x80:
                    break
                sh += 7
            out['fields'][fno] = v
        else:
            break
    if 2 in out['fields']:
        out['rand'] = out['fields'][2]
    if 3 in out['fields']:
        out['version'] = out['fields'][3].decode('ascii', 'replace')
    if 4 in out['fields']:
        algo = out['fields'][4].decode('ascii', 'replace').lower()
        algo = algo.replace('hmac_', '').replace('hmac-', '').replace('-', '')
        out['hmac_algo'] = algo if algo in sc.HMAC_SIZES else None
    if 5 in out['fields']:
        out['ts'] = out['fields'][5]
    return out


def uid_dir_hash(uid: str) -> str:
    inner = hashlib.md5(uid.encode()).hexdigest()
    return 'nt_qq_' + hashlib.md5(inner.encode() + b'nt_kernel').hexdigest()


def derive_passphrase(uid: str, rand: bytes | str) -> str:
    r = rand.encode() if isinstance(rand, str) else rand
    inner = hashlib.md5(uid.encode()).hexdigest().encode()
    return hashlib.md5(inner + r).hexdigest()


def find_account_dir(path: str) -> str | None:
    """从库路径里找出 nt_qq_<hash> 目录名。"""
    p = os.path.abspath(path)
    while True:
        name = os.path.basename(p)
        if name.startswith('nt_qq_'):
            return name
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


# ───────────────────────── login.db ─────────────────────────
def read_login_db(path: str) -> list[dict]:
    """解密全局 login.db 并读出本机登录过的账号。"""
    page1 = sc.read_page1(path)
    if not page1:
        return []
    ok, ek = sc.verify_passphrase(page1, PRE_LOGIN_KEY)
    if not ok:
        return []
    import sqlite3
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), 'login_plain_%d.db' % os.getpid())
    good, _ = sc.decrypt_db(path, tmp, ek)
    if not good:
        return []
    accs = []
    try:
        con = sqlite3.connect(tmp)
        cols = [r[1] for r in con.execute('PRAGMA table_info("login_table")')]
        q = 'SELECT %s FROM login_table' % ','.join('"%s"' % c for c in cols if c in
                                                   ('1000', '1001', '1007'))
        for row in con.execute(q):
            accs.append({'uin': str(row[0]), 'uid': row[1], 'nick': row[2]})
        con.close()
    except Exception:                                       # noqa: BLE001
        pass
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return accs


def discover_login_dbs(root: str = None) -> list[str]:
    root = root or os.path.expanduser('~')
    found = []
    for pat in LOGIN_DB_GLOBS:
        if pat.startswith('/'):
            found += glob.glob(pat)
        else:
            found += glob.glob(os.path.join(root, pat), recursive=True)
    return sorted(set(found))


# ───────────────────────── 主流程 ─────────────────────────
def solve(db: str, uids: list[str], login_dbs: list[str], log=print) -> dict | None:
    hdr = parse_nt_header(db)
    rand = hdr['rand']
    log('库        : %s' % db)
    log('私有头    : version=%s hmac=%s ts=%s' % (hdr['version'], hdr['hmac_algo'], hdr['ts']))
    if not rand:
        log('没有在私有头里找到 field2，无法推导')
        return None
    log('rand      : %r' % rand)
    if len(rand) > 32 and all(c in b'0123456789abcdefABCDEF' for c in rand):
        log('⚠️ field2 是 %d 个 hex 字符 —— 这是 **Windows NTQQ** 的格式，'
            '本方法不适用（Windows 口令只在登录进程内存里，见 scan_key_memory.py）' % len(rand))
        return None

    dirhash = find_account_dir(db)
    if dirhash:
        log('账号目录  : %s' % dirhash)

    cands = list(uids)
    for lp in login_dbs:
        for acc in read_login_db(lp):
            if acc['uid'] and acc['uid'] not in cands:
                cands.append(acc['uid'])
                log('login.db  : %s -> uid=%s nick=%r' % (acc['uin'], acc['uid'], acc['nick']))
    if not cands:
        log('没有 uid 候选：用 --uid 指定，或 --login-db 指定 login.db，或把库放回 nt_qq_<hash> 目录下')
        return None

    # 有目录名时优先匹配哈希
    if dirhash:
        hit = [u for u in cands if uid_dir_hash(u) == dirhash]
        if hit:
            cands = hit
            log('目录反查  : uid=%s 与目录名吻合' % hit[0])

    page1 = sc.read_page1(db)
    params = sc.Params(hdr['hmac_algo'] or 'sha1')
    for uid in cands:
        pw = derive_passphrase(uid, rand)
        ok, ek = sc.verify_passphrase(page1, pw.encode(), params)
        log('  试 uid=%-28s pass=%s  -> %s' % (uid, pw[:8] + '…', '★命中' if ok else '否'))
        if ok:
            return {'uid': uid, 'rand': rand.decode('ascii', 'replace'),
                    'passphrase': pw, 'enc_key': ek.hex(), 'params': params, 'db': db}
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description='iOS/Android NTQQ 离线密钥推导')
    ap.add_argument('--db')
    ap.add_argument('--uid', action='append', default=[], help='可多次指定')
    ap.add_argument('--login-db', action='append', default=[], help='login.db 路径（可多次）')
    ap.add_argument('--no-auto-login', action='store_true', help='不自动搜索 login.db')
    ap.add_argument('--decrypt', metavar='OUT', help='命中后顺便解密到 OUT')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest or not a.db:
        uid = 'u_EXAMPLE0123456789abc'
        r = 'Ab3dEf9Z'
        print('目录名示例 : %s' % uid_dir_hash(uid))
        print('口令示例   : %s' % derive_passphrase(uid, r))
        return 0

    login_dbs = list(a.login_db)
    if not login_dbs and not a.no_auto_login:
        login_dbs = discover_login_dbs()
        for lp in login_dbs:
            print('发现 login.db: %s' % lp)
    res = solve(a.db, a.uid, login_dbs)
    if not res:
        print('未能命中')
        return 1
    print()
    print('★ uid        = %s' % res['uid'])
    print('★ rand       = %s' % res['rand'])
    print('★ passphrase = %s' % res['passphrase'])
    print('★ enc_key    = %s' % res['enc_key'])
    if a.decrypt:
        good, msg = sc.decrypt_db(res['db'], a.decrypt, bytes.fromhex(res['enc_key']),
                                  res['params'])
        print('★ 解密       = %s - %s' % (good, msg))
        return 0 if good else 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
