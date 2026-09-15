#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QQ NT (NTQQ) SQLCipher v4 页解密 / 密钥校验。

适用于 iOS / Android / Windows / Linux / macOS 的 NTQQ 数据库（`nt_msg.db`、
`group_info.db` …）。这些库不是裸 SQLCipher：

    [ 1024 字节 QQ 私有头 ][ SQLCipher 第 1 页 ][ 第 2 页 ] ...

  * 页大小 4096；私有头里有版本 / HMAC 算法 / 密钥材料（见 derive_key_ios.py）
  * 第 1 页： [ salt(16) ][ CT(4032) ][ IV(16) ][ HMAC(20) ][ pad(12) ]
  * 普通页： [ CT(4048) ][ IV(16) ][ HMAC(20) ][ pad(12) ]
  * enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, 4000, 32)
  * hmac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)
  * 页 HMAC  = HMAC-SHA1(hmac_key, CT || IV || LE_u32(page_no))

`check_page1()` 是判定密钥是否正确的 2^-160 判据：只算 HMAC，不解密、不动数据库。

用法：
    python ntqq_sqlcipher.py --selftest                      # 自测
    python ntqq_sqlcipher.py --db nt_msg.db --key 0123...    # 校验 32 字节裸密钥
    python ntqq_sqlcipher.py --db nt_msg.db --pass 'xxxx'    # 校验口令
    python ntqq_sqlcipher.py --db nt_msg.db --pass 'xxxx' --out plain.db
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import os
import sqlite3
import struct
import sys

try:                       # Windows 控制台默认 GBK，中文输出会乱码
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:          # noqa: BLE001
    pass

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    print('需要 cryptography：pip install cryptography', file=sys.stderr)
    raise

# ───────────────────────── 参数 ─────────────────────────
EXT_HEADER = 1024
PAGE_SIZE = 4096
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
KDF_ITER = 4000
FAST_ITER = 2
HMAC_MASK = 0x3A

HMAC_SIZES = {'sha1': 20, 'sha256': 32, 'sha512': 64}
HMAC_NAMES = {20: 'sha1', 32: 'sha256', 64: 'sha512'}


class Params:
    """HMAC 摘要长度会决定页尾保留区大小（IV + HMAC + 对齐填充）。"""

    def __init__(self, hmac_algo: str = 'sha1', page_size: int = PAGE_SIZE,
                 kdf_iter: int = KDF_ITER, fast_iter: int = FAST_ITER,
                 ext_header: int = EXT_HEADER):
        if hmac_algo not in HMAC_SIZES:
            raise ValueError('hmac_algo 必须是 %s' % list(HMAC_SIZES))
        self.hmac_algo = hmac_algo
        self.page_size = page_size
        self.kdf_iter = kdf_iter
        self.fast_iter = fast_iter
        self.ext_header = ext_header

    @property
    def hmac_size(self) -> int:
        return HMAC_SIZES[self.hmac_algo]

    @property
    def reserve(self) -> int:
        """页尾保留区，向上取整到 16 字节边界。"""
        raw = IV_SIZE + self.hmac_size
        return raw + (-raw % 16)

    @property
    def data_end(self) -> int:
        return self.page_size - self.reserve

    @property
    def ct_page1(self) -> int:
        return self.data_end - SALT_SIZE


# ───────────────────────── 密钥派生 ─────────────────────────
def derive_enc_key(passphrase: bytes, salt: bytes, p: Params = None) -> bytes:
    p = p or Params()
    return hashlib.pbkdf2_hmac('sha512', passphrase, salt, p.kdf_iter, KEY_SIZE)


def derive_hmac_key(enc_key: bytes, salt: bytes, p: Params = None) -> bytes:
    p = p or Params()
    return hashlib.pbkdf2_hmac('sha512', enc_key, bytes(b ^ HMAC_MASK for b in salt),
                               p.fast_iter, KEY_SIZE)


def page_hmac(hmac_key: bytes, ct: bytes, iv: bytes, page_no: int, p: Params = None) -> bytes:
    p = p or Params()
    return _hmac.new(hmac_key, ct + iv + struct.pack('<I', page_no),
                     getattr(hashlib, p.hmac_algo)).digest()


# ───────────────────────── 页操作 ─────────────────────────
def _aes(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    ctx = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = ctx.encryptor() if encrypt else ctx.decryptor()
    return op.update(data) + op.finalize()


def check_page1(page1: bytes, enc_key: bytes, p: Params = None) -> bool:
    """只算第 1 页 HMAC：密钥是否正确。"""
    p = p or Params()
    salt = page1[:SALT_SIZE]
    hmac_key = derive_hmac_key(enc_key, salt, p)
    ct = page1[SALT_SIZE:p.data_end]
    iv = page1[p.data_end:p.data_end + IV_SIZE]
    stored = page1[p.data_end + IV_SIZE:p.data_end + IV_SIZE + p.hmac_size]
    return _hmac.compare_digest(page_hmac(hmac_key, ct, iv, 1, p), stored)


def verify_passphrase(page1: bytes, passphrase: bytes, p: Params = None):
    """返回 (是否正确, 派生出的 enc_key)。"""
    p = p or Params()
    ek = derive_enc_key(passphrase, page1[:SALT_SIZE], p)
    return check_page1(page1, ek, p), ek


def detect_params(page1: bytes, passphrase: bytes = None, enc_key: bytes = None):
    """在常见 (HMAC 算法, 迭代数) 组合里找出能让 page-1 HMAC 通过的那一组。"""
    combos = []
    for algo in ('sha1', 'sha256', 'sha512'):
        for iters in (4000, 256000, 64000):
            for fast in (2, 1):
                combos.append(Params(algo, kdf_iter=iters, fast_iter=fast))
    for p in combos:
        if enc_key is not None:
            if check_page1(page1, enc_key, p):
                return p
        elif passphrase is not None:
            ok, _ = verify_passphrase(page1, passphrase, p)
            if ok:
                return p
    return None


def decrypt_page(page_raw: bytes, page_no: int, enc_key: bytes, p: Params = None) -> bytes:
    p = p or Params()
    skip = SALT_SIZE if page_no == 1 else 0
    ct = page_raw[skip:p.data_end]
    iv = page_raw[p.data_end:p.data_end + IV_SIZE]
    return _aes(enc_key, iv, ct, False)


def encrypt_page(plain: bytes, page_no: int, enc_key: bytes, salt: bytes,
                 p: Params = None) -> bytes:
    """把明文 CT 区加密回完整密文页（自测用）。"""
    p = p or Params()
    iv = os.urandom(IV_SIZE)
    ct = _aes(enc_key, iv, plain, True)
    page = bytearray()
    if page_no == 1:
        page += salt
    page += ct + iv + page_hmac(derive_hmac_key(enc_key, salt, p), ct, iv, page_no, p)
    page += b'\x00' * (p.page_size - len(page))
    return bytes(page)


# ───────────────────────── 整库 ─────────────────────────
def read_page1(path: str, p: Params = None) -> bytes | None:
    p = p or Params()
    try:
        with open(path, 'rb') as f:
            f.seek(p.ext_header)
            d = f.read(p.page_size)
        return d if len(d) == p.page_size else None
    except OSError:
        return None


def decrypt_db(in_path: str, out_path: str, enc_key: bytes, p: Params = None,
               progress=None) -> tuple[bool, str]:
    p = p or Params()
    with open(in_path, 'rb') as f:
        f.seek(p.ext_header)
        body = f.read()
    if len(body) < p.page_size:
        return False, '文件太小'
    total = len(body) // p.page_size
    if not check_page1(body[:p.page_size], enc_key, p):
        return False, '第 1 页 HMAC 校验失败（密钥或参数不对）'

    out = bytearray()
    for pgno in range(1, total + 1):
        raw = body[(pgno - 1) * p.page_size: pgno * p.page_size]
        dec = decrypt_page(raw, pgno, enc_key, p)
        if pgno == 1:
            # 页 1 的前 16 字节明文被 salt 取代，这里补回标准 SQLite 魔数
            page = b'SQLite format 3\x00' + dec
            page += b'\x00' * (p.page_size - len(page))
            page = bytearray(page)
            page[16:18] = struct.pack('>H', p.page_size)   # 修正页大小字段
            out += page
        else:
            out += dec
    with open(out_path, 'wb') as f:
        f.write(out)

    try:
        con = sqlite3.connect(out_path)
        n = con.execute('SELECT count(*) FROM sqlite_master').fetchone()[0]
        integ = con.execute('PRAGMA integrity_check').fetchone()[0]
        con.close()
        return True, '%d 个 schema 对象, integrity_check=%s' % (n, integ)
    except Exception as e:                                  # noqa: BLE001
        return False, '输出库打不开: %s' % e


def _selftest() -> int:
    print('=' * 68)
    print('NTQQ SQLCipher 自测（不依赖任何真实库）')
    print('=' * 68)
    ok = True
    for algo in ('sha1', 'sha256'):
        p = Params(algo)
        assert p.ct_page1 % 16 == 0, p.ct_page1
        passphrase = b'#8xxxxxxxxxxx@uJ'
        salt = os.urandom(SALT_SIZE)
        ek = derive_enc_key(passphrase, salt, p)
        plain = os.urandom(p.ct_page1)
        page1 = encrypt_page(plain, 1, ek, salt, p)
        good = check_page1(page1, ek, p) and verify_passphrase(page1, passphrase, p)[0]
        bad = check_page1(page1, os.urandom(32), p)
        dec = decrypt_page(page1, 1, ek, p)
        same = dec == plain
        print('  %-6s reserve=%2d CT1=%4d 正确key=%-5s 错误key=%-5s 往返=%s'
              % (algo, p.reserve, p.ct_page1, good, bad, same))
        ok = ok and good and not bad and same
    print('VERDICT:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description='NTQQ SQLCipher 解密器')
    ap.add_argument('--db', help='加密库路径')
    ap.add_argument('--key', help='32 字节裸密钥（64 位 hex）')
    ap.add_argument('--pass', dest='passphrase', help='口令（字符串）')
    ap.add_argument('--out', help='解密输出路径')
    ap.add_argument('--hmac', default='sha1', choices=list(HMAC_SIZES))
    ap.add_argument('--kdf-iter', type=int, default=KDF_ITER)
    ap.add_argument('--fast-iter', type=int, default=FAST_ITER)
    ap.add_argument('--auto-params', action='store_true', help='自动尝试常见参数组合')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest or not a.db:
        return _selftest()

    p = Params(a.hmac, kdf_iter=a.kdf_iter, fast_iter=a.fast_iter)
    page1 = read_page1(a.db, p)
    if not page1:
        print('读不到 page1：%s' % a.db)
        return 1

    ek = None
    if a.key:
        ek = bytes.fromhex(a.key)
    elif a.passphrase:
        ok, ek = verify_passphrase(page1, a.passphrase.encode(), p)
        if not ok and a.auto_params:
            q = detect_params(page1, passphrase=a.passphrase.encode())
            if q:
                p = q
                ok, ek = verify_passphrase(page1, a.passphrase.encode(), p)
        print('口令校验: %s' % ok)
        if not ok:
            return 1
    else:
        print('需要 --key 或 --pass')
        return 1

    if not check_page1(page1, ek, p) and a.auto_params:
        q = detect_params(page1, enc_key=ek)
        if q:
            p = q
    if not check_page1(page1, ek, p):
        print('密钥校验失败')
        return 1
    print('密钥校验通过 (hmac=%s)' % p.hmac_algo)
    if a.out:
        good, msg = decrypt_db(a.db, a.out, ek, p,
                               progress=lambda i, n: print('  %d/%d' % (i, n), flush=True))
        print('解密: %s - %s' % (good, msg))
        return 0 if good else 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
