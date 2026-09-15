# 建议提交到 QQBackup/QQDecrypt 的 issue（草稿）

> ✅ **已提交：<https://github.com/QQBackup/QQDecrypt/issues/16>**（用本文件去掉元信息后的正文）

> 目标仓库：<https://github.com/QQBackup/QQDecrypt>
> 提交入口：<https://github.com/QQBackup/QQDecrypt/issues/new>
> 也可以直接对文档提 PR：`docs/decrypt/extract/NTQQ (iOS).md`

---

**标题（建议）**

`[补充] iOS NTQQ 可完全离线推导数据库口令（不需要 Frida / 内存扫描），已在 iOS QQ 9.3.55 实机验证`

**正文**

你好，感谢维护这套文档，帮了大忙。这里补充一条 `NTQQ (iOS)` 教程里还没有的信息，并申请补进文档。

### 结论

iOS（以及 Android）NTQQ 的数据库口令**可以从库文件本身离线推导出来**，不需要越狱 hook
`sqlite3_key_v2`、不需要 Frida、不需要读内存：

```text
账号目录名  = "nt_qq_" + md5(md5(uid) + "nt_kernel")
rand        = 库头 1024 字节私有头里 protobuf field 2 的值（8 个可打印字符，明文）
passphrase  = md5(md5(uid) + rand)        # 32 位 hex 的 ASCII 串，就是传给 sqlite3_key_v2 的 pKey
enc_key     = PBKDF2-HMAC-SHA512(passphrase, salt, 4000, 32)   # salt = 文件偏移 1024 起 16 字节
```

`uid` 的来源有两条，可以互相印证：

1. 全局 `login.db`（`nt_qq/global/nt_db/login.db`）：用文档里那个硬编码预登录口令
   `BD156D6710D54D8782F4` 解密后读 `login_table`，`"1000"` = uin，`"1001"` = uid；
2. 用上面的目录名公式反查。两条都命中即确认。

### 实测记录

- 设备/版本：Dopamine rootless iOS 15.5，QQ **9.3.55.609**（未注入、未 hook）
- 验证判据：SQLCipher 第 1 页 HMAC（`HMAC-SHA1(hmac_key, CT||IV||LE_u32(1))`），
  密钥正确时必然通过，错误时 2^-160，不存在误判；
- 整库解密：`nt_msg.db` 256 MB → `PRAGMA integrity_check` = `ok`，123 个 schema 对象；
- 导出：257,538 条消息 / 7,669 个会话（`c2c_msg_table` + `group_msg_table`）。

### 两个容易踩的坑（供文档参考）

1. 这 1024 字节私有头是真实存在的，文件大小恒为 `≡ 1024 (mod 4096)`；
   按"标准 SQLCipher 从偏移 0 取 salt"会怎么都解不开。
2. 第 1 页密文区是 4032 字节（salt 占掉了前 16 字节），普通页是 4048 字节；
   重建明文时第 1 页要补回 `"SQLite format 3\0"` 这 16 字节魔数（而不是补 100 字节的合成头），
   否则整页错位 84 字节，SQLite 会报 `database disk image is malformed`。

### 顺带一条 Windows 侧的补充（9.9.32-51246 实测）

- 文档说 Windows 端拿到的是 **16 个可打印字符**的口令，实测完全一致：同一口令能解开该账号
  **17 个库**（每库 salt 不同 → 密钥不同、口令相同），换账号即不同；该口令**不落盘**。
- 库头 field2 在 Windows 上是 **128 个 hex 字符**，与口令无关（我们按"切片 × uid 形态 × 4 种哈希 ×
  拼接顺序"打了十万级组合，page-1 HMAC 零命中），所以"拿到文件就能解"在 Windows 上不成立。
- 补充一条取密钥的旁路，可与 `x_key_scanner` 互补：QQ 内存里存在
  `x'<64位hex enc_key><32位hex salt>'` 形态的字符串（`sqlcipher_export` 相关路径），
  因此**搜某个库 salt 的 ASCII hex，其前 64 个 hex 字符就是已派生的裸密钥**；
  这次就是靠它先拿到密钥，再反推出那把 16 字符口令的。

### 申请

如果这些内容有价值，我可以给 `docs/decrypt/extract/NTQQ (iOS).md` 提 PR，补一节
"离线推导（无需 Frida）"，并附上最小复现脚本（解密 + page-1 HMAC 校验 + 导出）。
需要我按你们的文档格式写就说一声。

再次感谢！

---

## 提交时的注意事项

- 上面所有数值都是脱敏后的说明，**不要把自己的 uin / uid / salt / 密钥贴进 issue**。
- 如果要附实测截图，记得打码路径里的账号目录名（`nt_qq_<hash>` 可反推出 uid）。
- GitHub 网页提交即可，不需要本地 git。
