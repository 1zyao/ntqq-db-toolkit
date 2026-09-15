# NTQQ 本地聊天数据库取证复盘（iOS / Windows）

> 一次从「账号被封 + 聊天记录被删」出发，最终把 iOS 端 25 万条聊天记录解密导出、
> 并搞清 Windows 端密钥到底藏在哪的完整记录。
> 本文只讲**原理、可复现步骤和踩过的坑**，所有账号 / uid / 密钥 / 群号均已脱敏。

---

## 仓库内容 & 快速开始

```text
ntqq_sqlcipher.py      SQLCipher v4 页解密 + page-1 HMAC 判定（全平台通用）
derive_key_ios.py   ★  iOS/Android：只凭库文件离线推导口令（不需要内存 / root / Frida）
scan_key_memory.py     Windows：从已登录 QQ 进程内存取密钥（锚点法 + salt-hex 前缀法）
ntmsg_wire.py          40800 消息体最小解析器（不依赖 protobuf 运行时）
export_messages.py     明文库 → 可读转录 + 微调语料（sharegpt / chat / llama.cpp）
TRAINING.md            语料 → LoRA → Ollama(macOS) 的落地说明
```

```bash
pip install -r requirements.txt          # 只需要 cryptography

# 0) 自测（不需要任何真实库）
python ntqq_sqlcipher.py --selftest

# 1) iOS / Android：库文件 + uid 就能算（脚本会自动去找 login.db 里的 uid）
python derive_key_ios.py --db nt_msg.db --decrypt nt_msg_plain.db

# 2) Windows：QQ 必须正在运行且已登录
python scan_key_memory.py --list
python scan_key_memory.py --db ".../nt_qq/nt_db/nt_msg.db"

# 3) 导出可读转录 + 微调语料
python export_messages.py --db nt_msg_plain.db --out corpus --uin <uin> --target-uin <对端uin>
```

> 全部为只读操作：不注入、不调试、不修改 QQ 与其数据库文件。
> 使用时请先复制一份原始库（含 `-wal` / `-shm`）。

---

## 0. 结论速览（TL;DR）

| 平台 | 数据库密钥怎么来 | 能否离线推导 | 备注 |
| --- | --- | --- | --- |
| Android QQ / iOS QQ（NTQQ） | 库头 1024 字节扩展头里的 `rand`（8 字符明文）+ 账号 uid | ✅ **可以，纯离线** | `key = md5(md5(uid) + rand)`，再交给 SQLCipher 当口令 |
| Windows NTQQ | 16 个可打印字符的随机口令 | ❌ **不可以** | 只存在于**已登录 QQ 进程的内存**里；库头里那 128 个 hex 字符不是它 |
| Windows 旧版 PCQQ | 库内直接可解 / 另说 | — | 与 NTQQ 完全不同的一套 |
| `login.db`（全局库） | 客户端硬编码常量 `BD156D6710D54D8782F4` | ✅ 可以 | **所有账号、所有机器都一样**，可用来枚举本机登录过的账号 |
| `.qqxlog` 日志 | 自研加密 mmap 容器 | ❌ | 不是腾讯 Mars xlog，目前无公开解密方案 |

一句话：**iOS/Android 的库可以"拿到文件就能解"；Windows 的库不行，必须趁 QQ 登录着的时候从内存里掏。**

---

## 1. 先搞清文件长什么样

NTQQ 的每个库都不是"裸 SQLCipher"，而是：

```text
[ 1024 字节 QQ 私有头 ][ SQLCipher 第 1 页 ][ 第 2 页 ] ... [ 第 N 页 ]
                        ^ 前 16 字节 = salt
```

- 页大小 `4096`，页尾保留区 `48` 字节 = `IV(16) + HMAC(20) + 填充(12)`
- 第 1 页布局：`[salt(16)][CT(4032)][IV(16)][HMAC(20)][pad(12)]`
- 普通页：`[CT(4048)][IV(16)][HMAC(20)][pad(12)]`
- KDF：`enc_key = PBKDF2-HMAC-SHA512(passphrase, salt, 4000, 32)`；`hmac_key = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3A, 2, 32)`
- 页 HMAC：`HMAC-SHA1(hmac_key, CT || IV || LE_u32(page_no))`

**为什么这点很重要**：文件大小永远 `≡ 1024 (mod 4096)`，不是 `mod 4096 == 0`。
一开始按"标准 SQLCipher"从偏移 0 取 salt，会怎么都解不开。

### 1024 字节私有头的结构

```text
00..15  "SQLite header 3\0"        ← 注意是 header 不是 format
16..31  04 00 10 00 ...            ← 固定常量
32..39  "QQ_NT DB"
40..43  u32 LE：后面 protobuf 的长度
44..    protobuf：
          field 2 (tag 0x12) = rand / 密钥材料
          field 3 (tag 0x1a) = "1.1.0.1"     版本
          field 4 (tag 0x22) = "HMAC_SHA1"   HMAC 算法
          field 5 (tag 0x28) = 时间戳
其余    全 0
```

**platform 差异就在这里**：iOS/Android 的 `field 2` 是 **8 个可打印字符**（例如 `Ab3dEf9Z`），
Windows 的 `field 2` 是 **128 个 hex 字符（64 字节）**。这两者语义完全不同，后面第 3、4 节展开。

### 判定密钥对不对：page-1 HMAC 就是 2^-160 的判据

不需要解密、不需要 SQLite，只要重算第 1 页的 HMAC 即可：

```python
def check_page1(page1: bytes, enc_key: bytes) -> bool:
    salt = page1[:16]
    hmac_key = pbkdf2_sha512(enc_key, bytes(b ^ 0x3A for b in salt), 2, 32)
    ct  = page1[16:4048]          # 4032 字节
    iv  = page1[4048:4064]
    mac = page1[4064:4084]
    return hmac_sha1(hmac_key, ct + iv + struct.pack("<I", 1)) == mac
```

有了这个 oracle，所有"猜密钥"的实验都能在毫秒级验证，不用碰数据库内容。

---

## 2. iOS / Android：★ 纯离线密钥公式

这是整件事最关键的一条，也是"早知道能省掉 90% 工作量"的一条：

```text
# 1. 账号目录名 = md5(md5(uid) + "nt_kernel")
dir_name = "nt_qq_" + md5(md5(uid) + b"nt_kernel")

# 2. 从库头 1024 字节里读 field 2，得到 rand（8 字符）
rand = header_field2

# 3. 口令
passphrase = md5(md5(uid) + rand)      # 32 个 hex 字符，就是这个 ASCII 串

# 4. SQLCipher 再自己 PBKDF2
enc_key = PBKDF2-HMAC-SHA512(passphrase, salt, 4000, 32)
```

也就是说：**库文件 + 账号 uid 就够了**，不需要内存、不需要服务器、不需要 hook。

### uid 从哪来

两条互相印证的路径：

1. **全局 `login.db`**（`nt_qq/global/nt_db/login.db`）：用硬编码预登录口令 `BD156D6710D54D8782F4`
   解密后读 `login_table`，列名是数字字符串，`"1000"` = uin，`"1001"` = uid，`"1007"` = 昵称。
   这个库**记录了本机登录过的所有账号**，是最好用的 uid 来源。
2. **反查目录名**：拿到候选 uid 集合后，用 `md5(md5(uid) + "nt_kernel")` 去匹配 `nt_qq_<hash>` 目录名。
   命中即确认映射关系（我们就是这样确认四个账号的）。

### 为什么这条公式值得单独拎出来

它推翻了"密钥只存在于内存 / 由服务器下发"的常见说法（那种说法**对 Windows 成立**，对 iOS/Android 不成立）。
一旦知道它，iOS 端的解密就是纯文件操作，可以在完全离线的机器上、对任意历史备份完成。

> 出处：Android NTQQ 9.1.50 的实测文章（见文末引用）。我们在 iOS QQ 9.3.55 上独立验证成立。

---

## 3. Windows：为什么拿不到

Windows NTQQ（我们测的是 `9.9.32-51246`）的库头 `field 2` 是 **128 个 hex 字符**，
第一反应会以为它是"64 字节的 rand"，于是去试：

```
md5(md5(uid) + f2_ascii)      ❌
md5(md5(uid) + hexdec(f2))    ❌
md5(f2_ascii)、sha256、base64、各种切片和拼接……
```

我们把 field2 的所有可切形态 × uid 的 6 种形态 × 4 种哈希 × 两种拼接顺序（十万级组合）
全打了一遍 page-1 HMAC，**零命中**。结论：`field 2` 不是那把口令。

### 真正的口令长什么样

在活着的、已登录的 QQ 进程内存里，能直接找到真正的口令：

- 它是 **16 个可打印字符**（例如 `#8xxxxxxxxxxx@uJ` 这种形态），**不是** md5、不是 hex；
- 它对**同一个账号的所有库**都相同（我们一次性验通了该账号 17 个 db：`nt_msg / group_info / emoji / settings / ...`），
  每个库各自的 salt 不同 → 各自 `PBKDF2(同一口令, 自己的 salt)` → **每个库密钥不同、口令相同**；
- 换账号密码就变（实测两个账号的口令不同），因此可以认为它是**按账号（或按账号+安装）稳定**的：
  **只要拿到一次，该账号历史上所有库都能解**。

### 官方口径也一致

参考项目 `QQBackup/QQDecrypt` 的 Windows 教程给出的方法就是：hook `sqlite3_key_v2`
看第三个参数（`pKey` / `nKey`），或直接扫内存；示例输出正是一个 16 字符口令。
`QQBackup/x_key_scanner` 则把这件事做成了非侵入式工具：**扫进程内存里紧挨
`\x09HMAC_SHA1` 标记的那 16 字节窗口**（native 版 SQLCipher codec 结构里标记和密钥挨着）。

### 实战取密钥的两个技巧

1. **锚点法**（参考项目用的）：找 `\x09HMAC_SHA1`，在 ±0x200 内按 16 字节对齐取候选，
   过滤"全部可打印非空白、且不全是字母数字"，逐个用 page-1 HMAC 验。Electron 版（Linux）
   密钥离锚点很远，则退化为"锚点最密集簇的中心附近找"。
2. **salt-hex 前缀法**（我们实际命中的那条，可作为补充）：
   QQ 在内存里会留下 `x'<64位hex enc_key><32位hex salt>'` 这样的字符串（`sqlcipher_export`
   相关路径），所以只要在内存里搜 **salt 的 ASCII hex**，它前面 64 个 hex 字符就是**已派生的
   32 字节密钥**，可以直接用。我们这次就是靠它先拿到 key、再用它反向确认 16 字符口令的。

两条路都要求：**QQ 正在运行、且该账号已登录**。进程一关，密钥就没了——这就是为什么
Windows 端的"事后取证"几乎无解。

### 于是我们承认了

- 被封账号在这台机器上**没有**留下密钥：pagefile / swapfile / minidump / CrashDumps 都翻了，没有；
- 想解 Windows 那份库，只能等账号解封后**登录一次**，或者登录时抓内存；
- 这一点没有变通：**Windows 库的密钥不在磁盘上**。

---

## 4. 走错的路（每条都值得记录）

| 尝试 | 结果 | 为什么不行 |
| --- | --- | --- |
| 服务器 ext4 删库恢复 | ❌ 只捞到 1 个无关 inode | QQ 换成了 NTQQ 后数据不再以明文 SQLite 落盘；服务器上那套是 NapCat/QCE 的运行时，早已被清 |
| 原始块设备全盘扫 | ❌ 只复原出 journal | 同上 |
| iOS 全盘 grep 密钥 | ❌ 0 命中 | 明文密钥不在磁盘上（iOS 侧密钥是**算出来的**，不是存的） |
| iOS 内存扫描 / hook SQLCipher | ❌ 未命中 | 其实**根本不需要**：库头 + uid 就能算（见第 2 节） |
| `.material` 文件 | ❌ | 那是 SQLCipher 的页备份，内容是密文 |
| `.qqxlog` 日志 | ❌ | 自研加密 mmap 容器，不是标准 xlog |
| QCE / NapCat 数据目录 | ❌ | 只有 token，从未真正导出过聊天记录 |
| pagefile / minidump | ❌ | 目标账号的密钥早已随进程退出消失；且 pagefile 常被系统独占（err=32/5） |
| Windows 库头 field2 反推口令 | ❌ | field2 不是口令（第 3 节） |
| 用 iOS 的密钥解 Windows 的库 | ❌ | 同一账号不同平台、不同 salt，密钥不通 |

**教训：先花 10 分钟确认"密钥到底在哪"，再决定要不要做重活。**
我们前半程是按"密钥由服务器下发、只在内存"这个（对 Windows 成立的）前提在推进，
结果 90% 的取证工作（内存 dump、pagefile、ext4、日志解密）都是不必要的。

---

## 5. 消息内容怎么读（40800 protobuf）

`nt_msg.db` 里正文在 `c2c_msg_table` / `group_msg_table` 的 `40800` 列（bytes，protobuf）。
外层是 `repeated MsgContent content = 40800`，实际用得到的字段：

| 字段号 | 含义 |
| --- | --- |
| `45002` | `content_type`：1=文本，2=图片/视频，5=表情/引用，3=文件，8=转发，16=旧版转发，17=系统 |
| `45101` | **正文文本**（文本消息就是它） |
| `45815` | `text_fallback`（重复 bytes）：表情包的 `[名称]` 回退文本 |
| `45600` | 表情包原始数据 |
| `45411/45412` | 图片宽高（用来区分"图片消息"和"文本占位"） |
| `45402/45405/45419` | 文件名 / 大小 / 扩展名（文件消息） |
| `47703/47705` | 名片、引用里的 uid / 昵称 |
| `47710/47713` | 被引用消息本体 / 引用摘要 |
| `49154/49155` | `ext_proto_ver` / `ext_timestamp` |

外层的表字段（常用）：`40001` 消息 ID，`40050` 时间戳，`40013` **方向/类型**
（`1` = 自己发的，`0` = 对方发的，另有 `2/3/4/5` 等），`40020` 发送者 uid，`40033` 发送者 QQ 号，
`40021` 私聊是**对方 uid** / 群聊是**群号**，`40030` 私聊对方 QQ 号，`40011` 消息类型，`40090` 发送者昵称。

### 一个很容易踩的坑

**不要用"把所有 length-delimited 字段都当文本"的土办法抽正文。**
那样会把 `sender_uid`、`ext_proto_ver`（`nt_1` 之类）、通道号等全部拼进正文，
导出的"聊天记录"看起来是乱码一样的元数据，训练出来的模型全是垃圾。
老老实实按 `content_type == 1` 取 `45101`，表情取 `45815`。

另外一个反直觉的统计：**自己发的消息里表情包占比极高**。
我们这批数据里，文本 : 表情 ≈ 3.9k : 2.0k（私聊），去重后真正可用的"我的独立文本"只有 4 千条左右。
想训"模仿某人说话"，语料规模通常就是这样被表情包吃掉一半的。

---

## 6. 一份可用的工具链

### 别人写的（优先用，别重复造）

- [QQBackup/QQDecrypt](https://github.com/QQBackup/QQDecrypt)：各平台教程 + 数据库字段文档（**先看这个**）
- [QQBackup/x_key_scanner](https://github.com/QQBackup/x_key_scanner)：从**运行中的** QQ 进程内存取密钥（跨平台，非侵入）
- [QQBackup/qq-win-db-key](https://github.com/QQBackup/qq-win-db-key)：各平台取密钥 / 导出脚本（含 Frida hook）
- [QQBackup/nt_msg_db_util](https://github.com/QQBackup/nt_msg_db_util)：**40800 的 .proto 定义与解析器**（本文第 5 节字段表就来自它）
- [QQBackup/QQ-History-Backup](https://github.com/QQBackup/QQ-History-Backup)：导出成 HTML 的完整项目
- [Mythologyli/qq-nt-db](https://github.com/Mythologyli/qq-nt-db) / [Myth's Blog](https://myth.cx/p/qq-nt-db)：Windows 版 IDA 逆向全过程

### 自己写的（本文配套）

| 脚本 | 作用 |
| --- | --- |
| `ntqq_decrypt.py` | SQLCipher v4 页解密 + `check_page1` 判定（本文件第 1 节的全部参数都在这里） |
| `derive_key_ios.py` | iOS/Android 离线口令推导（第 2 节公式）+ 目录名反查 uid |
| `decrypt_ios.py` | 整库解密成可打开的 `plain.db`（重建 SQLite 头，`integrity_check` 通过） |
| `scan_mem_key.py` | 活进程取密钥：锚点法 + salt-hex 前缀法，用 page-1 HMAC 验证 |
| `ntmsg_wire.py` | 不依赖 protobuf 运行时的 40800 最小解析器（字段表见第 5 节） |
| `build_corpus.py` | 按 `40013` 判方向、按 `45002/45101` 取正文，导出转录 + SFT 语料 |

---

## 7. 工程与合规建议

1. **备份先行**：动手前把原始库 + `-wal` + `-shm` 一起复制一份（`-wal` 里有尚未 checkpoint 的新消息）。
2. **先确认密钥来源**：iOS/Android 看库头（第 2 节）；Windows 只有内存一条路，且必须"人还在登录"。
3. **别在主力账号上做实验**：注入 / hook / 改客户端都可能触发风控，代价是封号。
4. **导出后立刻脱敏**：uin、uid、群号、salt、密钥、头像 URL 全部替换再上传。
5. **`login.db` 是硬编码口令可解的**——它包含本机所有登录过的账号 uin/uid/昵称，属于高敏感文件。
6. **合规**：本文技术仅用于**恢复自己账号的数据 / 安全研究**。未经授权读取他人聊天记录在多数司法辖区违法。

---

## 8. 致谢与引用

- NTQQ 数据库结构、`40800` 字段、各平台密钥获取思路：QQBackup 系列项目（QQDecrypt / x_key_scanner / qq-win-db-key / nt_msg_db_util）
- Windows IDA 逆向过程：Myth《QQ NT Windows 数据库解密+图片/文件清理》
- iOS/Android 离线密钥公式：`jishuzhan.net` 上关于 Android NTQQ 9.1.50 的实测文章
- SQLCipher 官方 API 与源码：<https://www.zetetic.net/sqlcipher/sqlcipher-api/>

> 本文不含任何真实账号、密钥或聊天内容。
