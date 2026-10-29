# 密钥提取原理与适配指南

微信 4.x 的 `db_storage/*.db` 是 SQLCipher 加密的：文件头不是 `SQLite format 3\0`，而是 16 字节随机 salt。

## 页面格式（与这两个版本一致）

```
page 4096 bytes, reserve 80
p == 1 : [salt 16][ciphertext 4000][IV 16][HMAC 64]
p >  1 : [ciphertext 4016][IV 16][HMAC 64]
AES-256-CBC，无 padding
mac_key = PBKDF2-SHA512(enc_key, salt ^ 0x3a, 2 轮, 32B)
HMAC-SHA512(ciphertext || IV || pageNo-LE32) == 页尾 64 字节
```

`salt` 就藏在每页第 1 页的头部，所以「候选密钥 + 该库 page1 的 HMAC」就能判定真假，**不需要知道明文**。

## 两代密钥方案

### 4.0.x：内存里直接是 enc_key

微信把 `x'<64 hex enc_key><32 hex salt>'` 以 ASCII 明文缓存在进程内存里。扫描所有可读内存区域，用正则找这个形状，按结尾 32 hex 匹配 salt，再用 page1 的 HMAC 校验即可。

对应实现：`plugin/lib/wxkey.py` 的 `scan()`。

### 4.1.11+：Config.Cipher + XOR 掩码

明文 `x'...'` 不再出现，因为字符串被 XOR 掩码了。要走的链路：

```
内存中字符串 "com.Tencent.WCDB.Config.Cipher"
  → 引用它的 std::string 节点（内存里表现为 (数据指针, 长度) 两个 qword 相邻）
  → node + 0x28 指向 config 对象
  → config + 0x88 是缓冲描述：+0x08 数据指针，+0x10 长度（通常 99）
  → 读出 blob，按 32 字节掩码 XOR 解码
  → 得到 x'<64 hex enc_key><32 hex salt>'
  → 用结尾的 salt 定位库，再 HMAC 校验
```

blob 长度 99 = `x'` + 64 + 32 + `'`。

**掩码是固定 32 字节**，取自该版本 `Weixin.dll` 中的一段代码字节。当前掩码见 `wxkey.py` 的 `CONFIG_MASK`。

对应实现：`plugin/lib/wxkey.py` 的 `config_cipher_scan()`。

## 为什么不用 PBKDF2(主密钥, salt, 256000)

Linux / macOS 版只保留 passphrase，要靠调试器在派生瞬间抓寄存器，再 `PBKDF2-SHA512(passphrase, db_salt, 256000)` 得到每库密钥。**Windows 版不需要**：`Config.Cipher` 里直接就是每个库最终的 enc_key。把 Linux 那套套到 Windows 上会一直失败（本项目早期就踩过这个坑，浪费两小时）。

只有自动提取全失败时，才退回「用户提供 passphrase → PBKDF2」这条路，即 `wechat_set_master_key`。

## 微信升级后怎么适配

1. 先跑自检：

   ```powershell
   python plugin\lib\wxkey.py --db-dir "%USERPROFILE%\Documents\xwechat_files\<wxid_x>\db_storage"
   ```

   输出里的 `mode` 说明走了哪条路，`stats.matched` 是命中库数。

2. 若 `mode` 缺失或 `matched: 0`：
   - `4.0` 路径失效 → 确认 `scan()` 的正则与 salt 匹配逻辑；
   - `4.1` 路径失效 → 大概率是**掩码或结构偏移变了**。用 `x64dbg` / WinDbg 在 `x'` 解码处下断，或在 `Weixin.dll` 里重新提取掩码；也可以参考 [wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) 的「字符串交叉引用定位函数」做法，比硬编码偏移更耐用。

3. 无论怎么改，**校验标准只有一条**：候选密钥必须通过该库 page1 的 HMAC。没通过的一律丢弃。

## 排错速查

| 现象 | 含义 |
|---|---|
| `weixin-not-running` | `Weixin.exe` 没运行 / 没登录 |
| `no-key` + `need-master-key` | 两条自动路径都没命中，需要手动给 passphrase |
| `master-mismatch` | 给的密钥不属于当前账号 |
| `key-stale` | 缓存密钥过期（微信重新加密过），重取即可 |
| `matched` 数少于库数 | 部分库从未被微信打开过，无妨 |
