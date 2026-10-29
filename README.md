# wechat-local-reader

让 AI 直接读你**本机**的微信 4.x 聊天记录 —— 一个 DeepSeek Harness 插件 + 一份可复用的 Skill。

只读：微信原始文件一个字节都不改，解密副本落在缓存目录。

用它问 AI：

> 看看我微信最近在聊什么
> 把我和某某这个月的聊天总结一下，重点是他提的要求
> 谁跟我提过「合同」？原话是什么
> 我今天的英语课在什么时候

## 特性

| 能力 | 说明 |
|---|---|
| 会话列表 | 谁在聊、最后一条摘要、未读数 |
| 聊天记录 | 按人/群取消息，支持时间范围与条数 |
| 全文搜索 | 全库或指定聊天；**能搜到被 zstd 压缩的长消息** |
| 群聊还原 | 把 `wxid:\n内容` 拆出发送者并映射备注名 |
| 增量 | 自动把 `-wal` 里未落盘的消息 patch 进副本 |
| 多账号 | 自动选最近活跃账号，也可在配置里指定 |

## 支持版本与原理

微信本地库是 SQLCipher 加密的，直接打不开。插件要拿到每个库的密钥：

| 微信版本 | 密钥来源 | 状态 |
|---|---|---|
| 4.0.x | 进程内存里明文缓存 `x'<enc_key><salt>'` | ✅ 自动 |
| 4.1.11+ | 内存里 `com.Tencent.WCDB.Config.Cipher` 对象的 blob，**XOR 掩码**后的 `x'<enc_key><salt>'` | ✅ 自动（已在 4.1.15.56 验证 20/20 个库） |
| 已解密的库 | 目录里本身就是明文 SQLite | ✅ 直接读 |

拿到密钥后：AES-256-CBC（page 4096 / reserve 80）逐页解密 → WAL 增量 → `node:sqlite` 只读查询。

细节见 [docs/key-extraction.md](docs/key-extraction.md)。

## 安装

前置：Windows、微信 4.x、DeepSeek Harness（`@deepseek-ai/dsh`）。

```powershell
# 1. 复制插件
powershell -ExecutionPolicy Bypass -File .\plugin\install.ps1

# 2. 重启 DeepSeek Harness
```

`install.ps1` 会：

1. 把插件复制到 `%USERPROFILE%\.dsh\plugins\wechat-reader`
2. 在 `%USERPROFILE%\.dsh\profiles\<profile>\cordis.patch.yml` 追加一条 insert 记录
   （原文件先备份为 `cordis.patch.yml.bak-<时间戳>`）

卸载：

```powershell
powershell -ExecutionPolicy Bypass -File .\plugin\install.ps1 -Uninstall
```

## 工具

| 工具 | 作用 |
|---|---|
| `wechat_status` | 自检：账号、目录、库大小、密钥来源、会话数 |
| `wechat_sessions` | 最近会话 |
| `wechat_history` | 某个聊天/群的消息，支持 `start` / `end` |
| `wechat_search` | 全库或指定聊天搜关键词 |
| `wechat_contacts` | 按备注/昵称/wxid 搜联系人 |
| `wechat_set_master_key` | 手动提供主密钥（自动提取失败时的兜底） |

`chat` / `query` 支持备注名、昵称、群名模糊匹配，不用记 wxid。

## 测试

```powershell
node plugin\dev\test-sqlcipher.mjs   # 加解密 / HMAC / WAL patch
node plugin\dev\test-master.mjs      # 主密钥 PBKDF2 派生
node plugin\dev\test-queries.mjs     # 会话 / 聊天 / 搜索 / 工具注册（明文 fixture）
node plugin\dev\live-check.mjs 关键词  # 真机自检（需微信运行）
```

三套离线测试不接触真实微信数据。

## 目录结构

```
plugin/         DSH 插件（ESM，零运行时依赖，只用 node 内置模块 + 系统 python）
  lib/index.js      插件入口，注册 wechat_* 工具
  lib/store.js      密钥管理、解密缓存、查询
  lib/sqlcipher.js  SQLCipher 页解密 + WAL patch
  lib/wxkey.py      从 Weixin.exe 内存提取密钥（ctypes，纯标准库）
  dev/              测试与真机自检
skill/          可复用的 Agent Skill（中文，含踩坑记录）
docs/           密钥提取原理与适配指南
```

## 安全与边界

- 只读**你自己**账号在本机的数据。不要用它访问别人的微信。
- 解密缓存位于 `%USERPROFILE%\.dsh\cache\wechat-reader`，**包含明文聊天记录**（以及可能的 `master.key`），注意磁盘安全。
- 不采集、不上传、不联网；除微信自身数据目录外不读其它位置。
- 只解析文本类消息。图片、语音、视频、文件只给类型标签，不做附件解密。

## 已知限制

- 聊天记录以微信客户端为准；WAL 未落盘时可能少几条（点开对应聊天即可刷新）。
- 群成员显示名依赖 `contact.db`，通讯录里没有的成员会显示 wxid。
- 微信升级可能改动加密参数或表结构，维护点见 [docs/key-extraction.md](docs/key-extraction.md)。

## 致谢

密钥提取思路来自这些开源工作，本项目只是把它们整合进 DSH 工具链：

- [wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) — 4.1+ 的 `Config.Cipher` 扫描与 XOR 掩码
- [wechat-decrypt](https://github.com/328336690/wechat-decrypt) — 4.0 内存扫描与表结构
- [wechat-4.1.12-decrypt](https://github.com/stargazer-2026/wechat-4.1.12-decrypt) — PBKDF2 派生与 Frida 路线

## License

MIT © 2026 Leilong
