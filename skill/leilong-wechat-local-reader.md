---
name: leilong-wechat-local-reader
description: 在本机读取并分析微信 4.x 的聊天记录（Windows）。当用户说「看看我微信最近在聊什么」「帮我找某人说过的那句话」「总结这段聊天」「我微信里谁提过 X」「查聊天记录里的课表/快递/转账」「装一个能读微信记录的工具」，或需要处理 xwechat_files / SQLCipher / 微信数据库密钥时使用。不适用于：导出手机微信、微信云备份、读取别人的账号、企业微信、需要图片/语音/文件内容的场景。
metadata:
  author: Leilong
---

# Leilong WeChat Local Reader

微信 4.x 的本地库是 SQLCipher 加密的。这套流程用 `wechat_*` 工具把它解密成**只读副本**再查询，不改动微信原始文件。

## 环境事实

- Windows + 微信 4.x（4.0.x 与 4.1.11+ 均验证过）。
- 数据目录：`%USERPROFILE%\Documents\xwechat_files\<wxid>_<4位hex>\db_storage`。
- 解密缓存：`%USERPROFILE%\.dsh\cache\wechat-reader`（含明文，注意磁盘安全）。
- 取内存密钥需要微信**正在运行且已登录**；非管理员亦可。
- 装了插件后**必须重启 DSH** 才加载新模块。

## 三步流程

### 1. 先自检

```
wechat_status()
```

看 `账号`/`数据目录` 对不对、密钥来源、`会话数` 是否 > 0。异常就查文末排错表，别继续。

### 2. 按问题选工具

| 用户想干什么 | 调用 |
|---|---|
| 掌握最近动态 | `wechat_sessions(limit=20)` |
| 看和某人的聊天 | `wechat_history(chat="备注或群名", limit=50)` |
| 限定时间段 | `wechat_history(chat=..., start="2026-10-01", end="2026-10-29")` |
| 找「谁提过 X」 | `wechat_search(keyword="X", limit=30)` |
| 只在某个聊天里找 | `wechat_search(keyword="X", chat="某人")` |
| 确认 wxid | `wechat_contacts(query="张")` |

`chat` 支持备注名、昵称、群名、wxid，自动模糊匹配。

### 3. 回答带证据

- 引用消息给出**日期 + 说话人**：如「10-24 15:51 某人发的排课」。
- 多来源时**交叉验证**（排课表 + 前一天通知 + 当日值班教师，三者一致再下结论）。
- 区分「记录里写死的」与「推断的」；依据是图片就说图片读不到，别硬编。

## 领域知识（踩过的坑）

- **两代密钥**：4.0.x 内存里是明文 `x'<enc_key><salt>'`；4.1.11+ 是 `com.Tencent.WCDB.Config.Cipher` 对象里**XOR 掩码**后的同一串。掩码与结构偏移随版本变。
- **不要**把 Linux 的 `PBKDF2(主密钥, salt, 256000)` 套到 Windows：Windows 拿到的就是最终 enc_key。
- 候选密钥**必须通过 page1 的 HMAC** 才算对。
- 长消息正文是 **zstd 压缩 BLOB**，SQL `LIKE` 搜不到；工具已解码后再匹配。
- 群消息形如 `wxid_xxx:\n内容`，要拆发送者再映射名字。
- 图片(3)/语音(34)/视频(43)/表情(47) 正文是 protobuf/XML，**只有标签**，不要假装能读内容。
- 最新消息可能在 `-wal` 里；比微信少就让用户点开对应聊天刷新。
- 不要建议降级微信：schema 已升级、旧安装包下架、服务端会拦低版本。

## 边界

- 只读**用户自己**账号；要求读别人的微信直接拒绝。
- 绝不把密钥、`keys*.json`、`master.key`、解密后的 `.db` 提交到 git 或贴进对话。
- 只清理 `%USERPROFILE%\.dsh\cache\wechat-reader`，不要碰 `xwechat_files`。

## 验证

1. `wechat_status()` → `会话数 > 0`
2. `wechat_history(chat="<最近聊过的人>", limit=3)` → 返回带时间的真实消息

两条都过才算链路正常。

## 排错

| 现象 | 处理 |
|---|---|
| `Weixin.exe 未运行` | 打开微信并登录后重试 |
| `need-master-key` | 自动提取失败；用 `wechat_set_master_key` 给 passphrase |
| `主密钥和这个账号对不上` | 密钥属于别的账号 |
| `密钥校验失败` | 微信重新加密过；重启微信后缓存会自动失效重取 |
| 会话正常但历史为空 | 该聊天无消息，或表名规则变了 → 看「消息库」行 |
| 群成员显示 wxid | `contact.db` 里没有此人，正常 |

## 适配新版本

见仓库 `docs/key-extraction.md`：先跑 `wxkey.py` 看 `mode` 与 `matched`，再决定改正则、掩码还是结构偏移。校验标准永远是 page1 HMAC。
