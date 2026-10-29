/**
 * 真机自检：用真实的微信数据跑一遍取密钥 → 解密 → 查询。
 * 前提：微信（Weixin.exe）正在运行并已登录。
 *
 * 运行: node dev/live-check.mjs
 */
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import * as store from '../lib/store.js'

const config = {}
const step = (n, msg) => console.log(`\n[${n}] ${msg}`)

const t0 = Date.now()
const account = store.resolveAccount(config)
step(1, `账号: ${account.account}`)
console.log(`    ${account.dbDir}`)

const t1 = Date.now()
const keys = store.ensureKeys(account, config)
step(2, `密钥: ${Object.keys(keys.keys).length} 个库, 用时 ${Date.now() - t1}ms`)
if (keys.stats) console.log(`    扫描 ${keys.stats.readable_mb}MB 内存, ${keys.stats.seconds}s, 命中 ${keys.stats.candidates} 个候选`)
if (keys.missing?.length) console.log(`    未拿到密钥: ${keys.missing.join(', ')}`)

const contacts = store.loadContacts(account, keys, config)
step(3, `联系人: ${contacts.size}`)

const sessions = store.listSessions(account, keys, contacts, 10, config)
step(4, `会话（前 10）:`)
for (const s of sessions) {
  console.log(`    ${new Date(s.last_timestamp * 1000).toLocaleString('zh-CN')}  ${s.display}${s.isGroup ? ' [群]' : ''}`)
  console.log(`        ${String(s.summary).replace(/\s+/g, ' ').slice(0, 80)}`)
}

if (sessions.length) {
  const top = sessions[0]
  const t2 = Date.now()
  const res = store.readMessages(account, keys, contacts, top.username, { limit: 10 }, config)
  step(5, `${top.display} 最近 ${res.messages.length} 条（解密+查询 ${Date.now() - t2}ms, 库=${res.db || '-'}）`)
  for (const m of res.messages) {
    console.log(`    ${new Date(m.time * 1000).toLocaleString('zh-CN')}  ${m.senderName || m.sender ? (m.senderName || m.sender) + ': ' : ''}${String(m.text).replace(/\s+/g, ' ').slice(0, 100)}`)
  }

  const kw = process.argv[2]
  if (kw) {
    const t3 = Date.now()
    const hits = store.searchMessages(account, keys, contacts, kw, { limit: 5 }, config)
    step(6, `搜索「${kw}」: ${hits.length} 条（${Date.now() - t3}ms）`)
    for (const h of hits) {
      console.log(`    [${new Date(h.time * 1000).toLocaleString('zh-CN')}] ${h.chat}: ${String(h.text).slice(0, 80)}`)
    }
  }
}

// 数据新鲜度：最近一条消息 vs 库文件改时间
const msgDb = join(account.dbDir, 'message', 'message_0.db')
try {
  const st = statSync(msgDb)
  step(7, `message_0.db: ${(st.size / 1024 / 1024).toFixed(1)}MB, 更新于 ${new Date(st.mtimeMs).toLocaleString('zh-CN')}`)
} catch {}

console.log(`\n总计 ${Date.now() - t0}ms`)
