/**
 * 查询层 + 工具层测试：造一套"明文微信库"（结构与 4.x 一致），
 * 走真实 store.js / index.js 代码路径，验证会话、聊天、搜索、联系人。
 *
 * 这同时验证了 store.js 的"已是明文库则跳过解密"分支。
 */
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { zstdCompressSync } from 'node:zlib'
import assert from 'node:assert/strict'

import * as store from '../lib/store.js'
import { apply } from '../lib/index.js'

const md5 = (s) => createHash('md5').update(s, 'utf8').digest('hex')
const ACCOUNT_DIR = 'wxid_abc123def456_ab12' // 微信目录名 = wxid_xxx_4位hex
const EXPECT_ACCOUNT = 'wxid_abc123def456'   // 去掉结尾 _4位hex
const ME = 'wxid_me_0000'

const root = mkdtempSync(join(tmpdir(), 'wxfixture-'))
const wxRoot = join(root, 'xwechat_files')
const dbDir = join(wxRoot, ACCOUNT_DIR, 'db_storage')
for (const sub of ['session', 'contact', 'message']) mkdirSync(join(dbDir, sub), { recursive: true })

const now = Math.floor(Date.now() / 1000)

// ---- session.db ----
{
  const db = new DatabaseSync(join(dbDir, 'session', 'session.db'))
  db.exec(`CREATE TABLE SessionTable (
    username TEXT, unread_count INTEGER, summary TEXT, last_timestamp INTEGER,
    last_msg_type INTEGER, last_msg_sender TEXT, last_sender_display_name TEXT)`)
  const ins = db.prepare('INSERT INTO SessionTable VALUES (?,?,?,?,?,?,?)')
  ins.run('wxid_friend_0001', 3, '好的，明天见', now - 60, 1, ME, '')
  // 群聊摘要带发送者前缀
  ins.run('12345678@chatroom', 0, 'wxid_friend_0001:\n群里发的资料我收到了', now - 300, 1, 'wxid_friend_0001', '小王')
  ins.run('wxid_nomsg_0002', 0, '', 0, 0, '', '')
  db.close()
}

// ---- contact.db ----
{
  const db = new DatabaseSync(join(dbDir, 'contact', 'contact.db'))
  db.exec('CREATE TABLE contact (username TEXT, nick_name TEXT, remark TEXT, alias TEXT)')
  const ins = db.prepare('INSERT INTO contact VALUES (?,?,?,?)')
  ins.run('wxid_friend_0001', '阿伟', '张伟', 'zhangwei')
  ins.run('12345678@chatroom', '项目讨论组', '', '')
  ins.run(ME, '我自己', '', '')
  db.close()
}

// ---- message_0.db ----
{
  const db = new DatabaseSync(join(dbDir, 'message', 'message_0.db'))
  db.exec('CREATE TABLE Name2Id (user_name TEXT)')
  db.prepare('INSERT INTO Name2Id VALUES (?)').run('wxid_friend_0001')
  db.prepare('INSERT INTO Name2Id VALUES (?)').run('12345678@chatroom')

  for (const user of ['wxid_friend_0001', '12345678@chatroom']) {
    const table = `Msg_${md5(user)}`
    db.exec(`CREATE TABLE [${table}] (
      local_id INTEGER PRIMARY KEY, local_type INTEGER, create_time INTEGER,
      message_content TEXT, WCDB_CT_message_content INTEGER)`)
    const ins = db.prepare(`INSERT INTO [${table}] (local_type, create_time, message_content, WCDB_CT_message_content) VALUES (?,?,?,?)`)
    if (user === 'wxid_friend_0001') {
      ins.run(1, now - 7200, '在吗？想问问那个合同的事', 0)
      ins.run(1, now - 7100, '支付宝到账 200 元', 0)
      // zstd 压缩的大段文本，模拟 WCDB 压缩列
      const long = '这是一段很长的会议纪要。'.repeat(40)
      ins.run(1, now - 7000, zstdCompressSync(Buffer.from(long, 'utf8')), 4)
      ins.run(3, now - 6900, null, 0)
      ins.run(1, now - 60, '好的，明天见', 0)
    } else {
      ins.run(1, now - 400, 'wxid_friend_0001:\n群里发的资料我收到了', 0)
    }
  }
  db.close()
}
writeFileSync(join(dbDir, 'message', 'message_fts.db'), 'not-a-real-db') // 干扰项，不该被读

// ---- 1. 账号解析 ----
const CFG = { dbDir: wxRoot, cacheDir: join(root, 'cache') }
const account = store.resolveAccount(CFG)
assert.equal(account.account, EXPECT_ACCOUNT)
console.log(`[1] 账号解析: ${account.account}  ${account.dbDir}`)

// ---- 2. 明文库不需要密钥 ----
const keys = store.ensureKeys(account, CFG)
assert.equal(keys.plaintext, true)
console.log('[2] 明文库跳过密钥提取')

// ---- 3. 联系人 ----
const contacts = store.loadContacts(account, keys)
assert.equal(contacts.get('wxid_friend_0001').display, '张伟')
console.log('[3] 联系人: 张伟 / 项目讨论组')

// ---- 4. 会话 ----
const sessions = store.listSessions(account, keys, contacts, 10)
assert.equal(sessions.length, 2)
assert.equal(sessions[0].display, '张伟')
assert.equal(sessions[1].isGroup, true)
assert.ok(!sessions[1].summary.includes('wxid_friend_0001:\n'), '群摘要应只留正文')
console.log('[4] 会话:', sessions.map((s) => `${s.display}${s.isGroup ? '[群]' : ''}`).join(' / '))

// ---- 5. 聊天记录 ----
const res = store.readMessages(account, keys, contacts, 'wxid_friend_0001', { limit: 10 })
assert.equal(res.found, true)
assert.equal(res.messages.length, 5)
assert.equal(res.messages[0].text, '在吗？想问问那个合同的事')
assert.ok(res.messages[2].text.startsWith('这是一段很长的会议纪要'), 'zstd 压缩内容应被解压')
assert.equal(res.messages[3].text, '[图片]')
assert.ok(res.messages.at(-1).time > res.messages[0].time, '应按时间升序')
console.log('[5] 聊天记录:', res.messages.length, '条，含解压/z图片标签')
console.log('    ' + res.messages.slice(0, 3).map((m) => m.text.slice(0, 18)).join(' | '))

// ---- 6. 群聊发送者 ----
const grp = store.readMessages(account, keys, contacts, '12345678@chatroom', { limit: 10 })
assert.equal(grp.messages[0].sender, 'wxid_friend_0001')
assert.equal(grp.messages[0].senderName, '张伟')
assert.equal(grp.messages[0].text, '群里发的资料我收到了')
console.log('[6] 群聊发送者解析: 张伟: 群里发的资料我收到了')

// ---- 7. 搜索 ----
const hits = store.searchMessages(account, keys, contacts, '合同', { limit: 10 })
assert.equal(hits.length, 1)
assert.equal(hits[0].chat, '张伟')
console.log('[7] 搜索「合同」:', hits.length, '条 →', hits[0].chat)

// ---- 8. 时间过滤 ----
const recent = store.readMessages(account, keys, contacts, 'wxid_friend_0001', { limit: 10, since: now - 120 })
assert.equal(recent.messages.length, 1)
console.log('[8] 时间过滤: 最近 2 分钟 1 条')

// ---- 9. 工具层：注册 + 调用 ----
const tools = new Map()
const ctx = {
  tools: {
    register(def) {
      assert.equal(typeof def.output?.render, 'function', `${def.name} 缺少 output.render`)
      assert.ok(def.parameters && def.parameters.type === 'object', `${def.name} parameters 必须是 JSON Schema`)
      tools.set(def.name, def)
    },
  },
}
apply(ctx, CFG)
assert.deepEqual(
  [...tools.keys()].sort(),
  ['wechat_contacts', 'wechat_history', 'wechat_search', 'wechat_sessions', 'wechat_set_master_key', 'wechat_status'],
)
console.log('[9] 注册工具:', [...tools.keys()].join(', '))

const call = async (n, args) => tools.get(n).execute(args, {})

const outSessions = await call('wechat_sessions', { limit: 5 })
assert.ok(outSessions.includes('张伟'))
console.log('\n--- wechat_sessions ---\n' + outSessions)

const outHistory = await call('wechat_history', { chat: '张伟', limit: 10 })
assert.ok(outHistory.includes('合同'))
console.log('\n--- wechat_history(张伟) ---\n' + outHistory)

const outSearch = await call('wechat_search', { keyword: '会议纪要' })
assert.ok(outSearch.includes('会议纪要'))
console.log('\n--- wechat_search(会议纪要) ---\n' + outSearch.slice(0, 300))

const outContacts = await call('wechat_contacts', { query: '张' })
assert.ok(outContacts.includes('备注: 张伟'))
console.log('\n--- wechat_contacts(张) ---\n' + outContacts)

const outStatus = await call('wechat_status', {})
console.log('\n--- wechat_status ---\n' + outStatus)

// 找不到的人要给人话
const missing = await call('wechat_history', { chat: '不存在的人' })
assert.ok(missing.includes('找不到'))
console.log('\n--- 找不到时 ---\n' + missing)

console.log('\n全部通过  ' + root)
