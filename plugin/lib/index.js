/**
 * DSH 插件：微信本地聊天记录读取
 *
 * 暴露 wechat_* 工具，让模型直接查询本机微信 4.x 的会话、聊天记录、联系人。
 * 全部只读；解密产物落在缓存目录。
 */
import {
  WeChatError, ensureKeys, loadContacts, listSessions, readMessages,
  resolveAccount, searchMessages, displayName, withDb, deriveKeysFromMaster,
  saveMasterKey, readMasterKey,
} from './store.js'

export const name = 'wechat-reader'
export const inject = ['tools']

const HINT = '\n\n提示：需要微信正在运行并已登录（数据库密钥只存在于运行中的 Weixin.exe 内存里）。'

function textResult(text) {
  return {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  }
}

function fail(err, extra = '') {
  if (err instanceof WeChatError) {
    const hints = {
      'weixin-not-running': '请先打开微信客户端并登录，再重试。',
      'no-key': '请确认微信已登录，并随便点开几个聊天，然后重试。',
      'need-master-key': '微信 4.1.11+ 改用主密钥派生库密钥。用 wechat_set_master_key 提供一次 64 位十六进制主密钥即可。',
      'master-mismatch': '这个主密钥不属于当前账号，或账号切换过。',
      'bad-master': '主密钥格式应为 64 位十六进制（32 字节）。',
      'key-stale': '微信可能重新加密了数据库。关闭并重新打开微信后重试。',
      'no-python': '没找到 Python 运行时，无法从微信内存取密钥。',
      'no-wechat-dir': '没在默认位置找到微信数据目录，可在插件配置里用 dbDir 指定。',
    }
    return `❌ ${err.message}${hints[err.code] ? `\n${hints[err.code]}` : ''}${extra}`
  }
  return `❌ ${err?.message || err}${extra}`
}

/** 每次调用都重新解析账号 + 密钥（内部有缓存，代价很小）。 */
function prepare(config) {
  const account = resolveAccount(config)
  const keys = ensureKeys(account, config)
  const contacts = loadContacts(account, keys, config)
  return { account, keys, contacts }
}

function fmtTime(ts, withDate = true) {
  if (!ts) return '-'
  const d = new Date(ts * 1000)
  const p = (n) => String(n).padStart(2, '0')
  const md = `${p(d.getMonth() + 1)}-${p(d.getDate())}`
  const hm = `${p(d.getHours())}:${p(d.getMinutes())}`
  return withDate ? `${d.getFullYear()}-${md} ${hm}` : `${md} ${hm}`
}

/** 接受 2026-10-01 / 2026-10-01 12:30 / 数字时间戳，返回秒。 */
function parseTime(v) {
  if (v == null || v === '') return undefined
  if (typeof v === 'number') return Math.trunc(v)
  const s = String(v).trim()
  if (/^\d{9,13}$/.test(s)) {
    const n = Number(s)
    return n > 1e12 ? Math.trunc(n / 1000) : n
  }
  const m = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(s)
  if (!m) return undefined
  const [, y, mo, d, h = '0', mi = '0', se = '0'] = m
  return Math.floor(new Date(+y, +mo - 1, +d, +h, +mi, +se).getTime() / 1000)
}

/** 名字/备注/wxid/群名 → username。 */
function resolveChat(contacts, sessions, input) {
  const raw = String(input || '').trim()
  if (!raw) return null
  if (raw.includes('@chatroom') || raw.startsWith('wxid_') || raw.startsWith('gh_')) return raw
  if (contacts.has(raw)) return raw

  const lower = raw.toLowerCase()
  const pool = [...contacts.values()]
  let hit = pool.find((c) => c.display.toLowerCase() === lower)
  if (hit) return hit.username
  hit = pool.find((c) => c.remark && c.remark.toLowerCase() === lower)
  if (hit) return hit.username
  hit = pool.find((c) => c.display.toLowerCase().includes(lower))
  if (hit) return hit.username
  hit = pool.find((c) => c.nick && c.nick.toLowerCase().includes(lower))
  if (hit) return hit.username
  const s = sessions.find((x) => x.display && x.display.toLowerCase().includes(lower))
  return s ? s.username : null
}

export function apply(ctx, config = {}) {
  const cfg = {
    account: config.account,
    dbDir: config.dbDir,
    cacheDir: config.cacheDir,
    python: config.python,
  }

  ctx.tools.register({
    name: 'wechat_status',
    description:
      '检查微信聊天记录是否可读：账号、数据目录、密钥是否已取得、各库大小与最后更新时间、会话数量。'
      + '在其它 wechat_* 工具报错时先用它定位问题。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: textResult(),
    async execute() {
      try {
        const account = resolveAccount(cfg)
        let keys
        const sessions = (() => {
          try {
            keys = ensureKeys(account, cfg)
            const contacts = loadContacts(account, keys, cfg)
            return listSessions(account, keys, contacts, 500, cfg)
          } catch (err) {
            return { error: err }
          }
        })()
        const { statSync } = await import('node:fs')
        const { join } = await import('node:path')
        const dbs = ['session/session.db', 'contact/contact.db', 'message/message_0.db']
        const lines = []
        lines.push(`账号: ${account.account}`)
        lines.push(`数据目录: ${account.dbDir}`)
        const master = readMasterKey(cfg)
        lines.push(`主密钥: ${master ? '已配置（可离线派生）' : '未配置（会尝试内存自动提取）'}`)
        for (const rel of dbs) {
          const p = join(account.dbDir, rel.replaceAll('/', '\\'))
          try {
            const st = statSync(p)
            lines.push(`  ${rel}: ${(st.size / 1024 / 1024).toFixed(1)}MB, 更新于 ${fmtTime(Math.floor(st.mtimeMs / 1000))}`)
          } catch {
            lines.push(`  ${rel}: 不存在`)
          }
        }
        if (Array.isArray(sessions)) {
          const active = sessions.filter((s) => s.last_timestamp > 0)
          lines.push(`会话数: ${active.length}（有消息记录的）`)
          const newest = active[0]
          if (newest) lines.push(`最新一条: ${newest.display} · ${fmtTime(newest.last_timestamp)} · ${oneLine(newest.summary, 60)}`)
        } else {
          lines.push(`⚠️ 读取会话失败: ${fail(sessions.error)}`)
        }
        // 消息库结构自检：表名规则变了能马上看出来
        try {
          if (!keys) throw new Error('数据库密钥未取得，跳过结构检查')
          const schema = withDb(account, keys, 'message/message_0.db', (db) => {
            const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name)
            return {
              msgTables: tables.filter((t) => t.startsWith('Msg_')).length,
              hasName2Id: tables.includes('Name2Id'),
            }
          }, cfg)
          lines.push(`消息库: ${schema.msgTables} 个会话表, Name2Id ${schema.hasName2Id ? '存在' : '缺失'}`)
        } catch (err) {
          lines.push(`⚠️ 消息库结构检查失败: ${err?.message || err}`)
        }
        return lines.join('\n')
      } catch (err) {
        return fail(err, HINT)
      }
    },
  })

  ctx.tools.register({
    name: 'wechat_set_master_key',
    description:
      '保存微信数据库主密钥（64 位十六进制）。微信 4.1.11 起每个库的密钥由「主密钥 + 库 salt」'
      + '经 PBKDF2-SHA512(256000) 派生，自动内存扫描可能取不到；提供一次主密钥后，'
      + '所有库密钥会自动派生并逐一校验，之后 wechat_* 工具即可正常读取。',
    parameters: {
      type: 'object',
      properties: {
        key: { type: 'string', description: '64 位十六进制主密钥（32 字节）' },
      },
      required: ['key'],
      additionalProperties: false,
    },
    output: textResult(),
    async execute(args) {
      try {
        const account = resolveAccount(cfg)
        const { keys, missing } = deriveKeysFromMaster(account, args.key, cfg)
        const saved = saveMasterKey(cfg, args.key)
        const lines = [
          `主密钥已保存（${saved.slice(0, 8)}…），验证通过：${Object.keys(keys).length} 个库可解密。`,
        ]
        if (missing.length) lines.push(`未匹配的库（${missing.length} 个）：${missing.slice(0, 6).join(', ')}`)
        lines.push('现在可以直接问「我微信最近在聊什么」。')
        return lines.join('\n')
      } catch (err) {
        return fail(err)
      }
    },
  })

  ctx.tools.register({
    name: 'wechat_sessions',
    description:
      '列出微信最近的会话（谁在聊、最后一条消息摘要、未读数、时间）。'
      + '用来掌握最近动态，再决定深入读哪个聊天。',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: '返回多少个会话，默认 25' },
      },
      additionalProperties: false,
    },
    output: textResult(),
    async execute(args) {
      try {
        const { account, keys, contacts } = prepare(cfg)
        const limit = clampInt(args.limit, 25, 1, 200)
        const rows = listSessions(account, keys, contacts, limit, cfg)
        if (rows.length === 0) return '没有会话记录。'
        const out = [`最近 ${rows.length} 个会话（账号 ${account.account}）`, '']
        for (const r of rows) {
          const tag = r.isGroup ? ' [群]' : ''
          const unread = r.unread_count > 0 ? ` (${r.unread_count} 未读)` : ''
          const who = r.senderDisplay && r.isGroup ? `${r.senderDisplay}: ` : ''
          out.push(`${fmtTime(r.last_timestamp)}  ${r.display}${tag}${unread}`)
          out.push(`    ${who}${oneLine(r.summary, 200)}`)
        }
        return out.join('\n')
      } catch (err) {
        return fail(err, HINT)
      }
    },
  })

  ctx.tools.register({
    name: 'wechat_history',
    description:
      '读取与某个人/某个群的聊天记录，按时间升序返回。chat 可以是备注名、昵称、群名或 wxid，'
      + '会自动模糊匹配；群聊消息会标注发送者。用于总结、分析、找出处。',
    parameters: {
      type: 'object',
      properties: {
        chat: { type: 'string', description: '聊天对象的名字（备注/昵称/群名）或 wxid' },
        limit: { type: 'integer', description: '返回条数，默认 50，最多 500' },
        start: { type: 'string', description: '起始时间，如 2026-10-01 或 2026-10-01 08:00（含）' },
        end: { type: 'string', description: '结束时间（含）' },
      },
      required: ['chat'],
      additionalProperties: false,
    },
    output: textResult(),
    async execute(args) {
      try {
        const { account, keys, contacts } = prepare(cfg)
        const sessions = listSessions(account, keys, contacts, 1000, cfg)
        const username = resolveChat(contacts, sessions, args.chat)
        if (!username) {
          return `找不到「${args.chat}」。可以先用 wechat_contacts 或 wechat_sessions 确认名字。`
        }
        const opts = {
          limit: clampInt(args.limit, 50, 1, 500),
          since: parseTime(args.start),
          until: parseTime(args.end),
        }
        const res = readMessages(account, keys, contacts, username, opts, cfg)
        if (!res.found) return `${displayName(contacts, username)} 没有可读的消息记录（可能这个聊天还没产生消息）。`
        if (res.messages.length === 0) return `该时间段内没有消息。`
        const head = `${displayName(contacts, username)}（${username}） 最近 ${res.messages.length} 条消息`
          + (username.includes('@chatroom') ? ' [群聊]' : '')
        const lines = [head, '']
        for (const m of res.messages) {
          const who = m.senderName || m.sender || ''
          lines.push(`${fmtTime(m.time)}  ${who ? who + ': ' : ''}${oneLine(m.text, 1000)}`)
        }
        return lines.join('\n')
      } catch (err) {
        return fail(err, HINT)
      }
    },
  })

  ctx.tools.register({
    name: 'wechat_search',
    description:
      '在所有聊天记录里搜关键词（或限定某个聊天里搜），返回命中消息及所属会话、时间。'
      + '用于回忆「谁提过某件事」「那句话在哪」。',
    parameters: {
      type: 'object',
      properties: {
        keyword: { type: 'string', description: '要搜索的关键词' },
        chat: { type: 'string', description: '可选，只在某个聊天里搜（备注/昵称/群名）' },
        limit: { type: 'integer', description: '返回条数，默认 30，最多 200' },
        start: { type: 'string', description: '可选，从这个时间之后开始搜' },
      },
      required: ['keyword'],
      additionalProperties: false,
    },
    output: textResult(),
    async execute(args) {
      try {
        const { account, keys, contacts } = prepare(cfg)
        let username
        if (args.chat) {
          const sessions = listSessions(account, keys, contacts, 1000, cfg)
          username = resolveChat(contacts, sessions, args.chat)
          if (!username) return `找不到聊天「${args.chat}」。`
        }
        const hits = searchMessages(account, keys, contacts, String(args.keyword), {
          limit: clampInt(args.limit, 30, 1, 200),
          since: parseTime(args.start) ?? 0,
          username,
        }, cfg)
        if (hits.length === 0) return `没有搜到「${args.keyword}」。`
        const lines = [`「${args.keyword}」命中 ${hits.length} 条`, '']
        for (const h of hits) {
          const who = h.senderName || h.sender || ''
          lines.push(`[${fmtTime(h.time)}] ${h.chat}${who ? ' / ' + who : ''}`)
          lines.push(`    ${oneLine(h.text, 400)}`)
        }
        return lines.join('\n')
      } catch (err) {
        return fail(err, HINT)
      }
    },
  })

  ctx.tools.register({
    name: 'wechat_contacts',
    description: '搜索微信联系人（按备注、昵称、wxid 模糊匹配），用来确认某人对应哪个 wxid。',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: '关键词，留空则列出最近有会话的联系人' },
        limit: { type: 'integer', description: '返回条数，默认 30' },
      },
      additionalProperties: false,
    },
    output: textResult(),
    async execute(args) {
      try {
        const { account, keys, contacts } = prepare(cfg)
        const limit = clampInt(args.limit, 30, 1, 300)
        const q = String(args.query || '').trim().toLowerCase()
        let pool = [...contacts.values()]
        if (!q) {
          const sessions = listSessions(account, keys, contacts, 300, cfg)
          const seen = new Set()
          pool = sessions
            .map((s) => ({ username: s.username, display: s.display, remark: '', nick: '' }))
            .filter((x) => (seen.has(x.username) ? false : (seen.add(x.username), true)))
        } else {
          pool = pool.filter((c) =>
            c.display.toLowerCase().includes(q) || (c.nick || '').toLowerCase().includes(q) || c.username.toLowerCase().includes(q))
        }
        pool = pool.slice(0, limit)
        if (pool.length === 0) return `没有匹配「${args.query || ''}」的联系人。`
        const lines = [`${pool.length} 个联系人`, '']
        for (const c of pool) {
          const bits = [c.username]
          if (c.remark) bits.push(`备注: ${c.remark}`)
          if (c.nick) bits.push(`昵称: ${c.nick}`)
          lines.push(bits.join('  '))
        }
        return lines.join('\n')
      } catch (err) {
        return fail(err, HINT)
      }
    },
  })
}

function clampInt(v, dflt, lo, hi) {
  const n = Number(v)
  if (!Number.isFinite(n)) return dflt
  return Math.min(hi, Math.max(lo, Math.trunc(n)))
}

function oneLine(s, max) {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim()
  return t.length > max ? t.slice(0, max) + '…' : t
}
