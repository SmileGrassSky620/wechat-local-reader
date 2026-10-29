/**
 * 微信本地数据访问层。
 *
 * 职责：
 *  1. 定位账号数据目录（xwechat_files/<wxid>/db_storage）
 *  2. 调 wxkey.py 从 Weixin.exe 内存取密钥，并缓存/校验
 *  3. 把加密 .db 解密到缓存目录（含 WAL 增量），mtime 变了才重解
 *  4. 只读查询：会话、联系人、聊天记录、全文搜索
 *
 * 安全边界：只读微信原始文件；所有写入都发生在缓存目录。
 */
import { execFileSync } from 'node:child_process'
import { createHash, pbkdf2Sync } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { zstdDecompressSync } from 'node:zlib'
import { DatabaseSync } from 'node:sqlite'

import { decryptFile, patchWal, readPage1, verifyKey, SQLITE_HDR, SALT_SIZE } from './sqlcipher.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const ZSTD_MAGIC = 0xfd2fb528

/** 源文件是否已经是明文 SQLite（支持"别人已解密的库"这种目录）。 */
export function isPlaintextDb(path) {
  const head = readPage1(path)
  return head.length >= 16 && head.subarray(0, 16).equals(SQLITE_HDR)
}

export function walkDbs(dbDir) {
  const rels = []
  const walk = (dir, prefix) => {
    let entries = []
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const rel = prefix ? `${prefix}/${e.name}` : e.name
      if (e.isDirectory()) {
        walk(join(dir, e.name), rel)
      } else if (e.name.endsWith('.db')) {
        try {
          // 小于 1 页的必然不是真实库（占位/损坏文件）
          if (statSync(join(dir, e.name)).size >= 4096) rels.push(rel)
        } catch {}
      }
    }
  }
  walk(dbDir, '')
  return rels.sort()
}

/** 需要密钥的库（加密的那些）。 */
export function encryptedDbs(account) {
  return walkDbs(account.dbDir).filter((rel) => !isPlaintextDb(join(account.dbDir, rel.replaceAll('/', '\\'))))
}

export class WeChatError extends Error {
  constructor(message, code) {
    super(message)
    this.code = code
  }
}

// ---------------------------------------------------------------- 路径定位

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function findPython() {
  const candidates = []
  const rt = join(dshHome(), 'dsh-runtimes')
  try {
    for (const name of readdirSync(rt)) {
      candidates.push(join(rt, name, 'dependencies', 'python', 'python.exe'))
    }
  } catch {}
  candidates.push('python')
  for (const c of candidates) {
    if (c === 'python' || existsSync(c)) return c
  }
  throw new WeChatError('找不到 Python 运行时（取密钥需要它）', 'no-python')
}

/** 找 xwechat_files 根目录。 */
export function findDbRoot(config = {}) {
  if (config.dbDir) {
    if (!existsSync(config.dbDir)) throw new WeChatError(`配置的 dbDir 不存在: ${config.dbDir}`, 'no-db-dir')
    return config.dbDir.replace(/[\\/]db_storage$/, '')
  }
  const docs = join(homedir(), 'Documents')
  const roots = [join(docs, 'xwechat_files'), join(docs, 'WeChat Files')]
  for (const r of roots) {
    if (existsSync(r)) return r
  }
  throw new WeChatError('找不到微信数据目录（默认应在 文档\\xwechat_files）', 'no-wechat-dir')
}

/**
 * 选账号目录：配置指定优先，否则选 session.db 最新改动的那个。
 * @returns {account, accountDir, dbDir}
 */
export function resolveAccount(config = {}) {
  const root = findDbRoot(config)
  let dirs = []
  try {
    dirs = readdirSync(root, { withFileTypes: true })
      .filter((d) => d.isDirectory() && /^wxid_.+_[0-9a-f]+$/i.test(d.name))
      .map((d) => d.name)
  } catch {}
  if (dirs.length === 0) throw new WeChatError(`${root} 下没有账号目录`, 'no-account')

  if (config.account) {
    const hit = dirs.find((d) => d === config.account || d.startsWith(config.account + '_'))
    if (!hit) throw new WeChatError(`配置的账号不存在: ${config.account}（可用: ${dirs.join(', ')}）`, 'no-account')
    return mkAccount(root, hit)
  }

  const scored = dirs.map((d) => {
    const dbDir = join(root, d, 'db_storage')
    const probe = join(dbDir, 'session', 'session.db')
    let mtime = existsSync(probe) ? statSync(probe).mtimeMs : 0
    if (!mtime) {
      try {
        for (const f of readdirSync(join(dbDir, 'message'))) {
          if (f.endsWith('.db')) mtime = Math.max(mtime, statSync(join(dbDir, 'message', f)).mtimeMs)
        }
      } catch {}
    }
    return { dir: d, mtime }
  }).sort((a, b) => b.mtime - a.mtime)

  return mkAccount(root, scored[0].dir)
}

function mkAccount(root, dirName) {
  const accountDir = join(root, dirName)
  const dbDir = join(accountDir, 'db_storage')
  if (!existsSync(dbDir)) throw new WeChatError(`${accountDir} 下没有 db_storage`, 'no-db-dir')
  return { account: dirName.replace(/_[0-9a-f]+$/i, ''), accountDir, dbDir }
}

function cacheDirOf(config = {}) {
  const dir = config.cacheDir || join(dshHome(), 'cache', 'wechat-reader')
  mkdirSync(dir, { recursive: true })
  return dir
}

// ---------------------------------------------------------------- 密钥

/**
 * 主密钥（master key）路径：微信 4.1.11+ 不再在内存缓存 x'<hex>' 形式的库密钥，
 * 改为「一个 32 字节主密钥 + 每库 salt 经 PBKDF2-SHA512(256000) 派生」。
 * 拿到主密钥即可离线派生全部库密钥。
 */
export const KDF_ITERATIONS = 256_000

export function readMasterKey(config = {}) {
  if (config.masterKey) return String(config.masterKey).trim()
  const f = join(cacheDirOf(config), 'master.key')
  if (existsSync(f)) {
    const v = readFileSync(f, 'utf8').trim()
    return v || null
  }
  return null
}

export function saveMasterKey(config, hex) {
  const clean = normalizeMasterHex(hex)
  writeFileSync(join(cacheDirOf(config), 'master.key'), clean + '\n')
  return clean
}

function normalizeMasterHex(hex) {
  const clean = String(hex || '').trim().replace(/^x'|'$/g, '').replace(/\s+/g, '')
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new WeChatError('主密钥必须是 64 位十六进制字符串（32 字节）', 'bad-master')
  }
  return clean.toLowerCase()
}

/** 用主密钥为每个加密库派生 enc_key，只保留 HMAC 验证通过的。 */
export function deriveKeysFromMaster(account, masterHex, config = {}) {
  const master = Buffer.from(normalizeMasterHex(masterHex), 'hex')
  const keys = {}
  const missing = []
  for (const rel of encryptedDbs(account)) {
    const src = join(account.dbDir, rel.replaceAll('/', '\\'))
    let page1
    try {
      page1 = readPage1(src)
    } catch {
      continue
    }
    const salt = page1.subarray(0, SALT_SIZE)
    const encKey = pbkdf2Sync(master, salt, KDF_ITERATIONS, 32, 'sha512')
    if (verifyKey(encKey, page1)) {
      keys[rel] = { enc_key: encKey.toString('hex'), salt: salt.toString('hex'), derived: true }
    } else {
      missing.push(rel)
    }
  }
  if (Object.keys(keys).length === 0) {
    throw new WeChatError('主密钥和这个账号的数据库对不上（没有一个库能解），请确认是当前登录账号的密钥', 'master-mismatch')
  }
  return { keys, missing }
}

/**
 * 读/生成密钥缓存。缓存按 (账号, dbDir) 归属，且每次都用当前第 1 页校验，
 * 微信重置加密后旧 key 会自动失效。
 *
 * 优先级：有效缓存 → 主密钥（配置或已保存）→ 4.0 风格内存扫描。
 */
export function ensureKeys(account, config = {}, { force = false } = {}) {
  const cache = cacheDirOf(config)
  const keyFile = join(cache, `keys-${account.account.replace(/[^\w.-]/g, '_')}.json`)
  const sessionDb = join(account.dbDir, 'session', 'session.db')

  // 已经全是明文库（例如用户自己解密过），不需要密钥
  const needKey = encryptedDbs(account)
  if (needKey.length === 0) {
    return { account: account.account, dbDir: account.dbDir, plaintext: true, keys: {} }
  }

  if (!force && existsSync(keyFile)) {
    try {
      const saved = JSON.parse(readFileSync(keyFile, 'utf8'))
      if (saved.dbDir === account.dbDir && saved.keys?.['session/session.db']?.enc_key) {
        const page1 = readPage1(sessionDb)
        const key = Buffer.from(saved.keys['session/session.db'].enc_key, 'hex')
        if (verifyKey(key, page1)) return saved
      }
    } catch {}
  }

  // 主密钥路径
  const master = readMasterKey(config)
  if (master) {
    const { keys, missing } = deriveKeysFromMaster(account, master, config)
    const record = {
      account: account.account,
      dbDir: account.dbDir,
      generatedAt: new Date().toISOString(),
      source: 'master-key',
      missing,
      keys,
    }
    writeFileSync(keyFile, JSON.stringify(record, null, 2))
    return record
  }

  const py = findPython()
  const script = join(HERE, 'wxkey.py')
  let raw
  try {
    raw = execFileSync(py, [script, '--db-dir', account.dbDir], {
      encoding: 'utf8',
      timeout: 180_000,
      windowsHide: true,
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
    })
  } catch (err) {
    throw new WeChatError(`取密钥的脚本执行失败: ${err.message}`, 'key-exec')
  }
  let out
  try {
    out = JSON.parse(raw.trim().split('\n').pop())
  } catch {
    throw new WeChatError(`取密钥的脚本输出无法解析: ${raw.slice(0, 300)}`, 'key-parse')
  }
  if (!out.ok) {
    if (out.code === 'no-key') {
      throw new WeChatError(
        '没能在微信内存里自动取到密钥。微信 4.1.11 之后不再缓存旧格式密钥，需要提供主密钥。',
        'need-master-key',
      )
    }
    throw new WeChatError(out.message || '取密钥失败', out.code || 'key-failed')
  }

  const record = {
    account: account.account,
    dbDir: account.dbDir,
    generatedAt: new Date().toISOString(),
    pid: out.pid,
    stats: out.stats,
    missing: out.missing || [],
    keys: out.keys,
  }
  writeFileSync(keyFile, JSON.stringify(record, null, 2))
  return record
}

// ---------------------------------------------------------------- 解密缓存

const decryptState = new Map() // rel -> { dbMtime, walMtime, path }

/** 拿到 rel 对应的已解密文件路径（必要时重解）。 */
export function materialize(account, keys, rel, config = {}) {
  const src = join(account.dbDir, rel.replaceAll('/', '\\'))
  if (!existsSync(src)) throw new WeChatError(`源文件不存在: ${src}`, 'no-src')
  if (isPlaintextDb(src)) return src

  const keyInfo = keys.keys[rel]
  if (!keyInfo) {
    throw new WeChatError(`没有 ${rel} 的密钥（该库可能未被微信打开过）`, 'no-key-for-db')
  }

  const wal = src + '-wal'
  const dbMtime = statSync(src).mtimeMs
  const walMtime = existsSync(wal) ? statSync(wal).mtimeMs : 0

  const prev = decryptState.get(rel)
  if (prev && prev.dbMtime === dbMtime && prev.walMtime === walMtime && existsSync(prev.path)) {
    return prev.path
  }

  const outPath = join(cacheDirOf(config), 'db', rel.replaceAll('/', '_'))
  mkdirSync(dirname(outPath), { recursive: true })
  const encKey = Buffer.from(keyInfo.enc_key, 'hex')

  const page1 = readPage1(src)
  if (!verifyKey(encKey, page1)) {
    decryptState.delete(rel)
    throw new WeChatError(`密钥校验失败（微信可能重新加密过）。请重启微信或重试 wechat_status 刷新密钥`, 'key-stale')
  }

  decryptFile(src, outPath, encKey)
  if (walMtime) patchWal(wal, outPath, encKey)
  decryptState.set(rel, { dbMtime, walMtime, path: outPath })
  return outPath
}

/** 只读打开一个库并执行 fn。 */
export function withDb(account, keys, rel, fn, config = {}) {
  const path = materialize(account, keys, rel, config)
  const db = new DatabaseSync(path, { readOnly: true })
  try {
    return fn(db)
  } finally {
    db.close()
  }
}

// ---------------------------------------------------------------- 内容解码

/** message_content 可能是 TEXT、zstd 压缩的 BLOB，或二进制。 */
export function decodeContent(value) {
  if (value == null) return ''
  if (typeof value === 'string') return value
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value.buffer, value.byteOffset, value.byteLength)
  if (buf.length >= 4 && buf.readUInt32LE(0) === ZSTD_MAGIC) {
    try {
      return zstdDecompressSync(buf).toString('utf8')
    } catch {
      return '[解压失败]'
    }
  }
  return buf.toString('utf8')
}

// ---------------------------------------------------------------- 联系人 & 会话

export function loadContacts(account, keys, config = {}) {
  const map = new Map()
  const add = (r) => {
    const display = r.remark || r.nick_name || r.alias || r.username
    map.set(r.username, {
      username: r.username,
      nick: r.nick_name || '',
      remark: r.remark || '',
      alias: r.alias || '',
      display,
    })
  }
  try {
    withDb(account, keys, 'contact/contact.db', (db) => {
      try {
        for (const r of db.prepare('SELECT username, nick_name, remark, alias FROM contact').all()) add(r)
      } catch {
        for (const r of db.prepare('SELECT username, nick_name, remark FROM contact').all()) add(r)
      }
    }, config)
  } catch (err) {
    if (err instanceof WeChatError) throw err
  }
  return map
}

export function displayName(contacts, username) {
  if (!username) return ''
  return contacts.get(username)?.display || username
}

export function listSessions(account, keys, contacts, limit = 20, config = {}) {
  return withDb(account, keys, 'session/session.db', (db) => {
    const rows = db.prepare(`
      SELECT username, unread_count, summary, last_timestamp,
             last_msg_type, last_msg_sender, last_sender_display_name
      FROM SessionTable
      WHERE last_timestamp > 0
      ORDER BY last_timestamp DESC
      LIMIT ?
    `).all(limit)
    return rows.map((r) => {
      const isGroup = String(r.username).includes('@chatroom')
      const raw = decodeContent(r.summary)
      return {
        ...r,
        summary: isGroup ? splitSender(raw).text : raw,
        display: displayName(contacts, r.username),
        isGroup,
        senderDisplay: r.last_msg_sender ? displayName(contacts, r.last_msg_sender) : '',
      }
    })
  }, config)
}

/** 群消息正文形如 "wxid_xxx:\n内容"，拆出发送者。 */
export function splitSender(text) {
  const idx = text.indexOf(':\n')
  if (idx > 0 && idx <= 64 && !text.slice(0, idx).includes('\n')) {
    return { sender: text.slice(0, idx), text: text.slice(idx + 2) }
  }
  return { sender: '', text }
}

// ---------------------------------------------------------------- 聊天记录

export function msgTableOf(username) {
  return `Msg_${md5(username)}`
}

/** 在所有 message_N.db 里找这个人的消息表。 */
export function findMsgDb(account, keys, username, config = {}) {
  const table = msgTableOf(username)
  const dbs = listMessageDbs(account)
  for (const rel of dbs) {
    let hit = false
    try {
      hit = withDb(account, keys, rel, (db) => {
        const row = db.prepare("SELECT 1 AS x FROM sqlite_master WHERE type='table' AND name=?").get(table)
        return Boolean(row)
      }, config)
    } catch {
      continue
    }
    if (hit) return { rel, table }
  }
  return null
}

/** 所有 message_N.db（排除 fts/resource/biz）。 */
export function listMessageDbs(account) {
  return walkDbs(account.dbDir).filter((rel) => /^message\/message_\d+\.db$/.test(rel))
}

export function readMessages(account, keys, contacts, username, opts = {}, config = {}) {
  const limit = clamp(opts.limit ?? 50, 1, 500)
  const found = findMsgDb(account, keys, username, config)
  if (!found) return { messages: [], found: false }

  const { rel, table } = found
  const where = []
  const params = []
  if (opts.since) { where.push('create_time >= ?'); params.push(opts.since) }
  if (opts.until) { where.push('create_time <= ?'); params.push(opts.until) }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''

  const rows = withDb(account, keys, rel, (db) => {
    const sql = `SELECT local_id, local_type, create_time, message_content, WCDB_CT_message_content
                 FROM [${table}] ${whereSql} ORDER BY create_time DESC, local_id DESC LIMIT ?`
    return db.prepare(sql).all(...params, limit)
  }, config)

  const isGroup = String(username).includes('@chatroom')
  const messages = rows.reverse().map((r) => normalizeMessage(r, isGroup, contacts))
  return { messages, found: true, db: rel, total: messages.length }
}

export function searchMessages(account, keys, contacts, keyword, opts = {}, config = {}) {
  const limit = clamp(opts.limit ?? 30, 1, 200)
  const since = opts.since ?? 0
  const scanCap = opts.scanCap ?? 20_000
  const needle = String(keyword).toLowerCase()
  const onlyChat = opts.username ? findMsgDb(account, keys, opts.username, config) : null
  const dbs = onlyChat ? [onlyChat.rel] : listMessageDbs(account)

  const hits = []
  for (const rel of dbs) {
    if (hits.length >= limit) break
    let tables
    try {
      tables = withDb(account, keys, rel, (db) =>
        db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'").all()
          .map((r) => r.name), config)
    } catch {
      continue
    }
    const nameMap = tableToUser(account, keys, rel, config)
    for (const table of tables) {
      if (hits.length >= limit) break
      if (onlyChat && table !== onlyChat.table) continue
      let rows
      try {
        // 不能只用 SQL LIKE：压缩列是 BLOB，LIKE 搜不到，必须解码后再比
        rows = withDb(account, keys, rel, (db) =>
          db.prepare(`SELECT local_id, local_type, create_time, message_content, WCDB_CT_message_content
                      FROM [${table}] WHERE create_time >= ?
                      ORDER BY create_time DESC LIMIT ?`).all(since, scanCap), config)
      } catch {
        continue
      }
      const username = nameMap.get(table) || ''
      const isGroup = username.includes('@chatroom')
      for (const r of rows) {
        const text = decodeContent(r.message_content)
        if (!text || !text.toLowerCase().includes(needle)) continue
        hits.push({ ...normalizeMessage(r, isGroup, contacts), username, chat: displayName(contacts, username) || table })
        if (hits.length >= limit) break
      }
    }
  }
  hits.sort((a, b) => b.time - a.time || b.localId - a.localId)
  return hits.slice(0, limit)
}

/** Name2Id 表：user_name → Msg_<md5> 反查。 */
function tableToUser(account, keys, rel, config) {
  const map = new Map()
  try {
    withDb(account, keys, rel, (db) => {
      const rows = db.prepare('SELECT user_name FROM Name2Id').all()
      for (const r of rows) if (r.user_name) map.set(msgTableOf(r.user_name), r.user_name)
    }, config)
  } catch {}
  return map
}

const TYPE_LABEL = {
  3: '[图片]',
  34: '[语音]',
  42: '[名片]',
  43: '[视频]',
  47: '[表情]',
  48: '[位置]',
  50: '[通话]',
  10000: '[系统]',
  10002: '[撤回]',
}

/** 这些类型的正文是加密 protobuf/XML，没有可读文本，只给标签。 */
const LABEL_ONLY = new Set([3, 34, 42, 43, 47, 48, 50, 10002])

export function normalizeMessage(row, isGroup, contacts) {
  let text = decodeContent(row.message_content)
  let sender = ''
  if (isGroup) {
    const parts = splitSender(text)
    sender = parts.sender
    text = parts.text
  }
  const type = row.local_type
  if (LABEL_ONLY.has(type)) {
    text = TYPE_LABEL[type]
  } else if (type === 49) {
    const title = /<title>(?:<!\[CDATA\[)?([\s\S]{0,200}?)(?:\]\]>)?<\/title>/.exec(text)
    text = title ? `[链接/文件] ${dequote(title[1])}` : '[链接/文件]'
  } else if (type === 10000) {
    text = `[系统] ${text}`
  } else if (text.startsWith('<?xml') || text.includes('<appmsg')) {
    // 引用回复、小程序、文件等：正文是 XML，只留标题
    const t = /<title>(?:<!\[CDATA\[)?([\s\S]{0,120}?)(?:\]\]>)?<\/title>/.exec(text)
    text = t ? `[应用消息] ${dequote(t[1])}` : '[应用消息]'
  } else if (!text) {
    text = TYPE_LABEL[type] || `[type=${type}]`
  }
  return {
    localId: row.local_id,
    type,
    time: row.create_time,
    sender,
    senderName: sender ? displayName(contacts, sender) : '',
    text,
    raw: text,
  }
}

function dequote(s) {
  return s.replace(/^<!\[CDATA\[|\]\]>$/g, '').trim()
}

// ---------------------------------------------------------------- 杂项

function clamp(n, lo, hi) {
  const v = Number(n)
  return Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.trunc(v))) : lo
}

function md5(s) {
  return createHash('md5').update(s, 'utf8').digest('hex')
}
