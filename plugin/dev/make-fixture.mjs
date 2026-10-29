/**
 * 造一个"像微信加密库"的 fixture（含正确 salt/HMAC）。
 *
 * 用法:
 *   node make-fixture.mjs <outDir> [keyHex] [saltHex]
 *   node make-fixture.mjs <outDir> --master <64hex> [saltHex]   # 4.1 派生方式
 *
 * 输出: {"db": path, "key": hex, "salt": hex, "master": hex?}
 */
import { createCipheriv, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const PAGE = 4096
const IV_OFFSET = 4016

const argv = process.argv.slice(2)
const outDir = argv[0] || join(process.cwd(), 'dev', 'fixture')
let keyHex, saltHex, masterHex
if (argv[1] === '--master') {
  masterHex = argv[2]
  saltHex = argv[3]
} else {
  keyHex = argv[1]
  saltHex = argv[2]
}

const salt = saltHex ? Buffer.from(saltHex, 'hex') : randomBytes(16)
const master = masterHex ? Buffer.from(masterHex, 'hex') : null
// 4.1: enc_key = PBKDF2(master, salt, 256000, 32)
const key = master
  ? pbkdf2Sync(master, salt, 256000, 32, 'sha512')
  : keyHex ? Buffer.from(keyHex, 'hex') : randomBytes(32)

function macKey() {
  const s = Buffer.alloc(16)
  for (let i = 0; i < 16; i++) s[i] = salt[i] ^ 0x3a
  return pbkdf2Sync(key, s, 2, 32, 'sha512')
}

function encPage(plain, pgno) {
  const iv = randomBytes(16)
  const body = pgno === 1 ? plain.subarray(16, IV_OFFSET) : plain.subarray(0, IV_OFFSET)
  const c = createCipheriv('aes-256-cbc', key, iv)
  c.setAutoPadding(false)
  const ct = Buffer.concat([c.update(body), c.final()])
  const h = createHmac('sha512', macKey())
  h.update(ct).update(iv)
  const pn = Buffer.alloc(4)
  pn.writeUInt32LE(pgno, 0)
  h.update(pn)
  return pgno === 1 ? Buffer.concat([salt, ct, iv, h.digest()]) : Buffer.concat([ct, iv, h.digest()])
}

mkdirSync(join(outDir, 'session'), { recursive: true })
const pages = []
for (let i = 1; i <= 3; i++) {
  const p = Buffer.alloc(PAGE)
  randomBytes(IV_OFFSET).copy(p, 0)
  if (i === 1) Buffer.from('SQLite format 3\u0000', 'latin1').copy(p, 0)
  pages.push(encPage(p, i))
}
const dbPath = join(outDir, 'session', 'session.db')
writeFileSync(dbPath, Buffer.concat(pages))

console.log(JSON.stringify({
  db: dbPath,
  key: key.toString('hex'),
  salt: salt.toString('hex'),
  ...(master ? { master: master.toString('hex') } : {}),
}))
