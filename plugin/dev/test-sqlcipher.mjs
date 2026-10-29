/**
 * sqlcipher.js 单元测试：用合成页验证 加密/解密/HMAC/WAL patch。
 *
 * 为什么不用 SQLite 造测试库：真实微信库每页保留 80 字节（header[20]=80），
 * 普通 SQLite 库没有保留区，cell 内容会堆到页尾，无法模拟。
 * 真实库读取验证由 dev/live-check.mjs 在拿到密钥后执行。
 */
import { createCipheriv, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import assert from 'node:assert/strict'

import {
  PAGE, RESERVE, SALT_SIZE, IV_SIZE, IV_OFFSET, SQLITE_HDR,
  decryptFile, patchWal, readPage1, verifyKey,
} from '../lib/sqlcipher.js'

const ZEROS = Buffer.alloc(RESERVE)

function macKeyOf(encKey, salt) {
  const macSalt = Buffer.alloc(salt.length)
  for (let i = 0; i < salt.length; i++) macSalt[i] = salt[i] ^ 0x3a
  return pbkdf2Sync(encKey, macSalt, 2, 32, 'sha512')
}

/** 按微信布局加密一页；mac key 由该库的 salt 派生。 */
function encryptPage(encKey, plain, pgno, iv, dbSalt) {
  const body = pgno === 1 ? plain.subarray(16, IV_OFFSET) : plain.subarray(0, IV_OFFSET)
  const c = createCipheriv('aes-256-cbc', encKey, iv)
  c.setAutoPadding(false)
  const ct = Buffer.concat([c.update(body), c.final()])
  const salt = pgno === 1 ? plain.subarray(0, SALT_SIZE) : null
  const h = createHmac('sha512', macKeyOf(encKey, dbSalt))
  h.update(ct)
  h.update(iv)
  const pn = Buffer.alloc(4)
  pn.writeUInt32LE(pgno, 0)
  h.update(pn)
  return pgno === 1
    ? Buffer.concat([salt, ct, iv, h.digest()])
    : Buffer.concat([ct, iv, h.digest()])
}

const dir = mkdtempSync(join(tmpdir(), 'wxselftest-'))
const encKey = randomBytes(32)
const salt = randomBytes(16)

// ---- 合成明文页：前 4016 字节放内容，尾部 80 字节为保留区（全 0）----
const plainPages = []
for (let i = 0; i < 3; i++) {
  const page = Buffer.alloc(PAGE)
  randomBytes(IV_OFFSET).copy(page, 0)
  if (i === 0) salt.copy(page, 0) // 真实库里第 1 页前 16 字节被 salt 占位
  plainPages.push(page)
}
const plain = Buffer.concat(plainPages)

// ---- 加密 ----
const encPath = join(dir, 'enc.db')
writeFileSync(encPath, Buffer.concat(plainPages.map((p, i) => encryptPage(encKey, p, i + 1, randomBytes(IV_SIZE), salt))))
console.log(`[1] 合成加密库: 3 页 / ${readFileSync(encPath).length} bytes`)

// ---- 密钥校验 ----
const p1 = readPage1(encPath)
assert.equal(verifyKey(encKey, p1), true)
assert.equal(verifyKey(randomBytes(32), p1), false)
const flipped = Buffer.from(p1)
flipped[100] ^= 0xff
assert.equal(verifyKey(encKey, flipped), false)
console.log('[2] HMAC: 正确密钥通过 / 错误密钥拒绝 / 篡改检测')

// ---- 解密并逐字节比对 ----
const decPath = join(dir, 'dec.db')
decryptFile(encPath, decPath, encKey)
const dec = readFileSync(decPath)
assert.equal(dec.length, plain.length)
for (let i = 0; i < 3; i++) {
  // 第 1 页前 16 字节在密文里是 salt，解密后应还原成 SQLite 头
  const start = i === 0 ? 16 : 0
  assert.ok(plain.subarray(i * PAGE + start, i * PAGE + IV_OFFSET).equals(dec.subarray(i * PAGE + start, i * PAGE + IV_OFFSET)), `第 ${i + 1} 页明文不一致`)
  assert.ok(dec.subarray(i * PAGE + IV_OFFSET, (i + 1) * PAGE).equals(ZEROS), `第 ${i + 1} 页保留区未清零`)
}
assert.ok(dec.subarray(0, 16).equals(SQLITE_HDR))
console.log('[3] 全量解密: 3 页逐字节一致，保留区清零')

// ---- WAL patch ----
const salt1 = Math.floor(Math.random() * 0xffffffff)
const salt2 = Math.floor(Math.random() * 0xffffffff)
const newPage = Buffer.alloc(PAGE)
randomBytes(IV_OFFSET).copy(newPage, 0)
const encNew = encryptPage(encKey, newPage, 2, randomBytes(IV_SIZE), salt)
const fh = Buffer.alloc(24)
fh.writeUInt32BE(2, 0)
fh.writeUInt32BE(3, 4)
fh.writeUInt32BE(salt1, 8)
fh.writeUInt32BE(salt2, 12)
const wh = Buffer.alloc(32)
wh.writeUInt32BE(0x377f0683, 0)
wh.writeUInt32BE(3007000, 4)
wh.writeUInt32BE(PAGE, 8)
wh.writeUInt32BE(1, 12)
wh.writeUInt32BE(salt1, 16)
wh.writeUInt32BE(salt2, 20)
const walPath = join(dir, 'enc.db-wal')
writeFileSync(walPath, Buffer.concat([wh, fh, encNew]))

assert.equal(patchWal(walPath, decPath, encKey), 1)
const after = readFileSync(decPath)
assert.ok(after.subarray(PAGE, PAGE + IV_OFFSET).equals(newPage.subarray(0, IV_OFFSET)), 'WAL 帧未写入')
assert.ok(after.subarray(0, PAGE).equals(dec.subarray(0, PAGE)), '不该动第 1 页')
console.log('[4] WAL patch: 只改目标页，其余页不动')

// ---- 旧周期帧必须被跳过 ----
const oldFrame = Buffer.from(fh)
oldFrame.writeUInt32BE((salt1 ^ 0xdead) >>> 0, 8)
writeFileSync(walPath, Buffer.concat([wh, oldFrame, encNew, fh, encNew]))
assert.equal(patchWal(walPath, decPath, encKey), 1)
console.log('[5] WAL 周期过滤: 旧 salt 帧被跳过')

console.log('\n全部通过  ' + dir)
