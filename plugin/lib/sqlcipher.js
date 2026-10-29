/**
 * 微信 4.x 本地库解密（SQLCipher 4 变体）
 *
 * 参数（与 WCDB 实测一致）：
 *   AES-256-CBC, page=4096, reserve=80（末尾 IV 16 + HMAC-SHA512 64）
 *   每页布局 p>1 : [ciphertext 4016][IV 16][HMAC 64]
 *   每页布局 p=1 : [salt 16][ciphertext 4000][IV 16][HMAC 64]
 *   mac_key = PBKDF2-SHA512(enc_key, salt ^ 0x3a, 2 iters, 32B)
 *   HMAC-SHA512(ciphertext || IV || pageNo-LE32)
 *
 * 只读：解密结果写到缓存目录，绝不写回微信原始文件。
 */
import { createDecipheriv, createHmac, pbkdf2Sync, timingSafeEqual } from 'node:crypto'
import { closeSync, fstatSync, openSync, readFileSync, readSync, writeFileSync, writeSync } from 'node:fs'

export const PAGE = 4096
export const RESERVE = 80
export const IV_SIZE = 16
export const HMAC_SIZE = 64
export const SALT_SIZE = 16
export const SQLITE_HDR = Buffer.from('SQLite format 3\u0000', 'latin1')

const ZEROS = Buffer.alloc(RESERVE)
export const IV_OFFSET = PAGE - RESERVE // 4016

const PAGE_NO = Buffer.alloc(4)

function macKeyOf(encKey, salt) {
  const macSalt = Buffer.alloc(salt.length)
  for (let i = 0; i < salt.length; i++) macSalt[i] = salt[i] ^ 0x3a
  return pbkdf2Sync(encKey, macSalt, 2, 32, 'sha512')
}

function pageHmac(macKey, page, pgno) {
  const h = createHmac('sha512', macKey)
  h.update(page.subarray(SALT_SIZE, IV_OFFSET + IV_SIZE))
  PAGE_NO.writeUInt32LE(pgno, 0)
  h.update(PAGE_NO)
  return h.digest()
}

/** 用第 1 页校验密钥是否正确（HMAC + 解密后文件头双重校验）。 */
export function verifyKey(encKey, page1) {
  if (page1.length < PAGE) return false
  const salt = page1.subarray(0, SALT_SIZE)
  const expect = page1.subarray(PAGE - HMAC_SIZE)
  let ok = false
  try {
    const got = pageHmac(macKeyOf(encKey, salt), page1, 1)
    ok = got.length === expect.length && timingSafeEqual(got, expect)
  } catch {
    return false
  }
  if (!ok) return false
  try {
    const dec = decryptPage(encKey, page1, 1)
    return dec.subarray(0, 16).equals(SQLITE_HDR)
  } catch {
    return false
  }
}

/** 解密单页，返回 4096 字节明文页（尾部 80 字节为保留区，填 0）。 */
export function decryptPage(encKey, page, pgno) {
  const iv = page.subarray(IV_OFFSET, IV_OFFSET + IV_SIZE)
  const body = pgno === 1 ? page.subarray(SALT_SIZE, IV_OFFSET) : page.subarray(0, IV_OFFSET)
  const decipher = createDecipheriv('aes-256-cbc', encKey, iv)
  decipher.setAutoPadding(false)
  const out = Buffer.concat([decipher.update(body), decipher.final()])
  if (pgno === 1) return Buffer.concat([SQLITE_HDR, out, ZEROS])
  return Buffer.concat([out, ZEROS])
}

/** 全量解密一个 .db 到 dst。返回页数。 */
export function decryptFile(src, dst, encKey) {
  const buf = readFileSync(src)
  const pages = Math.ceil(buf.length / PAGE)
  const out = Buffer.alloc(pages * PAGE)
  for (let i = 0; i < pages; i++) {
    const page = buf.subarray(i * PAGE, Math.min((i + 1) * PAGE, buf.length))
    const full = page.length === PAGE ? page : Buffer.concat([page, Buffer.alloc(PAGE - page.length)])
    decryptPage(encKey, full, i + 1).copy(out, i * PAGE)
  }
  writeFileSync(dst, out)
  return pages
}

const WAL_HDR = 32
const WAL_FRAME = 24 + PAGE

/**
 * 把 WAL 中当前周期的有效帧 patch 进已解密副本。
 * WAL 预分配 4MB，含上一周期遗留帧，用 salt 区分。
 */
export function patchWal(walPath, dbPath, encKey) {
  let fd, outFd
  try {
    fd = openSync(walPath, 'r')
  } catch {
    return 0
  }
  const size = fstatSync(fd).size
  if (size <= WAL_HDR) {
    closeSync(fd)
    return 0
  }
  const wal = readFileSync(walPath)
  closeSync(fd)

  const salt1 = wal.readUInt32BE(16)
  const salt2 = wal.readUInt32BE(20)
  let patched = 0
  outFd = openSync(dbPath, 'r+')
  const frame = Buffer.alloc(WAL_FRAME)
  for (let off = WAL_HDR; off + WAL_FRAME <= wal.length; off += WAL_FRAME) {
    wal.copy(frame, 0, off, off + WAL_FRAME)
    const pgno = frame.readUInt32BE(0)
    if (pgno === 0 || pgno > 1_000_000) continue
    if (frame.readUInt32BE(8) !== salt1 || frame.readUInt32BE(12) !== salt2) continue
    const dec = decryptPage(encKey, frame.subarray(24), pgno)
    writeSync(outFd, dec, 0, dec.length, (pgno - 1) * PAGE)
    patched++
  }
  closeSync(outFd)
  return patched
}

/** 读第 1 页。 */
export function readPage1(path) {
  const fd = openSync(path, 'r')
  const buf = Buffer.alloc(PAGE)
  const n = readSync(fd, buf, 0, PAGE, 0)
  closeSync(fd)
  return n === PAGE ? buf : buf.subarray(0, n)
}
